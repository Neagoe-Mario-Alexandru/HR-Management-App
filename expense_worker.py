import os
import json
import time
import logging
from typing import Dict, Any, Optional

import pika
import stripe

from app import app, db  # reuse same SQLAlchemy config
from models import ExpenseClaim, ExpenseStatus

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("expense-worker")

# RabbitMQ
RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")

EXPENSES_EXCHANGE = os.environ.get("EXPENSES_EXCHANGE", "expenses")
EXPENSES_QUEUE = os.environ.get("EXPENSES_QUEUE", "expenses.process")
EXPENSES_BIND_KEY = os.environ.get("EXPENSES_BIND_KEY", "expense.requested")

NOTIFY_EXCHANGE = os.environ.get("NOTIFY_EXCHANGE", "notifications")
NOTIFY_ROUTING_KEY = os.environ.get("NOTIFY_ROUTING_KEY", "notify.expense")

# Stripe
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
stripe.api_key = STRIPE_SECRET_KEY

# Worker tuning
PREFETCH = int(os.environ.get("WORKER_PREFETCH", "10"))
MAX_RETRIES = int(os.environ.get("WORKER_CONNECT_RETRIES", "30"))
RETRY_SLEEP = float(os.environ.get("WORKER_CONNECT_RETRY_SLEEP", "2.0"))

# Behavior
# If false -> worker will ONLY process expenses that are APPROVED
WORKER_AUTO_PROCESS = os.environ.get("WORKER_AUTO_PROCESS", "0") == "1"

# If true -> when a not-approved expense is received, message is requeued
# (be careful: can cause tight loops; default is False => ACK and ignore)
REQUEUE_IF_NOT_APPROVED = os.environ.get("REQUEUE_IF_NOT_APPROVED", "0") == "1"


def _connect_with_retry() -> pika.BlockingConnection:
    last_err: Optional[Exception] = None
    for i in range(1, MAX_RETRIES + 1):
        try:
            params = pika.URLParameters(RABBITMQ_URL)
            params.heartbeat = 60
            params.blocked_connection_timeout = 60
            conn = pika.BlockingConnection(params)
            logger.info("Connected to RabbitMQ (%s)", RABBITMQ_URL)
            return conn
        except Exception as e:
            last_err = e
            logger.warning("RabbitMQ not ready (attempt %s/%s): %s", i, MAX_RETRIES, e)
            time.sleep(RETRY_SLEEP)
    raise RuntimeError(f"Could not connect to RabbitMQ after {MAX_RETRIES} retries: {last_err}")


def _publish(
    ch: pika.adapters.blocking_connection.BlockingChannel,
    exchange: str,
    routing_key: str,
    payload: Dict[str, Any],
) -> None:
    ch.exchange_declare(exchange=exchange, exchange_type="topic", durable=True)
    ch.basic_publish(
        exchange=exchange,
        routing_key=routing_key,
        body=json.dumps(payload).encode("utf-8"),
        properties=pika.BasicProperties(
            delivery_mode=2,
            content_type="application/json",
        ),
    )


def _mark_failed(exp: ExpenseClaim, reason: str) -> None:
    exp.status = ExpenseStatus.FAILED
    exp.failure_reason = (reason or "")[:2000]
    db.session.commit()


def _should_process_now(exp: ExpenseClaim) -> bool:
    """
    Decide if this expense should be processed (Stripe) now.

    Default behavior (recommended):
      - Only process when status == APPROVED.
      - Expenses newly created by employee stay QUEUED/WAITING.
    """
    if WORKER_AUTO_PROCESS:
        # legacy/demo behavior: process everything except finalized
        return exp.status not in (ExpenseStatus.PAID, ExpenseStatus.FAILED, ExpenseStatus.CANCELED)

    # Recommended: require approval
    return exp.status == getattr(ExpenseStatus, "APPROVED", None)


def _process_expense(expense_id: int, trace_id: Optional[str], notify_channel) -> None:
    """
    Business logic. Must be idempotent.
    """
    with app.app_context():
        exp = ExpenseClaim.query.get(expense_id)
        if not exp:
            logger.warning("Expense not found: id=%s", expense_id)
            return

        finalized = {ExpenseStatus.PAID, ExpenseStatus.FAILED, ExpenseStatus.CANCELED}
        # If you added REJECTED in models, include it safely:
        rejected = getattr(ExpenseStatus, "REJECTED", None)
        if rejected is not None:
            finalized.add(rejected)

        # idempotency: if already finalized, ignore
        if exp.status in finalized:
            logger.info("Expense already finalized: id=%s status=%s", exp.id, exp.status.value)
            return

        # ✅ Gate: don't process until APPROVED (unless WORKER_AUTO_PROCESS=1)
        if not _should_process_now(exp):
            logger.info("Expense not eligible for processing yet: id=%s status=%s", exp.id, exp.status.value)
            return

        # transition to PROCESSING
        exp.status = ExpenseStatus.PROCESSING
        db.session.commit()

        try:
            # DEMO Stripe logic:
            # - If no STRIPE_SECRET_KEY set -> mock success
            if not STRIPE_SECRET_KEY:
                logger.warning("STRIPE_SECRET_KEY not set -> mock PAID for expense_id=%s", exp.id)
                time.sleep(0.5)  # simulate work
                exp.status = ExpenseStatus.PAID
                db.session.commit()

                _publish(
                    notify_channel,
                    NOTIFY_EXCHANGE,
                    NOTIFY_ROUTING_KEY,
                    {
                        "event": "expense.paid",
                        "expense_id": exp.id,
                        "user_id": exp.user_id,
                        "amount_cents": exp.amount_cents,
                        "currency": exp.currency,
                        "message": "Decont procesat (mock, fara Stripe).",
                        "trace_id": trace_id,
                    },
                )
                return

            # NOTE: PaymentIntent is for charging a customer; reimbursements usually mean Stripe Connect + Transfers/Payouts.
            # For demo we create a PI. In real life, you'd handle webhooks and only mark paid on succeeded.
            pi = stripe.PaymentIntent.create(
                amount=exp.amount_cents,
                currency=exp.currency,
                description=exp.description or f"Expense reimbursement #{exp.id}",
                metadata={
                    "expense_id": str(exp.id),
                    "user_id": exp.user_id,
                    "trace_id": trace_id or "",
                },
            )
            exp.stripe_payment_intent_id = pi["id"]

            exp.status = ExpenseStatus.PAID
            db.session.commit()

            _publish(
                notify_channel,
                NOTIFY_EXCHANGE,
                NOTIFY_ROUTING_KEY,
                {
                    "event": "expense.paid",
                    "expense_id": exp.id,
                    "user_id": exp.user_id,
                    "amount_cents": exp.amount_cents,
                    "currency": exp.currency,
                    "message": "Decont procesat (demo Stripe).",
                    "stripe_payment_intent_id": exp.stripe_payment_intent_id,
                    "trace_id": trace_id,
                },
            )

            logger.info("Expense PAID: id=%s", exp.id)

        except Exception as e:
            logger.exception("Expense processing failed: id=%s err=%s", exp.id, e)
            _mark_failed(exp, str(e))

            try:
                _publish(
                    notify_channel,
                    NOTIFY_EXCHANGE,
                    NOTIFY_ROUTING_KEY,
                    {
                        "event": "expense.failed",
                        "expense_id": exp.id,
                        "user_id": exp.user_id,
                        "amount_cents": exp.amount_cents,
                        "currency": exp.currency,
                        "message": f"Decont esuat: {e}",
                        "trace_id": trace_id,
                    },
                )
            except Exception:
                logger.exception("Failed to publish failure notification for expense_id=%s", exp.id)


def main() -> None:
    conn = _connect_with_retry()
    ch = conn.channel()

    # Ensure topology
    ch.exchange_declare(exchange=EXPENSES_EXCHANGE, exchange_type="topic", durable=True)
    ch.queue_declare(queue=EXPENSES_QUEUE, durable=True)
    ch.queue_bind(queue=EXPENSES_QUEUE, exchange=EXPENSES_EXCHANGE, routing_key=EXPENSES_BIND_KEY)

    ch.exchange_declare(exchange=NOTIFY_EXCHANGE, exchange_type="topic", durable=True)
    ch.basic_qos(prefetch_count=PREFETCH)

    logger.info(
        "Worker started. exchange=%s queue=%s bind=%s notify_exchange=%s auto_process=%s",
        EXPENSES_EXCHANGE,
        EXPENSES_QUEUE,
        EXPENSES_BIND_KEY,
        NOTIFY_EXCHANGE,
        WORKER_AUTO_PROCESS,
    )

    def on_message(channel, method, properties, body: bytes):
        try:
            msg = json.loads(body.decode("utf-8"))
            expense_id = int(msg["expense_id"])
            trace_id = msg.get("trace_id")
        except Exception as e:
            logger.error("Invalid message body -> nack (drop). err=%s body=%s", e, body)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            return

        try:
            # If not approved yet, we can either ACK (default) or requeue (optional).
            with app.app_context():
                exp = ExpenseClaim.query.get(expense_id)

                if exp and not _should_process_now(exp):
                    logger.info("Skip message: expense not ready. id=%s status=%s", exp.id, exp.status.value)
                    if REQUEUE_IF_NOT_APPROVED:
                        channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
                    else:
                        channel.basic_ack(delivery_tag=method.delivery_tag)
                    return

            _process_expense(expense_id=expense_id, trace_id=trace_id, notify_channel=channel)
            channel.basic_ack(delivery_tag=method.delivery_tag)

        except Exception as e:
            # Unexpected crash -> requeue so it can be retried.
            logger.exception("Unexpected worker error -> nack requeue. err=%s", e)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

    ch.basic_consume(queue=EXPENSES_QUEUE, on_message_callback=on_message, auto_ack=False)

    try:
        ch.start_consuming()
    except KeyboardInterrupt:
        logger.info("Worker stopped by user")
    finally:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
