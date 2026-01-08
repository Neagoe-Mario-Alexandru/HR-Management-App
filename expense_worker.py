import os
import json
import time
import logging
from typing import Dict, Any, Optional

import pika
import stripe

from app import app, db
from models import ExpenseClaim, ExpenseStatus

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("expense-worker")

# ===================== RabbitMQ =====================

RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")

EXPENSES_EXCHANGE = os.environ.get("EXPENSES_EXCHANGE", "expenses")
EXPENSES_QUEUE = os.environ.get("EXPENSES_QUEUE", "expenses.process")
EXPENSES_BIND_KEY = os.environ.get("EXPENSES_BIND_KEY", "expense.requested")

NOTIFY_EXCHANGE = os.environ.get("NOTIFY_EXCHANGE", "notifications")
NOTIFY_ROUTING_KEY = os.environ.get("NOTIFY_ROUTING_KEY", "notify.expense")

# ===================== Stripe =====================

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "").strip()
USE_STRIPE_MOCK = not STRIPE_SECRET_KEY  # True dacă cheia nu există sau e goală

if USE_STRIPE_MOCK:
    logger.warning("⚠️ Stripe mock mode activated")
    
    class FakeStripePaymentIntent:
        @staticmethod
        def create(**kwargs):
            logger.info(f"[MOCK] Stripe PaymentIntent.create called with {kwargs}")
            return {"id": "pi_mocked", "status": "succeeded"}

    class FakeStripe:
        PaymentIntent = FakeStripePaymentIntent

    stripe = FakeStripe()
else:
    import stripe
    stripe.api_key = STRIPE_SECRET_KEY


# ===================== Worker tuning =====================

PREFETCH = int(os.environ.get("WORKER_PREFETCH", "10"))
MAX_RETRIES = int(os.environ.get("WORKER_CONNECT_RETRIES", "30"))
RETRY_SLEEP = float(os.environ.get("WORKER_CONNECT_RETRY_SLEEP", "2.0"))

# ===================== Behavior =====================

WORKER_AUTO_PROCESS = os.environ.get("WORKER_AUTO_PROCESS", "0") == "1"
REQUEUE_IF_NOT_APPROVED = False  # ❗ NU requeue business-state

# ====================================================


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
            logger.warning("RabbitMQ not ready (%s/%s): %s", i, MAX_RETRIES, e)
            time.sleep(RETRY_SLEEP)
    raise RuntimeError(f"RabbitMQ connection failed: {last_err}")


def _publish(ch, exchange: str, routing_key: str, payload: Dict[str, Any]) -> None:
    ch.exchange_declare(exchange=exchange, exchange_type="topic", durable=True)
    ch.basic_publish(
        exchange=exchange,
        routing_key=routing_key,
        body=json.dumps(payload).encode(),
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
    if WORKER_AUTO_PROCESS:
        return exp.status not in (
            ExpenseStatus.PAID,
            ExpenseStatus.FAILED,
            ExpenseStatus.CANCELED,
            ExpenseStatus.PROCESSING,
        )
    return exp.status == ExpenseStatus.QUEUED


# ====================================================


def _process_expense(expense_id: int, trace_id: Optional[str], notify_channel) -> None:
    """
    Business logic. Idempotent & safe.
    """
    with app.app_context():
        exp = ExpenseClaim.query.get(expense_id)
        if not exp:
            logger.warning("Expense not found: %s", expense_id)
            return

        finalized = {
            ExpenseStatus.PAID,
            ExpenseStatus.FAILED,
            ExpenseStatus.CANCELED,
            ExpenseStatus.PROCESSING,  # ❗ prevents double processing
        }

        rejected = getattr(ExpenseStatus, "REJECTED", None)
        if rejected:
            finalized.add(rejected)

        if exp.status in finalized:
            logger.info("Expense already handled: id=%s status=%s", exp.id, exp.status.value)
            return

        if not _should_process_now(exp):
            logger.info("Expense not eligible: id=%s status=%s", exp.id, exp.status.value)
            return

        # ===================== PROCESSING =====================
        exp.status = ExpenseStatus.PROCESSING
        db.session.commit()

        try:
            # ===================== MOCK MODE =====================
            if not STRIPE_SECRET_KEY:
                logger.warning("Stripe disabled → mock PAID (expense_id=%s)", exp.id)
                time.sleep(0.3)

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
                        "message": "Decont procesat (mock).",
                        "trace_id": trace_id,
                    },
                )
                return

            # ===================== STRIPE (SYNC MVP) =====================
            pi = stripe.PaymentIntent.create(
                amount=exp.amount_cents,
                currency=exp.currency,
                description=exp.description or f"Expense #{exp.id}",
                confirm=True,
                off_session=True,
                metadata={
                    "expense_id": str(exp.id),
                    "user_id": exp.user_id,
                    "trace_id": trace_id or "",
                },
            )

            if pi.status != "succeeded":
                raise RuntimeError(f"Stripe PI status={pi.status}")

            exp.stripe_payment_intent_id = pi.id
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
                    "stripe_payment_intent_id": pi.id,
                    "trace_id": trace_id,
                },
            )

            logger.info("Expense PAID: id=%s", exp.id)

        except Exception as e:
            logger.exception("Expense FAILED: id=%s err=%s", exp.id, e)
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
                        "message": str(e),
                        "trace_id": trace_id,
                    },
                )
            except Exception:
                logger.exception("Failed to publish failure event")


# ====================================================


def main() -> None:
    conn = _connect_with_retry()
    ch = conn.channel()

    ch.exchange_declare(exchange=EXPENSES_EXCHANGE, exchange_type="topic", durable=True)
    ch.queue_declare(queue=EXPENSES_QUEUE, durable=True)
    ch.queue_bind(queue=EXPENSES_QUEUE, exchange=EXPENSES_EXCHANGE, routing_key=EXPENSES_BIND_KEY)

    ch.exchange_declare(exchange=NOTIFY_EXCHANGE, exchange_type="topic", durable=True)
    ch.basic_qos(prefetch_count=PREFETCH)

    logger.info("Expense worker started")

    def on_message(channel, method, properties, body: bytes):
        try:
            msg = json.loads(body.decode())
            expense_id = int(msg["expense_id"])
            trace_id = msg.get("trace_id")
        except Exception:
            channel.basic_nack(method.delivery_tag, requeue=False)
            return

        try:
            _process_expense(expense_id, trace_id, channel)
            channel.basic_ack(method.delivery_tag)
        except Exception:
            logger.exception("Worker crash → requeue")
            channel.basic_nack(method.delivery_tag, requeue=True)

    ch.basic_consume(queue=EXPENSES_QUEUE, on_message_callback=on_message)
    ch.start_consuming()


if __name__ == "__main__":
    main()
