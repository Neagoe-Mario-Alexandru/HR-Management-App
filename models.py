from database import db
from datetime import datetime
from enum import Enum as PyEnum


class UserProfile(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    keycloak_id = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class LeaveStatus(PyEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class LeaveRequest(db.Model):
    __tablename__ = "leave_requests"

    id = db.Column(db.Integer, primary_key=True)

    # Keycloak sub
    user_id = db.Column(db.String(255), nullable=False)

    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)

    reason = db.Column(db.Text, nullable=True)

    status = db.Column(
        db.Enum(LeaveStatus, name="leave_status"),
        default=LeaveStatus.PENDING,
        nullable=False
    )

    approved_by = db.Column(db.String(255), nullable=True)  # HR keycloak sub
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "start_date": self.start_date.isoformat(),
            "end_date": self.end_date.isoformat(),
            "reason": self.reason,
            "status": self.status.value,
            "approved_by": self.approved_by,
            "created_at": self.created_at.isoformat(),
        }


# ==========================
# Expense reimbursement (Deconturi)
# ==========================

class ExpenseStatus(PyEnum):
    PENDING = "PENDING"             # creat de angajat, așteaptă HR
    HR_APPROVED = "HR_APPROVED"     # aprobat de HR, așteaptă Administrator
    QUEUED = "QUEUED"               # admin a aprobat și s-a trimis în RabbitMQ
    PROCESSING = "PROCESSING"       # worker procesează
    PAID = "PAID"                   # Stripe OK
    FAILED = "FAILED"               # eroare tehnică/Stripe
    REJECTED = "REJECTED"           # respins (HR sau Admin)
    CANCELED = "CANCELED"


class ExpenseClaim(db.Model):
    """
    Cerere de decont (expense reimbursement).
    Observatie: Stripe are mai multe abordari.
    Minim: salvezi un PaymentIntent id sau un Transfer/Payout id (in functie de flow-ul tau).
    """
    __tablename__ = "expense_claims"

    id = db.Column(db.Integer, primary_key=True)

    # Keycloak sub (angajat)
    user_id = db.Column(db.String(255), nullable=False, index=True)

    # bani
    amount_cents = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(10), nullable=False, default="ron")

    description = db.Column(db.Text, nullable=True)

    # status
    status = db.Column(
        db.Enum(ExpenseStatus, name="expense_status"),
        default=ExpenseStatus.PENDING,
        nullable=False,
        index=True
    )

    # Stripe fields (optional, depinde de implementare)
    stripe_payment_intent_id = db.Column(db.String(255), nullable=True)
    stripe_charge_id = db.Column(db.String(255), nullable=True)

    # pentru erori
    failure_reason = db.Column(db.Text, nullable=True)

    # optional: cine a aprobat decontul (daca ai un flow de aprobare)
    approved_by = db.Column(db.String(255), nullable=True)

    # timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "amount_cents": self.amount_cents,
            "currency": self.currency,
            "description": self.description,
            "status": self.status.value,
            "stripe_payment_intent_id": self.stripe_payment_intent_id,
            "stripe_charge_id": self.stripe_charge_id,
            "failure_reason": self.failure_reason,
            "approved_by": self.approved_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
