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
