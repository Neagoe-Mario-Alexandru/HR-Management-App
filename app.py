from flask import Flask, request, jsonify, redirect, session, url_for
from keycloak import KeycloakOpenID
from models import db, UserProfile, LeaveRequest, LeaveStatus, ExpenseClaim, ExpenseStatus
from datetime import datetime
import os
import time
import jwt
import smtplib
import json
from email.message import EmailMessage
import logging
import pika
import stripe
import uuid
from datetime import datetime
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app")

def read_secret_file(path: str) -> str:
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except Exception:
        return ""

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_PASS_FILE = os.environ.get("SMTP_PASS_FILE", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "no-reply@example.com")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "1") == "1"

if SMTP_PASS_FILE and not SMTP_PASS:
    SMTP_PASS = read_secret_file(SMTP_PASS_FILE)
    
    
# RabbitMQ configuration
#RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")
EXPENSES_EXCHANGE = os.environ.get("EXPENSES_EXCHANGE", "expenses")
EXPENSES_ROUTING_KEY = os.environ.get("EXPENSES_ROUTING_KEY", "expense.requested")

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")


def rabbit_publish(exchange: str, routing_key: str, payload: dict):
    params = pika.URLParameters(RABBITMQ_URL)
    conn = pika.BlockingConnection(params)
    ch = conn.channel()
    ch.exchange_declare(exchange=exchange, exchange_type="topic", durable=True)

    ch.basic_publish(
        exchange=exchange,
        routing_key=routing_key,
        body=json.dumps(payload).encode("utf-8"),
        properties=pika.BasicProperties(
            delivery_mode=2,  # persistent
            content_type="application/json",
        ),
    )
    conn.close()
    




# Environment detection
IN_DOCKER = os.environ.get("IN_DOCKER", "0") == "1"

# Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "SUPER_SECRET_SESSION_KEY")

# Roluri de business vizibile
VISIBLE_ROLES = {"Angajat", "HR", "Administrator"}

app.config.update(
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
)

# Database configuration
if IN_DOCKER:
    DB_HOST = "profile-db"
    FLASK_PORT = 5001
else:
    DB_HOST = "localhost"
    FLASK_PORT = 5002

DB_USER = os.environ.get("DB_USER", "profile")
DB_PASS = os.environ.get("DB_PASS", "profile")
DB_NAME = os.environ.get("DB_NAME", "profile")

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}"
)

db.init_app(app)


# Create tables
with app.app_context():
    for _ in range(10):
        try:
            db.create_all()
            break
        except Exception as e:
            print("Waiting for database...", e)
            time.sleep(2)


# Keycloak configuration
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "proiect-scd")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "backend-scd")

if IN_DOCKER:
    KEYCLOAK_INTERNAL = "http://keycloak:8080"
    KEYCLOAK_PUBLIC = "http://localhost:8080"
    REDIRECT_URI = "http://localhost:5001/callback"
else:
    KEYCLOAK_INTERNAL = "http://127.0.0.1:8080"
    KEYCLOAK_PUBLIC = "http://127.0.0.1:8080"
    REDIRECT_URI = "http://127.0.0.1:5002/callback"


def get_keycloak():
    return KeycloakOpenID(
        server_url=KEYCLOAK_INTERNAL,
        client_id=KEYCLOAK_CLIENT_ID,
        realm_name=KEYCLOAK_REALM,
    )


def decode_token(token):
    if not token:
        return {}
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return jwt.decode(
        token,
        options={"verify_signature": False, "verify_aud": False},
    )

def can_manage_leaves(userinfo):
    return has_role(userinfo, "HR") or has_role(userinfo, "Administrator")

def has_role(userinfo, role):
    return role in userinfo.get("realm_access", {}).get("roles", [])


def visible_roles_from_token(userinfo):
    all_roles = userinfo.get("realm_access", {}).get("roles", [])
    return [r for r in all_roles if r in VISIBLE_ROLES]


def username_for_sub(sub):
    if not sub:
        return "-"
    u = UserProfile.query.filter_by(keycloak_id=sub).first()
    return u.username if u and u.username else sub

def send_email(to_email: str, subject: str, body: str):
    if not to_email:
        logger.warning("No recipient email -> skip send")
        return

    if not SMTP_HOST:
        logger.warning("SMTP_HOST not set -> skip send")
        return

    logger.info("Sending email via %s:%s to=%s from=%s subj=%s",
                SMTP_HOST, SMTP_PORT, to_email, SMTP_FROM, subject)

    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        if SMTP_USE_TLS:
            server.starttls()
        if SMTP_USER:
            server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

    logger.info("Email sent OK to=%s", to_email)

        
def email_for_sub(sub):
    if not sub:
        return None
    u = UserProfile.query.filter_by(keycloak_id=sub).first()
    return u.email if u else None


def build_leave_email(status: LeaveStatus, leave: LeaveRequest):
    emp_username = username_for_sub(leave.user_id)
    approver = username_for_sub(leave.approved_by)

    subject = f"Cererea ta de concediu a fost {status.value}"
    body = f"""Salut, {emp_username}

Cererea ta de concediu a fost {status.value}.

Detalii:
- Perioadă: {leave.start_date} -> {leave.end_date}
- Motiv: {leave.reason or "-"}
- Status: {status.value}
- Procesată de: {approver}
- Data cererii: {leave.created_at.strftime('%Y-%m-%d')}

Mulțumim,
Sistem Concedii
"""
    return subject, body





# Home
# Routes
@app.route("/")
def home():
    if "access_token" not in session:
        return """
        <html><body style="font-family:Arial;text-align:center;margin-top:120px">
        <h2>Authentication Demo</h2>
        <a href="/login"><button>Login</button></a>
        </body></html>
        """

    userinfo = decode_token(session["access_token"])
    username = userinfo.get("preferred_username")
    email = userinfo.get("email")
    roles = visible_roles_from_token(userinfo)

    # Angajat: butoane
    leave_button = ""
    expense_button = ""
    my_leaves_button = ""
    my_expenses_button = ""

    if has_role(userinfo, "Angajat"):
        leave_button = """
            <a href="/leave/request">
                <button style="background:#28a745;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Fă cerere de concediu
                </button>
            </a>
        """
        expense_button = """
            <a href="/expenses/request">
                <button style="background:#17a2b8;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Fă cerere de decont
                </button>
            </a>
        """
        my_leaves_button = """
            <a href="/leave/my">
                <button style="background:#20c997;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Concediile mele
                </button>
            </a>
        """
        my_expenses_button = """
            <a href="/expenses/my">
                <button style="background:#0dcaf0;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Deconturile mele
                </button>
            </a>
        """

    # HR/Admin: butoane
    hr_button = ""
    profiles_button = ""
    expenses_hr_button = ""

    if can_manage_leaves(userinfo):
        hr_button = """
            <a href="/leave/all">
                <button style="background:#ff9800;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Vezi cereri concediu
                </button>
            </a>
        """
        profiles_button = """
            <a href="/users">
                <button style="background:#9c27b0;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Vezi profile angajați
                </button>
            </a>
        """
        expenses_hr_button = """
            <a href="/expenses/all">
                <button style="background:#795548;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Vezi cereri de decont
                </button>
            </a>
        """

    return f"""
    <html>
    <body style="font-family:Arial;background:#f4f6f8">
    <div style="background:white;width:520px;max-width:95vw;margin:80px auto;padding:30px;border-radius:12px;text-align:center;box-shadow:0 4px 10px rgba(0,0,0,0.1)">
        <h2>Welcome, {username}</h2>
        <p><strong>Email:</strong> {email}</p>
        <p><strong>Roles:</strong> {", ".join(roles) if roles else "No roles"}</p>

        <div style="margin-top:18px;display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
            {leave_button}
            {expense_button}
            {my_leaves_button}
            {my_expenses_button}
            {expenses_hr_button}
            {hr_button}
            {profiles_button}
        </div>

        <div style="margin-top:22px">
            <a href="/profile">
                <button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Profile
                </button>
            </a>
            <a href="/logout">
                <button style="background:#cc0000;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Logout
                </button>
            </a>
        </div>
    </div>
    </body>
    </html>
    """


@app.route("/leave/my")
def my_leaves():
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not has_role(userinfo, "Angajat"):
        return "Access denied", 403

    items = (
        LeaveRequest.query
        .filter_by(user_id=userinfo["sub"])
        .order_by(LeaveRequest.created_at.desc())
        .all()
    )

    rows = ""
    for l in items:
        rows += f"""
        <tr>
          <td>{l.id}</td>
          <td>{l.start_date}</td>
          <td>{l.end_date}</td>
          <td>{(l.reason or "").replace("<","&lt;").replace(">","&gt;")}</td>
          <td><strong>{l.status.value}</strong></td>
          <td>{(username_for_sub(l.approved_by) if l.approved_by else "-")}</td>
          <td>{l.created_at.strftime('%Y-%m-%d')}</td>
        </tr>
        """

    return f"""
    <html><body style="font-family:Arial;background:#f4f6f8">
    <div style="background:white;width:1000px;max-width:95vw;margin:60px auto;padding:30px;border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1)">
      <h2>Concediile mele</h2>

      <table width="100%" cellpadding="10" cellspacing="0" style="border-collapse:collapse">
        <tr style="background:#0066ff;color:white">
          <th align="left">ID</th>
          <th align="left">Start</th>
          <th align="left">End</th>
          <th align="left">Reason</th>
          <th align="left">Status</th>
          <th align="left">Approved by</th>
          <th align="left">Created</th>
        </tr>
        {rows if rows else "<tr><td colspan='7' style='padding:14px'>Nu există cereri de concediu.</td></tr>"}
      </table>

      <br>
      <a href="/"><button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Back</button></a>
    </div>
    </body></html>
    """




@app.route("/profile")
def profile():
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    roles = visible_roles_from_token(userinfo)

    return f"""
    <html><body style="font-family:Arial;background:#f4f6f8">
    <div style="background:white;width:650px;margin:60px auto;padding:30px;border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1)">
    <h2>User Profile</h2>
    <table border="0" width="100%" cellpadding="8" cellspacing="0" style="border-collapse:collapse">
        <tr><th align="left" style="background:#0066ff;color:white;width:35%;border-radius:8px 0 0 0">Username</th><td>{userinfo.get("preferred_username")}</td></tr>
        <tr><th align="left" style="background:#0066ff;color:white">Email</th><td>{userinfo.get("email")}</td></tr>
        <tr><th align="left" style="background:#0066ff;color:white">First name</th><td>{userinfo.get("given_name")}</td></tr>
        <tr><th align="left" style="background:#0066ff;color:white">Last name</th><td>{userinfo.get("family_name")}</td></tr>
        <tr><th align="left" style="background:#0066ff;color:white;border-radius:0 0 0 8px">Roles</th><td>{", ".join(roles)}</td></tr>
    </table>
    <br><a href="/"><button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Back</button></a>
    </div>
    </body></html>
    """


# Leave Request - Angajat
@app.route("/leave/request", methods=["GET", "POST"])
def leave_request():
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not has_role(userinfo, "Angajat"):
        return "Access denied", 403

    if request.method == "POST":
        leave = LeaveRequest(
            user_id=userinfo["sub"],
            start_date=datetime.strptime(request.form["start_date"], "%Y-%m-%d").date(),
            end_date=datetime.strptime(request.form["end_date"], "%Y-%m-%d").date(),
            reason=request.form.get("reason"),
            status=LeaveStatus.PENDING
        )
        db.session.add(leave)
        db.session.commit()
        return redirect(url_for("home"))

    return """
    <html><body style="font-family:Arial;background:#f4f6f8">
    <div style="background:white;width:480px;margin:60px auto;padding:30px;border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1)">
    <h2>Cerere concediu</h2>
    <form method="post">
        Data început:<br><input type="date" name="start_date" required style="padding:8px;width:100%"><br><br>
        Data sfârșit:<br><input type="date" name="end_date" required style="padding:8px;width:100%"><br><br>
        Motiv:<br><textarea name="reason" style="padding:8px;width:100%;height:90px"></textarea><br><br>
        <button type="submit" style="background:#28a745;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Trimite</button>
        <a href="/" style="margin-left:10px"><button type="button" style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Back</button></a>
    </form>
    </div>
    </body></html>
    """
    

# Expense Request - Angajat
@app.route("/expenses/request", methods=["GET", "POST"])
def expense_request():
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not has_role(userinfo, "Angajat"):
        return "Access denied", 403

    if request.method == "POST":
        amount = request.form.get("amount_cents", "").strip()
        currency = (request.form.get("currency") or "ron").strip().lower()
        description = request.form.get("description")

        try:
            amount_cents = int(amount)
            if amount_cents <= 0:
                return "Suma invalidă", 400
        except ValueError:
            return "Suma invalidă", 400

        exp = ExpenseClaim(
            user_id=userinfo["sub"],
            amount_cents=amount_cents,
            currency=currency,
            description=description,
            status=ExpenseStatus.PENDING,  # rămâne pending până aprobă HR
        )
        db.session.add(exp)
        db.session.commit()

        return redirect(url_for("my_expenses"))

    # IMPORTANT: aici trebuie HTML REAL
    return """
    <html><body style="font-family:Arial;background:#f4f6f8">
    <div style="background:white;width:480px;margin:60px auto;padding:30px;border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1)">
      <h2>Cerere de decont</h2>

      <form method="post">
        Suma (în bani, ex 1234 = 12.34):<br>
        <input type="number" name="amount_cents" min="1" required style="padding:8px;width:100%"><br><br>

        Monedă:<br>
        <input type="text" name="currency" value="ron" required style="padding:8px;width:100%"><br><br>

        Descriere:<br>
        <textarea name="description" style="padding:8px;width:100%;height:90px"></textarea><br><br>

        <button type="submit" style="background:#17a2b8;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
          Trimite
        </button>

        <a href="/" style="margin-left:10px">
          <button type="button" style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
            Back
          </button>
        </a>
      </form>
    </div>
    </body></html>
    """


# Deconturi - Angajat
@app.route("/expenses/my")
def my_expenses():
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not has_role(userinfo, "Angajat"):
        return "Access denied", 403

    items = (ExpenseClaim.query
             .filter_by(user_id=userinfo["sub"])
             .order_by(ExpenseClaim.created_at.desc())
             .all())

    rows = ""
    for e in items:
        rows += f"""
        <tr>
          <td>{e.id}</td>
          <td>{e.amount_cents}</td>
          <td>{(e.currency or "").upper()}</td>
          <td>{(e.description or "").replace("<","&lt;").replace(">","&gt;")}</td>
          <td><strong>{e.status.value}</strong></td>
          <td>{e.created_at.strftime('%Y-%m-%d')}</td>
        </tr>
        """

    return f"""
    <html><body style="font-family:Arial;background:#f4f6f8">
    <div style="background:white;width:900px;max-width:95vw;margin:60px auto;padding:30px;border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1)">
      <h2>Deconturile mele</h2>

      <table width="100%" cellpadding="10" cellspacing="0" style="border-collapse:collapse">
        <tr style="background:#0066ff;color:white">
          <th align="left">ID</th>
          <th align="left">Amount (cents)</th>
          <th align="left">Currency</th>
          <th align="left">Description</th>
          <th align="left">Status</th>
          <th align="left">Created</th>
        </tr>
        {rows if rows else "<tr><td colspan='6' style='padding:14px'>Nu există deconturi.</td></tr>"}
      </table>

      <br>
      <a href="/"><button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Back</button></a>
    </div>
    </body></html>
    """



# HR – Vede cereri de concediu
@app.route("/leave/all")
def view_all_leaves():
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not can_manage_leaves(userinfo):
        return "Access denied", 403

    leaves = LeaveRequest.query.order_by(LeaveRequest.created_at.desc()).all()

    rows = ""
    for l in leaves:
        employee_name = username_for_sub(l.user_id)
        approver_name = username_for_sub(l.approved_by) if l.approved_by else "-"

        actions = ""
        if l.status == LeaveStatus.PENDING:
            actions = f"""
            <div style="display:flex;gap:8px;justify-content:center">
                <form method="post" action="/leave/{l.id}/approve" style="margin:0">
                    <button style="background:#28a745;color:white;border:none;padding:8px 10px;border-radius:8px;cursor:pointer">Approve</button>
                </form>
                <form method="post" action="/leave/{l.id}/reject" style="margin:0">
                    <button style="background:#cc0000;color:white;border:none;padding:8px 10px;border-radius:8px;cursor:pointer">Reject</button>
                </form>
            </div>
            """
        else:
            actions = "-"

        rows += f"""
        <tr>
            <td>{employee_name}</td>
            <td>{l.start_date}</td>
            <td>{l.end_date}</td>
            <td>{(l.reason or "").replace("<", "&lt;").replace(">", "&gt;")}</td>
            <td><strong>{l.status.value}</strong></td>
            <td>{approver_name}</td>
            <td>{l.created_at.strftime('%Y-%m-%d')}</td>
            <td>{actions}</td>
        </tr>
        """

    return f"""
    <html>
    <body style="font-family:Arial;background:#f4f6f8">
    <div style="background:white;width:1100px;max-width:95vw;margin:60px auto;padding:30px;border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1)">
        <h2>Cereri de concediu</h2>
        <table width="100%" cellpadding="10" cellspacing="0" style="border-collapse:collapse">
            <tr style="background:#0066ff;color:white">
                <th align="left">User</th>
                <th align="left">Start</th>
                <th align="left">End</th>
                <th align="left">Reason</th>
                <th align="left">Status</th>
                <th align="left">Approved by</th>
                <th align="left">Created</th>
                <th align="center">Actions</th>
            </tr>
            {rows if rows else "<tr><td colspan='8' style='padding:14px'>No leave requests.</td></tr>"}
        </table>

        <br>
        <a href="/"><button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Back</button></a>
    </div>
    </body>
    </html>
    """
    
    
@app.route("/users")
def list_users():
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not can_manage_leaves(userinfo):
        return "Access denied", 403

    users = UserProfile.query.order_by(UserProfile.username.asc()).all()

    rows = ""
    for u in users:
        roles = set((u.role or "").split(","))

        # "useri normali" = au Angajat, dar NU au HR/Administrator
        if "Angajat" not in roles:
            continue
        if "HR" in roles or "Administrator" in roles:
            continue

        rows += f"""
        <tr>
            <td>{(u.username or "").replace("<","&lt;").replace(">","&gt;")}</td>
            <td>{(u.email or "").replace("<","&lt;").replace(">","&gt;")}</td>
            <td>{(u.role or "").replace("<","&lt;").replace(">","&gt;")}</td>
        </tr>
        """

    return f"""
    <html>
    <body style="font-family:Arial;background:#f4f6f8">
    <div style="background:white;width:900px;max-width:95vw;margin:60px auto;padding:30px;border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1)">
        <h2>Profile angajați</h2>

        <table width="100%" cellpadding="10" cellspacing="0" style="border-collapse:collapse">
            <tr style="background:#0066ff;color:white">
                <th align="left">Username</th>
                <th align="left">Email</th>
                <th align="left">Roluri</th>
            </tr>
            {rows if rows else "<tr><td colspan='3' style='padding:14px'>Nu există angajați.</td></tr>"}
        </table>

        <br>
        <a href="/"><button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Back</button></a>
    </div>
    </body>
    </html>
    """



# HR – Approve / Reject concediu
@app.route("/leave/<int:leave_id>/approve", methods=["POST"])
def approve_leave(leave_id):
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not can_manage_leaves(userinfo):
        return "Access denied", 403

    updated = (
        LeaveRequest.query
        .filter(LeaveRequest.id == leave_id, LeaveRequest.status == LeaveStatus.PENDING)
        .update(
            {
                LeaveRequest.status: LeaveStatus.APPROVED,
                LeaveRequest.approved_by: userinfo["sub"],
            },
            synchronize_session=False
        )
    )
    db.session.commit()

    if updated == 0:
        return "Cererea a fost deja procesată de alt HR.", 409

    # ✅ după ce a reușit update-ul, citim cererea și trimitem email
    leave = LeaveRequest.query.get_or_404(leave_id)
    emp_email = email_for_sub(leave.user_id)
    subject, body = build_leave_email(LeaveStatus.APPROVED, leave)

    try:
        logger.info("emp_email=%s leave_id=%s user_id=%s", emp_email, leave_id, leave.user_id)
        send_email(emp_email, subject, body)
    except Exception as e:
        print("Email send failed:", e)

    return redirect(url_for("view_all_leaves"))




@app.route("/leave/<int:leave_id>/reject", methods=["POST"])
def reject_leave(leave_id):
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not can_manage_leaves(userinfo):
        return "Access denied", 403

    updated = (
        LeaveRequest.query
        .filter(LeaveRequest.id == leave_id, LeaveRequest.status == LeaveStatus.PENDING)
        .update(
            {
                LeaveRequest.status: LeaveStatus.REJECTED,
                LeaveRequest.approved_by: userinfo["sub"],
            },
            synchronize_session=False
        )
    )
    db.session.commit()

    if updated == 0:
        return "Cererea a fost deja procesată de alt HR.", 409

    leave = LeaveRequest.query.get_or_404(leave_id)
    emp_email = email_for_sub(leave.user_id)
    subject, body = build_leave_email(LeaveStatus.REJECTED, leave)

    try:
        send_email(emp_email, subject, body)
    except Exception as e:
        print("Email send failed:", e)

    return redirect(url_for("view_all_leaves"))


@app.route("/expenses/all")
def view_all_expenses():
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not can_manage_leaves(userinfo):
        return "Access denied", 403

    items = ExpenseClaim.query.order_by(ExpenseClaim.created_at.desc()).all()

    rows = ""
    for e in items:
        employee_name = username_for_sub(e.user_id)

        actions = "-"
        if e.status == ExpenseStatus.PENDING:
            actions = f"""
            <div style="display:flex;gap:8px;justify-content:center">
              <form method="post" action="/expenses/{e.id}/approve" style="margin:0">
                <button style="background:#28a745;color:white;border:none;padding:8px 10px;border-radius:8px;cursor:pointer">Approve</button>
              </form>
              <form method="post" action="/expenses/{e.id}/reject" style="margin:0">
                <button style="background:#cc0000;color:white;border:none;padding:8px 10px;border-radius:8px;cursor:pointer">Reject</button>
              </form>
            </div>
            """

        rows += f"""
        <tr>
          <td>{e.id}</td>
          <td>{employee_name}</td>
          <td>{e.amount_cents}</td>
          <td>{(e.currency or "").upper()}</td>
          <td>{(e.description or "").replace("<","&lt;").replace(">","&gt;")}</td>
          <td><strong>{e.status.value}</strong></td>
          <td>{e.created_at.strftime('%Y-%m-%d')}</td>
          <td>{actions}</td>
        </tr>
        """

    return f"""
    <html><body style="font-family:Arial;background:#f4f6f8">
    <div style="background:white;width:1100px;max-width:95vw;margin:60px auto;padding:30px;border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1)">
      <h2>Cereri de decont</h2>

      <table width="100%" cellpadding="10" cellspacing="0" style="border-collapse:collapse">
        <tr style="background:#0066ff;color:white">
          <th align="left">ID</th>
          <th align="left">User</th>
          <th align="left">Amount (cents)</th>
          <th align="left">Currency</th>
          <th align="left">Description</th>
          <th align="left">Status</th>
          <th align="left">Created</th>
          <th align="center">Actions</th>
        </tr>
        {rows if rows else "<tr><td colspan='8' style='padding:14px'>Nu există cereri.</td></tr>"}
      </table>

      <br>
      <a href="/"><button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Back</button></a>
    </div>
    </body></html>
    """
    
    
    
@app.route("/expenses/<int:expense_id>/approve", methods=["POST"])
def approve_expense(expense_id):
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not can_manage_leaves(userinfo):
        return "Access denied", 403

    exp = ExpenseClaim.query.get_or_404(expense_id)

    # doar PENDING poate fi aprobat
    if exp.status != ExpenseStatus.PENDING:
        return "Expense already processed", 409

    trace_id = str(uuid.uuid4())
    msg = {
        "event": "expense.requested",
        "expense_id": exp.id,
        "user_id": exp.user_id,
        "amount_cents": exp.amount_cents,
        "currency": exp.currency,
        "description": exp.description,
        "requested_at": datetime.utcnow().isoformat() + "Z",
        "trace_id": trace_id,
        "approved_by": userinfo["sub"],
        "approved_at": datetime.utcnow().isoformat() + "Z",
    }

    rabbit_publish(EXPENSES_EXCHANGE, EXPENSES_ROUTING_KEY, msg)

    exp.status = ExpenseStatus.QUEUED
    exp.approved_by = userinfo["sub"]
    db.session.commit()

    return redirect(url_for("view_all_expenses"))


@app.route("/expenses/<int:expense_id>/reject", methods=["POST"])
def reject_expense(expense_id):
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not can_manage_leaves(userinfo):
        return "Access denied", 403

    exp = ExpenseClaim.query.get_or_404(expense_id)

    if exp.status != ExpenseStatus.PENDING:
        return "Expense already processed", 409

    exp.status = ExpenseStatus.REJECTED  # sau FAILED + reason
    exp.approved_by = userinfo["sub"]
    exp.failure_reason = "Rejected by HR"
    db.session.commit()

    return redirect(url_for("view_all_expenses"))




# Login
@app.route("/login")
def login():
    return redirect(
        f"{KEYCLOAK_PUBLIC}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"
        f"?client_id={KEYCLOAK_CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope=openid profile email"
    )


@app.route("/callback")
def callback():
    code = request.args.get("code")
    kc = get_keycloak()

    token = kc.token(
        grant_type="authorization_code",
        code=code,
        redirect_uri=REDIRECT_URI
    )

    session["access_token"] = token["access_token"]
    session["id_token"] = token.get("id_token")

    if not session["id_token"]:
        return "ID token missing – check Keycloak client scopes", 500

    # sync user
    userinfo = decode_token(token["access_token"])
    user = UserProfile.query.filter_by(keycloak_id=userinfo["sub"]).first()
    if not user:
        user = UserProfile(
            keycloak_id=userinfo["sub"],
            username=userinfo.get("preferred_username"),
            email=userinfo.get("email"),
            role=",".join(visible_roles_from_token(userinfo))
        )
        db.session.add(user)
        db.session.commit()

    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    id_token = session.get("id_token")
    session.clear()

    if not id_token:
        return redirect(url_for("home"))

    return redirect(
        f"{KEYCLOAK_PUBLIC}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout"
        f"?id_token_hint={id_token}"
        f"&post_logout_redirect_uri=http://localhost:{FLASK_PORT}"
    )

@app.route("/api/expenses", methods=["POST"])
def create_expense():
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not has_role(userinfo, "Angajat"):
        return "Access denied", 403

    data = request.get_json(force=True)
    amount_cents = int(data["amount_cents"])
    currency = (data.get("currency") or "ron").lower()
    description = data.get("description")

    exp = ExpenseClaim(
        user_id=userinfo["sub"],
        amount_cents=amount_cents,
        currency=currency,
        description=description,
        status=ExpenseStatus.PENDING,
    )
    db.session.add(exp)
    db.session.commit()

    # trimitem mesaj in RabbitMQ
    trace_id = str(uuid.uuid4())
    msg = {
        "event": "expense.requested",
        "expense_id": exp.id,
        "user_id": exp.user_id,
        "amount_cents": exp.amount_cents,
        "currency": exp.currency,
        "description": exp.description,
        "requested_at": datetime.utcnow().isoformat() + "Z",
        "trace_id": trace_id,
    }

    rabbit_publish(EXPENSES_EXCHANGE, EXPENSES_ROUTING_KEY, msg)

    exp.status = ExpenseStatus.QUEUED
    db.session.commit()

    return jsonify(exp.to_dict()), 201



@app.route("/api/expenses", methods=["GET"])
def list_my_expenses():
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not has_role(userinfo, "Angajat"):
        return "Access denied", 403

    items = (ExpenseClaim.query
             .filter_by(user_id=userinfo["sub"])
             .order_by(ExpenseClaim.created_at.desc())
             .all())
    return jsonify([x.to_dict() for x in items])



# Main
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=FLASK_PORT)
