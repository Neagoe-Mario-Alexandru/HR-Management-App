from flask import Flask, request, jsonify, redirect, session, url_for
from keycloak import KeycloakOpenID, KeycloakAdmin
from models import db, UserProfile, LeaveRequest, LeaveStatus, ExpenseClaim, ExpenseStatus
from datetime import datetime, timedelta
import os
import time
import jwt
import smtplib
import json
from email.message import EmailMessage
import logging
import pika
import uuid
import redis
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


#Redis
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)


#Rate limiting function
MAX_EXPENSES_PER_DAY = 5

def check_expense_rate_limit(user_id: str) -> bool:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    key = f"expense_limit:{user_id}:{today}"

    current = redis_client.get(key)
    if current and int(current) >= MAX_EXPENSES_PER_DAY:
        return False

    if not current:
        now = datetime.utcnow()
        tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0)
        ttl = int((tomorrow - now).total_seconds())

        redis_client.set(key, 1, ex=ttl)
    else:
        redis_client.incr(key)

    return True




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
KEYCLOAK_CLIENT_SECRET = os.environ.get("KEYCLOAK_SECRET", "")

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
        server_url=os.environ.get("KEYCLOAK_URL", "http://keycloak:8080"),
        client_id=os.environ.get("KEYCLOAK_CLIENT_ID", "backend-scd"),
        realm_name=os.environ.get("KEYCLOAK_REALM", "proiect-scd"),
        client_secret_key=os.environ.get("KEYCLOAK_SECRET", "")
    )
    
def get_admin_client():
    return KeycloakAdmin(
        server_url=os.environ.get("KEYCLOAK_URL", "http://keycloak:8080") + "/",
        client_id=os.environ.get("KEYCLOAK_CLIENT_ID", "backend-scd"),
        realm_name=os.environ.get("KEYCLOAK_REALM", "proiect-scd"),
        client_secret_key=os.environ.get("KEYCLOAK_SECRET", ""),
        user_realm_name=os.environ.get("KEYCLOAK_REALM", "proiect-scd"),
        verify=True
    )
    
VISIBLE_ROLES = ["Angajat", "HR", "Administrator"]
    
def update_keycloak_user_roles(user_id, roles_list):
    try:
        admin_kc = get_admin_client()
        all_realm_roles = admin_kc.get_realm_roles()
        
        roles_to_assign = [r for r in all_realm_roles if r['name'] in roles_list]
        roles_to_remove = [r for r in all_realm_roles if r['name'] in VISIBLE_ROLES and r['name'] not in roles_list]

        # REPARAT: Folosim delete_realm_roles_from_user
        if roles_to_remove:
            admin_kc.delete_realm_roles_of_user(user_id=user_id, roles=roles_to_remove)
            logger.info(f"Roluri eliminate pentru {user_id}: {[r['name'] for r in roles_to_remove]}")

        if roles_to_assign:
            admin_kc.assign_realm_roles(user_id=user_id, roles=roles_to_assign)
            logger.info(f"Roluri adăugate pentru {user_id}: {[r['name'] for r in roles_to_assign]}")

    except Exception as e:
        logger.error(f"Eroare în update_keycloak_user_roles: {str(e)}")
        raise e


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

def build_expense_email(status: ExpenseStatus, exp: ExpenseClaim):
    emp_username = username_for_sub(exp.user_id)

    # Subject & headline depend de status (QUEUED ≠ PAID)
    if status == ExpenseStatus.QUEUED:
        subject = "Decontul tău a fost aprobat și este în curs de procesare"
        status_label = "aprobat (în curs de procesare)"
    elif status == ExpenseStatus.PAID:
        subject = "Decontul tău a fost plătit"
        status_label = "plătit"
    elif status == ExpenseStatus.FAILED:
        subject = "Decontul tău nu a putut fi procesat"
        status_label = "eșuat"
    elif getattr(ExpenseStatus, "REJECTED", None) == status:
        subject = "Decontul tău a fost respins"
        status_label = "respins"
    else:
        subject = f"Actualizare decont: {status.value}"
        status_label = status.value.lower()

    body = f"""Salut, {emp_username}

Cererea ta de decont a fost {status_label}.

Detalii:
- Suma: {exp.amount:.2f} {(exp.currency or '').upper()}
- Descriere: {exp.description or '-'}
- Status curent: {status_label}
- Data cererii: {exp.created_at.strftime('%Y-%m-%d')}


Mulțumim,
Sistem Deconturi
"""

    return subject, body





def is_hr(userinfo):
    return has_role(userinfo, "HR")

def is_admin(userinfo):
    return has_role(userinfo, "Administrator")


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

    # Angajat
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

    # HR/Admin
    hr_leaves_button = ""
    profiles_button = ""
    expenses_hr_button = ""
    expenses_admin_button = ""

    if is_hr(userinfo):
        hr_leaves_button = """
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
            <a href="/expenses/hr">
                <button style="background:#795548;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Deconturi (HR)
                </button>
            </a>
        """

    if is_admin(userinfo):
        expenses_admin_button = """
            <a href="/expenses/admin">
                <button style="background:#607d8b;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Deconturi (Admin)
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
        hr_leaves_button = """
            <a href="/leave/all">
                <button style="background:#ff9800;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Vezi cereri concediu
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
            {expenses_admin_button}
            {hr_leaves_button}
            {profiles_button}
        </div>

        <div style="margin-top:22px">
            <a href="/profile">
                <button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Profile</button>
            </a>
            <a href="/logout">
                <button style="background:#cc0000;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Logout</button>
            </a>
        </div>
    </div>
    </body>
    </html>
    """
    
# Deconturi - HR
@app.route("/expenses/hr")
def view_hr_expenses():
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not (is_hr(userinfo) or is_admin(userinfo)):
        return "Access denied", 403

    items = (ExpenseClaim.query
             .filter(ExpenseClaim.status == ExpenseStatus.PENDING)
             .order_by(ExpenseClaim.created_at.desc())
             .all())

    rows = ""
    for e in items:
        employee_name = username_for_sub(e.user_id)
        actions = f"""
        <div style="display:flex;gap:8px;justify-content:center">
          <form method="post" action="/expenses/{e.id}/hr/approve" style="margin:0">
            <button style="background:#28a745;color:white;border:none;padding:8px 10px;border-radius:8px;cursor:pointer">Approve</button>
          </form>
          <form method="post" action="/expenses/{e.id}/hr/reject" style="margin:0">
            <button style="background:#cc0000;color:white;border:none;padding:8px 10px;border-radius:8px;cursor:pointer">Reject</button>
          </form>
        </div>
        """

        rows += f"""
        <tr>
          <td>{e.id}</td>
          <td>{employee_name}</td>
          <td>{e.amount:.2f}</td>
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
      <h2>Cereri de decont (HR) – PENDING</h2>

      <table width="100%" cellpadding="10" cellspacing="0" style="border-collapse:collapse">
        <tr style="background:#0066ff;color:white">
          <th align="left">ID</th>
          <th align="left">User</th>
          <th align="left">Amount</th>
          <th align="left">Currency</th>
          <th align="left">Description</th>
          <th align="left">Status</th>
          <th align="left">Created</th>
          <th align="center">Actions</th>
        </tr>
        {rows if rows else "<tr><td colspan='8' style='padding:14px'>Nu există cereri PENDING.</td></tr>"}
      </table>

      <br>
      <a href="/"><button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Back</button></a>
    </div>
    </body></html>
    """


@app.route("/expenses/<int:expense_id>/hr/approve", methods=["POST"])
def hr_approve_expense(expense_id):
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not (is_hr(userinfo) or is_admin(userinfo)):
        return "Access denied", 403

    exp = ExpenseClaim.query.get_or_404(expense_id)
    if exp.status != ExpenseStatus.PENDING:
        return "Expense already processed", 409

    exp.status = ExpenseStatus.HR_APPROVED
    exp.approved_by = userinfo["sub"]
    db.session.commit()

    return redirect(url_for("view_hr_expenses"))


@app.route("/expenses/<int:expense_id>/hr/reject", methods=["POST"])
def hr_reject_expense(expense_id):
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not (is_hr(userinfo) or is_admin(userinfo)):
        return "Access denied", 403

    exp = ExpenseClaim.query.get_or_404(expense_id)
    if exp.status != ExpenseStatus.PENDING:
        return "Expense already processed", 409

    exp.status = ExpenseStatus.REJECTED
    exp.failure_reason = "Rejected by HR"
    exp.approved_by = userinfo["sub"]
    db.session.commit()
    emp_email = email_for_sub(exp.user_id)
    subject, body = build_expense_email(ExpenseStatus.REJECTED, exp)

    try:
        send_email(emp_email, subject, body)
    except Exception as e:
        logger.error("Expense HR reject email failed: %s", e)


    return redirect(url_for("view_hr_expenses"))

@app.route("/admin/update-roles/<user_id>", methods=["POST"])
def admin_update_roles(user_id):
    if "access_token" not in session:
        return redirect(url_for("home"))
    
    try:
        # 1. Inițializăm clientul de Admin
        admin_kc = KeycloakAdmin(
            server_url=os.environ.get("KEYCLOAK_URL", "http://keycloak:8080") + "/",
            client_id=os.environ.get("KEYCLOAK_CLIENT_ID", "backend-scd"),
            realm_name=os.environ.get("KEYCLOAK_REALM", "proiect-scd"),
            client_secret_key=os.environ.get("KEYCLOAK_SECRET", ""),
            user_realm_name=os.environ.get("KEYCLOAK_REALM", "proiect-scd"),
            verify=True
        )

        # 2. Luăm lista actuală de roluri din Keycloak pentru a găsi obiectele de rol
        all_realm_roles = admin_kc.get_realm_roles()
        
        # 3. Luăm rolurile selectate de utilizator din formular (checkbox-uri)
        new_roles_names = request.form.getlist("roles")
        
        # Identificăm obiectele complete de rol (necesare pentru API)
        to_add = [r for r in all_realm_roles if r['name'] in new_roles_names]
        to_rem = [r for r in all_realm_roles if r['name'] in VISIBLE_ROLES and r['name'] not in new_roles_names]

        # 4. Executăm modificările folosind metodele CORECTE
        if to_rem:
            # Metoda corectă este remove_realm_roles_from_user (cu 'remove' nu 'delete')
            admin_kc.delete_realm_roles_of_user(user_id=user_id, roles=to_rem)
            
        if to_add:
            # Metoda pentru adăugare este assign_realm_roles
            admin_kc.assign_realm_roles(user_id=user_id, roles=to_add)

        # 5. Sincronizăm baza de date locală (Postgres)
        u = UserProfile.query.filter_by(keycloak_id=user_id).first()
        if u:
            u.role = ",".join(new_roles_names)
            db.session.commit()
            
        return redirect(url_for("list_users"))

    except Exception as e:
        logger.error(f"EROARE ADMIN: {str(e)}")
        return f"Eroare la procesare: {str(e)}", 500


@app.route("/expenses/admin")
def view_admin_expenses():
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not is_admin(userinfo):
        return "Access denied", 403

    items = (ExpenseClaim.query
             .filter(ExpenseClaim.status == ExpenseStatus.HR_APPROVED)
             .order_by(ExpenseClaim.created_at.desc())
             .all())

    rows = ""
    for e in items:
        employee_name = username_for_sub(e.user_id)
        actions = f"""
        <div style="display:flex;gap:8px;justify-content:center">
          <form method="post" action="/expenses/{e.id}/admin/approve" style="margin:0">
            <button style="background:#28a745;color:white;border:none;padding:8px 10px;border-radius:8px;cursor:pointer">Approve</button>
          </form>
          <form method="post" action="/expenses/{e.id}/admin/reject" style="margin:0">
            <button style="background:#cc0000;color:white;border:none;padding:8px 10px;border-radius:8px;cursor:pointer">Reject</button>
          </form>
        </div>
        """

        # Format amount as normal currency
        amount_display = f"{e.amount:.2f}"

        rows += f"""
        <tr>
          <td>{e.id}</td>
          <td>{employee_name}</td>
          <td>{amount_display}</td>
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
      <h2>Cereri de decont (Admin) – HR_APPROVED</h2>

      <table width="100%" cellpadding="10" cellspacing="0" style="border-collapse:collapse">
        <tr style="background:#0066ff;color:white">
          <th align="left">ID</th>
          <th align="left">User</th>
          <th align="left">Amount</th>
          <th align="left">Currency</th>
          <th align="left">Description</th>
          <th align="left">Status</th>
          <th align="left">Created</th>
          <th align="center">Actions</th>
        </tr>
        {rows if rows else "<tr><td colspan='8' style='padding:14px'>Nu există cereri HR_APPROVED.</td></tr>"}
      </table>

      <br>
      <a href="/"><button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Back</button></a>
    </div>
    </body></html>
    """



@app.route("/expenses/<int:expense_id>/admin/approve", methods=["POST"])
def admin_approve_expense(expense_id):
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not is_admin(userinfo):
        return "Access denied", 403

    exp = ExpenseClaim.query.get_or_404(expense_id)
    if exp.status != ExpenseStatus.HR_APPROVED:
        return "Expense not ready for admin approval", 409

    # 1) marchezi în DB că e gata de procesare
    exp.status = ExpenseStatus.QUEUED
    exp.approved_by = userinfo["sub"]  # opțional, dar util
    db.session.commit()

    emp_email = email_for_sub(exp.user_id)
    subject, body = build_expense_email(ExpenseStatus.QUEUED, exp)

    try:
        send_email(emp_email, subject, body)
    except Exception as e:
        logger.error("Expense admin approve email failed: %s", e)

    # 2) publish către RabbitMQ cu amount numeric
    trace_id = str(uuid.uuid4())
    msg = {
        "event": "expense.requested",
        "expense_id": exp.id,
        "user_id": exp.user_id,
        "amount": float(exp.amount),  # <--- aici
        "currency": exp.currency,
        "description": exp.description,
        "requested_at": datetime.utcnow().isoformat() + "Z",
        "trace_id": trace_id,
        "approved_by": userinfo["sub"],
        "approved_at": datetime.utcnow().isoformat() + "Z",
    }

    rabbit_publish(EXPENSES_EXCHANGE, EXPENSES_ROUTING_KEY, msg)

    return redirect(url_for("view_admin_expenses"))




@app.route("/expenses/<int:expense_id>/admin/reject", methods=["POST"])
def admin_reject_expense(expense_id):
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not is_admin(userinfo):
        return "Access denied", 403

    exp = ExpenseClaim.query.get_or_404(expense_id)
    if exp.status != ExpenseStatus.HR_APPROVED:
        return "Expense not ready for admin decision", 409

    exp.status = ExpenseStatus.REJECTED
    exp.failure_reason = "Rejected by Administrator"
    db.session.commit()
    emp_email = email_for_sub(exp.user_id)
    subject, body = build_expense_email(ExpenseStatus.REJECTED, exp)

    try:
        send_email(emp_email, subject, body)
    except Exception as e:
        logger.error("Expense admin reject email failed: %s", e)

    return redirect(url_for("view_admin_expenses"))



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
    

# Expense Request - Angajat (standard amounts, not cents)
@app.route("/expenses/request", methods=["GET", "POST"])
def expense_request():
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not has_role(userinfo, "Angajat"):
        return "Access denied", 403

    user_id = userinfo["sub"]

    if request.method == "POST":
        # ===============================
        # 🔒 RATE LIMIT: max 5 / zi / user
        # ===============================
        if not check_expense_rate_limit(user_id):
            return """
            <html><body style="font-family:Arial;background:#f4f6f8">
            <div style="background:white;width:480px;margin:60px auto;padding:30px;
                        border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1);
                        text-align:center">
              <h3 style="color:#cc0000">Limită depășită</h3>
              <p>Ai atins limita de <strong>5 cereri de decont pe zi</strong>.</p>
              <p>Încearcă din nou mâine.</p>
              <br>
              <a href="/"><button style="background:#0066ff;color:white;border:none;
              padding:10px 14px;border-radius:8px;cursor:pointer">
                Înapoi
              </button></a>
            </div>
            </body></html>
            """, 429

        # ===============================
        # Date din formular
        # ===============================
        amount_str = request.form.get("amount", "").strip()
        currency = (request.form.get("currency") or "ron").strip().lower()
        description = request.form.get("description")

        try:
            amount = float(amount_str)
            if amount <= 0:
                return "Suma invalidă", 400
        except ValueError:
            return "Suma invalidă", 400

        # ===============================
        # Creează cererea de decont
        # ===============================
        exp = ExpenseClaim(
            user_id=user_id,
            amount=amount,  # float, nu cents
            currency=currency,
            description=description,
            status=ExpenseStatus.PENDING,
        )

        db.session.add(exp)
        db.session.commit()

        return redirect(url_for("my_expenses"))

    # ===============================
    # GET – formular HTML
    # ===============================
    return """
    <html><body style="font-family:Arial;background:#f4f6f8">
    <div style="background:white;width:480px;margin:60px auto;padding:30px;
                border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1)">
      <h2>Cerere de decont</h2>

      <form method="post">
        Suma (ex: 123.45):<br>
        <input type="number" name="amount" min="0.01" step="0.01" required
               style="padding:8px;width:100%"><br><br>

        Monedă:<br>
        <input type="text" name="currency" value="ron" required
               style="padding:8px;width:100%"><br><br>

        Descriere:<br>
        <textarea name="description"
                  style="padding:8px;width:100%;height:90px"></textarea><br><br>

        <button type="submit"
                style="background:#17a2b8;color:white;border:none;
                       padding:10px 14px;border-radius:8px;cursor:pointer">
          Trimite
        </button>

        <a href="/" style="margin-left:10px">
          <button type="button"
                  style="background:#0066ff;color:white;border:none;
                         padding:10px 14px;border-radius:8px;cursor:pointer">
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
        # Format amount as standard currency
        amount_display = f"{e.amount:.2f}"

        rows += f"""
        <tr>
          <td>{e.id}</td>
          <td>{amount_display}</td>
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
          <th align="left">Amount</th>
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
    
    # Verificăm dacă este HR sau Admin pentru a vedea lista
    user_is_admin = is_admin(userinfo)
    user_is_hr = is_hr(userinfo)
    
    if not (user_is_admin or user_is_hr):
        return "Access denied. Trebuie să fii HR sau Admin.", 403

    users = UserProfile.query.order_by(UserProfile.username.asc()).all()

    # Definim rolurile pe care Adminul le poate bifa
    VISIBLE_ROLES = ["Angajat", "HR", "Administrator"]

    rows = ""
    for u in users:
        current_roles = (u.role or "").split(",")
        
        # Generăm celula de acțiuni (doar pentru Admin)
        management_cell = ""
        if user_is_admin:
            checkboxes = ""
            for r in VISIBLE_ROLES:
                checked = "checked" if r in current_roles else ""
                checkboxes += f"""
                    <label style="margin-right:10px; font-size: 0.9em;">
                        <input type="checkbox" name="roles" value="{r}" {checked}> {r}
                    </label>
                """
            
            management_cell = f"""
            <td style="border-bottom:1px solid #eee">
                <form method="POST" action="/admin/update-roles/{u.keycloak_id}" style="margin:0; display:flex; align-items:center">
                    <div style="flex-grow:1">{checkboxes}</div>
                    <button type="submit" style="background:#28a745;color:white;border:none;padding:5px 10px;border-radius:4px;cursor:pointer;font-size:0.8em">Save</button>
                </form>
            </td>
            """
        else:
            # Dacă e HR, nu vede coloana de management
            management_cell = ""

        rows += f"""
        <tr>
            <td style="border-bottom:1px solid #eee">{(u.username or "").replace("<","&lt;")}</td>
            <td style="border-bottom:1px solid #eee">{(u.email or "").replace("<","&lt;")}</td>
            <td style="border-bottom:1px solid #eee">{(u.role or "")}</td>
            {management_cell}
        </tr>
        """

    # Antetul tabelului se schimbă în funcție de cine privește
    actions_header = '<th align="left">Management Roluri (Admin Only)</th>' if user_is_admin else ""

    return f"""
    <html>
    <body style="font-family:Arial;background:#f4f6f8">
    <div style="background:white;width:1100px;max-width:95vw;margin:60px auto;padding:30px;border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1)">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px">
            <h2 style="margin:0">Management Utilizatori</h2>
            <span style="background:#eee; padding:5px 10px; border-radius:5px; font-size:0.9em">
                Logat ca: <b>{"Admin" if user_is_admin else "HR"}</b>
            </span>
        </div>

        <table width="100%" cellpadding="12" cellspacing="0" style="border-collapse:collapse">
            <tr style="background:#0066ff;color:white">
                <th align="left">Username</th>
                <th align="left">Email</th>
                <th align="left">Roluri Curente</th>
                {actions_header}
            </tr>
            {rows if rows else "<tr><td colspan='4'>Nu există utilizatori în baza de date.</td></tr>"}
        </table>

        <br>
        <a href="/"><button style="background:#6c757d;color:white;border:none;padding:10px 18px;border-radius:8px;cursor:pointer">Inapoi la Dashboard</button></a>
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





# Main
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=FLASK_PORT)
