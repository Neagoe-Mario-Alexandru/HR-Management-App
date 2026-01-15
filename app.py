from flask import Flask, request, redirect, session, url_for, jsonify
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
    
    
# RabbitMQ config
RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")
EXPENSES_EXCHANGE = os.environ.get("EXPENSES_EXCHANGE", "expenses")
EXPENSES_ROUTING_KEY = os.environ.get("EXPENSES_ROUTING_KEY", "expense.requested")
EMAIL_EXCHANGE = "email_exchange"
EMAIL_ROUTING_KEY = "email.send"


#Redis config
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)



#Rate limiting cu Redis
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


# Publish pt RabbitMQ
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
            # delivery mode persistent
            delivery_mode=2,
            content_type="application/json",
        ),
    )
    conn.close()
    




# Check sa vad daca rulez in Docker
IN_DOCKER = os.environ.get("IN_DOCKER", "0") == "1"

# Flask setup
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "SUPER_SECRET_SESSION_KEY")

# Rolurile
VISIBLE_ROLES = {"Angajat", "HR", "Administrator"}

app.config.update(
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
)

# Database (si pt cand testam local)
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


# Clienti Keycloak
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
   
    

# Update de useri in Keycloak
def update_keycloak_user_roles(user_id, roles_list):
    try:
        admin_kc = get_admin_client()
        all_realm_roles = admin_kc.get_realm_roles()
        
        roles_to_assign = [r for r in all_realm_roles if r['name'] in roles_list]
        roles_to_remove = [r for r in all_realm_roles if r['name'] in VISIBLE_ROLES and r['name'] not in roles_list]

        # Delete roles - admin
        if roles_to_remove:
            admin_kc.delete_realm_roles_of_user(user_id=user_id, roles=roles_to_remove)
            logger.info(f"Roluri eliminate pentru {user_id}: {[r['name'] for r in roles_to_remove]}")
        # Give roles
        if roles_to_assign:
            admin_kc.assign_realm_roles(user_id=user_id, roles=roles_to_assign)
            logger.info(f"Roluri adaugate pentru {user_id}: {[r['name'] for r in roles_to_assign]}")
    # Exceptie + debug
    except Exception as e:
        logger.error(f"Eroare update_keycloak_user_roles: {str(e)}")
        raise e


# Decode JWT token
def decode_token(token):
    if not token:
        return {}
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return jwt.decode(
        token,
        options={"verify_signature": False, "verify_aud": False},
    )

# Checkuri pe roluri
def can_manage_leaves(userinfo):
    return has_role(userinfo, "HR") or has_role(userinfo, "Administrator")

def has_role(userinfo, role):
    return role in userinfo.get("realm_access", {}).get("roles", [])

# Nu are sens sa afisez alte roluri in UI
def visible_roles_from_token(userinfo):
    all_roles = userinfo.get("realm_access", {}).get("roles", [])
    return [r for r in all_roles if r in VISIBLE_ROLES]


# Get username/email din sub
def username_for_sub(sub):
    if not sub:
        return "-"
    u = UserProfile.query.filter_by(keycloak_id=sub).first()
    return u.username if u and u.username else sub

# Pt trimis emailuri
def send_email(to_email: str, subject: str, body: str):
    if not to_email:
        logger.warning("Niciun destinatar la mail -> skip send")
        return

    if not SMTP_HOST:
        logger.warning("SMTP_HOST not set -> skip send")
        return

    logger.info("Trimit mail prin %s:%s to=%s from=%s subj=%s",
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


# Get email din sub      
def email_for_sub(sub):
    if not sub:
        return None
    u = UserProfile.query.filter_by(keycloak_id=sub).first()
    return u.email if u else None

# Emailuri pt concedii
def build_leave_email(status: LeaveStatus, leave: LeaveRequest):
    emp_username = username_for_sub(leave.user_id)
    approver = username_for_sub(leave.approved_by)

    subject = f"Cererea ta de concediu a fost {status.value}"
    body = f"""Salut, {emp_username}

Cererea ta de concediu a fost {status.value}.

Detalii:
- Perioada: {leave.start_date} -> {leave.end_date}
- Motiv: {leave.reason or "-"}
- Status: {status.value}
- Procesata de: {approver}
- Data cererii: {leave.created_at.strftime('%Y-%m-%d')}

Multumim,
Sistem Concedii
"""
    return subject, body



# Emailuri pt deconturi
def build_expense_email(status: ExpenseStatus, exp: ExpenseClaim):
    emp_username = username_for_sub(exp.user_id)

    # Subject & headline depend de status (QUEUED ≠ PAID)
    if status == ExpenseStatus.QUEUED:
        subject = "Decontul tau a fost aprobat si este in curs de procesare"
        status_label = "aprobat (in curs de procesare)"
    elif status == ExpenseStatus.PAID:
        subject = "Decontul tau a fost platit"
        status_label = "platit"
    elif status == ExpenseStatus.FAILED:
        subject = "Decontul tau nu a putut fi procesat"
        status_label = "esuat"
    elif getattr(ExpenseStatus, "REJECTED", None) == status:
        subject = "Decontul tau a fost respins"
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


Multumim,
Sistem Deconturi
"""

    return subject, body




# Check HR/Admin
def is_hr(userinfo):
    return has_role(userinfo, "HR")

def is_admin(userinfo):
    return has_role(userinfo, "Administrator")


# Home / Butoane principale
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
                    Fa o cerere de concediu
                </button>
            </a>
        """
        expense_button = """
            <a href="/expenses/request">
                <button style="background:#17a2b8;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Fa o cerere de decont
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
                    Vezi profile angajati
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
                    Vezi profile angajati
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
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1] if auth_header and auth_header.startswith("Bearer ") else session.get("access_token")

    if not token:
        if auth_header: return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for("home"))

    try:
        userinfo = decode_token(token)
    except:
        return jsonify({"error": "Invalid token"}), 401

    if not (is_hr(userinfo) or is_admin(userinfo)):
        return "Access denied", 403

    items = (ExpenseClaim.query
             .filter(ExpenseClaim.status == ExpenseStatus.PENDING)
             .order_by(ExpenseClaim.created_at.desc())
             .all())

    # JSON pt Postman
    if auth_header:
        return jsonify([{
            "id": e.id,
            "employee": username_for_sub(e.user_id),
            "amount": float(e.amount),
            "currency": (e.currency or "").upper(),
            "description": e.description,
            "status": e.status.value,
            "created_at": e.created_at.strftime('%Y-%m-%d')
        } for e in items])

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
        {rows if rows else "<tr><td colspan='8' style='padding:14px'>Nu exista cereri PENDING.</td></tr>"}
      </table>

      <br>
      <a href="/"><button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Back</button></a>
    </div>
    </body></html>
    """


# HR - Approve Decont
@app.route("/expenses/<int:expense_id>/hr/approve", methods=["POST"])
def hr_approve_expense(expense_id):
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1] if auth_header and auth_header.startswith("Bearer ") else session.get("access_token")

    if not token:
        if auth_header: return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for("home"))

    try:
        userinfo = decode_token(token)
    except:
        return jsonify({"error": "Invalid token"}), 401

    if not (is_hr(userinfo) or is_admin(userinfo)):
        return "Access denied", 403

    exp = ExpenseClaim.query.get_or_404(expense_id)
    
    # Verificam daca este in starea corecta pentru a fi aprobata de HR
    if exp.status != ExpenseStatus.PENDING:
        if auth_header:
            return jsonify({"error": f"Expense is in status {exp.status.value}, cannot approve"}), 400
        return redirect(url_for("view_hr_expenses"))

    exp.status = ExpenseStatus.HR_APPROVED
    exp.approved_by = userinfo["sub"]
    db.session.commit()
    
    logger.info(f"HR {userinfo.get('preferred_username')} a aprobat decontul ID {expense_id}")

    if auth_header:
        return jsonify({
            "status": "success",
            "message": f"Expense {expense_id} has been approved by HR",
            "new_status": exp.status.value
        }), 200

    # Redirect pentru Browser
    return redirect(url_for("view_hr_expenses"))


# HR - Reject Decont
@app.route("/expenses/<int:expense_id>/hr/reject", methods=["POST"])
def hr_reject_expense(expense_id):
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1] if auth_header and auth_header.startswith("Bearer ") else session.get("access_token")

    if not token:
        if auth_header: return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for("home"))

    try:
        userinfo = decode_token(token)
    except:
        return jsonify({"error": "Invalid token"}), 401

    if not (is_hr(userinfo) or is_admin(userinfo)):
        return "Access denied", 403

    exp = ExpenseClaim.query.get_or_404(expense_id)
    
    if exp.status != ExpenseStatus.PENDING:
        if auth_header:
            return jsonify({"error": f"Expense already processed, status is {exp.status.value}"}), 409
        return "Expense already processed", 409

    # Actualizare status
    exp.status = ExpenseStatus.REJECTED
    exp.failure_reason = "Rejected by HR"
    exp.approved_by = userinfo["sub"]
    db.session.commit()
    
    # Notificare prin email
    emp_email = email_for_sub(exp.user_id)
    subject, body = build_expense_email(ExpenseStatus.REJECTED, exp)

    try:
        email_payload = {
            "to": emp_email,
            "subject": subject,
            "body": body
        }
        rabbit_publish(EMAIL_EXCHANGE, EMAIL_ROUTING_KEY, email_payload)
        logger.info(f"HR {userinfo.get('preferred_username')} a respins decontul ID {expense_id}. Email trimis in coada.")
    except Exception as e:
        logger.error("Expense HR reject email fail: %s", e)

    # JSON pt Postman
    if auth_header:
        return jsonify({
            "status": "rejected",
            "message": f"Expense {expense_id} was rejected",
            "notified_user": emp_email
        }), 200

    return redirect(url_for("view_hr_expenses"))





# Admin - Vezi Deconturi
@app.route("/expenses/admin")
def view_admin_expenses():
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    else:
        token = session.get("access_token")

    if not token:
        if auth_header: return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for("home"))

    try:
        userinfo = decode_token(token)
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    if not is_admin(userinfo):
        return "Access denied", 403

    # Adminul vede doar ce a fost aprobat de HR
    items = (ExpenseClaim.query
             .filter(ExpenseClaim.status == ExpenseStatus.HR_APPROVED)
             .order_by(ExpenseClaim.created_at.desc())
             .all())

    # JSON pt Postman
    if auth_header:
        return jsonify([{
            "id": e.id,
            "user": username_for_sub(e.user_id),
            "amount": float(e.amount),
            "currency": (e.currency or "").upper(),
            "description": e.description,
            "status": e.status.value,
            "created_at": e.created_at.strftime('%Y-%m-%d')
        } for e in items])

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

        amount_display = f"{e.amount:.2f}"

        rows += f"""
        <tr>
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
          <th align="left">User</th>
          <th align="left">Amount</th>
          <th align="left">Currency</th>
          <th align="left">Description</th>
          <th align="left">Status</th>
          <th align="left">Created</th>
          <th align="center">Actions</th>
        </tr>
        {rows if rows else "<tr><td colspan='7' style='padding:14px'>Nu exista cereri HR_APPROVED.</td></tr>"}
      </table>

      <br>
      <a href="/"><button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Back</button></a>
    </div>
    </body></html>
    """

# Admin - Approve la Decont
@app.route("/expenses/<int:expense_id>/admin/approve", methods=["POST"])
def admin_approve_expense(expense_id):
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1] if auth_header and auth_header.startswith("Bearer ") else session.get("access_token")

    if not token:
        if auth_header: return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for("home"))

    try:
        userinfo = decode_token(token)
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    if not is_admin(userinfo):
        return "Access denied", 403

    exp = ExpenseClaim.query.get_or_404(expense_id)
    if exp.status != ExpenseStatus.HR_APPROVED:
        error_msg = f"Expense {expense_id} is in status {exp.status.value}, not ready for admin approval"
        if auth_header:
            return jsonify({"error": error_msg}), 409
        return error_msg, 409

    exp.status = ExpenseStatus.QUEUED
    exp.approved_by = userinfo["sub"]
    db.session.commit()

    emp_email = email_for_sub(exp.user_id)
    subject, body = build_expense_email(ExpenseStatus.QUEUED, exp)

    try:
        email_payload = {
            "to": emp_email,
            "subject": subject,
            "body": body
        }
        rabbit_publish(EMAIL_EXCHANGE, EMAIL_ROUTING_KEY, email_payload)
    except Exception as e:
        logger.error("Expense admin approve email failed: %s", e)

    # Public mesajul
    trace_id = str(uuid.uuid4())
    msg = {
        "event": "expense.requested",
        "expense_id": exp.id,
        "user_id": exp.user_id,
        "amount": float(exp.amount),
        "currency": exp.currency,
        "description": exp.description,
        "requested_at": datetime.utcnow().isoformat() + "Z",
        "trace_id": trace_id,
        "approved_by": userinfo["sub"],
        "approved_at": datetime.utcnow().isoformat() + "Z",
    }

    rabbit_publish(EXPENSES_EXCHANGE, EXPENSES_ROUTING_KEY, msg)
    logger.info(f"Admin a aprobat decontul {expense_id}. Mesaj trimis spre Expense Worker cu trace_id: {trace_id}")

    # JSON pt Postman
    if auth_header:
        return jsonify({
            "status": "success",
            "message": "Expense approved and sent to payment queue",
            "expense_id": exp.id,
            "trace_id": trace_id
        }), 200

    return redirect(url_for("view_admin_expenses"))



# Admin - Reject Decont
@app.route("/expenses/<int:expense_id>/admin/reject", methods=["POST"])
def admin_reject_expense(expense_id):
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1] if auth_header and auth_header.startswith("Bearer ") else session.get("access_token")

    if not token:
        if auth_header: return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for("home"))

    try:
        userinfo = decode_token(token)
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    if not is_admin(userinfo):
        return "Access denied", 403

    exp = ExpenseClaim.query.get_or_404(expense_id)
    
    # Admin poate sa respinga doar daca HR a aprobat deja
    if exp.status != ExpenseStatus.HR_APPROVED:
        error_msg = f"Expense {expense_id} is in status {exp.status.value}, cannot be rejected by Admin"
        if auth_header:
            return jsonify({"error": error_msg}), 409
        return error_msg, 409

    # Actualizare status in baza de date
    exp.status = ExpenseStatus.REJECTED
    exp.failure_reason = "Rejected by an Admin"
    exp.approved_by = userinfo["sub"]
    db.session.commit()
    
    # Notificare prin email
    emp_email = email_for_sub(exp.user_id)
    subject, body = build_expense_email(ExpenseStatus.REJECTED, exp)

    try:
        email_payload = {
            "to": emp_email,
            "subject": subject,
            "body": body
        }
        rabbit_publish(EMAIL_EXCHANGE, EMAIL_ROUTING_KEY, email_payload)
        logger.info(f"Admin {userinfo.get('preferred_username')} a respins decontul {expense_id}. Email trimis in coada.")
    except Exception as e:
        logger.error("Expense admin reject email fail: %s", e)

    # JSON pt Postman
    if auth_header:
        return jsonify({
            "status": "rejected",
            "message": f"Expense {expense_id} was rejected by Admin",
            "notified_user": emp_email
        }), 200

    return redirect(url_for("view_admin_expenses"))


@app.route("/leave/my")
def my_leaves():
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1] if auth_header and auth_header.startswith("Bearer ") else session.get("access_token")

    if not token:
        return redirect(url_for("home"))

    try:
        userinfo = decode_token(token)
    except:
        return jsonify({"error": "Invalid token"}), 401
        
    if not has_role(userinfo, "Angajat"):
        return "Access denied", 403

    items = (
        LeaveRequest.query
        .filter_by(user_id=userinfo["sub"])
        .order_by(LeaveRequest.created_at.desc())
        .all()
    )

    # JSON pt Postman
    if auth_header:
        return jsonify([{
            "id": l.id, "start": str(l.start_date), "end": str(l.end_date),
            "reason": l.reason, "status": l.status.value
        } for l in items])

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
          <th align="left">ID</th><th align="left">Start</th><th align="left">End</th>
          <th align="left">Reason</th><th align="left">Status</th><th align="left">Approved by</th><th align="left">Created</th>
        </tr>
        {rows if rows else "<tr><td colspan='7' style='padding:14px'>Nu exista cereri de concediu.</td></tr>"}
      </table>
      <br><a href="/"><button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Back</button></a>
    </div>
    </body></html>
    """


# Toti - Vezi profilul tau
@app.route("/profile")
def profile():
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = None

    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    else:
        token = session.get("access_token")
        
    if not token:
        if auth_header:
            return jsonify({"error": "Unauthorized", "message": "Missing token"}), 401
        return redirect(url_for("home"))

    try:

        userinfo = decode_token(token)
        roles = visible_roles_from_token(userinfo)


        if auth_header:
            return jsonify({
                "username": userinfo.get("preferred_username"),
                "email": userinfo.get("email"),
                "first_name": userinfo.get("given_name"),
                "last_name": userinfo.get("family_name"),
                "roles": roles
            })

    except Exception as e:
        logger.error(f"Eroare la procesarea profilului: {e}")
        return jsonify({"error": "Invalid token"}), 401

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
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1] if auth_header and auth_header.startswith("Bearer ") else session.get("access_token")

    if not token:
        if auth_header: return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for("home"))

    userinfo = decode_token(token)
    if not has_role(userinfo, "Angajat"):
        return "Access denied", 403

    if request.method == "POST":
        data = request.get_json() if request.is_json else request.form
        
        start_date_str = data.get("start_date")
        end_date_str = data.get("end_date")
        reason = data.get("reason", "")

        try:
            new_request = LeaveRequest(
                user_id=userinfo["sub"],
                start_date=datetime.strptime(start_date_str, '%Y-%m-%d'),
                end_date=datetime.strptime(end_date_str, '%Y-%m-%d'),
                reason=reason,
                status=LeaveStatus.PENDING
            )
            db.session.add(new_request)
            db.session.commit()
            
            if auth_header:
                return jsonify({"status": "success", "message": "Leave request created", "id": new_request.id}), 201
            return redirect(url_for("home"))
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    return """
    <html><body style="font-family:Arial;background:#f4f6f8">
    <div style="background:white;width:480px;margin:60px auto;padding:30px;border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1)">
    <h2>Cerere concediu</h2>
    <form method="post">
        Data inceput:<br><input type="date" name="start_date" required style="padding:8px;width:100%"><br><br>
        Data sfarsit:<br><input type="date" name="end_date" required style="padding:8px;width:100%"><br><br>
        Motiv:<br><textarea name="reason" style="padding:8px;width:100%;height:90px"></textarea><br><br>
        <button type="submit" style="background:#28a745;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Trimite</button>
        <a href="/" style="margin-left:10px"><button type="button" style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Back</button></a>
    </form>
    </div>
    </body></html>
    """
    

@app.route("/expenses/request", methods=["GET", "POST"])
def expense_request():
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = None
    
    print(f"DEBUG: Auth Header present: {bool(auth_header)}")

    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        print("DEBUG: Token preluat din Header (Postman)")
    else:
        token = session.get("access_token")
        if token: print("DEBUG: Token preluat din Sesiune (Browser)")

    if not token:
        print("DEBUG: Nu s-a gasit niciun token! Redirect la home/login.")
        if request.is_json or auth_header:
            return jsonify({"error": "Unauthorized", "message": "Missing token"}), 401
        return redirect(url_for("home"))

    try:
        userinfo = decode_token(token)
    except Exception as e:
        print(f"DEBUG: Eroare decodare token: {e}")
        return jsonify({"error": "Invalid token"}), 401

    if not has_role(userinfo, "Angajat"):
        return "Access denied", 403

    user_id = userinfo["sub"]

    if request.method == "POST":
        if not check_expense_rate_limit(user_id):
            print(f"DEBUG: Rate limit atins pentru user {user_id}")
            if auth_header or request.is_json:
                return jsonify({"error": "Rate limit exceeded", "limit": 5}), 429
            return "Limita depasita (5/zi)", 429

        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        amount_str = data.get("amount", "0")
        currency = data.get("currency", "ron").strip().lower()
        description = data.get("description", "")

        try:
            amount = float(amount_str)
            if amount <= 0: return jsonify({"error": "Suma invalida"}), 400
        except ValueError:
            return jsonify({"error": "Suma invalida"}), 400

        exp = ExpenseClaim(
            user_id=user_id,
            amount=amount,
            currency=currency,
            description=description,
            status=ExpenseStatus.PENDING,
        )
        db.session.add(exp)
        db.session.commit()
        print(f"DEBUG: Decont salvat cu succes. ID: {exp.id}")

        if auth_header or request.is_json:
            return jsonify({"status": "success", "id": exp.id}), 201
        return redirect(url_for("my_expenses"))

    return """
    <html><body style="font-family:Arial;background:#f4f6f8">
    <div style="background:white;width:480px;margin:60px auto;padding:30px;border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1)">
      <h2>Cerere de decont</h2>
      <form method="post">
        Suma: <input type="number" name="amount" step="0.01" required style="width:100%"><br><br>
        Moneda: <input type="text" name="currency" value="ron" required style="width:100%"><br><br>
        Descriere: <textarea name="description" style="width:100%;height:80px"></textarea><br><br>
        <button type="submit" style="background:#17a2b8;color:white;border:none;padding:10px 14px;border-radius:8px">Trimite</button>
      </form>
    </div>
    </body></html>
    """


# Deconturi - Angajat
@app.route("/expenses/my")
def my_expenses():
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1] if auth_header and auth_header.startswith("Bearer ") else session.get("access_token")

    if not token:
        return redirect(url_for("home"))

    try:
        userinfo = decode_token(token)
    except:
        return jsonify({"error": "Invalid token"}), 401

    if not has_role(userinfo, "Angajat"):
        return "Access denied", 403

    items = (ExpenseClaim.query
             .filter_by(user_id=userinfo["sub"])
             .order_by(ExpenseClaim.created_at.desc())
             .all())

    # JSON pt Postman
    if auth_header:
        return jsonify([{
            "id": e.id, "amount": float(e.amount), "currency": e.currency,
            "description": e.description, "status": e.status.value
        } for e in items])

    rows = ""
    for e in items:
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
          <th align="left">ID</th><th align="left">Amount</th><th align="left">Currency</th>
          <th align="left">Description</th><th align="left">Status</th><th align="left">Created</th>
        </tr>
        {rows if rows else "<tr><td colspan='6' style='padding:14px'>Nu exista deconturi.</td></tr>"}
      </table>
      <br><a href="/"><button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Back</button></a>
    </div>
    </body></html>
    """




# HR – Vede cereri de concediu
@app.route("/leave/all")
def view_all_leaves():
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    else:
        token = session.get("access_token")

    if not token:
        if auth_header: return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for("home"))

    try:
        userinfo = decode_token(token)
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    if not can_manage_leaves(userinfo):
        return "Access denied", 403

    leaves = LeaveRequest.query.order_by(LeaveRequest.created_at.desc()).all()

    # JSON pt Postman
    if auth_header:
        return jsonify([{
            "id": l.id,
            "employee": username_for_sub(l.user_id),
            "start_date": str(l.start_date),
            "end_date": str(l.end_date),
            "reason": l.reason,
            "status": l.status.value,
            "approved_by": username_for_sub(l.approved_by) if l.approved_by else "-",
            "created_at": l.created_at.strftime('%Y-%m-%d')
        } for l in leaves])

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

# Admin - Creare Utilizator Nou
@app.route("/admin/create-user", methods=["POST"])
def admin_create_user():
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1] if auth_header and auth_header.startswith("Bearer ") else session.get("access_token")

    if not token:
        if auth_header: return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for("home"))

    try:
        userinfo = decode_token(token)
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    if not is_admin(userinfo):
        return "Access denied. Admin only.", 403

    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    first_name = data.get("first_name")
    last_name = data.get("last_name")

    try:
        # Creare utilizator an Keycloak
        admin_kc = get_admin_client()
        
        # Structura API Keycloak
        new_user_kc = admin_kc.create_user({
            "email": email,
            "username": username,
            "enabled": True,
            "firstName": first_name,
            "lastName": last_name,
            "credentials": [{"value": password, "type": "password", "temporary": False}]
        }, exist_ok=False)

        # ID utilizator nou
        new_id = new_user_kc if isinstance(new_user_kc, str) else admin_kc.get_user_id(username)

        # Salvare in baza de date
        new_user_db = UserProfile(
            keycloak_id=new_id,
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            role="Angajat"
        )
        db.session.add(new_user_db)
        db.session.commit()

        logger.info(f"Admin {userinfo.get('preferred_username')} a creat utilizatorul {username} cu ID {new_id}")

        if auth_header:
            return jsonify({
                "status": "success",
                "message": "User created in Keycloak and Local DB",
                "keycloak_id": new_id
            }), 201

    except Exception as e:
        logger.error(f"Error creating user: {e}")
        db.session.rollback()
        if auth_header:
            return jsonify({"error": str(e)}), 500
        return f"Eroare la creare: {str(e)}", 500

    return redirect(url_for("list_users"))
        

# Admin - Manage Users
@app.route("/admin/user/<user_id>", methods=["PUT", "DELETE"])
def rest_manage_user(user_id):
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1] if auth_header and auth_header.startswith("Bearer ") else session.get("access_token")

    if not token:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        userinfo = decode_token(token)
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    if not is_admin(userinfo):
        return jsonify({"error": "Forbidden. Admin access required."}), 403

    # Delete user
    if request.method == "DELETE":
        try:
            # Din keycloak
            admin_kc = get_admin_client()
            admin_kc.delete_user(user_id)
            
            # Din baza de date
            user_db = UserProfile.query.filter_by(keycloak_id=user_id).first()
            if user_db:
                username_deleted = user_db.username
                db.session.delete(user_db)
                db.session.commit()
                logger.info(f"Admin {userinfo.get('preferred_username')} a sters userul: {username_deleted}")
            
            return jsonify({"status": "success", "message": "User deleted from Keycloak and DB"}), 200
        except Exception as e:
            logger.error(f"Error deleting user {user_id}: {e}")
            return jsonify({"error": str(e)}), 500

    # Actualizeaza roluri
    if request.method == "PUT":
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        new_roles_names = data.get("roles", [])
        
        try:
            # In keycloak
            update_keycloak_user_roles(user_id, new_roles_names)
            
            # IN baza de date
            u = UserProfile.query.filter_by(keycloak_id=user_id).first()
            if u:
                u.role = ",".join(new_roles_names)
                db.session.commit()
                logger.info(f"Admin {userinfo.get('preferred_username')} a actualizat rolurile lui {u.username}: {u.role}")
            
            return jsonify({"status": "success", "message": "Roles updated in Keycloak and DB"}), 200
        except Exception as e:
            logger.error(f"Error updating roles for user {user_id}: {e}")
            return jsonify({"error": str(e)}), 500
        
 
# Admin / HR - Lista Utilizatori
@app.route("/users")
def list_users():
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    else:
        token = session.get("access_token")

    if not token:
        if auth_header: return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for("home"))

    try:
        userinfo = decode_token(token)
    except:
        return jsonify({"error": "Invalid token"}), 401

    user_is_admin = is_admin(userinfo)
    user_is_hr = is_hr(userinfo)
    
    if not (user_is_admin or user_is_hr):
        return "Access denied. Trebuie sa fii HR sau Admin.", 403

    # Toti din db
    users = UserProfile.query.order_by(UserProfile.username.asc()).all()

    # JSON pt Postman
    if auth_header:
        return jsonify([{
            "id": u.id,
            "keycloak_id": u.keycloak_id,
            "username": u.username,
            "email": u.email,
            "first_name": u.first_name,
            "last_name": u.last_name,
            "roles": u.role.split(",") if u.role else []
        } for u in users])

    VISIBLE_ROLES = ["Angajat", "HR", "Administrator"]

    create_user_form = ""
    if user_is_admin:
        create_user_form = """
        <div style="background:#e9ecef; padding:20px; border-radius:8px; margin-bottom:30px; border:1px solid #ced4da;">
            <h3 style="margin-top:0; color:#333;">➕ Adauga Utilizator Nou</h3>
            <form method="POST" action="/admin/create-user" style="display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end;">
                <div>
                    <label style="font-size:0.85em; font-weight:bold;">Username:</label><br>
                    <input type="text" name="username" required style="padding:6px; border-radius:4px; border:1px solid #ccc;">
                </div>
                <div>
                    <label style="font-size:0.85em; font-weight:bold;">Email:</label><br>
                    <input type="email" name="email" required style="padding:6px; border-radius:4px; border:1px solid #ccc;">
                </div>
                <div>
                    <label style="font-size:0.85em; font-weight:bold;">Prenume:</label><br>
                    <input type="text" name="first_name" required style="padding:6px; border-radius:4px; border:1px solid #ccc;">
                </div>
                <div>
                    <label style="font-size:0.85em; font-weight:bold;">Nume:</label><br>
                    <input type="text" name="last_name" required style="padding:6px; border-radius:4px; border:1px solid #ccc;">
                </div>
                <div>
                    <label style="font-size:0.85em; font-weight:bold;">Parola:</label><br>
                    <input type="password" name="password" required style="padding:6px; border-radius:4px; border:1px solid #ccc;">
                </div>
                <button type="submit" style="background:#28a745; color:white; border:none; padding:8px 16px; border-radius:4px; cursor:pointer; font-weight:bold; height:35px;">Creeaza User</button>
            </form>
        </div>
        """

    rows = ""
    for u in users:
        current_roles = (u.role or "").split(",")
        management_cell = ""
        delete_button = ""

        if user_is_admin:
            checkboxes = ""
            for r in VISIBLE_ROLES:
                checked = "checked" if r in current_roles else ""
                checkboxes += f"""
                    <label style="margin-right:8px; font-size: 0.8em; cursor:pointer; display:inline-block; background:#f8f9fa; padding:2px 5px; border-radius:3px; border:1px solid #ddd;">
                        <input type="checkbox" class="role-cb-{u.keycloak_id}" value="{r}" {checked}> {r}
                    </label>
                """
            
            management_cell = f"""
            <td style="border-bottom:1px solid #eee">
                <div style="margin:0; display:flex; align-items:center; gap:5px">
                    <div style="display:flex; flex-wrap:wrap; gap:2px;">{checkboxes}</div>
                    <button onclick="updateUserRoles('{u.keycloak_id}')" style="background:#007bff; color:white; border:none; padding:4px 8px; border-radius:4px; cursor:pointer; font-size:0.75em">Save</button>
                </div>
            </td>
            """
            
            delete_button = f"""
            <td style="border-bottom:1px solid #eee; text-align:center;">
                <button onclick="deleteUser('{u.keycloak_id}', '{u.username}')" style="background:#dc3545; color:white; border:none; padding:6px 10px; border-radius:4px; cursor:pointer; font-size:0.8em">DELETE</button>
            </td>
            """

        rows += f"""
        <tr>
            <td style="border-bottom:1px solid #eee"><b>{(u.username or "")}</b></td>
            <td style="border-bottom:1px solid #eee">{(u.email or "")}</td>
            <td style="border-bottom:1px solid #eee">{(u.first_name or "-")}</td>
            <td style="border-bottom:1px solid #eee">{(u.last_name or "-")}</td>
            <td style="border-bottom:1px solid #eee"><small style="background:#fff3cd; padding:2px 4px; border-radius:3px;">{(u.role or "fara rol")}</small></td>
            {management_cell}
            {delete_button}
        </tr>
        """

    admin_headers = '<th align="left">Modifica Roluri</th><th align="center">Actiuni</th>' if user_is_admin else ""

    return f"""
    <html>
    <head>
        <title>Management Utilizatori</title>
        <script>
        async function deleteUser(userId, username) {{
            if (!confirm('Sigur vrei sa stergi utilizatorul ' + username + '?')) return;
            try {{
                const response = await fetch('/admin/user/' + userId, {{ method: 'DELETE' }});
                const data = await response.json();
                if (response.ok) {{ alert('Utilizator sters!'); window.location.reload(); }}
                else {{ alert('Eroare: ' + (data.error || 'Problema')); }}
            }} catch (err) {{ alert('Eroare retea: ' + err); }}
        }}
        async function updateUserRoles(userId) {{
            const checkboxes = document.querySelectorAll('.role-cb-' + userId);
            const selectedRoles = Array.from(checkboxes).filter(cb => cb.checked).map(cb => cb.value);
            try {{
                const response = await fetch('/admin/user/' + userId, {{
                    method: 'PUT',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ roles: selectedRoles }})
                }});
                const data = await response.json();
                if (response.ok) {{ alert('Roluri actualizate!'); window.location.reload(); }}
                else {{ alert('Eroare: ' + (data.error || 'Problema')); }}
            }} catch (err) {{ alert('Eroare retea: ' + err); }}
        }}
        </script>
    </head>
    <body style="font-family:Arial, sans-serif; background:#f4f6f8; color:#333;">
    <div style="background:white; width:1300px; max-width:98vw; margin:40px auto; padding:30px; border-radius:12px; box-shadow:0 4px 15px rgba(0,0,0,0.1)">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; border-bottom:2px solid #eee; padding-bottom:15px;">
            <h2 style="margin:0; color:#2c3e50;">👥 Management Utilizatori</h2>
            <div style="text-align:right">
                <span style="background:#007bff; color:white; padding:5px 12px; border-radius:20px; font-size:0.85em; font-weight:bold;">
                    Status: {"Administrator" if user_is_admin else "HR"}
                </span>
            </div>
        </div>
        {create_user_form}
        <table width="100%" cellpadding="12" cellspacing="0" style="border-collapse:collapse">
            <thead>
                <tr style="background:#343a40; color:white">
                    <th align="left">Username</th><th align="left">Email</th><th align="left">Prenume</th>
                    <th align="left">Nume</th><th align="left">Roluri</th>{admin_headers}
                </tr>
            </thead>
            <tbody>{rows if rows else "<tr><td colspan='7' align='center'>Nu exista utilizatori.</td></tr>"}</tbody>
        </table>
        <div style="margin-top:30px;">
            <a href="/"><button style="background:#6c757d; color:white; border:none; padding:12px 24px; border-radius:8px; cursor:pointer; font-weight:bold;">⬅ Inapoi</button></a>
        </div>
    </div>
    </body>
    </html>
    """


# HR – Approve concediu
@app.route("/leave/<int:leave_id>/approve", methods=["POST"])
def approve_leave(leave_id):
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1] if auth_header and auth_header.startswith("Bearer ") else session.get("access_token")

    if not token:
        if auth_header: return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for("home"))

    try:
        userinfo = decode_token(token)
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    if not can_manage_leaves(userinfo):
        return "Access denied", 403

    # Update direct in baza de date ca sa nu am race conditions
    updated = (
        db.session.query(LeaveRequest)
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
        error_msg = "Cererea a fost deja procesata sau nu exista."
        if auth_header:
            return jsonify({"error": error_msg}), 409
        return error_msg, 409

    # Luat date pt email
    leave = LeaveRequest.query.get(leave_id)
    emp_email = email_for_sub(leave.user_id)
    subject, body = build_leave_email(LeaveStatus.APPROVED, leave)

    try:
        logger.info("Trimitere email aprobare: emp_email=%s leave_id=%s", emp_email, leave_id)
        email_payload = {
            "to": emp_email,
            "subject": subject,
            "body": body
        }
        rabbit_publish(EMAIL_EXCHANGE, EMAIL_ROUTING_KEY, email_payload)
    except Exception as e:
        logger.error("Email send failed for leave %s: %s", leave_id, e)

    # JSON pt Postman
    if auth_header:
        return jsonify({
            "status": "success",
            "message": f"Leave request {leave_id} approved",
            "notified_email": emp_email
        }), 200

    return redirect(url_for("view_all_leaves"))


# HR – Reject concediu
@app.route("/leave/<int:leave_id>/reject", methods=["POST"])
def reject_leave(leave_id):
    # Token hibrid
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1] if auth_header and auth_header.startswith("Bearer ") else session.get("access_token")

    if not token:
        if auth_header: return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for("home"))

    try:
        userinfo = decode_token(token)
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    if not can_manage_leaves(userinfo):
        return "Access denied", 403

    # Daca e in pending
    updated = (
        db.session.query(LeaveRequest)
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
        error_msg = "Cererea a fost deja procesata de alt cineva sau nu exista."
        if auth_header:
            return jsonify({"error": error_msg}), 409
        return error_msg, 409e

    # Date pt email
    leave = LeaveRequest.query.get(leave_id)
    emp_email = email_for_sub(leave.user_id)
    subject, body = build_leave_email(LeaveStatus.REJECTED, leave)

    try:
        email_payload = {
            "to": emp_email,
            "subject": subject,
            "body": body
        }
        rabbit_publish(EMAIL_EXCHANGE, EMAIL_ROUTING_KEY, email_payload)
        logger.info(f"Concediu ID {leave_id} respins de {userinfo.get('preferred_username')}. Email trimis in RabbitMQ.")
    except Exception as e:
        logger.error("Email send failed for rejection leave %s: %s", leave_id, e)

    # JSON pt Postman
    if auth_header:
        return jsonify({
            "status": "rejected",
            "message": f"Leave request {leave_id} has been rejected",
            "notified_email": emp_email
        }), 200

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

# Callback dupa login
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

    # Decodare token pt info user
    userinfo = decode_token(token["access_token"])
    
    # Caut in baza de date
    user = UserProfile.query.filter_by(keycloak_id=userinfo["sub"]).first()
    
    if not user:
        # Daca nu e, il fac
        user = UserProfile(
            keycloak_id=userinfo["sub"],
            username=userinfo.get("preferred_username"),
            email=userinfo.get("email"),
            first_name=userinfo.get("given_name"),
            last_name=userinfo.get("family_name"),
            role=",".join(visible_roles_from_token(userinfo))
        )
        db.session.add(user)
        logger.info(f"Utilizator nou creat in DB: {user.username}")
    else:
        # Daca exista, ii dau update la date/roluri
        user.first_name = userinfo.get("given_name")
        user.last_name = userinfo.get("family_name")
        user.email = userinfo.get("email")
        user.role = ",".join(visible_roles_from_token(userinfo))
        logger.info(f"Datele utilizatorului {user.username} au fost sincronizate la login.")

    db.session.commit()

    return redirect(url_for("home"))


# Logout (sa nu ramana logat in aplicatie, trebuie sa se logheze iar)
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
