from flask import Flask, request, jsonify, redirect, session, url_for
from keycloak import KeycloakOpenID
from models import db, UserProfile, LeaveRequest, LeaveStatus
from datetime import datetime
import os
import time
import jwt

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

    leave_button = ""
    if has_role(userinfo, "Angajat"):
        leave_button = """
            <a href="/leave/request">
                <button style="background:#28a745;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Fă cerere de concediu
                </button>
            </a>
        """

    hr_button = ""
    if can_manage_leaves(userinfo):
        hr_button = """
            <a href="/leave/all">
                <button style="background:#ff9800;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">
                    Vezi cereri concediu
                </button>
            </a>
        """

    return f"""
    <html>
    <body style="font-family:Arial;background:#f4f6f8">
    <div style="background:white;width:480px;margin:80px auto;padding:30px;border-radius:12px;text-align:center;box-shadow:0 4px 10px rgba(0,0,0,0.1)">
        <h2>Welcome, {username}</h2>
        <p><strong>Email:</strong> {email}</p>
        <p><strong>Roles:</strong> {", ".join(roles) if roles else "No roles"}</p>

        <div style="margin-top:18px;display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
            {leave_button}
            {hr_button}
        </div>

        <div style="margin-top:22px">
            <a href="/profile"><button style="background:#0066ff;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Profile</button></a>
            <a href="/logout"><button style="background:#cc0000;color:white;border:none;padding:10px 14px;border-radius:8px;cursor:pointer">Logout</button></a>
        </div>
    </div>
    </body>
    </html>
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


# HR – Approve / Reject concediu
@app.route("/leave/<int:leave_id>/approve", methods=["POST"])
def approve_leave(leave_id):
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not can_manage_leaves(userinfo):
        return "Access denied", 403

    leave = LeaveRequest.query.get_or_404(leave_id)
    if leave.status != LeaveStatus.PENDING:
        return redirect(url_for("view_all_leaves"))

    leave.status = LeaveStatus.APPROVED
    leave.approved_by = userinfo["sub"]
    db.session.commit()

    return redirect(url_for("view_all_leaves"))


@app.route("/leave/<int:leave_id>/reject", methods=["POST"])
def reject_leave(leave_id):
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session["access_token"])
    if not can_manage_leaves(userinfo):
        return "Access denied", 403

    leave = LeaveRequest.query.get_or_404(leave_id)
    if leave.status != LeaveStatus.PENDING:
        return redirect(url_for("view_all_leaves"))

    leave.status = LeaveStatus.REJECTED
    leave.approved_by = userinfo["sub"]
    db.session.commit()

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
