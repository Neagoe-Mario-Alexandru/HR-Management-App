from flask import Flask, request, jsonify, redirect, session, url_for
from keycloak import KeycloakOpenID
from models import db, UserProfile
import os
import time
import jwt

# Environment detection
IN_DOCKER = os.environ.get("IN_DOCKER", "0") == "1"

# Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "SUPER_SECRET_SESSION_KEY")

# Roluri de business vizibile în aplicație
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
    """Decode JWT fără verificare semnătură (dev)."""
    if not token:
        return {}

    if isinstance(token, bytes):
        token = token.decode("utf-8")

    return jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_aud": False,
        },
    )

# Routes
@app.route("/")
def home():
    if "access_token" not in session:
        return """
        <html>
        <head>
            <title>Authentication Demo</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: #f4f6f8;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                }
                .card {
                    background: white;
                    padding: 30px;
                    border-radius: 12px;
                    box-shadow: 0 4px 10px rgba(0,0,0,0.1);
                    text-align: center;
                    width: 350px;
                }
                button {
                    background: #0066ff;
                    color: white;
                    border: none;
                    padding: 12px 20px;
                    border-radius: 8px;
                    font-size: 16px;
                    cursor: pointer;
                }
                button:hover {
                    background: #004ecc;
                }
            </style>
        </head>
        <body>
            <div class="card">
                <h2>Authentication Demo</h2>
                <p>Please login using Keycloak</p>
                <a href="/login"><button>Login</button></a>
            </div>
        </body>
        </html>
        """

    userinfo = decode_token(session.get("access_token"))
    username = userinfo.get("preferred_username", "unknown")
    email = userinfo.get("email", "unknown")
    all_roles = userinfo.get("realm_access", {}).get("roles", [])
    roles = [r for r in all_roles if r in VISIBLE_ROLES]


    return f"""
    <html>
    <head>
        <title>Home</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f4f6f8;
            }}
            .card {{
                background: white;
                max-width: 450px;
                margin: 80px auto;
                padding: 30px;
                border-radius: 12px;
                box-shadow: 0 4px 10px rgba(0,0,0,0.1);
                text-align: center;
            }}
            .actions a {{
                margin: 10px;
                display: inline-block;
            }}
            button {{
                background: #0066ff;
                color: white;
                border: none;
                padding: 10px 18px;
                border-radius: 8px;
                font-size: 14px;
                cursor: pointer;
            }}
            button.logout {{
                background: #cc0000;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h2>Welcome, {username}</h2>
            <p><strong>Email:</strong> {email}</p>
            <p><strong>Roles:</strong> {", ".join(roles) if roles else "No roles"}</p>

            <div class="actions">
                <a href="/profile"><button>View Profile</button></a>
                <a href="/logout"><button class="logout">Logout</button></a>
            </div>
        </div>
    </body>
    </html>
    """



@app.route("/profile")
def profile():
    if "access_token" not in session:
        return redirect(url_for("home"))

    userinfo = decode_token(session.get("access_token"))
    all_roles = userinfo.get("realm_access", {}).get("roles", [])
    roles = [r for r in all_roles if r in VISIBLE_ROLES]


    rows = ""
    labels = {
        "preferred_username": "Username",
        "email": "Email",
        "given_name": "First name",
        "family_name": "Last name",
        "email_verified": "Email verified"
    }

    for key, label in labels.items():
        rows += f"<tr><th>{label}</th><td>{userinfo.get(key, '')}</td></tr>"

    rows += f"<tr><th>Roles</th><td>{', '.join(roles) if roles else 'No roles'}</td></tr>"

    return f"""
    <html>
    <head>
        <title>User Profile</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f4f6f8;
            }}
            .card {{
                background: white;
                max-width: 600px;
                margin: 60px auto;
                padding: 30px;
                border-radius: 12px;
                box-shadow: 0 4px 10px rgba(0,0,0,0.1);
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                padding: 10px;
                border-bottom: 1px solid #ddd;
                text-align: left;
            }}
            th {{
                background: #0066ff;
                color: white;
                width: 40%;
            }}
            .actions {{
                text-align: center;
                margin-top: 20px;
            }}
            button {{
                background: #0066ff;
                color: white;
                border: none;
                padding: 10px 18px;
                border-radius: 8px;
                cursor: pointer;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h2>User Profile</h2>
            <table>
                {rows}
            </table>
            <div class="actions">
                <a href="/"><button>Back</button></a>
            </div>
        </div>
    </body>
    </html>
    """


@app.route("/login")
def login():
    auth_url = (
        f"{KEYCLOAK_PUBLIC}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"
        f"?client_id={KEYCLOAK_CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope=openid%20profile%20email"
        f"&prompt=login"
    )
    return redirect(auth_url)


@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return jsonify(dict(request.args)), 400

    try:
        kc = get_keycloak()
        token = kc.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri=REDIRECT_URI
        )
        session["access_token"] = token.get("access_token")
        return redirect(url_for("home"))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/logout")
def logout():
    session.clear()

    redirect_after_logout = "http://localhost:5001" if IN_DOCKER else "http://localhost:5002"

    logout_url = (
        f"{KEYCLOAK_PUBLIC}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout"
        f"?redirect_uri={redirect_after_logout}"
    )
    return redirect(logout_url)


@app.route("/profiles/sync", methods=["POST"])
def sync_profile():
    data = request.json or {}

    sub = data.get("sub")
    if not sub:
        return jsonify({"error": "missing sub"}), 400

    user = UserProfile.query.filter_by(keycloak_id=sub).first()
    if not user:
        user = UserProfile(
            keycloak_id=sub,
            username=data.get("preferred_username"),
            email=data.get("email"),
            role=data.get("role")
        )
        db.session.add(user)
        db.session.commit()

    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=FLASK_PORT)
