import os
import secrets
import sqlite3
from functools import wraps

from dotenv import load_dotenv
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash

load_dotenv()

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set SESSION_COOKIE_SECURE=1 in production (cookie only sent over HTTPS)
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=16 * 1024,  # reject huge request bodies
)

DATABASE = os.environ.get("DATABASE", "messages.db")
ADMIN_PASSWORD_HASH = os.environ["ADMIN_PASSWORD_HASH"]

MAX_ALIAS_LEN = 50
MAX_MESSAGE_LEN = 2000


# =====================================================================
# Database
# =====================================================================

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # rows behave like dicts: row["message"]
    return db


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def execute_db(query, args=()):
    db = get_db()
    db.execute(query, args)
    db.commit()


@app.teardown_appcontext
def close_db_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        execute_db("""
            CREATE TABLE IF NOT EXISTS messages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                alias      TEXT,
                message    TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)


init_db()  # module level, so it also runs under gunicorn


# =====================================================================
# Security helpers
# =====================================================================

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not secrets.compare_digest(token, session.get("csrf_token", "")):
            abort(400, "Invalid or missing form token. Refresh the page and try again.")


# =====================================================================
# Routes
# =====================================================================

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        alias = request.form.get("alias", "").strip()[:MAX_ALIAS_LEN]
        message = request.form.get("message", "").strip()

        if not message:
            flash("Message can't be empty.", "error")
            return redirect(url_for("home"))
        if len(message) > MAX_MESSAGE_LEN:
            flash(f"Message is too long (max {MAX_MESSAGE_LEN} characters).", "error")
            return redirect(url_for("home"))

        execute_db(
            "INSERT INTO messages (alias, message) VALUES (?, ?)",
            (alias or None, message),
        )
        flash("Message sent. Thanks!", "success")
        return redirect(url_for("home"))

    return render_template("index.html", max_len=MAX_MESSAGE_LEN, max_alias=MAX_ALIAS_LEN)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("admin"))

    if request.method == "POST":
        password = request.form.get("password", "")
        if check_password_hash(ADMIN_PASSWORD_HASH, password):
            session.clear()
            session["logged_in"] = True
            next_url = request.args.get("next", "")
            # only allow redirects to pages on this site
            if not next_url.startswith("/") or next_url.startswith("//"):
                next_url = url_for("admin")
            return redirect(next_url)
        flash("Wrong password.", "error")
        return redirect(request.full_path)

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("home"))


@app.route("/admin")
@login_required
def admin():
    messages = query_db("SELECT * FROM messages ORDER BY id DESC")
    return render_template("admin.html", messages=messages)


@app.route("/admin/delete/<int:message_id>", methods=["POST"])
@login_required
def delete_message(message_id):
    execute_db("DELETE FROM messages WHERE id = ?", (message_id,))
    flash("Message deleted.", "success")
    return redirect(url_for("admin"))


if __name__ == "__main__":
    app.run(port=5000, debug=True)
