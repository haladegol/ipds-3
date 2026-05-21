"""Auth routes: signup, login, logout."""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from models.database import db, User

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            from models.database import SystemLog
            db.session.add(SystemLog(level="INFO", event="User Login", details=f"User {username} logged in."))
            db.session.commit()
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard.index"))
        flash("Invalid username or password", "error")

    return render_template("login.html")


@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("All fields are required", "error")
        elif password != confirm:
            flash("Passwords do not match", "error")
        elif len(password) < 6:
            flash("Password must be at least 6 characters", "error")
        elif User.query.filter_by(username=username).first():
            flash("Username already exists", "error")
        elif User.query.filter_by(email=email).first():
            flash("Email already registered", "error")
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            from models.database import SystemLog
            db.session.add(SystemLog(level="SUCCESS", event="User Signup", details=f"New user {username} registered."))
            db.session.commit()
            flash("Account created successfully! Please login.", "success")
            return redirect(url_for("auth.login"))

    return render_template("signup.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    from flask import session
    session.pop("hades_root_authenticated", None)
    return redirect(url_for("auth.login"))

from functools import wraps
from flask import session, current_app

def hades_root_required(f):
    """Requires the separate, dedicated root password to access sensitive paths."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash("Administrator access required for this area.", "error")
            return redirect(url_for("dashboard.index"))
        if not session.get("hades_root_authenticated"):
            flash("Secondary authentication required for HADES internals.", "warning")
            return redirect(url_for("auth.root_login", next=request.url))
        return f(*args, **kwargs)
    return decorated

@auth_bp.route("/root-auth", methods=["GET", "POST"])
@login_required
def root_login():
    if not current_user.is_admin:
        flash("You are not authorized to access this page.", "error")
        return redirect(url_for("dashboard.index"))

    # Already authenticated for root this session?
    if session.get("hades_root_authenticated"):
        return redirect(request.args.get("next") or url_for("dashboard.index"))

    if request.method == "POST":
        password = request.form.get("root_password", "")
        if password == current_app.config.get("HADES_ROOT_PASSWORD", "hades_root_secure_2026"):
            session["hades_root_authenticated"] = True
            
            from models.database import SystemLog
            db.session.add(SystemLog(level="WARNING", event="Root Elevation", details=f"User {current_user.username} entered root mode."))
            db.session.commit()
            
            # Go back to where they came from
            next_url = request.args.get("next")
            return redirect(next_url or url_for("dashboard.index"))
        else:
            flash("Invalid root password. Access denied.", "error")
            
            from models.database import SystemLog
            db.session.add(SystemLog(level="CRITICAL", event="Failed Root Elevation", details=f"User {current_user.username} failed root auth."))
            db.session.commit()

    return render_template("auth/root_login.html", next_url=request.args.get("next"))
