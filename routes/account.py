from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from models.database import db, User, SystemLog

account_bp = Blueprint("account", __name__)

@account_bp.route("/account")
@login_required
def index():
    return render_template("account.html", user=current_user)

@account_bp.route("/account/update", methods=["POST"])
@login_required
def update():
    email = request.form.get("email")
    if email and email != current_user.email:
        # Check if email exists
        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("Email is already in use by another account.", "error")
        else:
            current_user.email = email
            db.session.commit()
            db.session.add(SystemLog(level="INFO", event="Account Updated", details=f"User {current_user.username} updated their email."))
            db.session.commit()
            flash("Account settings updated successfully.", "success")
            
    return redirect(url_for("account.index"))
