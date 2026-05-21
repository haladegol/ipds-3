"""Settings routes — user preferences and configuration."""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from models.database import db, AlertConfig, SystemLog

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/settings")
@login_required
def index():
    config = AlertConfig.query.filter_by(user_id=current_user.id).first()
    if not config:
        config = AlertConfig(user_id=current_user.id)
        db.session.add(config)
        db.session.commit()

    return render_template("settings.html", config=config)


@settings_bp.route("/settings/update", methods=["POST"])
@login_required
def update():
    config = AlertConfig.query.filter_by(user_id=current_user.id).first()
    if not config:
        config = AlertConfig(user_id=current_user.id)
        db.session.add(config)

    tab = request.form.get("tab", "general")

    if tab == "general":
        config.severity_threshold = request.form.get("severity_threshold", "low")
        config.items_per_page = int(request.form.get("items_per_page", 20))
        ops_mode = request.form.get("ops_mode", "passive")
        if ops_mode == "hybrid":
            config.ips_mode_enabled = True
            config.auto_block_critical = True
        elif ops_mode == "active":
            config.ips_mode_enabled = True
            config.auto_block_critical = False
        else: # passive
            config.ips_mode_enabled = False
            config.auto_block_critical = False
        flash("General settings updated successfully.", "success")

    elif tab == "ips":
        # Tier 2 Logic
        config.ips_inline_filtering = "ips_inline_filtering" in request.form
        config.ips_rst_injection = "ips_rst_injection" in request.form
        config.ips_dynamic_shunning = "ips_dynamic_shunning" in request.form
        config.ips_rate_limiting = "ips_rate_limiting" in request.form
        config.ips_protocol_normalization = "ips_protocol_normalization" in request.form
        config.ips_payload_sanitization = "ips_payload_sanitization" in request.form
        config.ips_signature_matching = "ips_signature_matching" in request.form
        config.ips_anomaly_detection = "ips_anomaly_detection" in request.form
        config.ips_virtual_patching = "ips_virtual_patching" in request.form
        config.ips_vlan_steering = "ips_vlan_steering" in request.form
        
        # Tier 3 & Operational Logic
        config.ips_bypass_mode = "ips_bypass_mode" in request.form
        config.ips_json_logging = "ips_json_logging" in request.form
        config.ips_reputation_check = "ips_reputation_check" in request.form
        config.ips_protocol_analysis = "ips_protocol_analysis" in request.form
        config.ips_stream_reassembly = "ips_stream_reassembly" in request.form
        config.ips_file_hashing = "ips_file_hashing" in request.form

        # Tier 4 Logic
        config.ips_geoip_filtering = "ips_geoip_filtering" in request.form
        config.ips_honeypot_routing = "ips_honeypot_routing" in request.form
        config.ips_ddos_protection = "ips_ddos_protection" in request.form

        flash("Advanced IPS configurations updated.", "success")

    elif tab == "notifications":
        config.email_notifications = "email_notifications" in request.form
        flash("Notification settings updated successfully.", "success")

    elif tab == "security":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if current_password and new_password:
            if not current_user.check_password(current_password):
                flash("Current password is incorrect.", "error")
                return redirect(url_for("settings.index"))
            if new_password != confirm_password:
                flash("New passwords do not match.", "error")
                return redirect(url_for("settings.index"))
            if len(new_password) < 6:
                flash("Password must be at least 6 characters.", "error")
                return redirect(url_for("settings.index"))

            current_user.set_password(new_password)
            db.session.add(SystemLog(
                level="WARNING", event="Password Changed",
                details=f"User {current_user.username} changed their password."
            ))
            flash("Password updated successfully.", "success")
        else:
            flash("Please fill in all password fields.", "error")
            return redirect(url_for("settings.index"))

    db.session.commit()
    return redirect(url_for("settings.index"))
