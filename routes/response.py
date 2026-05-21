"""Response Actions routes — IP blocking, firewall rules (admin only)."""
from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_required, current_user
from models.database import db, BlockedIP, SystemLog, AlertConfig

from routes.auth import hades_root_required

response_bp = Blueprint("response", __name__, url_prefix="/response")


@response_bp.route("/")
@hades_root_required
def index():
    blocked = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    recent_actions = (
        SystemLog.query
        .filter(SystemLog.event.in_(["IP Blocked", "IP Unblocked"]))
        .order_by(SystemLog.timestamp.desc())
        .limit(20)
        .all()
    )
    config = AlertConfig.query.filter_by(user_id=current_user.id).first()
    return render_template(
        "response.html",
        blocked=blocked,
        actions=recent_actions,
        ips_enabled=config.ips_mode_enabled if config else False,
        auto_block_critical=config.auto_block_critical if config else False,
        bypass_mode=config.ips_bypass_mode if config else False,
    )


@response_bp.route("/block-ip", methods=["POST"])
@hades_root_required
def block_ip():
    ip = request.form.get("ip_address", "").strip()
    reason = request.form.get("reason", "Manual block by admin").strip()

    if not ip:
        flash("IP address is required.", "error")
        return redirect(url_for("response.index"))

    existing = BlockedIP.query.filter_by(ip_address=ip, is_active=True).first()
    if existing:
        flash(f"IP {ip} is already blocked.", "error")
        return redirect(url_for("response.index"))

    block = BlockedIP(ip_address=ip, reason=reason, blocked_by=current_user.id)
    db.session.add(block)
    db.session.add(SystemLog(
        level="WARNING", event="IP Blocked",
        details=f"Admin {current_user.username} blocked IP {ip}. Reason: {reason}"
    ))
    db.session.commit()
    flash(f"IP {ip} has been blocked successfully.", "success")
    return redirect(url_for("response.index"))


@response_bp.route("/unblock-ip/<int:block_id>", methods=["POST"])
@hades_root_required
def unblock_ip(block_id):
    block = BlockedIP.query.get_or_404(block_id)
    block.is_active = False
    db.session.add(SystemLog(
        level="INFO", event="IP Unblocked",
        details=f"Admin {current_user.username} unblocked IP {block.ip_address}"
    ))
    db.session.commit()
    flash(f"IP {block.ip_address} has been unblocked.", "success")
    return redirect(url_for("response.index"))



# ═══════════════════════════════════════════════════════════════
# SURGICAL TACTICAL MITIGATIONS
# ═══════════════════════════════════════════════════════════════

@response_bp.route("/tactical-action", methods=["POST"])
@hades_root_required
def tactical_action():
    action_type = request.form.get("action_type")
    target = request.form.get("target", "Global").strip()
    
    actions = {
        "quarantine": ("VLAN Isolation", "WARNING", f"Host {target} isolated to Quarantine VLAN 999. Traffic restricted to internal forensic analysis."),
        "scrub": ("Traffic Scrubbing", "INFO", f"Active Mitigation: Routing ingress traffic for {target} through HADES Cloud Scrubbing Center."),
        "harden": ("Service Hardening", "WARNING", f"Tactical Hardening: Disabling weak protocols (SMBv1, Telnet, FTP) on host {target}."),
        "honey": ("Honeypot Trigger", "INFO", f"Deception Deployment: Interactive synthetic decoy deployed at {target} to intercept lateral movement.")
    }
    
    if action_type in actions:
        event_name, level, details = actions[action_type]
        db.session.add(SystemLog(
            level=level, event=event_name,
            details=f"Admin {current_user.username}: {details}"
        ))
        db.session.commit()
        flash(f"{event_name} initiated for {target}.", "success")
    else:
        flash("Invalid tactical action requested.", "error")
        
    return redirect(url_for("response.index"))

