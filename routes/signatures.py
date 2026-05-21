"""Signature Management routes — Admin controls for IPS patterns."""
from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user
from models.database import db, Signature, SystemLog
import re

signatures_bp = Blueprint("signatures", __name__, url_prefix="/signatures")

@signatures_bp.route("/")
@login_required
def index():
    if not current_user.is_admin:
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard.index"))

    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    sev_filter = request.args.get('severity', '')
    status_filter = request.args.get('status', '')
    source_filter = request.args.get('source', '')

    query = Signature.query
    if search:
        query = query.filter(
            Signature.name.ilike(f'%{search}%') |
            Signature.sid.ilike(f'%{search}%') |
            Signature.pattern.ilike(f'%{search}%')
        )
    if sev_filter:
        query = query.filter(Signature.severity == sev_filter)
    if status_filter == 'active':
        query = query.filter(Signature.is_active == True)
    elif status_filter == 'inactive':
        query = query.filter(Signature.is_active == False)
    if source_filter == 'et':
        query = query.filter(Signature.sid.like('ET-%'))
    elif source_filter == 'talos':
        query = query.filter(Signature.sid.like('TALOS-%'))
    elif source_filter == 'custom':
        query = query.filter(
            ~Signature.sid.like('ET-%'),
            ~Signature.sid.like('TALOS-%')
        )

    pagination = query.order_by(Signature.hit_count.desc(), Signature.created_at.desc()).paginate(page=page, per_page=50, error_out=False)

    total_sigs   = Signature.query.count()
    active_sigs  = Signature.query.filter_by(is_active=True).count()
    total_hits   = db.session.query(db.func.sum(Signature.hit_count)).scalar() or 0
    critical_sigs = Signature.query.filter_by(severity='critical').count()

    # Source counts for filter badges
    et_count     = Signature.query.filter(Signature.sid.like('ET-%')).count()
    talos_count  = Signature.query.filter(Signature.sid.like('TALOS-%')).count()
    custom_count = Signature.query.filter(
        ~Signature.sid.like('ET-%'), ~Signature.sid.like('TALOS-%')
    ).count()

    return render_template("signatures/index.html",
        signatures=pagination.items,
        pagination=pagination,
        total_sigs=total_sigs,
        active_sigs=active_sigs,
        total_hits=total_hits,
        critical_sigs=critical_sigs,
        search=search,
        sev_filter=sev_filter,
        status_filter=status_filter,
        source_filter=source_filter,
        et_count=et_count,
        talos_count=talos_count,
        custom_count=custom_count,
    )

@signatures_bp.route("/add", methods=["POST"])
@login_required
def add():
    if not current_user.is_admin:
        abort(403)
        
    sid = request.form.get("sid")
    name = request.form.get("name")
    pattern = request.form.get("pattern")
    severity = request.form.get("severity", "medium")
    mitre_id = request.form.get("mitre_id")
    mitre_tactic = request.form.get("mitre_tactic")
    description = request.form.get("description")

    # Basic regex validation
    try:
        re.compile(pattern)
    except re.error:
        flash("Invalid PCAP/Regex pattern format.", "error")
        return redirect(url_for("signatures.index"))

    if Signature.query.filter_by(sid=sid).first():
        flash(f"Signature ID {sid} already exists.", "error")
        return redirect(url_for("signatures.index"))

    new_sig = Signature(
        sid=sid, name=name, pattern=pattern, 
        severity=severity, description=description,
        mitre_id=mitre_id, mitre_tactic=mitre_tactic
    )
    db.session.add(new_sig)
    db.session.add(SystemLog(
        level="WARNING", event="Signature Added",
        details=f"Admin {current_user.username} added new IPS signature: {sid}"
    ))
    db.session.commit()
    
    flash(f"Signature {sid} successfully deployed to the engine.", "success")
    return redirect(url_for("signatures.index"))

@signatures_bp.route("/toggle/<int:sig_id>")
@login_required
def toggle(sig_id):
    if not current_user.is_admin:
        abort(403)
        
    sig = Signature.query.get_or_404(sig_id)
    sig.is_active = not sig.is_active
    db.session.commit()
    
    status = "activated" if sig.is_active else "deactivated"
    flash(f"Signature {sig.sid} has been {status}.", "info")
    return redirect(url_for("signatures.index"))

@signatures_bp.route("/delete/<int:sig_id>")
@login_required
def delete(sig_id):
    if not current_user.is_admin:
        abort(403)
        
    sig = Signature.query.get_or_404(sig_id)
    sid = sig.sid
    db.session.delete(sig)
    db.session.add(SystemLog(
        level="DANGER", event="Signature Removed",
        details=f"Admin {current_user.username} deleted IPS signature: {sid}"
    ))
    db.session.commit()
    
    flash(f"Signature {sid} removed from the engine.", "warning")
    return redirect(url_for("signatures.index"))
