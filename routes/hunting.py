"""Threat Hunting Workbench: Power-user interface for signal discovery."""
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from models.database import AttackLog, db
from sqlalchemy import or_

hunting_bp = Blueprint("hunting", __name__, url_prefix="/hunting")

@hunting_bp.route("/")
@login_required
def index():
    return render_template("hunting/workbench.html")

@hunting_bp.route("/query", methods=["POST"])
@login_required
def run_query():
    data = request.json
    query_str = data.get("query", "").strip()
    severity = data.get("severity", "all")
    limit = int(data.get("limit", 100))
    
    # Base query
    q = AttackLog.query.filter_by(user_id=current_user.id)
    
    # Filter by search string
    if query_str:
        search_filter = or_(
            AttackLog.source_ip.like(f"%{query_str}%"),
            AttackLog.attack_category.like(f"%{query_str}%"),
            AttackLog.specific_attack.like(f"%{query_str}%"),
            AttackLog.filename.like(f"%{query_str}%")
        )
        q = q.filter(search_filter)
    
    # Filter by severity
    if severity != "all":
        q = q.filter(AttackLog.severity == severity)
        
    results = q.order_by(AttackLog.timestamp.desc()).limit(limit).all()
    
    output = []
    for r in results:
        output.append({
            "id": r.id,
            "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source": r.source_ip or "Internal",
            "category": r.attack_category,
            "specific": r.specific_attack,
            "severity": r.severity,
            "action": "Dropped" if r.is_ips_action else "Logged"
        })
        
    return jsonify({"results": output})
