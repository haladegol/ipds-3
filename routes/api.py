"""API endpoints for dashboard charts and data."""
import json
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from sqlalchemy import func
from models.database import db, AttackLog, AnalysisSession

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/stats")
@login_required
def stats():
    """Overall statistics for dashboard cards."""
    total_sessions = AnalysisSession.query.filter_by(user_id=current_user.id).count()

    from utils.stats import get_accurate_stats
    _acc = get_accurate_stats(user_id=current_user.id)
    total_flows = _acc["total_flows"]
    total_normal = _acc["total_normal"]
    total_anomaly = _acc["total_anomalies"]
    detection_rate = _acc["detection_rate"]

    return jsonify({
        "total_sessions": total_sessions,
        "total_flows": total_flows,
        "total_normal": total_normal,
        "total_anomaly": total_anomaly,
        "detection_rate": detection_rate,
    })


@api_bp.route("/attack-distribution")
@login_required
def attack_distribution():
    """Attack category distribution — uses scaled actual flow counts from dataset."""
    # Get scale ratio from latest session: total_rows / sample_size
    latest = (
        AnalysisSession.query
        .filter_by(user_id=current_user.id, status="completed")
        .order_by(AnalysisSession.upload_time.desc())
        .first()
    )

    logs = (
        AttackLog.query
        .filter_by(user_id=current_user.id)
        .filter(AttackLog.attack_category.isnot(None))
        .filter(AttackLog.results_json.isnot(None))
        .all()
    )

    # Sum sampled flow counts per category from results_json
    sampled_totals = {}   # category -> sampled flow count
    sampled_grand  = 0
    for log in logs:
        try:
            rj = json.loads(log.results_json)
            cnt = rj.get("count", 0)
        except Exception:
            cnt = 0
        cat = log.attack_category
        sampled_totals[cat] = sampled_totals.get(cat, 0) + cnt
        sampled_grand += cnt

    # Scale to full dataset
    total_rows   = latest.total_flows   if latest else 0
    anomaly_rows = latest.anomaly_count if latest else 0
    scale = (anomaly_rows / sampled_grand) if sampled_grand > 0 else 1

    data = {cat: round(cnt * scale) for cat, cnt in sorted(sampled_totals.items(), key=lambda x: x[1], reverse=True)}
    return jsonify(data)


@api_bp.route("/specific-attacks")
@login_required
def specific_attacks():
    """Specific attack distribution — scaled to full dataset flow counts."""
    # Latest session for scale factor
    latest = (
        AnalysisSession.query
        .filter_by(user_id=current_user.id, status="completed")
        .order_by(AnalysisSession.upload_time.desc())
        .first()
    )

    logs = (
        AttackLog.query
        .filter_by(user_id=current_user.id)
        .filter(AttackLog.specific_attack.isnot(None))
        .filter(AttackLog.results_json.isnot(None))
        .all()
    )

    # CVSS representative scores (mid-range of each band)
    cvss_map = {'info': 0.0, 'low': 2.1, 'medium': 5.3, 'high': 7.5, 'critical': 9.8}

    # Accumulate sampled counts per (category, specific) key
    sampled = {}   # key -> {count, severity, cvss}
    sampled_grand = 0
    for log in logs:
        try:
            rj = json.loads(log.results_json)
            cnt = rj.get("count", 0)
        except Exception:
            cnt = 0
        key = f"{log.attack_category}: {log.specific_attack}"
        sev = (log.severity or "info").lower()
        cvss = cvss_map.get(sev, 0.0)
        if key not in sampled:
            sampled[key] = {"count": 0, "severity": sev, "cvss": cvss}
        sampled[key]["count"] += cnt
        sampled_grand += cnt
        # Keep highest severity CVSS
        if cvss > sampled[key]["cvss"]:
            sampled[key]["severity"] = sev
            sampled[key]["cvss"] = cvss

    # Scale sampled counts → full dataset anomaly counts
    anomaly_rows = latest.anomaly_count if latest else 0
    scale = (anomaly_rows / sampled_grand) if sampled_grand > 0 else 1

    data = {}
    for key, info in sampled.items():
        data[key] = {
            "count": round(info["count"] * scale),
            "severity": info["severity"],
            "cvss": info["cvss"],
        }

    data = dict(sorted(data.items(), key=lambda x: x[1]["count"], reverse=True))
    return jsonify(data)


@api_bp.route("/severity-distribution")
@login_required
def severity_distribution():
    """Severity level distribution for gauge/chart."""
    results = (
        db.session.query(
            AttackLog.severity,
            func.count(AttackLog.id).label("count"),
        )
        .filter(AttackLog.user_id == current_user.id)
        .group_by(AttackLog.severity)
        .all()
    )

    data = {r.severity: r.count for r in results}
    return jsonify(data)


@api_bp.route("/timeline")
@login_required
def timeline():
    """Attacks over time for line chart."""
    results = (
        db.session.query(
            func.date(AttackLog.timestamp).label("date"),
            func.count(AttackLog.id).label("count"),
        )
        .filter(AttackLog.user_id == current_user.id)
        .group_by(func.date(AttackLog.timestamp))
        .order_by(func.date(AttackLog.timestamp))
        .limit(30)
        .all()
    )

    data = [
        {"date": str(r.date), "scans": r.count, "anomalies": r.count}
        for r in results
    ]
    return jsonify(data)


@api_bp.route("/logs")
@login_required
def logs():
    """Paginated attack logs."""
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    category_filter = request.args.get("category")
    severity_filter = request.args.get("severity")

    query = AttackLog.query.filter_by(user_id=current_user.id)

    if category_filter:
        query = query.filter(AttackLog.attack_category == category_filter)
    if severity_filter:
        query = query.filter(AttackLog.severity == severity_filter)

    query = query.order_by(AttackLog.timestamp.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    logs_data = [
        {
            "id": log.id,
            "filename": log.filename,
            "timestamp": log.timestamp.isoformat() if log.timestamp else "",
            "attack_category": log.attack_category,
            "specific_attack": log.specific_attack,
            "severity": log.severity,
            "total_flows": log.total_flows,
            "anomaly_count": log.anomaly_count,
            "detected_by": log.detected_by,
            "category_confidence": log.category_confidence,
            "specific_confidence": log.specific_confidence,
        }
        for log in pagination.items
    ]

    return jsonify({
        "logs": logs_data,
        "total": pagination.total,
        "pages": pagination.pages,
        "current_page": page,
    })
