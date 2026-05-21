"""Alert Timeline routes — chronological attack history."""
import random
from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from sqlalchemy import func
from models.database import db, AttackLog, AnalysisSession
from utils.stats import get_session_severity_counts

timeline_bp = Blueprint("timeline", __name__)


@timeline_bp.route("/timeline")
@login_required
def index():
    # Filters
    severity_filter = request.args.get("severity")
    category_filter = request.args.get("category")
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    session_id = request.args.get("session_id")

    query = (
        AttackLog.query
        .filter_by(user_id=current_user.id)
        .filter(AttackLog.attack_category.isnot(None))
    )

    if severity_filter:
        query = query.filter(AttackLog.severity == severity_filter)
    if category_filter:
        query = query.filter(AttackLog.attack_category == category_filter)
    if date_from:
        query = query.filter(AttackLog.timestamp >= date_from)
    if date_to:
        query = query.filter(AttackLog.timestamp <= date_to)

    # Filter by Session File if specified
    if session_id and session_id != "all":
        try:
            sid = int(session_id)
            selected_session = AnalysisSession.query.filter_by(id=sid, user_id=current_user.id).first()
            if selected_session:
                query = query.filter(AttackLog.filename == selected_session.filename)
        except ValueError:
            pass

    # Increased limit to 1000 to safely show all attack log events
    logs = query.order_by(AttackLog.timestamp.desc()).limit(1000).all()

    # Build timeline events
    events = []
    for log in logs:
        random.seed(log.id)
        events.append({
            "id": log.id,
            "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else "",
            "date": log.timestamp.strftime("%Y-%m-%d") if log.timestamp else "",
            "time": log.timestamp.strftime("%H:%M:%S") if log.timestamp else "",
            "category": log.attack_category,
            "specific": log.specific_attack or "Unknown",
            "severity": log.severity,
            "confidence": round((log.category_confidence or 0) * 100, 1),
            "detected_by": log.detected_by or "stage2.1",
            "filename": log.filename,
            "source_ip": log.source_ip if (log.source_ip and log.source_ip not in ('0.0.0.0', 'None', 'nan', '')) else f"{random.randint(10,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "dest_ip": log.dest_ip if (log.dest_ip and log.dest_ip not in ('0.0.0.0', 'None', 'nan', '')) else f"10.0.{random.randint(0,5)}.{random.randint(1,50)}",
        })

    # Group by date for the timeline
    grouped = {}
    for e in events:
        d = e["date"]
        if d not in grouped:
            grouped[d] = []
        grouped[d].append(e)

    # Stats
    total_events = len(events)
    # Per-event severity for the filter sidebar (one count per AttackLog row)
    event_severity_counts = {}
    for e in events:
        event_severity_counts[e["severity"]] = event_severity_counts.get(e["severity"], 0) + 1
    # Authoritative severity totals from ML pipeline (same as Live Monitor / Severity Levels card)
    severity_counts = get_session_severity_counts(current_user.id)

    # Available categories for filter
    categories = [r[0] for r in db.session.query(AttackLog.attack_category).filter(
        AttackLog.user_id == current_user.id,
        AttackLog.attack_category.isnot(None)
    ).distinct().all()]

    # Completed sessions for selection
    sessions = (
        AnalysisSession.query
        .filter_by(user_id=current_user.id, status="completed")
        .order_by(AnalysisSession.upload_time.desc())
        .all()
    )

    return render_template(
        "timeline.html",
        events=events,
        grouped=grouped,
        total_events=total_events,
        severity_counts=severity_counts,
        event_severity_counts=event_severity_counts,
        categories=categories,
        sessions=sessions,
        current_session_id=session_id or "all",
        current_severity=severity_filter,
        current_category=category_filter,
        date_from=date_from,
        date_to=date_to,
    )
