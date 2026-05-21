"""Reports routes — session history, export, and detailed views."""
from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from sqlalchemy import func
from models.database import db, AttackLog, AnalysisSession
from utils.stats import get_session_severity_counts
import json

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports")
@login_required
def index():
    page = request.args.get("page", 1, type=int)
    per_page = 15

    # All sessions with pagination
    pagination = (
        AnalysisSession.query
        .filter_by(user_id=current_user.id)
        .order_by(AnalysisSession.upload_time.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )

    # Summary stats
    session_stats = db.session.query(
        func.count(AnalysisSession.id).label("total"),
        func.sum(AnalysisSession.total_flows).label("total_flows"),
        func.sum(AnalysisSession.anomaly_count).label("total_anomalies"),
    ).filter_by(user_id=current_user.id).first()

    completed = AnalysisSession.query.filter_by(user_id=current_user.id, status="completed").count()
    failed = AnalysisSession.query.filter_by(user_id=current_user.id, status="failed").count()

    # Get severity counts from latest session ML pipeline results (same source as Live Monitor)
    severity_counts = get_session_severity_counts(current_user.id)

    return render_template(
        "reports.html",
        sessions=pagination,
        total_sessions=session_stats.total or 0,
        total_flows=session_stats.total_flows or 0,
        total_anomalies=session_stats.total_anomalies or 0,
        completed=completed,
        failed=failed,
        severity_counts=severity_counts,
    )
