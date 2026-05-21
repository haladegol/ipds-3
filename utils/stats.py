"""Shared statistics utility — deduplicates AnalysisSession data by filename
to produce accurate aggregate numbers across the HADES platform."""
import json
from sqlalchemy import func
from models.database import db, AnalysisSession


def get_accurate_stats(user_id=None):
    """Return accurate, deduplicated stats from AnalysisSession.
    
    Args:
        user_id: If provided, filter to sessions owned by this user.
                 If None, aggregate across all users (admin/global view).

    Returns:
        dict with keys: total_flows, total_anomalies, total_normal,
                        unique_files, detection_rate
    """
    query = db.session.query(
        AnalysisSession.filename,
        func.max(AnalysisSession.total_flows).label("flows"),
        func.max(AnalysisSession.anomaly_count).label("anomalies"),
        func.max(AnalysisSession.normal_count).label("normals"),
    )
    if user_id is not None:
        query = query.filter(AnalysisSession.user_id == user_id)
    rows = query.group_by(AnalysisSession.filename).all()

    total_flows = sum(r.flows or 0 for r in rows)
    total_anomalies = sum(r.anomalies or 0 for r in rows)
    total_normal = sum(r.normals or 0 for r in rows)
    # Fallback: if normal_count wasn't stored, derive it
    if total_normal == 0 and total_flows > 0:
        total_normal = total_flows - total_anomalies

    return {
        "total_flows": total_flows,
        "total_anomalies": total_anomalies,
        "total_normal": total_normal,
        "unique_files": len(rows),
        "detection_rate": round(total_anomalies / total_flows * 100, 2) if total_flows > 0 else 0,
    }


def get_session_severity_counts(user_id):
    """Return CVSS-mapped severity counts from the latest completed session's
    ML pipeline results — the single authoritative source used by Live Monitor.

    This ensures Threats, Reports, Timeline, and all other pages show the
    same numbers as the Severity Levels card (e.g. 141,738 Critical, not 626).

    Returns a dict with keys: critical, high, medium, low, info
    Always returns all 5 keys (defaulting to 0 if absent).
    """
    ZERO = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    latest = (
        AnalysisSession.query
        .filter_by(user_id=user_id, status="completed")
        .order_by(AnalysisSession.upload_time.desc())
        .first()
    )
    if not latest or not latest.results_json:
        return ZERO

    try:
        data = json.loads(latest.results_json)
        sev_dist = data.get("summary", {}).get("severity_distribution", {})
        return {
            "critical": int(sev_dist.get("critical", 0)),
            "high":     int(sev_dist.get("high",     0)),
            "medium":   int(sev_dist.get("medium",   0)),
            "low":      int(sev_dist.get("low",      0)),
            # 'info' = benign flows (normal_count stored on session)
            "info":     int(latest.normal_count or 0),
        }
    except Exception:
        return ZERO

