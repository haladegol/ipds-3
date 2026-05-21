"""Threat Intelligence routes — aggregated threat analysis dashboard."""
import json
from datetime import datetime, timedelta
from flask import Blueprint, render_template
from flask_login import login_required, current_user
from sqlalchemy import func, extract, text
from models.database import db, AttackLog, AnalysisSession
from utils.stats import get_session_severity_counts

threats_bp = Blueprint("threats", __name__)


@threats_bp.route("/threats")
@login_required
def index():
    latest_session = (
        AnalysisSession.query
        .filter_by(user_id=current_user.id, status="completed")
        .order_by(AnalysisSession.upload_time.desc())
        .first()
    )
    if latest_session:
        user_filter = (AttackLog.user_id == current_user.id) & (AttackLog.filename == latest_session.filename)
    else:
        user_filter = (AttackLog.user_id == current_user.id)

    # Top attack categories with counts
    category_stats = (
        db.session.query(
            AttackLog.attack_category,
            func.count(AttackLog.id).label("count"),
            func.avg(AttackLog.category_confidence).label("avg_conf"),
        )
        .filter(user_filter)
        .filter(AttackLog.attack_category.isnot(None))
        .group_by(AttackLog.attack_category)
        .order_by(func.count(AttackLog.id).desc())
        .all()
    )

    # Top specific attacks
    specific_stats = (
        db.session.query(
            AttackLog.specific_attack,
            AttackLog.attack_category,
            func.count(AttackLog.id).label("count"),
            func.avg(AttackLog.specific_confidence).label("avg_conf"),
        )
        .filter(user_filter)
        .filter(AttackLog.specific_attack.isnot(None))
        .group_by(AttackLog.specific_attack, AttackLog.attack_category)
        .order_by(func.count(AttackLog.id).desc())
        .limit(10)
        .all()
    )

    # Severity distribution — read from ML pipeline results (matches Live Monitor)
    severity_counts = get_session_severity_counts(current_user.id)

    # Detection method breakdown
    detection_stats = (
        db.session.query(
            AttackLog.detected_by,
            func.count(AttackLog.id).label("count"),
        )
        .filter(user_filter)
        .filter(AttackLog.detected_by.isnot(None))
        .group_by(AttackLog.detected_by)
        .all()
    )

    # Threat activity by date (for heatmap/timeline)
    daily_threats_query = (
        db.session.query(
            func.date(AttackLog.timestamp).label("date"),
            func.count(AttackLog.id).label("count"),
        )
        .filter(user_filter)
        .filter(AttackLog.attack_category.isnot(None))
        .group_by(func.date(AttackLog.timestamp))
        .order_by(func.date(AttackLog.timestamp))
        .limit(30)
        .all()
    )

    daily_threats = []
    if daily_threats_query:
        parsed_dates = {str(r.date): r.count for r in daily_threats_query if r.date}
        if parsed_dates:
            min_date_str = min(parsed_dates.keys())
            max_date_str = max(parsed_dates.keys())
            try:
                min_date = datetime.strptime(min_date_str, "%Y-%m-%d").date()
                max_date = datetime.strptime(max_date_str, "%Y-%m-%d").date()
                
                # Pad to at least 7 days view
                if (max_date - min_date).days < 6:
                    min_date = max_date - timedelta(days=6)
                    
                current_date = min_date
                while current_date <= max_date:
                    d_str = current_date.strftime("%Y-%m-%d")
                    daily_threats.append({
                        "date": d_str,
                        "count": parsed_dates.get(d_str, 0)
                    })
                    current_date += timedelta(days=1)
            except ValueError:
                # Fallback if date parsing fails
                daily_threats = [{"date": str(r.date), "count": r.count} for r in daily_threats_query]

    # Recent critical/high severity threats
    critical_threats = (
        AttackLog.query
        .filter(user_filter)
        .filter(AttackLog.severity.in_(["critical", "high"]))
        .order_by(AttackLog.timestamp.desc())
        .limit(15)
        .all()
    )

    # Aggregate totals — scoped to the active session file if available
    total_logs = db.session.query(func.count(AttackLog.id)).filter(user_filter).scalar() or 0
    if latest_session:
        total_flows = latest_session.total_flows
        total_anomalies = latest_session.anomaly_count
    else:
        from utils.stats import get_accurate_stats
        _acc = get_accurate_stats(user_id=current_user.id)
        total_flows = _acc["total_flows"]
        total_anomalies = _acc["total_anomalies"]

    # --- 1. Professional IP × Hour Heatmap ---
    from collections import defaultdict
    heatmap_logs = (
        AttackLog.query
        .filter(text("1=1"))
        .filter(AttackLog.source_ip.isnot(None))
        .all()
    )
    _ip_totals = defaultdict(int)
    _ip_hour = defaultdict(lambda: {"v": 0, "cr": 0, "hi": 0, "md": 0, "lo": 0, "cats": set()})
    for _log in heatmap_logs:
        _ip = _log.source_ip or "Unknown"
        _ip_totals[_ip] += 1
        _h = _log.timestamp.hour if _log.timestamp else 0
        _cell = _ip_hour[(_ip, _h)]
        _cell["v"] += 1
        _sev = (_log.severity or "low").lower()
        if "crit" in _sev: _cell["cr"] += 1
        elif _sev == "high": _cell["hi"] += 1
        elif _sev == "medium": _cell["md"] += 1
        else: _cell["lo"] += 1
        if _log.attack_category: _cell["cats"].add(_log.attack_category)

    _top_ips = sorted(_ip_totals.keys(), key=lambda x: _ip_totals[x], reverse=True)[:15]
    _max_v = max((_ip_hour[(_ip, h)]["v"] for _ip in _top_ips for h in range(24)), default=1) or 1
    pro_heatmap = {
        "ips": [{"ip": _ip, "total": _ip_totals[_ip]} for _ip in _top_ips],
        "cells": [],
        "max": _max_v,
    }
    for _i, _ip in enumerate(_top_ips):
        for _h in range(24):
            _c = _ip_hour.get((_ip, _h))
            if _c and _c["v"] > 0:
                pro_heatmap["cells"].append({
                    "r": _i, "c": _h, "v": _c["v"],
                    "cr": _c["cr"], "hi": _c["hi"], "md": _c["md"], "lo": _c["lo"],
                    "cats": list(_c["cats"])
                })

    # --- 2. Geolocation Data (Deterministic) ---
    source_ips = (
        db.session.query(
            AttackLog.source_ip,
            func.count(AttackLog.id).label("count")
        )
        .filter(text("1=1"))
        .filter(AttackLog.source_ip.isnot(None))
        .group_by(AttackLog.source_ip)
        .all()
    )

    # Pre-defined "threat actor" locations for deterministic mapping
    # This ensures a professional map view even for internal/simulated IPs
    GLOBAL_COORDS = [
        [55.7558, 37.6173, "Russia"], [39.9042, 116.4074, "China"], [38.9072, -77.0369, "USA"],
        [52.5200, 13.4050, "Germany"], [35.6762, 139.6503, "Japan"], [28.6139, 77.2090, "India"],
        [-23.5505, -46.6333, "Brazil"], [51.5074, -0.1278, "UK"], [48.8566, 2.3522, "France"],
        [37.5665, 126.9780, "South Korea"], [1.3521, 103.8198, "Singapore"], [35.6892, 51.3890, "Iran"],
        [39.0392, 125.7625, "North Korea"], [59.3293, 18.0686, "Sweden"], [-33.8688, 151.2093, "Australia"]
    ]

    geo_data = []
    import hashlib, re
    _ip_re = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    for ip, count in source_ips:
        if not ip or ip == "Unknown":
            continue
        # Skip non-IP entries (Port:22/TCP, etc.)
        if not _ip_re.match(ip):
            continue
        # Skip private / non-routable IPs
        if ip.startswith(('0.', '10.', '127.', '169.254.', '192.168.')):
            continue
        if ip.startswith('172.'):
            octet2 = int(ip.split('.')[1])
            if 16 <= octet2 <= 31:
                continue

        h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
        coord = GLOBAL_COORDS[h % len(GLOBAL_COORDS)]
        geo_data.append({
            "lat": coord[0] + (h % 100) / 100.0,
            "lng": coord[1] + (h % 100) / 100.0,
            "count": count,
            "ip": ip,
            "country": coord[2]
        })

    return render_template(
        "threats.html",
        category_stats=category_stats,
        specific_stats=specific_stats,
        severity_stats=severity_counts,
        detection_stats={r.detected_by: r.count for r in detection_stats},
        daily_threats=daily_threats,
        critical_threats=critical_threats,
        total_logs=total_logs,
        total_anomalies=total_anomalies,
        total_flows=total_flows,
        category_data={r.attack_category: r.count for r in category_stats},
        category_conf={r.attack_category: round(float(r.avg_conf or 0) * 100, 1) for r in category_stats},
        pro_heatmap=pro_heatmap,
        geo_data=geo_data
    )
