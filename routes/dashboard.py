"""Dashboard routes."""
import json
import os
from flask import Blueprint, render_template
from flask_login import login_required, current_user
from sqlalchemy import func, text, inspect
from models.database import db, AttackLog, AnalysisSession, SystemLog

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    # Get aggregate stats for current user
    total_sessions = AnalysisSession.query.filter_by(user_id=current_user.id).count()
    total_logs = AttackLog.query.filter_by(user_id=current_user.id).count()

    # Recent logs for the table
    recent_logs = (
        AttackLog.query
        .filter_by(user_id=current_user.id)
        .order_by(AttackLog.timestamp.desc())
        .limit(10)
        .all()
    )

    # Get latest completed analysis session with results
    latest_session = (
        AnalysisSession.query
        .filter_by(user_id=current_user.id, status="completed")
        .order_by(AnalysisSession.upload_time.desc())
        .first()
    )

    if latest_session:
        total_flows = latest_session.total_flows
        total_anomaly = latest_session.anomaly_count
        total_normal = latest_session.normal_count
        if total_normal == 0 and total_flows > 0:
            total_normal = total_flows - total_anomaly
        total_logs = (
            AttackLog.query
            .filter_by(user_id=current_user.id, filename=latest_session.filename)
            .count()
        )
    else:
        # Aggregate stats — deduplicated from AnalysisSession
        from utils.stats import get_accurate_stats
        _acc = get_accurate_stats(user_id=current_user.id)
        total_flows = _acc["total_flows"]
        total_normal = _acc["total_normal"]
        total_anomaly = _acc["total_anomalies"]

    latest_results = None
    if latest_session and latest_session.results_json:
        try:
            latest_results = json.loads(latest_session.results_json)
            # ── Enrich per_flow IPs from the actual uploaded CSV ─────────────
            # Many sessions were stored without IP data. Re-read the source file
            # and map IPs onto each flow using flow_index (3-tier strategy).
            per_flow = latest_results.get('per_flow', [])
            needs_enrich = any(
                not f.get('source_ip') or f.get('source_ip') in ('0.0.0.0', 'None', '', 'nan')
                for f in per_flow
            )
            if needs_enrich and latest_session.filepath:
                from utils.ip_utils import enrich_per_flow_ips
                enriched = enrich_per_flow_ips(per_flow, latest_session.filepath)
                if enriched > 0:
                    # Persist the enriched IPs so we don't re-scan on every page load
                    try:
                        latest_results['per_flow'] = per_flow
                        latest_session.results_json = json.dumps(latest_results, default=str)
                        db.session.commit()
                        print(f"[HADES] Persisted {enriched} enriched IPs for session {latest_session.id}")
                    except Exception as _save_err:
                        print(f"[HADES] Failed to persist enriched IPs: {_save_err}")
        except Exception:
            latest_results = None


    # ── Full-file aggregations: aggregate ALL batch CSVs for this user ────
    # The latest session CSV is a 50k-row sample — rare attacks (XSS, Web-BF)
    # may only appear across multiple batch files. We aggregate all of them.
    file_stats = {}
    all_per_flow = []  # all flows for the Per-Flow table
    if latest_session and latest_session.filepath:
        if latest_results and 'full_file_stats' in latest_results:
            file_stats = latest_results['full_file_stats']
            all_per_flow = latest_results.get('per_flow', [])
        
        if not file_stats:
            try:
                import pandas as pd
                upload_dir = os.path.dirname(latest_session.filepath)
                user_prefix = f"{current_user.id}_"

                # Collect all small batch CSVs for this user (< 50 MB, has 'Batch_Dataset' in name)
                batch_paths = sorted([
                    os.path.join(upload_dir, f)
                    for f in os.listdir(upload_dir)
                    if f.startswith(user_prefix)
                    and 'Batch_Dataset' in f
                    and os.path.exists(os.path.join(upload_dir, f))
                    and os.path.getsize(os.path.join(upload_dir, f)) < 50_000_000
                ])

                # Fallback: use latest session file alone
                if not batch_paths and os.path.exists(latest_session.filepath):
                    batch_paths = [latest_session.filepath]

                if not batch_paths:
                    raise ValueError('No batch CSV files found')

                print(f'[HADES] Aggregating {len(batch_paths)} batch CSV(s) for charts...')
                df_full = pd.concat(
                    [pd.read_csv(p, low_memory=False, on_bad_lines='skip') for p in batch_paths],
                    ignore_index=True
                )
                df_full.columns = df_full.columns.str.strip()
                # Drop header rows that snuck in from concat
                cols = df_full.columns.tolist()

                import re as _re
                def _fc(*cands):
                    cm = {_re.sub(r'[^a-z0-9]', '', c.strip().lower()): c for c in cols}
                    for c in cands:
                        r = cm.get(_re.sub(r'[^a-z0-9]', '', c.strip().lower()))
                        if r: return r
                    return None

                # Scaling factor: combined sampled rows → real total
                sampled_n  = len(df_full)
                real_total = latest_session.total_flows or sampled_n
                scale = real_total / sampled_n if sampled_n > 0 else 1.0

                def _scale(d):
                    return {k: int(round(v * scale)) for k, v in d.items()}

                # ── Protocol distribution ──────────────────────────────────
                proto_col = _fc('Protocol', 'proto')
                PROTO_NAMES = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 0: 'HOPOPT', 58: 'IPv6-ICMP'}
                if proto_col:
                    pc = df_full[proto_col].dropna()
                    proto_counts = {}
                    for v in pc:
                        try:
                            p = int(float(v))
                            name = PROTO_NAMES.get(p, f'PROTO {p}')
                            proto_counts[name] = proto_counts.get(name, 0) + 1
                        except: pass
                    file_stats['protocol_distribution'] = _scale(proto_counts)

                # ── Top Target Ports ───────────────────────────────────────
                port_col = _fc('Dst Port', 'dst_port', 'Destination Port')
                # Comprehensive port → service name map (covers all ports in CIC-IDS-2018 + common)
                PORT_SVC = {
                    0:     'Reserved',
                    20:    'FTP-Data',    21:    'FTP',
                    22:    'SSH',         23:    'Telnet',
                    25:    'SMTP',        53:    'DNS',
                    67:    'DHCP',        68:    'DHCP-Client',
                    69:    'TFTP',        80:    'HTTP',
                    110:   'POP3',        111:   'SunRPC',
                    119:   'NNTP',        123:   'NTP',
                    135:   'MSRPC',       137:   'NetBIOS-NS',
                    138:   'NetBIOS-DGM', 139:   'NetBIOS-SS',
                    143:   'IMAP',        161:   'SNMP',
                    162:   'SNMP-Trap',   179:   'BGP',
                    194:   'IRC',         389:   'LDAP',
                    443:   'HTTPS',       445:   'SMB',
                    500:   'IKE/IPSec',   514:   'Syslog',
                    587:   'SMTP-TLS',    636:   'LDAPS',
                    993:   'IMAPS',       995:   'POP3S',
                    1080:  'SOCKS',       1194:  'OpenVPN',
                    1433:  'MSSQL',       1521:  'Oracle-DB',
                    1723:  'PPTP',        3128:  'Squid-Proxy',
                    3306:  'MySQL',       3389:  'RDP',
                    4444:  'Metasploit',  4500:  'IKE-NAT',
                    5355:  'LLMNR',       5432:  'PostgreSQL',
                    5900:  'VNC',         6379:  'Redis',
                    6667:  'IRC-Chat',    8080:  'HTTP-Alt',
                    8443:  'HTTPS-Alt',   8888:  'HTTP-Dev',
                    9200:  'Elasticsearch',
                    27017: 'MongoDB',     27018: 'MongoDB-Shard',
                    50050: 'CobaltStrike',
                }
                if port_col:
                    pv = df_full[port_col].dropna()
                    port_counts = {}
                    for v in pv:
                        try:
                            p = int(float(v))
                            if p == 0: continue
                            label = f"Port {p} / {PORT_SVC[p]}" if p in PORT_SVC else f"Port {p}"
                            port_counts[label] = port_counts.get(label, 0) + 1
                        except: pass
                    top_ports = dict(sorted(port_counts.items(), key=lambda x: -x[1])[:15])
                    file_stats['port_distribution'] = _scale(top_ports)

                # ── Attack category & specific threats from Label column ───
                label_col = _fc('label', 'Label', 'Attack', 'Class', 'Label/Attack')
                CVSS_MAP = {'critical': 9.8, 'high': 7.5, 'medium': 5.3, 'low': 2.1, 'info': 0.0}

                # Severity rules: substring-based, handles all CIC-IDS-2018 label variants
                # Note: CIC-IDS-2018 misspells "Infiltration" as "Infilteration"
                def _severity(lo):
                    # Critical
                    if ('bot' in lo or 'infilter' in lo or 'infiltration' in lo
                            or 'sql injection' in lo or 'heartbleed' in lo
                            or 'shellshock' in lo or 'ransomware' in lo):
                        return 'critical'
                    # High
                    if ('ddos' in lo or 'dos' in lo or 'brute' in lo or 'ftp-' in lo
                            or 'ssh-' in lo or 'web attack' in lo or 'xss' in lo
                            or 'loic' in lo or 'hoic' in lo or 'hulk' in lo
                            or 'goldeneye' in lo or 'slowhttp' in lo or 'slowloris' in lo
                            or 'flood' in lo):
                        return 'high'
                    # Medium
                    if 'portscan' in lo or 'port scan' in lo or 'scan' in lo or 'recon' in lo:
                        return 'medium'
                    # Low (rare in CIC-IDS)
                    if 'probe' in lo or 'noise' in lo:
                        return 'low'
                    return 'high'  # default unknown attacks to high

                if label_col:
                    labels = df_full[label_col].dropna().astype(str)
                    cat_counts = {}
                    sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
                    threat_counts = {}
                    for lbl in labels:
                        lbl = lbl.strip()
                        lo  = lbl.lower()
                        if lo in ('benign', 'normal', 'benign traffic'):
                            sev_counts['info'] += 1
                            continue

                        # Category bucket
                        if 'bot' in lo:                                               cat = 'Botnet'
                        elif 'ddos' in lo or 'loic' in lo or 'hoic' in lo:           cat = 'DDoS'
                        elif 'dos' in lo or 'hulk' in lo or 'goldeneye' in lo \
                             or 'slowhttp' in lo or 'slowloris' in lo:                cat = 'DoS'
                        elif 'sql' in lo or 'xss' in lo or 'web attack' in lo \
                             or 'injection' in lo:                                    cat = 'Web Attack'
                        elif 'ftp' in lo and 'brute' in lo:                           cat = 'FTP-BruteForce'
                        elif 'ssh' in lo and 'brute' in lo:                           cat = 'SSH-BruteForce'
                        elif 'brute' in lo:                                           cat = 'Brute Force'
                        elif 'infilter' in lo or 'infiltration' in lo:               cat = 'Infiltration'
                        elif 'portscan' in lo or 'port scan' in lo:                   cat = 'Port Scan'
                        elif 'heartbleed' in lo:                                       cat = 'Heartbleed'
                        else: cat = lbl.split(' ')[0]
                        cat_counts[cat] = cat_counts.get(cat, 0) + 1

                        # Severity
                        sev = _severity(lo)
                        sev_counts[sev] += 1

                        # Specific threats
                        threat_counts[lbl] = threat_counts.get(lbl, 0) + 1

                    file_stats['category_distribution_file'] = _scale(cat_counts)
                    file_stats['severity_distribution_file'] = {
                        k: int(round(v * scale))
                        for k, v in sev_counts.items() if v > 0
                    }
                    # CVSS-labelled severity — ALL 5 tiers always shown (0 if not present)
                    ORDER = ['critical', 'high', 'medium', 'low', 'info']
                    file_stats['severity_with_cvss'] = {
                        f"{k.upper()} (CVSS {CVSS_MAP[k]})": int(round(sev_counts.get(k, 0) * scale))
                        for k in ORDER
                    }

                    # ── All HADES-detectable specific attacks with CVSS v3.1 scores ──
                    # These are the 15 canonical attack types trained in the ML pipeline.
                    # Label→canonical name mapping handles CIC-IDS-2018 naming variants.
                    HADES_ATTACKS = {
                        # DoS / DDoS (HIGH)
                        'DoS-Hulk':          {'cvss': 7.5, 'sev': 'high',     'file_labels': ['dos attacks-hulk']},
                        'DoS-GoldenEye':     {'cvss': 7.5, 'sev': 'high',     'file_labels': ['dos attacks-goldeneye']},
                        'DoS-Slowloris':     {'cvss': 7.5, 'sev': 'high',     'file_labels': ['dos attacks-slowloris']},
                        'DoS-SlowHTTPTest':  {'cvss': 7.5, 'sev': 'high',     'file_labels': ['dos attacks-slowhttptest']},
                        'DDoS-LOIC-HTTP':    {'cvss': 7.5, 'sev': 'high',     'file_labels': ['ddos attacks-loic-http']},
                        'DDoS-LOIC-UDP':     {'cvss': 7.5, 'sev': 'high',     'file_labels': ['ddos attack-loic-udp']},
                        'DDoS-HOIC':         {'cvss': 7.5, 'sev': 'high',     'file_labels': ['ddos attack-hoic']},
                        # Botnet (CRITICAL)
                        'Botnet-Ares':           {'cvss': 9.8, 'sev': 'critical', 'file_labels': ['bot', 'botnet-ares']},
                        # Infiltration (CRITICAL) — two distinct variants
                        'Infiltration-Dropbox':  {'cvss': 9.1, 'sev': 'critical', 'file_labels': ['infilteration', 'infiltration-dropbox', 'infiltration']},
                        'Infiltration-CoolDisk': {'cvss': 9.1, 'sev': 'critical', 'file_labels': ['infiltration-cooldisk']},
                        # Web Attacks (HIGH / CRITICAL)
                        'SQL-Injection':         {'cvss': 9.8, 'sev': 'critical', 'file_labels': ['sql injection']},
                        'XSS':                   {'cvss': 8.0, 'sev': 'high',     'file_labels': ['brute force -xss', 'xss', 'web attack - xss']},
                        'Brute-Force-Web':       {'cvss': 7.8, 'sev': 'high',     'file_labels': ['brute force -web', 'brute-force-web', 'web bruteforce']},
                        # Brute Force
                        'FTP-BruteForce':        {'cvss': 7.5, 'sev': 'high',     'file_labels': ['ftp-bruteforce', 'ftp bruteforce']},
                        'SSH-BruteForce':        {'cvss': 8.1, 'sev': 'high',     'file_labels': ['ssh-bruteforce', 'ssh bruteforce']},
                    }

                    # Map detected label counts → canonical HADES names
                    canonical_counts = {}
                    for canonical, info in HADES_ATTACKS.items():
                        count = 0
                        for fl in info['file_labels']:
                            for raw_lbl, raw_cnt in threat_counts.items():
                                if fl in raw_lbl.lower():
                                    count += raw_cnt
                        canonical_counts[canonical] = count

                    # Specific Threats: all canonical attacks, detected first, then 0s
                    sorted_canonical = dict(sorted(
                        canonical_counts.items(),
                        key=lambda x: (-x[1], x[0])   # by count desc, then alphabetical
                    ))
                    file_stats['specific_threats_file'] = _scale(sorted_canonical)
                    file_stats['threat_count'] = len(HADES_ATTACKS)

                    # CVSS chart: sorted Critical (9.8) → Info, for the polar-area chart
                    cvss_sorted = dict(sorted(
                        {k: v['cvss'] for k, v in HADES_ATTACKS.items()}.items(),
                        key=lambda x: -x[1]
                    ))
                    file_stats['attack_cvss_scores'] = cvss_sorted


                # ── Enrich per_flow for the table ─────────────────────────
                if latest_results:
                    all_per_flow = latest_results.get('per_flow', [])
                
                # ── Save to cache to avoid 30s delays on reload ───────────
                if latest_results is not None and file_stats:
                    latest_results['full_file_stats'] = file_stats
                    latest_session.results_json = json.dumps(latest_results)
                    db.session.commit()

            except Exception as e:
                print(f"[HADES] Dashboard aggregation error: {e}")

    # Get all completed sessions for listing
    recent_sessions = (
        AnalysisSession.query
        .filter_by(user_id=current_user.id)
        .order_by(AnalysisSession.upload_time.desc())
        .limit(5)
        .all()
    )

    # ─── Admin Control Center data ───
    admin_data = None
    if current_user.is_admin:
        admin_data = _build_admin_data()

    threat_count = file_stats.get('threat_count', 0)
    return render_template(
        "dashboard.html",
        total_sessions=total_sessions,
        total_logs=total_logs,
        total_flows=total_flows,
        total_normal=total_normal,
        total_anomaly=total_anomaly,
        recent_logs=recent_logs,
        latest_session=latest_session,
        latest_results=latest_results,
        recent_sessions=recent_sessions,
        admin_data=admin_data,
        file_stats=file_stats,
        all_per_flow=all_per_flow,
        threat_count=threat_count,
    )


def _build_admin_data():
    """Gather all admin panel data for the dashboard."""
    from models.ml.stage1_binary import Stage1BinaryClassifier
    from models.ml.stage2_category import Stage2CategoryClassifiers
    from models.ml.stage3_specific import Stage3SpecificClassifiers

    # Stage 1 model metrics
    s1 = Stage1BinaryClassifier()
    s1_metrics = s1.get_performance_metrics()

    # Stage 2 model info
    s2 = Stage2CategoryClassifiers()
    s2_info = s2.get_model_info()
    s2_detections = db.session.query(func.count(AttackLog.id)).filter(
        AttackLog.detected_by.in_(["stage2.1", "stage2.2"])
    ).scalar() or 0

    # Stage 3 model info
    s3 = Stage3SpecificClassifiers()
    s3_info = s3.get_model_info()
    total_attack_types = sum(len(c["attacks"]) for c in s3_info["classifiers"])

    # Database stats
    inspector = inspect(db.engine)
    table_names = inspector.get_table_names()
    total_records = 0
    for tbl in table_names:
        result = db.session.execute(text(f"SELECT COUNT(*) FROM {tbl}"))
        total_records += result.scalar()

    from models.database import User
    db_users = User.query.count()
    db_attack_logs = AttackLog.query.count()

    # Recent system logs
    sys_logs = (
        SystemLog.query
        .order_by(SystemLog.timestamp.desc())
        .limit(8)
        .all()
    )

    return {
        "stage1_accuracy": s1_metrics.get("accuracy", 0),
        "stage1_precision": s1_metrics.get("precision", 0),
        "stage2_categories": len(s2_info.get("categories", [])),
        "stage2_detections": s2_detections,
        "stage3_attacks": total_attack_types,
        "stage3_models": len(s3_info.get("classifiers", [])),
        "db_tables": len(table_names),
        "db_total_records": total_records,
        "db_attack_logs": db_attack_logs,
        "db_users": db_users,
        "recent_logs": sys_logs,
    }

