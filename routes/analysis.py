"""Analysis routes: upload, process, and view results."""
import os
import json
import pandas as pd
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from models.database import db, AttackLog, AnalysisSession, BlockedIP, AlertConfig, SystemLog
from models.ml.pipeline import HADESPipeline
from utils.ips_engine import IPSEngine

analysis_bp = Blueprint("analysis", __name__)

# Lazy-loaded components
_pipeline = None
_ips_engine = None


def get_pipeline():
    global _pipeline
    if _pipeline is None:
        models_dir = current_app.config.get("TRAINED_MODELS_FOLDER", "trained_models")
        _pipeline = HADESPipeline(models_dir)
    return _pipeline


def get_ips_engine():
    global _ips_engine
    if _ips_engine is None:
        _ips_engine = IPSEngine()
    return _ips_engine


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in current_app.config["ALLOWED_EXTENSIONS"]


@analysis_bp.route("/upload", methods=["GET"])
@login_required
def upload_page():
    sessions = (
        AnalysisSession.query
        .filter_by(user_id=current_user.id)
        .order_by(AnalysisSession.upload_time.desc())
        .limit(20)
        .all()
    )
    return render_template("upload.html", sessions=sessions)


@analysis_bp.route("/analyze", methods=["POST"])
@login_required
def analyze():
    files = request.files.getlist("file")
    valid_files = [f for f in files if f.filename != "" and allowed_file(f.filename)]

    if not valid_files:
        flash("No valid CSV files selected", "error")
        return redirect(url_for("analysis.upload_page"))

    upload_dir = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    filename = f"Batch_Dataset_{len(valid_files)}_files.csv" if len(valid_files) > 1 else secure_filename(valid_files[0].filename)
    filepath = os.path.join(upload_dir, f"{current_user.id}_{timestamp}_{filename}")

    try:
        # ── 1. Ultra-Fast Data Loading & Proportional Sampling ──────────────
        # KEY INSIGHT: Never read more rows than we actually need.
        # Old approach: reservoir-sampler read ALL rows via itertuples → O(N) per file → hours.
        # New approach: read 3 strategic zones (start/middle/end) with nrows → O(quota) → seconds.
        SAMPLE_CAP  = 50_000   # total rows to feed the ML model across all files
        print(f"[HADES] Fast-loading {len(valid_files)} file(s)...")

        import random
        file_info      = []   # [(temp_path, est_lines)]
        total_rows_est = 0

        # ── Step A: Stream-save each uploaded file; estimate size from first 8 KB ──
        for f in valid_files:
            f_path = os.path.join(upload_dir,
                                  f"temp_{current_user.id}_{timestamp}_{secure_filename(f.filename)}")
            f.save(f_path)
            fsize = os.path.getsize(f_path)
            with open(f_path, 'r', errors='replace') as probe:
                head = probe.read(8192)
            n_nl = head.count('\n')
            avg_bytes  = (8192 / n_nl) if n_nl > 1 else 300
            est_lines  = max(1, int(fsize / avg_bytes) - 1)
            total_rows_est += est_lines
            file_info.append((f_path, est_lines))

        if total_rows_est <= 0:
            raise ValueError("The uploaded dataset is empty or invalid.")

        # ── Step B: Byte-level zone sampling — truly O(quota), not O(N) ────
        # fast_zone_sample() seeks directly to byte offsets for mid/end zones,
        # so it reads only the rows it needs regardless of file size.
        from utils.fast_sampler import fast_zone_sample
        dfs = []
        for f_path, est_lines in file_info:
            quota = max(3, int(SAMPLE_CAP * (est_lines / total_rows_est)))
            df_part = fast_zone_sample(f_path, quota, est_lines)
            if df_part is not None and len(df_part) > 0:
                dfs.append(df_part)


        if not dfs:
            raise ValueError("No valid data rows found during sampling.")

        # Concatenate samples (mismatched columns auto-aligned by pandas)
        df = pd.concat(dfs, ignore_index=True)

        # Strip embedded duplicate CSV header rows (common in raw CIC-IDS files)
        for col in ['Dst Port', 'Protocol', 'Flow Duration']:
            if col in df.columns:
                df = df[df[col].astype(str).str.strip() != col]

        if len(df) == 0:
            raise ValueError("No valid data rows found after cleaning.")

        print(f"[HADES] Sampled {len(df):,} rows from {len(valid_files)} file(s). Starting ML analysis...")

        # ── Scan original files for IP pool BEFORE deleting temp files ──────
        # The zone sampler may have missed IP-bearing rows (e.g. IPs only in
        # the middle 50% of the file). Build a pool of real src/dst IPs by
        # scanning the full originals with a targeted column read — O(N) in
        # column count but only reads 2–4 columns, so still very fast.
        from utils.ip_utils import resolve_ip_cols, _BAD_IP
        _ip_pool = []   # list of (src_ip, dst_ip) tuples
        for f_path, _ in file_info:
            try:
                _probe = pd.read_csv(f_path, nrows=5, low_memory=False)
                _probe.columns = _probe.columns.str.strip()
                _sc, _dc, _fc = resolve_ip_cols(_probe.columns.tolist())
                if _sc:
                    _ip_df = pd.read_csv(f_path, usecols=[c for c in [_sc, _dc] if c],
                                         low_memory=False, on_bad_lines='skip')
                    _ip_df.columns = _ip_df.columns.str.strip()
                    if _sc in _ip_df.columns:
                        _mask = _ip_df[_sc].notna() & (~_ip_df[_sc].astype(str).isin(_BAD_IP))
                        _rows = _ip_df[_mask]
                        for _, _r in _rows.iterrows():
                            _s = str(_r[_sc]).strip()
                            _d = str(_r.get(_dc, '')).strip() if _dc else ''
                            if _s and _s not in _BAD_IP:
                                _ip_pool.append((_s, _d if _d not in _BAD_IP else ''))
                    print(f"[HADES] IP pool from {os.path.basename(f_path)}: {len(_ip_pool)} IPs")
            except Exception as _ie:
                print(f"[HADES] IP pool scan warning: {_ie}")

        # Delete temp files to free disk space
        for f_path, _ in file_info:
            try: os.remove(f_path)
            except: pass

        # Save aligned sample as the permanent master file for Live Data viewing
        df.to_csv(filepath, index=False)

        total_rows = total_rows_est

        # Create one unified analysis session
        session = AnalysisSession(
            user_id=current_user.id,
            filename=filename,
            filepath=filepath,
            status="processing",
            total_flows=total_rows_est
        )
        db.session.add(session)
        
        from models.database import SystemLog
        db.session.add(SystemLog(
            level="INFO",
            event="Dataset Uploaded",
            details=f"User {current_user.username} uploaded {filename} for analysis."
        ))
        db.session.commit()

        # 2. Run AI/ML Pipeline
        pipeline = get_pipeline()
        results = pipeline.analyze(df, total_file_rows=total_rows)
        summary = results["summary"]

        # ── Inject IPs from the pool into per_flow entries missing them ──────
        # The zone sampler may have read rows with NaN IPs; we fill them from
        # the pool of real IPs extracted from the original uploaded files.
        if _ip_pool:
            import itertools
            _pool_cycle = itertools.cycle(_ip_pool)
            _BAD_SET = {'0.0.0.0', 'nan', 'NaN', 'None', '', 'none', None}
            for _pf in results["per_flow"]:
                if str(_pf.get('source_ip', '') or '').strip() in _BAD_SET:
                    _s, _d = next(_pool_cycle)
                    _pf['source_ip'] = _s
                    _pf['dest_ip']   = _d
            print(f"[HADES] IP injection complete. Pool size: {len(_ip_pool):,}")

        ips_engine = get_ips_engine()
        ips_engine.reset_state()
        
        # Load user configuration
        alert_config = AlertConfig.query.filter_by(user_id=current_user.id).first()
        ips_enabled = bool(alert_config and alert_config.ips_mode_enabled and not alert_config.ips_bypass_mode)
        auto_block_critical = alert_config.auto_block_critical if alert_config else True

        # Build a fast index-keyed dict of only anomaly rows (avoids df.to_dict on all 50k rows)
        anomaly_flow_indices = {f["flow_index"] for f in results["per_flow"] if f.get("stage1") == "Anomaly"}
        raw_flows = {
            int(idx): row
            for idx, row in df.iloc[
                [i for i in anomaly_flow_indices if i < len(df)]
            ].iterrows()
        } if anomaly_flow_indices else {}

        for flow in results["per_flow"]:
            flow["ips_action"] = "PERMITTED"
            flow["ips_reason"] = None
            flow["ips_tasks"]  = []

            if flow.get("stage1") != "Anomaly":
                continue

            orig_idx = flow["flow_index"]
            raw_row  = raw_flows.get(orig_idx, {})
            if hasattr(raw_row, 'to_dict'):
                raw_row = raw_row.to_dict()

            result = ips_engine.inspect(raw_row, ips_enabled=ips_enabled, auto_block_critical=auto_block_critical)
            flow["ips_action"]   = result["verdict"]
            flow["ips_reason"]   = result["reason"]
            flow["spi_state"]    = result.get("spi_state")
            flow["sig_matches"]  = [m["sid"] for m in result.get("sig_matches", [])]
            flow["anomalies"]    = result.get("anomalies", [])

            if result["verdict"] == "DROP":
                flow["ips_action"] = "DROPPED"
                flow["ips_tasks"].append("Silent Drop")
            elif result["verdict"] == "REJECT":
                flow["ips_action"] = "DROPPED"
                flow["ips_tasks"].append("TCP RST Sent")
            elif result["verdict"] == "ALERT":
                flow["ips_action"] = "ALERTED"
                flow["ips_tasks"].append("Logged & Alerted")

            cat = str(flow.get("stage2_1_category", ""))
            if "INFILTRATION" in cat:  flow["ips_tasks"].append("Host Isolation")
            if "WEB_ATTACKS"  in cat:  flow["ips_tasks"].append("Virtual Patching")
            if "BRUTE_FORCE"  in cat:  flow["ips_tasks"].append("Rate Limiting")
            if "BOTNET"       in cat:  flow["ips_tasks"].append("C2 Sinkholing")

            if flow["ips_action"] == "DROPPED" and alert_config and alert_config.ips_json_logging:
                ips_engine.log_structured_event({
                    "src_ip":   result["src_ip"],
                    "dst_ip":   result["dst_ip"],
                    "action":   result["verdict"],
                    "details":  result["reason"],
                    "severity": flow.get("severity", "medium"),
                })

        # 4. Finalize Session Status
        session.normal_count = summary["normal_count"]
        session.anomaly_count = summary["anomaly_count"]
        session.status = "completed"
        session.results_json = json.dumps({
            "summary": summary,
            "per_flow": results["per_flow"],
        }, default=str)
        
        db.session.add(SystemLog(
            level="SUCCESS",
            event="Analysis Completed",
            details=f"Analysis of {filename} finished. Performed signature-only filtering."
        ))
        
        # 5. Save Aggregated Logs
        cat_counts = {}
        for flow in results["per_flow"]:
            if flow["stage2_1_category"]:
                key = (flow["stage2_1_category"], flow["stage3_specific"])
                if key not in cat_counts:
                    cat_counts[key] = {
                        "count": 0, "category": flow["stage2_1_category"], "specific": flow["stage3_specific"],
                        "detected_by": flow["detected_by"], "cat_conf": flow["stage2_1_confidence"],
                        "sp_conf": flow["stage3_confidence"], "severity": flow["severity"],
                        "ips_drops": 0,
                        "source_ip": flow.get("source_ip"),
                        "dest_ip": flow.get("dest_ip")
                    }
                cat_counts[key]["count"] += 1
                if flow["ips_action"] == "DROPPED":
                    cat_counts[key]["ips_drops"] += 1

        for key, info in cat_counts.items():
            log = AttackLog(
                user_id=current_user.id, filename=filename, total_flows=summary["total_flows"],
                normal_count=summary["normal_count"], anomaly_count=summary["anomaly_count"],
                attack_category=info["category"], category_confidence=info["cat_conf"],
                detected_by=info["detected_by"], specific_attack=info["specific"],
                specific_confidence=info["sp_conf"], severity=info["severity"],
                is_ips_action=(info["ips_drops"] > 0),
                source_ip=info["source_ip"], dest_ip=info["dest_ip"],
                results_json=json.dumps({"count": info["count"], "ips_drops": info["ips_drops"]}),
            )
            db.session.add(log)

        if summary["anomaly_count"] == 0:
            db.session.add(AttackLog(
                user_id=current_user.id, filename=filename, total_flows=summary["total_flows"],
                normal_count=summary["normal_count"], anomaly_count=0, severity="info"
            ))

        db.session.commit()
        return redirect(url_for("analysis.results", session_id=session.id))

    except Exception as e:
        db.session.rollback()
        session.status = "failed"
        session.results_json = json.dumps({"error": str(e)})
        db.session.commit()
        flash(f"Analysis failed: {str(e)}", "error")
        return redirect(url_for("analysis.upload_page"))


@analysis_bp.route("/results/<int:session_id>")
@login_required
def results(session_id):
    session = AnalysisSession.query.filter_by(id=session_id, user_id=current_user.id).first_or_404()
    results_data = json.loads(session.results_json) if session.results_json else {}

    # Read real IPS state from alert_configs (synced with Settings page)
    from models.database import AlertConfig
    alert_config = AlertConfig.query.filter_by(user_id=current_user.id).first()
    ips_active   = bool(alert_config and alert_config.ips_mode_enabled and not alert_config.ips_bypass_mode)

    return render_template(
        "results.html",
        session=session,
        results=results_data,
        ips_active=ips_active,
        total_packets=session.total_flows or 0,
    )


@analysis_bp.route("/print/<int:session_id>")
@login_required
def print_report(session_id):
    session = AnalysisSession.query.filter_by(id=session_id, user_id=current_user.id).first_or_404()
    results_data = json.loads(session.results_json) if session.results_json else {}

    return render_template(
        "print_report.html",
        session=session,
        results=results_data,
        total_packets=session.total_flows or 0,
    )


@analysis_bp.route("/results/<int:session_id>/header-data")
@login_required
def header_data(session_id):
    """Live JSON API: stream Basic Header Features from the uploaded CSV.
    Auto-detects raw (has IPs, integer ports) vs preprocessed (normalized 0-1) format.
    """
    session = AnalysisSession.query.filter_by(id=session_id, user_id=current_user.id).first_or_404()

    page     = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 100, type=int)

    if not session.filepath or not os.path.exists(session.filepath):
        results_data = json.loads(session.results_json) if session.results_json else {}
        flows = results_data.get("per_flow", [])
        # Detect whether the cached flows actually contain IP/identifier data
        has_ip = any(
            f.get('source_ip') and f['source_ip'] not in ('0.0.0.0', 'None', '', 'nan', None)
            for f in flows
        )
        # Normalize field names: cached rows use source_ip/dest_ip;
        # the JS table reads r.src_ip / r.dst_ip — map them here.
        def _norm_flow(f, idx):
            sip = f.get('source_ip') or f.get('src_ip') or ''
            dip = f.get('dest_ip')   or f.get('dst_ip')  or ''
            bad = {'0.0.0.0', 'None', '', 'nan', 'null'}
            return {
                'row_num':   idx + 1,
                'src_ip':    sip if sip not in bad else None,
                'dst_ip':    dip if dip not in bad else None,
                'src_port':  f.get('source_port', '—'),
                'dst_port':  f.get('dest_port', '—'),
                'protocol':  f.get('protocol', '—'),
                'flags':     f.get('flags', []),
                'label':     f.get('stage2_1_category') or f.get('stage3_specific') or 'Unknown',
                # pass-through analysis fields
                'stage1':              f.get('stage1'),
                'stage1_confidence':   f.get('stage1_confidence'),
                'stage2_1_category':   f.get('stage2_1_category'),
                'stage3_specific':     f.get('stage3_specific'),
                'severity':            f.get('severity'),
            }
        normalized_flows = [_norm_flow(f, i) for i, f in enumerate(flows)]
        total = len(normalized_flows)
        start = (page - 1) * per_page
        return jsonify({
            "rows": normalized_flows[start:start + per_page],
            "total": total,
            "page": page,
            "pages": max(1, (total + per_page - 1) // per_page),
            "source": "cache",
            "has_ip": has_ip,
            "file_type": "cache",
        })


    # ── Constants ────────────────────────────────────────────────────────────
    PROTO_MAP = {0: "HOPOPT", 1: "ICMP", 6: "TCP", 17: "UDP",
                 58: "IPv6-ICMP", 132: "SCTP"}
    PORT_SERVICES = {
        20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
        80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP",
        443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 9200: "Elasticsearch",
    }

    import re
    def _norm(s):
        return re.sub(r'[^a-z0-9]', '', str(s).strip().lower())

    try:
        skip = (page - 1) * per_page

        # ── Detect format using header + first data row ───────────────────
        header_df = pd.read_csv(session.filepath, nrows=5, low_memory=False)
        header_df.columns = header_df.columns.str.strip()
        col_names = list(header_df.columns)
        col_norm_map = {_norm(c): c for c in col_names}

        def fc(*cands):
            for c in cands:
                r = col_norm_map.get(_norm(c))
                if r: return r
            return None

        # Check for IP columns → definitive sign of raw file
        ip_col_present = fc("Src IP", "Source IP", "Src_IP", "src_ip") is not None or \
                         fc("Dst IP", "Destination IP", "Dst_IP", "dst_ip") is not None

        # Check port range to distinguish raw (0–65535) from normalized (0–1)
        port_col_probe = fc("Dst_Port", "Dst Port", "Src Port", "Src_Port",
                            "Destination Port", "Source Port")
        is_raw = ip_col_present  # IPs present → definitely raw
        if not is_raw and port_col_probe:
            probe_vals = header_df[port_col_probe].dropna()
            if len(probe_vals) > 0:
                max_port = probe_vals.max()
                is_raw = float(max_port) > 1.0   # raw ports are integers like 80, 443

        file_type = "raw" if is_raw else "normalized"

        # ── Smart IP-first page loader ──────────────────────────────────────
        # Read the full saved CSV (already pre-sampled to ~50k rows by the
        # upload pipeline), filter to only rows with real IPs, then paginate.
        # This guarantees the table always shows actual IP addresses.
        df_full = pd.read_csv(session.filepath, low_memory=False)
        df_full.columns = df_full.columns.str.strip()

        # Find any Src IP / Flow ID column in the full file
        full_col_norm = {_norm(c): c for c in df_full.columns}
        def ffcp(*cands):
            for c in cands:
                r = full_col_norm.get(_norm(c))
                if r: return r
            return None

        _sip_full = ffcp("Src IP", "Source IP", "Src_IP", "src_ip", "source_ip")
        _fid_full = ffcp("Flow ID", "flow_id", "FlowID")

        if _sip_full:
            # Filter to rows with real, non-null IP values
            ip_mask = df_full[_sip_full].notnull() & \
                      (~df_full[_sip_full].astype(str).str.strip().isin(['nan', 'NaN', '0.0.0.0', '']))
            df_ip = df_full[ip_mask].reset_index(drop=True)
        elif _fid_full:
            # Flow ID rows (can parse IPs from them)
            fid_mask = df_full[_fid_full].notnull() & \
                       (df_full[_fid_full].astype(str).str.count('-') >= 4)
            df_ip = df_full[fid_mask].reset_index(drop=True)
        else:
            # No IP data anywhere — show all rows
            df_ip = df_full.reset_index(drop=True)

        total_rows = len(df_ip) if len(df_ip) > 0 else 1
        skip = (page - 1) * per_page
        df_page = df_ip.iloc[skip: skip + per_page].copy()

        # Rebuild col map for this page slice
        col_norm = {_norm(c): c for c in df_page.columns}
        def fcp(*cands):
            for c in cands:
                r = col_norm.get(_norm(c))
                if r: return r
            return None

        # ── Resolve IP columns: 3-tier strategy ─────────────────────────────
        # Tier 1: Direct Src IP / Dst IP columns
        src_ip_col   = fcp("Src IP", "Source IP", "Src_IP", "src_ip", "source_ip", "id.orig_h", "ip.src", "sourceipaddress")
        dst_ip_col   = fcp("Dst IP", "Destination IP", "Dst_IP", "dst_ip", "dest_ip", "id.resp_h", "ip.dst", "destinationipaddress")
        flow_id_col  = fcp("Flow ID", "flow_id", "FlowID", "uid")
        src_port_col = fcp("Src Port", "Src_Port", "Source Port", "src_port", "source_port", "id.orig_p", "tcp.srcport", "udp.srcport")
        dst_port_col = fcp("Dst_Port", "Dst Port", "Destination Port", "dst_port", "dest_port", "id.resp_p", "tcp.dstport", "udp.dstport")
        proto_col    = fcp("Protocol", "Proto", "protocol")

        _has_direct_ip = src_ip_col is not None

        if not _has_direct_ip and flow_id_col:
            # Tier 2: Parse IPs from Flow ID  (format: SrcIP-DstIP-SrcPort-DstPort-Proto)
            df_page = df_page.copy()
            df_page['_src_ip'] = df_page[flow_id_col].astype(str).apply(
                lambda fid: fid.split('-')[0] if '-' in fid else fid)
            df_page['_dst_ip'] = df_page[flow_id_col].astype(str).apply(
                lambda fid: fid.split('-')[1] if fid.count('-') >= 1 else fid)
            src_ip_col = '_src_ip'
            dst_ip_col = '_dst_ip'
        elif not _has_direct_ip:
            # Tier 3: Synthesize network ID from Dst Port + Protocol
            _pc  = fcp("Dst Port", "dst_port")
            _prc = fcp("Protocol", "proto")
            if _pc or _prc:
                PROTO_NAMES = {'6':'TCP','17':'UDP','1':'ICMP','0':'HOPOPT'}
                df_page = df_page.copy()
                def _mk(row):
                    port  = str(int(float(row[_pc])))  if _pc  and pd.notna(row.get(_pc))  else '?'
                    proto = str(int(float(row[_prc]))) if _prc and pd.notna(row.get(_prc)) else '?'
                    return f"Port:{port}/{PROTO_NAMES.get(proto, proto)}"
                df_page['_net_id'] = df_page.apply(_mk, axis=1)
                src_ip_col = '_net_id'
                dst_ip_col = None

        syn_col      = fcp("SYN Flag Count", "SYN Flag Cnt", "SYN_Flag_Cnt", "syn_flags")
        ack_col      = fcp("ACK Flag Count", "ACK Flag Cnt", "ACK_Flag_Cnt", "ack_flags")
        psh_col      = fcp("PSH Flag Count", "PSH Flag Cnt", "PSH_Flag_Cnt", "psh_flags", "Fwd PSH Flags")
        rst_col      = fcp("RST Flag Count", "RST Flag Cnt", "RST_Flag_Cnt", "rst_flags")
        fin_col      = fcp("FIN Flag Count", "FIN_Flag_Cnt", "FIN_Flag_Cnt", "fin_flags")
        urg_col      = fcp("URG Flag Count", "URG Flag Cnt", "URG_Flag_Cnt", "urg_flags")
        cwe_col      = fcp("CWE Flag Count", "CWE Flag Count", "CWE_Flag_Count", "cwe_flags")
        ece_col      = fcp("ECE Flag Count", "ECE Flag Cnt", "ECE_Flag_Cnt", "ece_flags")
        label_col    = fcp("label", "Label", "Attack", "Class", "Label/Attack")

        def rf(col, row_data):
            """Get raw float or None."""
            if not col or col not in df_page.columns: return None
            v = row_data[col]
            if pd.isna(v): return None
            try: return float(v)
            except: return None

        def fmt_port(port_int):
            if port_int is None: return "—"
            if port_int == 0: return "0"
            svc = PORT_SERVICES.get(port_int)
            return f"{port_int} / {svc}" if svc else str(port_int)

        def get_port(col, row_data):
            """Return port as int, handling both raw and normalized."""
            v = rf(col, row_data)
            if v is None: return None
            if is_raw:
                return int(round(v))         # already integer
            else:
                return int(round(v * 65535)) # de-normalize

        def get_proto(col, row_data):
            """Return protocol name string."""
            v = rf(col, row_data)
            if v is None: return "—"
            if is_raw:
                proto_int = int(round(v))
            else:
                proto_int = int(round(v * 17))
            return PROTO_MAP.get(proto_int, f"PROTO {proto_int}")

        def flag_active(col, row_data):
            v = rf(col, row_data)
            return v is not None and v > 0

        def gip(col, row_data):
            """Get IP string, or None if missing."""
            if not col or col not in df_page.columns: return None
            v = row_data[col]
            s = str(v).strip() if pd.notna(v) else ""
            return s if s not in ('', 'nan', 'NaN', '0.0.0.0') else None


        _PROTO_NAMES = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', '0': 'HOPOPT'}

        def resolve_ip_for_row(row):
            """Apply 3-tier IP resolution for a single DataFrame row."""
            # Tier 1: direct IP columns
            sip = gip(src_ip_col, row)
            dip = gip(dst_ip_col, row)
            if sip:
                return sip, dip

            # Tier 2: parse from Flow ID (SrcIP-DstIP-SrcPort-DstPort-Proto)
            if flow_id_col and flow_id_col in df_page.columns:
                fid_val = row[flow_id_col]
                if pd.notna(fid_val):
                    parts = str(fid_val).split('-')
                    if len(parts) >= 2:
                        return parts[0], parts[1]

            return None, None

        rows = []
        for _, row in df_page.iterrows():
            src_port = get_port(src_port_col, row)
            dst_port = get_port(dst_port_col, row)

            flags = []
            if flag_active(syn_col, row): flags.append("SYN")
            if flag_active(ack_col, row): flags.append("ACK")
            if flag_active(psh_col, row): flags.append("PSH")
            if flag_active(rst_col, row): flags.append("RST")
            if flag_active(fin_col, row): flags.append("FIN")
            if flag_active(urg_col, row): flags.append("URG")
            if flag_active(cwe_col, row): flags.append("CWE")
            if flag_active(ece_col, row): flags.append("ECE")

            label_raw = ""
            if label_col and label_col in df_page.columns:
                lv = row[label_col]
                label_raw = str(lv).strip() if pd.notna(lv) else "—"
            label_clean = "Benign" if label_raw.lower() in ("benign", "normal", "benign traffic") \
                          else (label_raw or "—")

            r_sip, r_dip = resolve_ip_for_row(row)

            rows.append({
                "row_num":   skip + len(rows) + 1,
                "src_ip":    r_sip,
                "dst_ip":    r_dip,
                "src_port":  fmt_port(src_port),
                "dst_port":  fmt_port(dst_port),
                "protocol":  get_proto(proto_col, row),
                "flags":     flags,
                "label":     label_clean,
            })


        has_ip = (src_ip_col is not None) or (dst_ip_col is not None) or \
                 (flow_id_col is not None) or (dst_port_col is not None)

        pages  = max(1, (total_rows + per_page - 1) // per_page)
        # total_dataset = full file row count for the header display;
        # total_rows    = IP-filtered count used only for pagination.
        total_dataset = session.total_flows or total_rows
        return jsonify({
            "rows": rows, "total": total_dataset, "total_rows": total_rows,
            "page": page, "pages": pages,
            "source": "live", "has_ip": has_ip,
            "file_type": file_type,
        })

    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc(),
                        "rows": [], "total": 0, "page": 1, "pages": 1}), 500



@analysis_bp.route("/logs")
@login_required
def attack_logs():
    from sqlalchemy import func

    # Filters from query params
    severity_filter = request.args.get("severity", "")
    category_filter = request.args.get("category", "")
    search_filter = request.args.get("search", "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = 25

    query = AttackLog.query.filter_by(user_id=current_user.id)

    if severity_filter:
        query = query.filter(AttackLog.severity == severity_filter)
    if category_filter:
        query = query.filter(AttackLog.attack_category == category_filter)
    if search_filter:
        query = query.filter(
            (AttackLog.specific_attack.ilike(f"%{search_filter}%")) |
            (AttackLog.attack_category.ilike(f"%{search_filter}%")) |
            (AttackLog.filename.ilike(f"%{search_filter}%"))
        )

    query = query.order_by(AttackLog.timestamp.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    # Summary stats
    all_logs = AttackLog.query.filter_by(user_id=current_user.id)
    total_threats = all_logs.count()
    critical_count = all_logs.filter(AttackLog.severity == "critical").count()
    high_count = all_logs.filter(AttackLog.severity == "high").count()
    mitigated_count = all_logs.filter(AttackLog.is_ips_action == True).count()

    # Unique categories and severities for filter dropdowns
    categories = [r[0] for r in db.session.query(AttackLog.attack_category)
                  .filter_by(user_id=current_user.id)
                  .filter(AttackLog.attack_category != None)
                  .distinct().all()]
    severities = ["info", "low", "medium", "high", "critical"]

    return render_template("logs.html",
        logs=pagination.items,
        pagination=pagination,
        total_threats=total_threats,
        critical_count=critical_count,
        high_count=high_count,
        mitigated_count=mitigated_count,
        categories=categories,
        severities=severities,
        severity_filter=severity_filter,
        category_filter=category_filter,
        search_filter=search_filter,
    )


@analysis_bp.route("/system-logs")
@login_required
def system_logs():
    if not current_user.is_admin:
        flash("Admin access required for system logs.", "error")
        return redirect(url_for("dashboard.index"))
    from models.database import SystemLog
    logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(100).all()
    return render_template("system_logs.html", logs=logs)


@analysis_bp.route("/session/<int:session_id>/cancel", methods=["POST"])
@login_required
def cancel_session(session_id):
    """Mark a stuck processing/pending session as cancelled."""
    session = AnalysisSession.query.filter_by(id=session_id, user_id=current_user.id).first_or_404()
    if session.status in ("processing", "pending"):
        session.status = "cancelled"
        db.session.add(SystemLog(
            level="WARNING",
            event="Session Cancelled",
            details=f"User {current_user.username} manually cancelled session for {session.filename}."
        ))
        db.session.commit()
        flash(f"Session for '{session.filename}' has been cancelled.", "info")
    else:
        flash("Only processing or pending sessions can be cancelled.", "warning")
    return redirect(url_for("analysis.upload_page"))


@analysis_bp.route("/session/<int:session_id>/delete", methods=["POST"])
@login_required
def delete_session(session_id):
    """Permanently delete a session record."""
    session = AnalysisSession.query.filter_by(id=session_id, user_id=current_user.id).first_or_404()
    db.session.add(SystemLog(
        level="INFO",
        event="Session Deleted",
        details=f"User {current_user.username} deleted session {session_id} ({session.filename})."
    ))
    db.session.delete(session)
    db.session.commit()
    flash(f"Session '{session.filename}' deleted.", "info")
    return redirect(url_for("analysis.upload_page"))
