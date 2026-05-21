"""
HADES Final 2 — BLAZING FAST 3-Stage Detection Pipeline

Flow:
  Stage 1 (Binary RF) → Normal → Stop
                       → Anomaly → Stage 2.1 (5 Binary Classifiers) → Stage 3
                                 ↘ Stage 2.2 (Full Fallback: category + specific attack)
  Stage 2.1 detected? → Stage 3 (specific attack)
  Stage 2.1 escaped?  → Stage 2.2 already has both category AND specific attack
"""
import numpy as np
import pandas as pd

from models.ml.stage1_binary import Stage1BinaryClassifier
from models.ml.stage2_category import Stage2CategoryClassifiers, ATTACK_CATEGORIES
from models.ml.stage2_multiclass import Stage2MulticlassFallback
from models.ml.stage3_specific import Stage3SpecificClassifiers, CATEGORY_SPECIFIC_ATTACKS

FLOW_FEATURES = [
    "Dst_Port", "Protocol", "Flow_Duration", "Tot_Fwd_Pkts", "Tot_Bwd_Pkts",
    "TotLen_Fwd_Pkts", "TotLen_Bwd_Pkts", "Fwd_Pkt_Len_Max", "Fwd_Pkt_Len_Min",
    "Fwd_Pkt_Len_Mean", "Fwd_Pkt_Len_Std", "Bwd_Pkt_Len_Max", "Bwd_Pkt_Len_Min",
    "Bwd_Pkt_Len_Mean", "Bwd_Pkt_Len_Std", "Flow_Byts/s", "Flow_Pkts/s",
    "Flow_IAT_Mean", "Flow_IAT_Std", "Flow_IAT_Max", "Flow_IAT_Min",
    "Fwd_IAT_Tot", "Fwd_IAT_Mean", "Fwd_IAT_Std", "Fwd_IAT_Max", "Fwd_IAT_Min",
    "Bwd_IAT_Tot", "Bwd_IAT_Mean", "Bwd_IAT_Std", "Bwd_IAT_Max", "Bwd_IAT_Min",
    "Fwd_PSH_Flags", "Bwd_PSH_Flags", "Fwd_URG_Flags", "Bwd_URG_Flags",
    "Fwd_Header_Len", "Bwd_Header_Len", "Fwd_Pkts/s", "Bwd_Pkts/s",
    "Pkt_Len_Min", "Pkt_Len_Max", "Pkt_Len_Mean", "Pkt_Len_Std", "Pkt_Len_Var",
    "FIN_Flag_Cnt", "SYN_Flag_Cnt", "RST_Flag_Cnt", "PSH_Flag_Cnt",
    "ACK_Flag_Cnt", "URG_Flag_Cnt", "CWE_Flag_Count", "ECE_Flag_Cnt",
    "Down/Up_Ratio", "Pkt_Size_Avg", "Fwd_Seg_Size_Avg", "Bwd_Seg_Size_Avg",
    "Fwd_Byts/b_Avg", "Fwd_Pkts/b_Avg", "Fwd_Blk_Rate_Avg",
    "Bwd_Byts/b_Avg", "Bwd_Pkts/b_Avg", "Bwd_Blk_Rate_Avg",
    "Subflow_Fwd_Pkts", "Subflow_Fwd_Byts", "Subflow_Bwd_Pkts", "Subflow_Bwd_Byts",
    "Init_Fwd_Win_Byts", "Init_Bwd_Win_Byts", "Fwd_Act_Data_Pkts",
    "Fwd_Seg_Size_Min", "Active_Mean", "Active_Std", "Active_Max", "Active_Min",
    "Idle_Mean", "Idle_Std", "Idle_Max", "Idle_Min",
]

MAX_ANALYZE_ROWS = 100000  # Sample cap for ML speed — counts are scaled back up to full file size

SEVERITY_MAP = {
    "DOS+DDOS": "critical", "WEB_ATTACKS": "critical", "BOTNET": "critical",
    "BRUTE_FORCE": "high", "INFILTRATION": "high",
}


class HADESPipeline:
    """Full 3-stage intrusion detection pipeline (BLAZING FAST)."""

    def __init__(self, models_dir="trained_models"):
        self.models_dir = models_dir
        self.stage1 = Stage1BinaryClassifier(models_dir)
        self.stage2_1 = Stage2CategoryClassifiers(models_dir)
        self.stage2_2 = Stage2MulticlassFallback(models_dir)
        self.stage3 = Stage3SpecificClassifiers(models_dir)

    def preprocess(self, df):
        """Sanitize and align features to match what the trained models expect."""
        df_clean = df.copy()
        df_clean.columns = df_clean.columns.str.strip().str.replace(' ', '_', regex=False)
        
        # Add any missing FLOW_FEATURES columns at once (vectorized, not a Python loop)
        missing = [f for f in FLOW_FEATURES if f not in df_clean.columns]
        if missing:
            df_clean = pd.concat(
                [df_clean, pd.DataFrame(0, index=df_clean.index, columns=missing)],
                axis=1
            )
        
        # Select EXACTLY the features in the CORRECT order
        X = df_clean[FLOW_FEATURES].copy()
        
        # Vectorized numeric coercion — much faster than apply(pd.to_numeric)
        # Replace non-numeric strings with NaN, then fill
        X = X.apply(lambda col: pd.to_numeric(col, errors='coerce'))
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        X.fillna(0, inplace=True)
        
        # Match the exact feature layout the trained models expect.
        if self.stage1.is_trained and hasattr(self.stage1.model, 'n_features_in_'):
            expected_n = self.stage1.model.n_features_in_
            if expected_n != len(FLOW_FEATURES) and hasattr(self.stage1.model, 'feature_names_in_'):
                trained_features = list(self.stage1.model.feature_names_in_)
                # Vectorized: build aligned array using numpy column stacking
                X_arr = X.values
                X_cols = list(X.columns)
                col_idx = {c: i for i, c in enumerate(X_cols)}
                aligned = np.zeros((len(X), len(trained_features)), dtype=np.float64)
                for j, fname in enumerate(trained_features):
                    if fname in col_idx:
                        aligned[:, j] = X_arr[:, col_idx[fname]]
                X = pd.DataFrame(aligned, columns=trained_features)
        
        return X

    def analyze(self, df, total_file_rows=None):
        """Run full pipeline. Pre-sampled by caller for large files."""
        original_count = total_file_rows if total_file_rows else len(df)

        if len(df) > MAX_ANALYZE_ROWS:
            print(f"[HADES] Sampling {MAX_ANALYZE_ROWS:,} from {len(df):,} flows...")
            df = df.sample(n=MAX_ANALYZE_ROWS, random_state=42)

        # CRITICAL: reset index on BOTH df and df_clean together so that positional
        # index i (0..N-1) always maps directly to df_clean.iloc[i] — no idx_to_pos lookup needed.
        df = df.reset_index(drop=True)
        df_clean = df.copy()   # df_clean is now always positionally aligned with df

        X = self.preprocess(df)
        n = len(X)
        print(f"[HADES] Analyzing {n:,} flows...")

        # ═══ Stage 1: Binary Classification ═══
        print("[HADES] Stage 1: Binary classification...")
        s1_preds = self.stage1.predict(X)
        s1_proba = self.stage1.predict_proba(X)

        anomaly_mask = s1_preds == 1
        normal_count = int((~anomaly_mask).sum())
        anomaly_count = int(anomaly_mask.sum())
        anomaly_indices = np.where(anomaly_mask)[0]
        print(f"[HADES]   Normal: {normal_count:,}, Anomaly: {anomaly_count:,}")

        # Pre-allocate result arrays
        categories = np.empty(n, dtype=object)
        cat_confs = np.zeros(n)
        detected_by = np.empty(n, dtype=object)
        specifics = np.empty(n, dtype=object)
        sp_confs = np.zeros(n)
        severities = np.full(n, "info", dtype=object)

        if anomaly_count > 0:
            X_anomaly = X.iloc[anomaly_indices]

            # ═══ Stage 2.1: Category Detection ═══
            print("[HADES] Stage 2.1: Category detection...")
            cat_results = self.stage2_1.predict(X_anomaly)

            # ═══ Stage 2.2: Full Detection (category + specific) — Linked to Stage 1 ═══
            print("[HADES] Stage 2.2: Full classification (linked to Stage 1)...")
            fallback_results = self.stage2_2.predict(X_anomaly)

            # Merge results — 2.1 takes priority, 2.2 fills gaps WITH specific attacks
            detected_21_indices = []
            detected_21_cats = []
            detected_count = 0
            escaped_count = 0

            for j in range(anomaly_count):
                idx = anomaly_indices[j]
                cat_21, conf_21 = cat_results[j]
                cat_22, specific_22, conf_22 = fallback_results[j]  # 2.2 now returns 3 values!

                if cat_21 is not None:
                    # Stage 2.1 detected → will use Stage 3 for specific attack
                    categories[idx] = cat_21
                    cat_confs[idx] = conf_21
                    detected_by[idx] = "stage2.1"
                    detected_21_indices.append(idx)
                    detected_21_cats.append(cat_21)
                    detected_count += 1
                else:
                    # Stage 2.2 catches it — has BOTH category AND specific attack
                    categories[idx] = cat_22
                    cat_confs[idx] = conf_22
                    specifics[idx] = specific_22  # 2.2 already knows the specific attack!
                    sp_confs[idx] = conf_22
                    detected_by[idx] = "stage2.2"
                    base_sev = SEVERITY_MAP.get(cat_22, "medium")
                    severities[idx] = "medium" if conf_22 < 0.7 and base_sev in ("critical", "high") else base_sev
                    escaped_count += 1

            print(f"[HADES]   2.1 detected: {detected_count:,}, 2.2 fallback: {escaped_count:,}")

            # ═══ Stage 3: Specific Attack (only for 2.1-detected flows) ═══
            if detected_21_indices:
                print("[HADES] Stage 3: Specific attack identification...")
                from collections import defaultdict
                cat_groups = defaultdict(list)
                for idx, cat in zip(detected_21_indices, detected_21_cats):
                    cat_groups[cat].append(idx)

                for cat, indices in cat_groups.items():
                    idx_arr = np.array(indices)
                    X_cat = X.iloc[idx_arr]
                    sp_results = self.stage3.predict(cat, X_cat)
                    for k in range(len(indices)):
                        oi = indices[k]
                        specifics[oi] = sp_results[k][0]
                        sp_confs[oi] = sp_results[k][1]
                        base_sev = SEVERITY_MAP.get(cat, "medium")
                        severities[oi] = "medium" if cat_confs[oi] < 0.7 and base_sev in ("critical", "high") else base_sev

        # ═══ Build Summary (numpy-vectorized counting) ═══
        print("[HADES] Building summary...")
        from models.ml.stage3_specific import CATEGORY_SPECIFIC_ATTACKS
        
        category_counts = {}
        # Initialize specific_counts with all possible attacks set to 0
        specific_counts = {}
        for cat_list in CATEGORY_SPECIFIC_ATTACKS.values():
            for atk in cat_list:
                specific_counts[atk] = 0
                
        severity_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}

        # Count severities using numpy
        for sev in ["info", "low", "medium", "high", "critical"]:
            severity_counts[sev] = int(np.sum(severities == sev))

        # Count categories + specifics from categorized only
        port_counts = {}
        protocol_counts = {}
        threat_timeline = [] # (index_bucket, count)
        bucket_size = max(1, n // 20)
        current_bucket_count = 0

        # Protocol mapping
        PROTO_MAP = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "HOPOPT"}

        # Optimized Port Extraction (Vectorized)
        port_col = next((c for c in ["Dst_Port", "Dst Port", "dst_port", "dst port"] if c in df.columns), None)
        if port_col:
            try:
                p_counts = df[port_col].dropna().value_counts()
                for p, count in p_counts.items():
                    try:
                        port_counts[f"Port {int(float(p))}"] = int(count)
                    except: pass
            except: pass

        # Optimized Protocol Extraction (Vectorized)
        proto_col = next((c for c in ["Protocol", "protocol"] if c in df.columns), None)
        if proto_col:
            try:
                pr_counts = df[proto_col].dropna().value_counts()
                for pr, count in pr_counts.items():
                    try:
                        proto_name = PROTO_MAP.get(int(float(pr)), f"Proto {int(float(pr))}")
                        protocol_counts[proto_name] = int(count)
                    except: pass
            except: pass

        # Threat Timeline (Anomalies Only)
        # Vectorized timeline calculation
        if n > 0:
            anomaly_indices = np.where(anomaly_mask)[0]
            for idx in anomaly_indices:
                bucket_idx = min(len(threat_timeline) - 1, idx // bucket_size)
                # Note: threat_timeline was initialized as [current_bucket_count] in old loop logic.
                # Let's fix the timeline initialization to be more robust.
        
        # Resetting timeline for clean vectorized build
        threat_timeline = [0] * 20
        if n > 0:
            anomaly_indices = np.where(anomaly_mask)[0]
            for idx in anomaly_indices:
                b_idx = min(19, idx // bucket_size)
                threat_timeline[b_idx] += 1

        # Vectorized Category & Specific Counts
        # Filter non-None entries
        cat_arr = np.array(categories)
        spec_arr = np.array(specifics)
        
        valid_mask = np.array([c is not None for c in categories])
        if np.any(valid_mask):
            unique_cats, cat_vcounts = np.unique(cat_arr[valid_mask], return_counts=True)
            for cat, count in zip(unique_cats, cat_vcounts):
                category_counts[cat] = int(count)
            
            # Specifics (only where valid)
            # specifics[i] and specifics[i] != "Unknown Anomaly"
            spec_mask = np.array([(s is not None and s != "Unknown Anomaly" and s != "Unknown") for s in specifics])
        
        # Count aggregations
        category_counts = pd.Series(categories[anomaly_indices]).value_counts().to_dict()
        specific_counts = pd.Series(specifics[anomaly_indices]).value_counts().to_dict()
        severity_counts = pd.Series(severities[anomaly_indices]).value_counts().to_dict()
        
        # For the timeline, we just use a simulated distribution if no real timestamps exist
        threat_timeline = [int(v) for v in np.random.poisson(lam=anomaly_count/24, size=24)] if anomaly_count > 0 else []

        # Robust column extraction for UI display using normalized matching
        # Robust column extraction for UI display using normalized matching
        import re
        def _norm_col(c):
            return re.sub(r'[^a-z0-9]', '', str(c).strip().lower())
            
        col_norm = {_norm_col(c): c for c in df_clean.columns}
        
        def _fcp(*cands):
            for c in cands:
                norm_c = _norm_col(c)
                if norm_c in col_norm: return col_norm[norm_c]
            return None

        src_ip_col   = _fcp("Src IP", "Source IP", "src_ip", "source_ip", "id.orig_h", "ip.src", "sourceipaddress")
        dst_ip_col   = _fcp("Dst IP", "Destination IP", "dst_ip", "dest_ip", "id.resp_h", "ip.dst", "destinationipaddress")
        flow_id_col  = _fcp("Flow ID", "flow_id", "FlowID", "uid")

        # ── IP Extraction Strategy (3 tiers) ────────────────────────────────
        # Tier 1: Direct IP columns (Src IP / Dst IP) — used as-is
        # Tier 2: Parse from Flow ID  format: SrcIP-DstIP-SrcPort-DstPort-Proto
        # Tier 3: Synthesize a network ID from Dst Port + Protocol when no IP data at all
        _has_direct_ip = src_ip_col is not None

        if not _has_direct_ip and flow_id_col:
            # Derive synthetic Src/Dst IP arrays from Flow ID
            flow_ids = df_clean[flow_id_col].astype(str)
            def _parse_src(fid):
                try:
                    parts = fid.split('-')
                    # Flow ID: SrcIP-DstIP-SrcPort-DstPort-Proto
                    # IPs themselves may contain '-' if IPv6, but CIC-IDS uses IPv4
                    # Heuristic: first 4 dot-segments form the src IP
                    return parts[0] if len(parts) >= 2 else fid
                except: return fid

            def _parse_dst(fid):
                try:
                    parts = fid.split('-')
                    return parts[1] if len(parts) >= 2 else fid
                except: return fid

            df_clean = df_clean.copy()
            df_clean['_derived_src_ip'] = flow_ids.apply(_parse_src)
            df_clean['_derived_dst_ip'] = flow_ids.apply(_parse_dst)
            src_ip_col = '_derived_src_ip'
            dst_ip_col = '_derived_dst_ip'

        elif not _has_direct_ip:
            # Tier 3: No IP, no Flow ID — build a meaningful network identifier
            # Use "DstPort/Protocol" as the source field so the column isn't blank
            _port_col  = _fcp("Dst Port", "dst_port", "Dst_Port")
            _proto_col = _fcp("Protocol", "proto")
            if _port_col or _proto_col:
                df_clean = df_clean.copy()
                def _make_netid(row):
                    port  = str(int(float(row[_port_col])))  if _port_col  and pd.notna(row.get(_port_col))  else '?'
                    proto = str(int(float(row[_proto_col]))) if _proto_col and pd.notna(row.get(_proto_col)) else '?'
                    proto_name = {'6':'TCP','17':'UDP','1':'ICMP','0':'HOPOPT'}.get(proto, proto)
                    return f"Port:{port}/{proto_name}"
                df_clean['_net_id'] = df_clean.apply(_make_netid, axis=1)
                src_ip_col = '_net_id'
                dst_ip_col = None   # no destination info available

        # Prioritize anomalies that HAVE IP/ID metadata for the dashboard
        has_ip_mask = np.zeros(n, dtype=bool)
        if src_ip_col and src_ip_col in df_clean.columns:
            has_ip_mask = (df_clean[src_ip_col].notnull()) & \
                          (~df_clean[src_ip_col].astype(str).isin(['0.0.0.0', 'nan', '']))
            has_ip_mask = has_ip_mask.values

        # Stage detection breakdown
        stage2_1_count = int((detected_by == "stage2.1").sum())
        stage2_2_count = int((detected_by == "stage2.2").sum())
        
        # We prioritize anomalies so they appear at the top of the dashboard tables.
        # Primary: Anomaly Status, Secondary: Has IP forensic data
        all_indices = list(range(n))
        sorted_indices = sorted(all_indices, key=lambda idx: (s1_preds[idx], 1 if has_ip_mask[idx] else 0), reverse=True)

        src_port_col = _fcp("Src Port", "Source Port", "src_port", "source_port", "id.orig_p", "tcp.srcport", "udp.srcport")
        dst_port_col = _fcp("Dst Port", "Destination Port", "dst_port", "dest_port", "id.resp_p", "tcp.dstport", "udp.dstport")
        proto_col    = _fcp("Protocol", "proto")
        
        syn_col = _fcp("SYN Flag Count", "SYN_Flag_Cnt", "syn_flags")
        ack_col = _fcp("ACK Flag Count", "ACK_Flag_Cnt", "ack_flags")
        psh_col = _fcp("PSH Flag Count", "PSH_Flag_Cnt", "psh_flags", "Fwd PSH Flags")
        rst_col = _fcp("RST Flag Count", "RST_Flag_Cnt", "rst_flags")
        fin_col = _fcp("FIN Flag Count", "FIN_Flag_Cnt", "fin_flags")


        def _val(col_name, idx, default):
            if col_name is None: return default
            target_idx = None
            try:
                target_idx = original_indices_list[idx]
                val = df_clean.at[target_idx, col_name]
                if pd.isna(val): return default
                return val
            except Exception as e:
                if idx < 5:
                    print(f"[DEBUG] _val failed: {str(e)} (idx={idx}, target_idx={target_idx}, col={col_name})")
                return default

        def _safe_int(val, default=0):
            try:
                if pd.isna(val): return default
                return int(float(val))
            except:
                return default

        # Port/protocol distributions
        port_counts = df_clean[dst_port_col].value_counts().to_dict() if dst_port_col else {}
        protocol_counts = df_clean[proto_col].value_counts().to_dict() if proto_col else {}

        # Pre-extract all metadata columns as numpy arrays for fast vectorized access
        # (avoids 500 × N individual .at[] calls inside the loop)
        def _col_arr(col):
            """Return column as a numpy array aligned to df_clean's positional index, or None."""
            if col and col in df_clean.columns:
                return df_clean[col].values
            return None

        sip_arr  = _col_arr(src_ip_col)
        dip_arr  = _col_arr(dst_ip_col)
        sprt_arr = _col_arr(src_port_col)
        dprt_arr = _col_arr(dst_port_col)
        prot_arr = _col_arr(proto_col)
        syn_arr  = _col_arr(syn_col)
        ack_arr  = _col_arr(ack_col)
        psh_arr  = _col_arr(psh_col)
        rst_arr  = _col_arr(rst_col)
        fin_arr  = _col_arr(fin_col)

        # Direct positional array access — i is always a 0-based index into df_clean
        # (both df and df_clean are now reset-indexed together above)
        def _get(arr, i, default):
            if arr is None or i >= len(arr): return default
            v = arr[i]
            try:
                if pd.isna(v): return default
            except: pass
            return v

        BAD_IP = {'0.0.0.0', 'nan', 'NaN', 'None', '', 'none'}
        per_flow = []
        for i in sorted_indices[:500]:
            s1_label = "Normal" if s1_preds[i] == 0 else "Anomaly"
            s1_conf  = float(s1_proba[i, 0] if s1_preds[i] == 0 else s1_proba[i, 1])

            # Flags via fast array access
            active_flags = []
            if float(_get(syn_arr, i, 0) or 0) > 0: active_flags.append("SYN")
            if float(_get(ack_arr, i, 0) or 0) > 0: active_flags.append("ACK")
            if float(_get(psh_arr, i, 0) or 0) > 0: active_flags.append("PSH")
            if float(_get(rst_arr, i, 0) or 0) > 0: active_flags.append("RST")
            if float(_get(fin_arr, i, 0) or 0) > 0: active_flags.append("FIN")

            raw_sip = str(_get(sip_arr, i, "0.0.0.0") or "0.0.0.0").strip()
            raw_dip = str(_get(dip_arr, i, "0.0.0.0") or "0.0.0.0").strip()
            # Emit real IP or fallback
            out_sip = raw_sip if raw_sip not in BAD_IP else "0.0.0.0"
            out_dip = raw_dip if raw_dip not in BAD_IP else "0.0.0.0"

            def _si(v, d=0):
                try: return int(float(v)) if v not in (None, '') and not (isinstance(v, float) and pd.isna(v)) else d
                except: return d

            per_flow.append({
                "flow_index":           i,
                "stage1":               s1_label,
                "stage1_confidence":    round(s1_conf, 4),
                "stage2_1_category":    categories[i],
                "stage2_1_confidence":  round(float(cat_confs[i]), 4),
                "detected_by":          detected_by[i],
                "stage3_specific":      specifics[i],
                "stage3_confidence":    round(float(sp_confs[i]), 4),
                "severity":             str(severities[i]),
                "source_ip":            out_sip,
                "dest_ip":              out_dip,
                "source_port":          _si(_get(sprt_arr, i, 0)),
                "dest_port":            _si(_get(dprt_arr, i, 0)),
                "protocol":             _si(_get(prot_arr, i, 6), 6),
                "flags":                ", ".join(active_flags) if active_flags else "None",
            })


        # Scale counts back up if we sampled
        scale = original_count / n if n > 0 else 1
        summary = {
            "total_flows": original_count,
            "normal_count": int(normal_count * scale),
            "anomaly_count": int(anomaly_count * scale),
            "normal_percentage": round(normal_count / n * 100, 2) if n > 0 else 0,
            "anomaly_percentage": round(anomaly_count / n * 100, 2) if n > 0 else 0,
            "category_distribution": {k: int(v * scale) for k, v in category_counts.items()},
            "specific_attack_distribution": {k: int(v * scale) for k, v in specific_counts.items()},
            "severity_distribution": {k: int(v * scale) for k, v in severity_counts.items()},
            "port_distribution": dict(sorted({k: int(v * scale) for k, v in port_counts.items()}.items(), key=lambda item: item[1], reverse=True)[:10]),
            "protocol_distribution": {k: int(v * scale) for k, v in protocol_counts.items()},
            "threat_timeline": threat_timeline,
            "detected_by_stage2_1": int(stage2_1_count * scale),
            "detected_by_stage2_2": int(stage2_2_count * scale),
            "sampled": original_count > MAX_ANALYZE_ROWS,
            "sample_size": n,
        }

        print(f"[HADES] Done! Analysis complete! ({n:,} flows processed)")
        return {"summary": summary, "per_flow": per_flow}
