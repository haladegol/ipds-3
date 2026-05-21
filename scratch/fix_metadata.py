import sqlite3
import json
import pandas as pd
import os

DB_PATH = 'hades_secure.db'

def _norm(s):
    return str(s).strip().lower().replace(' ', '_').replace('/', '_').replace('-', '_')

def fix_metadata():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get recent or batch sessions
    cursor.execute("SELECT id, filepath, results_json FROM analysis_sessions WHERE status='completed' AND (filename LIKE '%Batch%' OR id > 60) ORDER BY id DESC")
    sessions = cursor.fetchall()
    
    print(f"Found {len(sessions)} sessions to check.")
    
    for sess_id, filepath, results_json in sessions:
        if not results_json:
            continue
        if not filepath or not os.path.exists(filepath):
            print(f"  Skipping session {sess_id}: File not found ({filepath})")
            continue
            
        print(f"  Processing session {sess_id}: {os.path.basename(filepath)}...")
        results = json.loads(results_json)
        per_flow = results.get('per_flow', [])
        
        if not per_flow:
            print(f"    No per_flow data found.")
            continue

        try:
            # Read CSV
            df = pd.read_csv(filepath, low_memory=False)
            
            col_norm = {c.strip().lower().replace(' ', '_').replace('/', '_'): c for c in df.columns}
            def fcp_local(*cands):
                for c in cands:
                    norm_c = c.strip().lower().replace(' ', '_').replace('/', '_')
                    if norm_c in col_norm: return col_norm[norm_c]
                return None

            src_ip_col   = fcp_local("Src IP", "Source IP", "src_ip", "source_ip")
            dst_ip_col   = fcp_local("Dst IP", "Destination IP", "dst_ip", "dest_ip")
            src_port_col = fcp_local("Src Port", "Source Port", "src_port", "source_port")
            dst_port_col = fcp_local("Dst Port", "Destination Port", "dst_port", "dest_port")
            proto_col    = fcp_local("Protocol", "proto")
            
            def _val(col, idx):
                if col is None or col not in df.columns: return "0.0.0.0"
                try:
                    v = df.iloc[idx][col]
                    return str(v) if pd.notna(v) else "0.0.0.0"
                except: return "0.0.0.0"

            def _vint(col, idx, default=0):
                if col is None or col not in df.columns: return default
                try:
                    v = df.iloc[idx][col]
                    return int(float(v)) if pd.notna(v) else default
                except: return default

            # Update per_flow entries
            fixed_count = 0
            for flow in per_flow:
                idx = flow.get('flow_index', 0)
                if idx < len(df):
                    sip = _val(src_ip_col, idx)
                    dip = _val(dst_ip_col, idx)
                    if sip != "0.0.0.0" or dip != "0.0.0.0":
                        fixed_count += 1
                    
                    flow['source_ip'] = sip
                    flow['dest_ip'] = dip
                    flow['source_port'] = _vint(src_port_col, idx)
                    flow['dest_port'] = _vint(dst_port_col, idx)
                    flow['protocol'] = _vint(proto_col, idx, 6)
            
            print(f"    Updated {fixed_count} flows with real metadata.")
            
            # Save back to DB
            new_json = json.dumps(results, default=str)
            cursor.execute("UPDATE analysis_sessions SET results_json=? WHERE id=?", (new_json, sess_id))
            conn.commit()

        except Exception as e:
            print(f"    Error processing session {sess_id}: {str(e)}")

    # Now fix AttackLog table (Aggregated logs)
    print("Fixing AttackLog table...")
    cursor.execute("SELECT id, filename, attack_category, specific_attack, source_ip FROM attack_logs WHERE (source_ip IS NULL OR source_ip = '0.0.0.0') AND attack_category IS NOT NULL")
    logs = cursor.fetchall()
    
    file_cache = {}
    for log_id, filename, cat, spec, sip_val in logs:
        cursor.execute("SELECT filepath FROM analysis_sessions WHERE filename=? AND status='completed' LIMIT 1", (filename,))
        f_row = cursor.fetchone()
        if not f_row or not f_row[0]: continue
        fpath = f_row[0]
        
        if fpath not in file_cache:
            if os.path.exists(fpath):
                try:
                    file_cache[fpath] = pd.read_csv(fpath, low_memory=False)
                except: continue
            else: continue
            
        df = file_cache[fpath]
        col_norm = {_norm(c): c for c in df.columns}
        sip_col = next((col_norm[k] for k in [_norm('Src IP'), _norm('Source IP'), 'src_ip', 'source_ip'] if k in col_norm), None)
        dip_col = next((col_norm[k] for k in [_norm('Dst IP'), _norm('Destination IP'), 'dst_ip', 'dest_ip'] if k in col_norm), None)
        
        if not sip_col: continue
        
        # Pick first non-null IP as representative
        valid_rows = df[df[sip_col].notna()]
        if not valid_rows.empty:
            first_row = valid_rows.iloc[0]
            new_sip = str(first_row[sip_col])
            new_dip = str(first_row[dip_col]) if dip_col and pd.notna(first_row[dip_col]) else "0.0.0.0"
            cursor.execute("UPDATE attack_logs SET source_ip=?, dest_ip=? WHERE id=?", (new_sip, new_dip, log_id))
            print(f"  Fixed AttackLog {log_id} with IPs {new_sip} -> {new_dip}")

    conn.commit()
    conn.close()
    print("Done!")

if __name__ == "__main__":
    fix_metadata()
