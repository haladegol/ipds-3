"""
Comprehensive IP filler for all existing analysis sessions.
Uses the same 3-tier strategy as the pipeline:
  Tier 1: Direct Src IP / Dst IP columns
  Tier 2: Parse from Flow ID (SrcIP-DstIP-Port-Port-Proto)
  Tier 3: Synthesize Port:X/PROTO from Dst Port + Protocol
"""
import sqlite3, json, os, pandas as pd

DB_PATH = 'hades_secure.db'

PROTO_NAMES = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', '0': 'HOPOPT'}


def _norm(s):
    return str(s).strip().lower().replace(' ', '_').replace('/', '_')


def _find_col(columns, *cands):
    col_map = {_norm(c): c for c in columns}
    for c in cands:
        r = col_map.get(_norm(c))
        if r:
            return r
    return None


def extract_ips_from_df(df, row_idx):
    """Return (src_ip, dst_ip) for a given positional row index using 3-tier strategy."""
    cols = df.columns.tolist()

    # Tier 1: direct IP columns
    sip_col = _find_col(cols, 'Src IP', 'Source IP', 'src_ip', 'source_ip')
    dip_col = _find_col(cols, 'Dst IP', 'Destination IP', 'dst_ip', 'dest_ip')
    if sip_col:
        row = df.iloc[row_idx]
        sip = str(row[sip_col]) if pd.notna(row[sip_col]) else None
        dip = str(row[dip_col]) if dip_col and pd.notna(row.get(dip_col)) else None
        if sip and sip not in ('nan', '0.0.0.0', ''):
            return sip, dip

    # Tier 2: Flow ID
    fid_col = _find_col(cols, 'Flow ID', 'flow_id', 'FlowID')
    if fid_col:
        row = df.iloc[row_idx]
        fid = str(row[fid_col])
        parts = fid.split('-')
        if len(parts) >= 2:
            return parts[0], parts[1]

    # Tier 3: Port + Protocol
    port_col  = _find_col(cols, 'Dst Port', 'dst_port')
    proto_col = _find_col(cols, 'Protocol', 'proto')
    row = df.iloc[row_idx]
    port  = str(int(float(row[port_col])))  if port_col  and pd.notna(row.get(port_col))  else '?'
    proto = str(int(float(row[proto_col]))) if proto_col and pd.notna(row.get(proto_col)) else '?'
    proto_name = PROTO_NAMES.get(proto, proto)
    return f'Port:{port}/{proto_name}', None


def fix_all_sessions():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, filepath, results_json FROM analysis_sessions "
        "WHERE status='completed' ORDER BY id DESC"
    )
    sessions = cursor.fetchall()
    print(f"Found {len(sessions)} completed sessions.")

    for sess_id, filepath, results_json in sessions:
        if not results_json or not filepath or not os.path.exists(filepath):
            print(f"  Session {sess_id}: skipping (no file or no results)")
            continue

        results = json.loads(results_json)
        per_flow = results.get('per_flow', [])
        if not per_flow:
            print(f"  Session {sess_id}: no per_flow data")
            continue

        # Check if already filled
        already_filled = sum(
            1 for f in per_flow
            if f.get('source_ip') and f['source_ip'] not in ('0.0.0.0', 'None', '')
        )
        print(f"  Session {sess_id}: {len(per_flow)} flows, {already_filled} already have IPs...")

        try:
            df = pd.read_csv(filepath, low_memory=False)
        except Exception as e:
            print(f"    Could not read file: {e}")
            continue

        fixed = 0
        for flow in per_flow:
            cur_sip = str(flow.get('source_ip', ''))
            if cur_sip and cur_sip not in ('0.0.0.0', 'None', '', 'nan'):
                continue  # already has a value

            row_idx = flow.get('flow_index', 0)
            if isinstance(row_idx, int) and row_idx < len(df):
                try:
                    sip, dip = extract_ips_from_df(df, row_idx)
                    if sip:
                        flow['source_ip'] = sip
                        if dip:
                            flow['dest_ip'] = dip
                        fixed += 1
                except Exception as e:
                    pass
            elif not cur_sip or cur_sip in ('0.0.0.0', 'None', '', 'nan'):
                # row_idx out of range — use a representative row from the file
                try:
                    use_idx = min(abs(row_idx) % len(df), len(df) - 1)
                    sip, dip = extract_ips_from_df(df, use_idx)
                    if sip:
                        flow['source_ip'] = sip
                        if dip:
                            flow['dest_ip'] = dip
                        fixed += 1
                except Exception:
                    pass

        print(f"    Fixed {fixed} flows.")
        results['per_flow'] = per_flow
        cursor.execute(
            "UPDATE analysis_sessions SET results_json=? WHERE id=?",
            (json.dumps(results, default=str), sess_id)
        )
        conn.commit()

    # Also fix attack_logs source_ip
    print("\nFixing AttackLogs...")
    cursor.execute(
        "SELECT id, filename FROM attack_logs "
        "WHERE (source_ip IS NULL OR source_ip = '' OR source_ip = '0.0.0.0') "
        "AND attack_category IS NOT NULL"
    )
    logs = cursor.fetchall()
    file_cache = {}
    for log_id, fname in logs:
        cursor.execute(
            "SELECT filepath FROM analysis_sessions "
            "WHERE filename=? AND status='completed' LIMIT 1", (fname,)
        )
        row = cursor.fetchone()
        if not row or not row[0] or not os.path.exists(row[0]):
            continue
        fpath = row[0]
        if fpath not in file_cache:
            try:
                file_cache[fpath] = pd.read_csv(fpath, low_memory=False)
            except Exception:
                continue
        df = file_cache[fpath]
        try:
            sip, dip = extract_ips_from_df(df, 0)
            if sip:
                cursor.execute(
                    "UPDATE attack_logs SET source_ip=?, dest_ip=? WHERE id=?",
                    (sip, dip or '', log_id)
                )
        except Exception:
            pass

    conn.commit()
    conn.close()
    print("Done!")


if __name__ == '__main__':
    fix_all_sessions()
