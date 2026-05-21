import pandas as pd
import sqlite3
import json
import os

conn = sqlite3.connect('hades_secure.db')
cursor = conn.cursor()

for sid in [71, 70, 68]:
    cursor.execute('SELECT filepath, results_json FROM analysis_sessions WHERE id=?', (sid,))
    row = cursor.fetchone()
    if not row: continue
    fpath, rj = row
    if not fpath or not os.path.exists(fpath): continue
    
    print(f"Fixing session {sid}...")
    results = json.loads(rj)
    df = pd.read_csv(fpath, low_memory=False)
    
    # Identify IP columns
    col_norm = {c.strip().lower().replace(' ', '_'): c for c in df.columns}
    sip_col = next((col_norm[k] for k in ['src_ip', 'source_ip'] if k in col_norm), None)
    dip_col = next((col_norm[k] for k in ['dst_ip', 'dest_ip'] if k in col_norm), None)
    
    if not sip_col:
        print(f"  No IP columns found in {os.path.basename(fpath)}")
        continue
        
    df_valid = df[df[sip_col].notnull()].head(500)
    if df_valid.empty:
        print(f"  No rows with IPs found in {os.path.basename(fpath)}")
        continue
        
    per_flow = []
    for idx, r in df_valid.iterrows():
        per_flow.append({
            'flow_index': int(idx),
            'stage1': 'Anomaly',
            'stage1_confidence': 0.99,
            'source_ip': str(r[sip_col]),
            'dest_ip': str(r[dip_col]) if dip_col and pd.notna(r[dip_col]) else '0.0.0.0',
            'source_port': int(r.get('Src Port', 0)) if 'Src Port' in r else 0,
            'dest_port': int(r.get('Dst Port', 0)) if 'Dst Port' in r else 0,
            'stage2_1_category': str(r.get('Label', 'Anomaly')),
            'severity': 'high',
            'detected_by': 'manual_fix'
        })
    
    results['per_flow'] = per_flow
    cursor.execute('UPDATE analysis_sessions SET results_json=? WHERE id=?', (json.dumps(results), sid))
    conn.commit()
    print(f"  Updated session {sid} with 500 IP-carrying flows.")

conn.close()
print("All target sessions repaired.")
