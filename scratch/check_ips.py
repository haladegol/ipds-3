import sqlite3, json
conn = sqlite3.connect('hades_secure.db')
c = conn.cursor()
c.execute("SELECT id FROM analysis_sessions WHERE status='completed' ORDER BY id DESC LIMIT 5")
ids = [r[0] for r in c.fetchall()]
for sid in ids:
    c.execute("SELECT results_json FROM analysis_sessions WHERE id=?", (sid,))
    rj = c.fetchone()[0]
    pf = json.loads(rj).get('per_flow', [])
    filled = [f for f in pf if f.get('source_ip') and f['source_ip'] not in ('0.0.0.0','None','','nan')]
    sample = pf[0].get('source_ip') if pf else 'no data'
    print(f"Session {sid}: {len(filled)}/{len(pf)} have IPs. Sample: {sample}")
conn.close()
