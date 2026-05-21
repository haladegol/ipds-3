import sqlite3
conn = sqlite3.connect('hades_secure.db')
c = conn.cursor()

# Check total_flows for latest sessions
c.execute("SELECT id, filename, total_flows, normal_count, anomaly_count FROM analysis_sessions WHERE status='completed' ORDER BY id DESC LIMIT 5")
print("Sessions:")
for row in c.fetchall():
    print(f"  id={row[0]} file={row[1][:40]} total_flows={row[2]} normal={row[3]} anomaly={row[4]}")

# Check IPS settings
c.execute("SELECT user_id, ips_mode_enabled, ips_bypass_mode FROM alert_config LIMIT 5")
print("\nIPS Config:")
for row in c.fetchall():
    print(f"  user_id={row[0]} ips_enabled={row[1]} bypass={row[2]}")

conn.close()
