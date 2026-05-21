import sqlite3
c = sqlite3.connect('hades_secure.db')
tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print("Tables:", tables)
for t in tables:
    cols = [r[1] for r in c.execute(f"PRAGMA table_info({t})").fetchall()]
    if any('ips' in col.lower() for col in cols):
        print(f"\nTable {t} IPS cols:", [col for col in cols if 'ips' in col.lower()])
        row = c.execute(f"SELECT * FROM {t} LIMIT 1").fetchone()
        print("Row:", row)
