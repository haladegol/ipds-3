import sqlite3
import json

conn = sqlite3.connect('hades_secure.db')
cursor = conn.cursor()

# Get total
cursor.execute("SELECT COUNT(*) FROM signatures")
total = cursor.fetchone()[0]

# Get non-ET counts
cursor.execute("SELECT COUNT(*) FROM signatures WHERE description NOT LIKE '%ET Open%'")
non_et = cursor.fetchone()[0]

print(f"Total Signatures: {total}")
print(f"Non-ET Signatures: {non_et}")

# Let's inspect the Non-ET signatures
if non_et > 0:
    cursor.execute("SELECT name, description FROM signatures WHERE description NOT LIKE '%ET Open%' LIMIT 10")
    for row in cursor.fetchall():
        print(f"- {row[0]}: {row[1]}")
