from src.database.db import get_connection

conn = get_connection()

print("Nombre de scans :",
      conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0])

print("Nombre de résultats d'analyse :",
      conn.execute("SELECT COUNT(*) FROM scan_analysis_results").fetchone()[0])

print("\nDerniers scans :")

rows = conn.execute(
    "SELECT scan_id, status FROM scans ORDER BY rowid DESC LIMIT 5"
).fetchall()

for row in rows:
    print(row)

conn.close()