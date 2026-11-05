from src.database.db import get_connection

conn = get_connection()

tables = conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
).fetchall()

print("Tables disponibles :")
for table in tables:
    print("-", table[0])

conn.close()