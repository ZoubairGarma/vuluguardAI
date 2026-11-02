
from src.database.db import get_connection

connection = get_connection()

# Retrieve all tables from the SQLite database
tables = connection.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
).fetchall()

print("Tables found in the database:")

for table in tables:
    print("-", table["name"])

# Check the columns of the scans table
print("\nColumns in the scans table:")

columns = connection.execute(
    "PRAGMA table_info(scans)"
).fetchall()

for column in columns:
    print("-", column["name"])

connection.close()
