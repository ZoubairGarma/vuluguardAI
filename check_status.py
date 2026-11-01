
from src.database.db import get_connection


connection = get_connection()

try:

    scans = connection.execute(
        """
        SELECT scan_id, project_name, status, updated_at
        FROM scans
        ORDER BY received_at DESC
        """
    ).fetchall()

    for scan in scans:

        print("\n" + "=" * 55)

        print(f"Project: {scan['project_name']}")
        print(f"Scan ID: {scan['scan_id']}")
        print(f"Current status: {scan['status']}")
        print(f"Last update: {scan['updated_at']}")

        print("\nStatus history:")

        history = connection.execute(
            """
            SELECT status, changed_at, details
            FROM scan_status_history
            WHERE scan_id = ?
            ORDER BY history_id
            """,
            (scan["scan_id"],)
        ).fetchall()

        for record in history:

            print(
                f"{record['changed_at']} | "
                f"{record['status']} | "
                f"{record['details']}"
            )

    print("\n" + "=" * 55)

finally:

    connection.close()
