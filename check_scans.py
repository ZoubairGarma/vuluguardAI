
from src.database.db import get_connection


connection = get_connection()

try:

    print("\n========== SCAN HISTORY ==========\n")

    scans = connection.execute(
        """
        SELECT scan_id, project_name, status, received_at
        FROM scans
        ORDER BY received_at DESC
        """
    ).fetchall()

    for scan in scans:

        print(f"Scan ID: {scan['scan_id']}")
        print(f"Project: {scan['project_name']}")
        print(f"Status: {scan['status']}")
        print(f"Received at: {scan['received_at']}")

        print("\nDependencies:")

        dependencies = connection.execute(
            """
            SELECT ecosystem, name, version
            FROM dependencies
            WHERE scan_id = ?
            """,
            (scan["scan_id"],)
        ).fetchall()

        for dependency in dependencies:

            print(
                f"- {dependency['name']} "
                f"== {dependency['version']} "
                f"({dependency['ecosystem']})"
            )

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
                f"- {record['status']} "
                f"at {record['changed_at']}"
            )

        print("\n" + "-" * 50)

finally:

    connection.close()
