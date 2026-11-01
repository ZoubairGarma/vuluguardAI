
from src.database.db import get_connection


def get_scan_summary():
    """
    Retrieve the actual number of scans for each status.
    """

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT status, COUNT(*) AS total
            FROM scans
            GROUP BY status
            """
        ).fetchall()

        summary = {
            "total": 0,
            "RECEIVED": 0,
            "WAITING_ANALYSIS": 0,
            "ANALYZED": 0,
            "WAITING_APPROVAL": 0,
            "APPROVED": 0,
            "REJECTED": 0,
            "TESTING": 0,
            "COMPLETED": 0,
            "FAILED": 0
        }

        for row in rows:
            summary[row["status"]] = row["total"]

        summary["total"] = sum(
            summary[status]
            for status in summary
            if status != "total"
        )

        return summary

    finally:
        connection.close()


def get_scan_history(
    status_filter=None,
    search_term=None,
    limit=200
):
    """
    Retrieve scans with their number of dependencies.

    Optional filters:
    - status_filter: scan status
    - search_term: project name or scan ID
    """

    connection = get_connection()

    try:

        query = """
            SELECT
                s.scan_id,
                s.project_name,
                s.submitted_at,
                s.received_at,
                s.status,
                s.updated_at,
                COUNT(d.dependency_id) AS dependency_count

            FROM scans s

            LEFT JOIN dependencies d
                ON s.scan_id = d.scan_id

            WHERE 1=1
        """

        parameters = []

        if status_filter:
            query += " AND s.status = ?"
            parameters.append(status_filter)

        if search_term:

            query += """
                AND (
                    s.project_name LIKE ?
                    OR s.scan_id LIKE ?
                )
            """

            search_pattern = f"%{search_term}%"

            parameters.extend([
                search_pattern,
                search_pattern
            ])

        query += """
            GROUP BY s.scan_id
            ORDER BY s.received_at DESC
            LIMIT ?
        """

        parameters.append(limit)

        rows = connection.execute(
            query,
            parameters
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()
