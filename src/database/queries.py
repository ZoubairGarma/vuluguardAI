
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

import json


def get_scan_details(scan_id: str):
    """
    Retrieve all information related to one scan.

    Returns:
        A dictionary containing:
        - scan information
        - dependencies
        - status history
        - original Kafka event

        Returns None if the scan does not exist.
    """

    connection = get_connection()

    try:

        # 1. Retrieve general scan information
        scan_row = connection.execute(
            """
            SELECT
                scan_id,
                project_name,
                submitted_at,
                received_at,
                status,
                updated_at,
                event_json
            FROM scans
            WHERE scan_id = ?
            """,
            (scan_id,)
        ).fetchone()

        if scan_row is None:
            return None

        scan = dict(scan_row)

        # 2. Retrieve all dependencies
        dependency_rows = connection.execute(
            """
            SELECT
                dependency_id,
                ecosystem,
                name,
                version
            FROM dependencies
            WHERE scan_id = ?
            ORDER BY name
            """,
            (scan_id,)
        ).fetchall()

        dependencies = [
            dict(row) for row in dependency_rows
        ]

        # 3. Retrieve status history
        history_rows = connection.execute(
            """
            SELECT
                history_id,
                status,
                changed_at,
                details
            FROM scan_status_history
            WHERE scan_id = ?
            ORDER BY history_id ASC
            """,
            (scan_id,)
        ).fetchall()

        status_history = [
            dict(row) for row in history_rows
        ]

        # 4. Decode original Kafka event
        try:
            event = json.loads(scan["event_json"])

        except (json.JSONDecodeError, TypeError):
            event = {
                "raw_event": scan["event_json"],
                "error": "Unable to decode the original event."
            }

        return {
            "scan": scan,
            "dependencies": dependencies,
            "status_history": status_history,
            "event": event
        }

    finally:
        connection.close()
