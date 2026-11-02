
import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone


# --------------------------------------------------
# 1. DATABASE LOCATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DB_PATH = PROJECT_ROOT / "data" / "vulnguard.db"


# --------------------------------------------------
# 2. DATABASE SCHEMA
# --------------------------------------------------

SCHEMA = """

CREATE TABLE IF NOT EXISTS scans (

    scan_id TEXT PRIMARY KEY,

    project_name TEXT NOT NULL,

    submitted_at TEXT NOT NULL,

    received_at TEXT NOT NULL,

    status TEXT NOT NULL CHECK (
        status IN (
            'RECEIVED',
            'WAITING_ANALYSIS',
            'ANALYZED',
            'WAITING_APPROVAL',
            'APPROVED',
            'REJECTED',
            'TESTING',
            'COMPLETED',
            'FAILED'
        )
    ),

    event_json TEXT NOT NULL,

    updated_at TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS dependencies (

    dependency_id INTEGER PRIMARY KEY AUTOINCREMENT,

    scan_id TEXT NOT NULL,

    ecosystem TEXT NOT NULL,

    name TEXT NOT NULL,

    version TEXT NOT NULL,

    FOREIGN KEY (scan_id)
        REFERENCES scans(scan_id)
        ON DELETE CASCADE,

    UNIQUE(scan_id, ecosystem, name, version)
);


CREATE TABLE IF NOT EXISTS scan_status_history (

    history_id INTEGER PRIMARY KEY AUTOINCREMENT,

    scan_id TEXT NOT NULL,

    status TEXT NOT NULL,

    changed_at TEXT NOT NULL,

    details TEXT,

    FOREIGN KEY (scan_id)
        REFERENCES scans(scan_id)
        ON DELETE CASCADE
);


CREATE INDEX IF NOT EXISTS idx_scans_status
ON scans(status);


CREATE INDEX IF NOT EXISTS idx_dependencies_scan_id
ON dependencies(scan_id);


CREATE INDEX IF NOT EXISTS idx_history_scan_id
ON scan_status_history(scan_id);

"""


# --------------------------------------------------
# 3. GET DATABASE CONNECTION
# --------------------------------------------------

def get_connection():

    """
    Create and return a SQLite connection.
    """

    DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DB_PATH,
        timeout=10
    )

    connection.row_factory = sqlite3.Row

    # Enable foreign key constraints
    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    # Improve concurrent read/write behavior
    connection.execute(
        "PRAGMA journal_mode = WAL"
    )

    return connection


# --------------------------------------------------
# 4. INITIALIZE DATABASE
# --------------------------------------------------

def initialize_database():

    """
    Create all database tables if they do not exist.
    """

    connection = get_connection()

    try:

        connection.executescript(SCHEMA)

        connection.commit()

        print("Database initialized successfully.")
        print(f"Database location: {DB_PATH}")

    except sqlite3.Error:

        connection.rollback()
        raise

    finally:

        connection.close()


# --------------------------------------------------
# 5. GET CURRENT UTC TIME
# --------------------------------------------------

def get_current_timestamp():

    return datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds").replace("+00:00", "Z")


def validate_scan_event(event: dict):
    """
    Validate the structure of a scan event before inserting it.
    """

    if not isinstance(event, dict):
        raise ValueError("Scan event must be a dictionary.")

    scan_id = event.get("scan_id")
    project_name = event.get("project_name")
    submitted_at = event.get("submitted_at")
    dependencies = event.get("dependencies")

    if not scan_id or not str(scan_id).strip():
        raise ValueError("Missing scan_id.")

    if event.get("event_type") != "scan_request":
        raise ValueError("Invalid event type.")

    if not project_name or not str(project_name).strip():
        raise ValueError("Missing project name.")

    if not submitted_at:
        raise ValueError("Missing submission timestamp.")

    if not isinstance(dependencies, list) or not dependencies:
        raise ValueError("No dependencies provided.")

    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ValueError("Invalid dependency format.")

        for field in ("ecosystem", "name", "version"):
            value = dependency.get(field)

            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Missing or invalid dependency field: {field}"
                )

    return {
        "scan_id": str(scan_id).strip(),
        "project_name": str(project_name).strip(),
        "submitted_at": submitted_at,
        "dependencies": dependencies,
    }


def save_scan_event(event: dict) -> bool:
    """
    Save a Kafka scan event and its dependencies in SQLite.

    Returns:
        True  -> new scan successfully inserted.
        False -> scan already exists (duplicate event).
    """

    normalized_event = validate_scan_event(event)

    scan_id = normalized_event["scan_id"]
    project_name = normalized_event["project_name"]
    submitted_at = normalized_event["submitted_at"]
    dependencies = normalized_event["dependencies"]

    # 3. Prepare database values
    received_at = get_current_timestamp()

    serialized_event = json.dumps(
        event,
        ensure_ascii=False
    )

    connection = get_connection()

    try:

        # 4. Insert the scan
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO scans (
                scan_id,
                project_name,
                submitted_at,
                received_at,
                status,
                event_json,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                project_name.strip(),
                submitted_at,
                received_at,
                "RECEIVED",
                serialized_event,
                received_at
            )
        )

        # 5. Avoid inserting an existing scan twice
        if cursor.rowcount == 0:
            connection.rollback()
            return False

        # 6. Insert all dependencies
        dependency_rows = [
            (
                scan_id,
                dependency["ecosystem"],
                dependency["name"],
                dependency["version"]
            )
            for dependency in dependencies
        ]

        connection.executemany(
            """
            INSERT INTO dependencies (
                scan_id,
                ecosystem,
                name,
                version
            )
            VALUES (?, ?, ?, ?)
            """,
            dependency_rows
        )

        # 7. Record the initial status
        connection.execute(
            """
            INSERT INTO scan_status_history (
                scan_id,
                status,
                changed_at,
                details
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                scan_id,
                "RECEIVED",
                received_at,
                "Scan request received and stored from Kafka."
            )
        )

        # 8. Commit all changes together
        connection.commit()

        return True

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

ALLOWED_TRANSITIONS = {
    "RECEIVED": {"WAITING_ANALYSIS", "FAILED"},

    "WAITING_ANALYSIS": {"ANALYZED", "FAILED"},

    "ANALYZED": {"WAITING_APPROVAL", "FAILED"},

    "WAITING_APPROVAL": {
        "APPROVED",
        "REJECTED",
        "FAILED"
    },

    "APPROVED": {"TESTING", "FAILED"},

    "TESTING": {"COMPLETED", "FAILED"},

    "REJECTED": set(),
    "COMPLETED": set(),
    "FAILED": set()
}


# --------------------------------------------------
# 6. MAIN
# --------------------------------------------------

def update_scan_status(
    scan_id: str,
    new_status: str,
    details: str = None
) -> bool:

    """
    Update a scan status and record its history.

    Returns:
        True  -> status successfully updated.
        False -> status was already the requested status.

    Raises:
        ValueError -> scan does not exist or transition is invalid.
    """

    new_status = new_status.strip().upper()

    if new_status not in ALLOWED_TRANSITIONS:
        raise ValueError(
            f"Unknown status: {new_status}"
        )

    connection = get_connection()

    try:

        # Start an explicit transaction.
        connection.execute("BEGIN IMMEDIATE")

        # Retrieve the current status.
        scan = connection.execute(
            """
            SELECT status
            FROM scans
            WHERE scan_id = ?
            """,
            (scan_id,)
        ).fetchone()

        if scan is None:
            raise ValueError(
                f"Scan not found: {scan_id}"
            )

        current_status = scan["status"]

        # Avoid duplicate history entries.
        if current_status == new_status:
            connection.rollback()
            return False

        # Check whether the transition is allowed.
        allowed = ALLOWED_TRANSITIONS[current_status]

        if new_status not in allowed:

            raise ValueError(
                f"Invalid transition: "
                f"{current_status} -> {new_status}"
            )

        now = get_current_timestamp()

        # Update the current status.
        connection.execute(
            """
            UPDATE scans
            SET status = ?,
                updated_at = ?
            WHERE scan_id = ?
            """,
            (new_status, now, scan_id)
        )

        # Add an entry to the status history.
        connection.execute(
            """
            INSERT INTO scan_status_history (
                scan_id,
                status,
                changed_at,
                details
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                scan_id,
                new_status,
                now,
                details
            )
        )

        connection.commit()

        print(
            f"Status updated: "
            f"{current_status} -> {new_status}"
        )

        return True

    except Exception:

        connection.rollback()
        raise

    finally:

        connection.close()



def get_scan_status(scan_id: str):

    """
    Retrieve the current status of a scan.
    """

    connection = get_connection()

    try:

        result = connection.execute(
            """
            SELECT status
            FROM scans
            WHERE scan_id = ?
            """,
            (scan_id,)
        ).fetchone()

        return result["status"] if result else None

    finally:

        connection.close()


def get_scan_history(scan_id: str) -> list[dict]:
    """
    Return the ordered lifecycle history for a scan.
    """

    if not scan_id or not str(scan_id).strip():
        raise ValueError("Missing scan_id.")

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT history_id, scan_id, status, changed_at, details
            FROM scan_status_history
            WHERE scan_id = ?
            ORDER BY history_id ASC
            """,
            (str(scan_id).strip(),)
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_scan_status_history(scan_id: str) -> list[dict]:
    """
    Backwards-compatible alias for status lifecycle history.
    """

    return get_scan_history(scan_id)


def mark_scan_failed(scan_id: str, details: str = None) -> bool:
    """
    Mark a scan as failed after an internal processing error or partial retry.
    """

    if not scan_id or not str(scan_id).strip():
        raise ValueError("Missing scan_id.")

    current_status = get_scan_status(scan_id)

    if current_status is None:
        raise ValueError(f"Scan not found: {scan_id}")

    if current_status in {"REJECTED", "COMPLETED", "FAILED"}:
        raise ValueError(
            f"Cannot fail a scan already in terminal state: {current_status}"
        )

    if "FAILED" not in ALLOWED_TRANSITIONS.get(current_status, set()):
        raise ValueError(
            f"Invalid transition: {current_status} -> FAILED"
        )

    return update_scan_status(
        scan_id=scan_id,
        new_status="FAILED",
        details=details or "Scan marked failed after processing error or retry failure."
    )

if __name__ == "__main__":

    initialize_database()
