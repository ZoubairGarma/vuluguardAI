
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


def save_scan_event(event: dict) -> bool:
    """
    Save a Kafka scan event and its dependencies in SQLite.

    Returns:
        True  -> new scan successfully inserted.
        False -> scan already exists (duplicate event).
    """

    # 1. Validate the event structure
    scan_id = event.get("scan_id")
    project_name = event.get("project_name")
    submitted_at = event.get("submitted_at")
    dependencies = event.get("dependencies")

    if not scan_id:
        raise ValueError("Missing scan_id.")

    if event.get("event_type") != "scan_request":
        raise ValueError("Invalid event type.")

    if not project_name or not project_name.strip():
        raise ValueError("Missing project name.")

    if not submitted_at:
        raise ValueError("Missing submission timestamp.")

    if not isinstance(dependencies, list) or not dependencies:
        raise ValueError("No dependencies provided.")

    # 2. Validate each dependency
    for dependency in dependencies:

        if not isinstance(dependency, dict):
            raise ValueError("Invalid dependency format.")

        for field in ("ecosystem", "name", "version"):
            value = dependency.get(field)

            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Missing or invalid dependency field: {field}"
                )

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

# --------------------------------------------------
# 6. MAIN
# --------------------------------------------------

if __name__ == "__main__":

    initialize_database()
