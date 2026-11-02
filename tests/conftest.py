
import pytest
import uuid

from datetime import datetime, timezone

from src.database import db


@pytest.fixture
def test_database(tmp_path, monkeypatch):
    """
    Create an isolated SQLite database for each test.
    The real VulnGuard database is never modified.
    """

    temporary_db = tmp_path / "vulnguard_test.db"

    # Redirect the database module to the temporary database.
    monkeypatch.setattr(db, "DB_PATH", temporary_db)

    db.initialize_database()

    return db


@pytest.fixture
def sample_event():
    """
    Return a synthetic Kafka scan request.
    """

    return {
        "scan_id": str(uuid.uuid4()),
        "event_type": "scan_request",
        "schema_version": "1.0",
        "project_name": "test-python-project",
        "submitted_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "dependencies": [
            {
                "ecosystem": "PyPI",
                "name": "requests",
                "version": "2.31.0"
            },
            {
                "ecosystem": "PyPI",
                "name": "flask",
                "version": "3.0.0"
            }
        ]
    }
