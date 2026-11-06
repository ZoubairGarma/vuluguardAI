
import pytest
from src.database import db

from src.database.db import (
    initialize_database,
    save_scan_event,
    update_scan_status,
    get_scan_status,
    get_scan_history,
    mark_scan_failed,
)

from datetime import datetime, timezone

import uuid


@pytest.fixture
def isolated_status_database(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "status_test.db")
    initialize_database()


def create_test_scan():

    initialize_database()

    scan_id = str(uuid.uuid4())

    event = {
        "scan_id": scan_id,
        "event_type": "scan_request",
        "schema_version": "1.0",
        "project_name": "status-test-project",
        "submitted_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "dependencies": [
            {
                "ecosystem": "PyPI",
                "name": "requests",
                "version": "2.31.0"
            }
        ]
    }

    save_scan_event(event)

    return scan_id


def test_duplicate_scan_is_rejected(isolated_status_database):
    initialize_database()

    scan_id = str(uuid.uuid4())
    event = {
        "scan_id": scan_id,
        "event_type": "scan_request",
        "schema_version": "1.0",
        "project_name": "duplicate-check",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "dependencies": [
            {
                "ecosystem": "PyPI",
                "name": "requests",
                "version": "2.31.0",
            }
        ],
    }

    assert save_scan_event(event) is True
    assert save_scan_event(event) is False


def test_invalid_transition_raises_value_error(isolated_status_database):
    scan_id = create_test_scan()

    with pytest.raises(ValueError, match="Invalid transition"):
        update_scan_status(scan_id, "COMPLETED", "Invalid test transition.")


def test_failed_status_is_recorded_in_history(isolated_status_database):
    scan_id = create_test_scan()

    update_scan_status(scan_id, "WAITING_ANALYSIS", "Waiting for analysis.")
    mark_scan_failed(scan_id, "Analysis crashed after partial processing.")

    history = get_scan_history(scan_id)
    statuses = [entry["status"] for entry in history]

    assert statuses == ["RECEIVED", "WAITING_ANALYSIS", "FAILED"]
    assert get_scan_status(scan_id) == "FAILED"


if __name__ == "__main__":

    scan_id = create_test_scan()

    print("\nInitial:", get_scan_status(scan_id))

    # Valid transition
    update_scan_status(
        scan_id,
        "WAITING_ANALYSIS",
        "Analysis is pending."
    )

    print("After update:", get_scan_status(scan_id))

    # Invalid transition: analysis has not happened.
    try:

        update_scan_status(
            scan_id,
            "COMPLETED",
            "Invalid test transition."
        )

    except ValueError as error:

        print("\nExpected error:", error)

    print(
        "\nFinal status:",
        get_scan_status(scan_id)
    )
