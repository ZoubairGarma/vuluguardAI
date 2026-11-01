
from src.database.db import (
    initialize_database,
    save_scan_event,
    update_scan_status,
    get_scan_status
)

from datetime import datetime, timezone

import uuid


def create_test_scan():

    initialize_database()

    scan_id = str(uuid.uuid4())

    event = {
        "scan_id": scan_id,
        "event_type": "scan_request",
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
