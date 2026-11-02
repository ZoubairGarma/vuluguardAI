
from src.database.queries import (
    get_scan_summary,
    get_scan_history,
    get_scan_details
)


def test_scan_summary(test_database, sample_event):

    test_database.save_scan_event(sample_event)

    summary = get_scan_summary()

    assert summary["total"] == 1
    assert summary["RECEIVED"] == 1
    assert summary["COMPLETED"] == 0


def test_scan_history(test_database, sample_event):

    test_database.save_scan_event(sample_event)

    scans = get_scan_history()

    assert len(scans) == 1

    assert (
        scans[0]["project_name"]
        == sample_event["project_name"]
    )

    assert scans[0]["dependency_count"] == 2


def test_scan_history_status_filter(
    test_database,
    sample_event
):

    test_database.save_scan_event(sample_event)

    test_database.update_scan_status(
        sample_event["scan_id"],
        "WAITING_ANALYSIS"
    )

    received_scans = get_scan_history(
        status_filter="RECEIVED"
    )

    waiting_scans = get_scan_history(
        status_filter="WAITING_ANALYSIS"
    )

    assert len(received_scans) == 0
    assert len(waiting_scans) == 1


def test_scan_details(test_database, sample_event):

    test_database.save_scan_event(sample_event)

    details = get_scan_details(
        sample_event["scan_id"]
    )

    assert details is not None

    assert details["scan"]["project_name"] == (
        sample_event["project_name"]
    )

    assert len(details["dependencies"]) == 2

    assert len(details["status_history"]) == 1

    assert details["event"]["scan_id"] == (
        sample_event["scan_id"]
    )


def test_nonexistent_scan_details(test_database):

    details = get_scan_details("unknown-scan")

    assert details is None
