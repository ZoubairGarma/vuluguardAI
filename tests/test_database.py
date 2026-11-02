
import pytest


def test_save_scan_event(test_database, sample_event):
    """
    Verify that a scan and its dependencies are saved.
    """

    result = test_database.save_scan_event(sample_event)

    assert result is True

    connection = test_database.get_connection()

    try:

        scan = connection.execute(
            "SELECT * FROM scans WHERE scan_id = ?",
            (sample_event["scan_id"],)
        ).fetchone()

        dependencies = connection.execute(
            """
            SELECT * FROM dependencies
            WHERE scan_id = ?
            """,
            (sample_event["scan_id"],)
        ).fetchall()

        history = connection.execute(
            """
            SELECT * FROM scan_status_history
            WHERE scan_id = ?
            """,
            (sample_event["scan_id"],)
        ).fetchall()

        assert scan is not None
        assert scan["project_name"] == "test-python-project"
        assert scan["status"] == "RECEIVED"

        assert len(dependencies) == 2

        assert len(history) == 1
        assert history[0]["status"] == "RECEIVED"

    finally:
        connection.close()


def test_duplicate_scan_is_not_inserted(
    test_database,
    sample_event
):
    """
    Repeated delivery of the same scan must not
    create duplicate database records.
    """

    first_result = test_database.save_scan_event(
        sample_event
    )

    second_result = test_database.save_scan_event(
        sample_event
    )

    assert first_result is True
    assert second_result is False

    connection = test_database.get_connection()

    try:

        count = connection.execute(
            "SELECT COUNT(*) FROM scans"
        ).fetchone()[0]

        assert count == 1

    finally:
        connection.close()


def test_event_without_scan_id_is_rejected(
    test_database,
    sample_event
):

    invalid_event = sample_event.copy()
    invalid_event.pop("scan_id")

    with pytest.raises(ValueError):
        test_database.save_scan_event(invalid_event)


def test_valid_status_transition(
    test_database,
    sample_event
):

    test_database.save_scan_event(sample_event)

    result = test_database.update_scan_status(
        sample_event["scan_id"],
        "WAITING_ANALYSIS",
        "Waiting for vulnerability analysis."
    )

    assert result is True

    status = test_database.get_scan_status(
        sample_event["scan_id"]
    )

    assert status == "WAITING_ANALYSIS"


def test_invalid_status_transition(
    test_database,
    sample_event
):

    test_database.save_scan_event(sample_event)

    with pytest.raises(ValueError):
        test_database.update_scan_status(
            sample_event["scan_id"],
            "COMPLETED"
        )

    # The original status must remain unchanged.
    status = test_database.get_scan_status(
        sample_event["scan_id"]
    )

    assert status == "RECEIVED"


def test_nonexistent_scan_status_update(test_database):

    with pytest.raises(ValueError):
        test_database.update_scan_status(
            "nonexistent-scan",
            "WAITING_ANALYSIS"
        )
