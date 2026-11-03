import pytest
import json


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


def test_save_scan_result(test_database, sample_event):
    """
    Verify that vulnerability results are saved correctly.
    """

    test_database.save_scan_event(sample_event)

    verified_facts = {
        "description": "A test vulnerability.",
        "risk": {
            "score": 85,
            "level": "CRITICAL",
            "is_kev": True
        }
    }

    explanation = "This vulnerability requires immediate attention."

    result = test_database.save_scan_result(
        scan_id=sample_event["scan_id"],
        cve_id="CVE-2026-12345",
        verified_facts=verified_facts,
        llm_explanation=explanation
    )

    assert result is True

    connection = test_database.get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM scan_results
            WHERE scan_id = ?
            AND cve_id = ?
            """,
            (sample_event["scan_id"], "CVE-2026-12345")
        ).fetchone()

        assert row is not None
        assert row["llm_explanation"] == explanation
        assert json.loads(row["verified_facts_json"]) == verified_facts
        assert row["created_at"] is not None

    finally:
        connection.close()


def test_save_scan_result_updates_existing_cve(
    test_database,
    sample_event
):
    """
    Saving the same CVE twice must update the existing result.
    """

    test_database.save_scan_event(sample_event)

    test_database.save_scan_result(
        scan_id=sample_event["scan_id"],
        cve_id="CVE-2026-12345",
        verified_facts={"risk_score": 50},
        llm_explanation="First explanation."
    )

    test_database.save_scan_result(
        scan_id=sample_event["scan_id"],
        cve_id="CVE-2026-12345",
        verified_facts={"risk_score": 90},
        llm_explanation="Updated explanation."
    )

    connection = test_database.get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM scan_results
            WHERE scan_id = ?
            AND cve_id = ?
            """,
            (sample_event["scan_id"], "CVE-2026-12345")
        ).fetchall()

        assert len(rows) == 1
        assert json.loads(rows[0]["verified_facts_json"]) == {
            "risk_score": 90
        }
        assert rows[0]["llm_explanation"] == "Updated explanation."

    finally:
        connection.close()


def test_save_scan_result_rejects_nonexistent_scan(test_database):
    """
    Results cannot be saved for a scan that does not exist.
    """

    with pytest.raises(ValueError, match="Scan not found"):
        test_database.save_scan_result(
            scan_id="nonexistent-scan",
            cve_id="CVE-2026-12345",
            verified_facts={"risk_score": 80},
            llm_explanation="Test explanation."
        )