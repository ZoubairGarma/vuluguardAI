from src.streaming.producer import build_scan_error_event


def test_build_scan_error_event_for_invalid_json():
    raw_payload = "{not valid json}"
    event = build_scan_error_event(
        source_topic="scan-requests",
        raw_payload=raw_payload,
        error_type="INVALID_JSON",
        details="Unable to decode Kafka message as JSON.",
    )

    assert event["event_type"] == "scan_error"
    assert event["source_topic"] == "scan-requests"
    assert event["error_type"] == "INVALID_JSON"
    assert event["raw_payload"] == raw_payload
    assert "received_at" in event
    assert event["details"] == "Unable to decode Kafka message as JSON."


def test_build_scan_error_event_for_invalid_scan_payload():
    payload = {
        "scan_id": "123",
        "event_type": "scan_request",
        "project_name": "demo",
        "dependencies": [],
    }

    event = build_scan_error_event(
        source_topic="scan-requests",
        raw_payload=payload,
        error_type="INVALID_SCAN_PAYLOAD",
        details="No dependencies were provided.",
    )

    assert event["event_type"] == "scan_error"
    assert event["source_topic"] == "scan-requests"
    assert event["error_type"] == "INVALID_SCAN_PAYLOAD"
    assert event["raw_payload"] == payload
    assert event["details"] == "No dependencies were provided."
