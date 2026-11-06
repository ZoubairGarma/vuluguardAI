
import pytest

from src.streaming.consumer import build_consumer_config, process_scan_event


def test_consumer_poll_interval_allows_slow_llm(monkeypatch):
    monkeypatch.setattr(
        "src.streaming.consumer.KAFKA_MAX_POLL_INTERVAL_MS",
        "900000",
    )

    assert build_consumer_config()["max.poll.interval.ms"] == 900000


def test_consumer_poll_interval_can_be_configured(monkeypatch):
    monkeypatch.setattr(
        "src.streaming.consumer.KAFKA_MAX_POLL_INTERVAL_MS",
        "1200000",
    )

    assert build_consumer_config()["max.poll.interval.ms"] == 1200000


def test_consumer_rejects_invalid_poll_interval(monkeypatch):
    monkeypatch.setattr(
        "src.streaming.consumer.KAFKA_MAX_POLL_INTERVAL_MS",
        "invalid",
    )

    with pytest.raises(ValueError, match="positive integer"):
        build_consumer_config()


def test_process_scan_event_displays_dependencies(
    sample_event,
    capsys
):

    process_scan_event(sample_event)

    captured = capsys.readouterr()

    assert "NEW SCAN EVENT" in captured.out

    assert sample_event["scan_id"] in captured.out

    assert "test-python-project" in captured.out
    assert "Dependencies: 2" in captured.out


def test_process_scan_event_displays_project_name(
    sample_event,
    capsys
):

    process_scan_event(sample_event)

    captured = capsys.readouterr()

    assert "Project:" in captured.out
    assert "test-python-project" in captured.out
