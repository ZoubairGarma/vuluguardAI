
from src.streaming.consumer import process_scan_event


def test_process_scan_event_displays_dependencies(
    sample_event,
    capsys
):

    process_scan_event(sample_event)

    captured = capsys.readouterr()

    assert "NEW VULNGUARD SCAN REQUEST" in captured.out

    assert sample_event["scan_id"] in captured.out

    assert "test-python-project" in captured.out

    assert "requests" in captured.out

    assert "flask" in captured.out


def test_process_scan_event_displays_project_name(
    sample_event,
    capsys
):

    process_scan_event(sample_event)

    captured = capsys.readouterr()

    assert "Project:" in captured.out
    assert "test-python-project" in captured.out
