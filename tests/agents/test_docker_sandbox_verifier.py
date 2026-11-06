import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from src.agents.docker_sandbox_verifier import DockerSandboxVerifier


def test_verifier_uses_limited_container_and_returns_metadata(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if "download" in command:
            wheel_dir = Path(command[command.index("--dest") + 1])
            (wheel_dir / "urllib3-2.2.1-py3-none-any.whl").touch()
            return CompletedProcess(command, 0, stdout="downloaded", stderr="")
        if command[1] == "run":
            return CompletedProcess(
                command,
                0,
                stdout=(
                    "pip output\n"
                    "{\"ok\": true, \"package_name\": \"urllib3\", "
                    "\"requested_version\": \"2.2.1\", "
                    "\"installed_version\": \"2.2.1\", "
                    "\"verification\": \"WHEEL_INSTALLED_METADATA_ONLY\", "
                    "\"container_network_access\": false}\n"
                ),
                stderr="",
            )
        return CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(
        "src.agents.docker_sandbox_verifier.subprocess.run",
        fake_run,
    )

    result = DockerSandboxVerifier().verify("urllib3", "2.2.1")

    docker_call = next(
        call for call in calls
        if call[0][0] == "docker" and len(call[0]) > 1 and call[0][1] == "run"
    )
    docker_command, docker_kwargs = docker_call
    assert result["installed_version"] == "2.2.1"
    assert result["version_source"] == "DOCKER_ISOLATED_WHEEL_INSTALL"
    assert result["project_code_executed"] is False
    assert result["container_network_access"] is False
    assert "--network=none" in docker_command
    assert f"--platform={DockerSandboxVerifier().docker_platform}" in docker_command
    assert "--network=bridge" not in docker_command
    assert any("target=/tmp/vulnguard-wheels,readonly" in arg for arg in docker_command)
    assert "--read-only" in docker_command
    assert "--cap-drop=ALL" in docker_command
    assert "--pids-limit=64" in docker_command
    assert docker_kwargs["shell"] is False
    download_command = next(
        command for command, _ in calls if "download" in command
    )
    assert "--only-binary=:all:" in download_command
    assert "--no-deps" in download_command
    assert "https://pypi.org/simple" in download_command
    assert download_command[
        download_command.index("--python-version") + 1
    ] == "3.12"
    assert download_command[
        download_command.index("--implementation") + 1
    ] == "cp"
    assert "--abi" in download_command
    assert "cp312" in download_command


def test_verifier_rejects_url_like_package_input():
    with pytest.raises(ValueError, match="unsupported characters"):
        DockerSandboxVerifier._validate_requirement(
            "sample-package; touch /tmp/pwned",
            "1.0.0",
        )


def test_verifier_rejects_url_and_marker_requirements():
    with pytest.raises(ValueError, match="unsupported characters"):
        DockerSandboxVerifier._validate_requirement(
            "sample-package",
            "1.0.0; python_version > '3.10'",
        )


def test_verifier_reports_docker_failure(monkeypatch):
    def fake_run(command, **kwargs):
        if "download" in command:
            wheel_dir = Path(command[command.index("--dest") + 1])
            (wheel_dir / "urllib3-2.2.1-py3-none-any.whl").touch()
            return CompletedProcess(command, 0, stdout="downloaded", stderr="")
        if command[1] == "run":
            return CompletedProcess(command, 125, stdout="", stderr="daemon unavailable")
        return CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(
        "src.agents.docker_sandbox_verifier.subprocess.run",
        fake_run,
    )

    with pytest.raises(RuntimeError, match="daemon unavailable"):
        DockerSandboxVerifier().verify("urllib3", "2.2.1")


def test_extract_result_ignores_non_json_lines():
    result = DockerSandboxVerifier._extract_result(
        "pip output\n" + json.dumps({"ok": True, "installed_version": "1.0"})
    )
    assert result["installed_version"] == "1.0"
