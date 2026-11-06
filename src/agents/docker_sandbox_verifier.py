"""Inspect one pinned PyPI wheel in an offline, constrained Docker container.

The host downloads only the binary wheel. The container installs that local
wheel without dependencies and reads distribution metadata. Neither package
nor project code is imported or run.
"""

from __future__ import annotations

import json
import os
import platform as host_platform
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version


_RESULT_PREFIX = "VULNGUARD_SANDBOX_RESULT="
_CONTAINER_CHECK_SCRIPT = r'''
import json
import re
import subprocess
import sys
from importlib.metadata import distributions

package_name, requested_version = sys.argv[1], sys.argv[2]
target = "/tmp/vulnguard-site"
requirement = f"{package_name}=={requested_version}"
command = [
    sys.executable,
    "-m",
    "pip",
    "--disable-pip-version-check",
    "--no-input",
    "--no-cache-dir",
    "install",
    "--no-index",
    "--find-links=/tmp/vulnguard-wheels",
    "--no-deps",
    "--only-binary=:all:",
    "--target",
    target,
    requirement,
]
install = subprocess.run(command, capture_output=True, text=True, timeout=180)
if install.returncode:
    print(json.dumps({
        "ok": False,
        "error": (install.stderr or install.stdout)[-2000:],
    }))
    raise SystemExit(2)

wanted = re.sub(r"[-_.]+", "-", package_name).lower()
matching = [
    dist for dist in distributions(path=[target])
    if re.sub(r"[-_.]+", "-", dist.metadata.get("Name", "")).lower() == wanted
]
if len(matching) != 1:
    print(json.dumps({
        "ok": False,
        "error": "Could not identify exactly one installed distribution.",
    }))
    raise SystemExit(3)

print(json.dumps({
    "ok": True,
    "package_name": package_name,
    "requested_version": requested_version,
    "installed_version": matching[0].version,
    "verification": "WHEEL_INSTALLED_METADATA_ONLY",
    "container_network_access": False,
}))
'''


class DockerSandboxError(RuntimeError):
    """Raised when Docker cannot complete the constrained package check."""


class DockerSandboxVerifier:
    """Verify one exact PyPI dependency in a limited, ephemeral container."""

    DEFAULT_IMAGE = "python:3.12-slim-bookworm"
    CONTAINER_PYTHON_VERSION = "3.12"
    PYTHON_TARGETS = (
        {"version": "3.12", "abi": "cp312", "image": "python:3.12-slim-bookworm"},
        {"version": "3.11", "abi": "cp311", "image": "python:3.11-slim-bookworm"},
    )
    MAX_OUTPUT_CHARS = 2000
    WHEEL_PLATFORMS = {
        "amd64": (
            "manylinux_2_36_x86_64",
            "manylinux_2_35_x86_64",
            "manylinux_2_34_x86_64",
            "manylinux_2_31_x86_64",
            "manylinux_2_28_x86_64",
            "manylinux_2_27_x86_64",
            "manylinux_2_26_x86_64",
            "manylinux_2_24_x86_64",
            "manylinux_2_23_x86_64",
            "manylinux_2_22_x86_64",
            "manylinux_2_17_x86_64",
            "manylinux2014_x86_64",
            "manylinux_2_12_x86_64",
            "manylinux_2_5_x86_64",
            "linux_x86_64",
        ),
        "arm64": (
            "manylinux_2_36_aarch64",
            "manylinux_2_35_aarch64",
            "manylinux_2_34_aarch64",
            "manylinux_2_31_aarch64",
            "manylinux_2_28_aarch64",
            "manylinux_2_27_aarch64",
            "manylinux_2_26_aarch64",
            "manylinux_2_24_aarch64",
            "manylinux_2_23_aarch64",
            "manylinux_2_22_aarch64",
            "manylinux_2_17_aarch64",
            "manylinux2014_aarch64",
            "linux_aarch64",
        ),
    }

    def __init__(
        self,
        image: str = DEFAULT_IMAGE,
        timeout_seconds: int = 240,
        docker_command: str = "docker",
    ) -> None:
        if not isinstance(image, str) or not re.fullmatch(
            r"[A-Za-z0-9._/:@-]+", image
        ):
            raise ValueError("A valid fixed Docker image reference is required.")
        if timeout_seconds < 30 or timeout_seconds > 600:
            raise ValueError("timeout_seconds must be between 30 and 600.")
        self.image = image
        self.timeout_seconds = timeout_seconds
        self.docker_command = docker_command
        machine = host_platform.machine().lower()
        if machine in {"amd64", "x86_64"}:
            self.docker_platform = "linux/amd64"
            self.wheel_platforms = self.WHEEL_PLATFORMS["amd64"]
        elif machine in {"arm64", "aarch64"}:
            self.docker_platform = "linux/arm64"
            self.wheel_platforms = self.WHEEL_PLATFORMS["arm64"]
        else:
            raise ValueError(
                f"Unsupported host architecture for Docker verification: {machine}."
            )

    def verify(self, package_name: str, version: str) -> dict[str, Any]:
        """Fetch a wheel, then install and inspect it offline in Docker."""
        self._validate_requirement(package_name, version)
        container_name = f"vulnguard-check-{uuid.uuid4().hex[:16]}"

        with tempfile.TemporaryDirectory(prefix="vulnguard-wheel-") as wheel_dir:
            wheel_path, selected_image = self._download_wheel(package_name, version, wheel_dir)
            self._validate_wheel(wheel_path, package_name, version)
            command = [
                self.docker_command,
                "run",
                "--rm",
                "--pull=missing",
                f"--platform={self.docker_platform}",
                "--name",
                container_name,
                "--network=none",
                "--memory=512m",
                "--cpus=1",
                "--pids-limit=64",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777",
                "--mount",
                f"type=bind,source={Path(wheel_dir).resolve()},target=/tmp/vulnguard-wheels,readonly",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--user=65532:65532",
                "--env",
                "HOME=/tmp",
                "--env",
                "PIP_NO_CACHE_DIR=1",
                "--env",
                "PIP_DISABLE_PIP_VERSION_CHECK=1",
                selected_image,
                "python",
                "-I",
                "-c",
                _CONTAINER_CHECK_SCRIPT,
                package_name,
                version,
            ]

            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    shell=False,
                )
            except FileNotFoundError as exc:
                raise DockerSandboxError(
                    "Docker CLI was not found. Install/start Docker Desktop and retry."
                ) from exc
            except subprocess.TimeoutExpired as exc:
                self._remove_container(container_name)
                raise DockerSandboxError(
                    f"Isolated package check timed out after {self.timeout_seconds} seconds."
                ) from exc
            except OSError as exc:
                raise DockerSandboxError(f"Could not start Docker: {exc}") from exc
            finally:
                self._remove_container(container_name)

        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "No Docker output.")[-self.MAX_OUTPUT_CHARS:]
            raise DockerSandboxError(
                "The offline wheel installation/metadata check failed: "
                f"{detail.strip()}"
            )

        payload = self._extract_result(completed.stdout)
        if not payload.get("ok"):
            raise DockerSandboxError(
                str(payload.get("error", "The isolated check returned an invalid result."))
            )
        if payload.get("container_network_access") is not False:
            raise DockerSandboxError(
                "The isolated check did not confirm its network-disabled configuration."
            )

        return {
            "installed_version": payload["installed_version"],
            "requested_version": payload["requested_version"],
            "version_source": "DOCKER_ISOLATED_WHEEL_INSTALL",
            "verification": payload["verification"],
            "docker_image": selected_image,
            "container_network_access": False,
            "project_code_executed": False,
            "package_code_executed": False,
        }

    def _download_wheel(
        self,
        package_name: str,
        version: str,
        wheel_dir: str,
    ) -> tuple[Path, str]:
        """Fetch exactly one PyPI binary wheel without running package code."""
        targets = (
            self.PYTHON_TARGETS
            if self.image == self.DEFAULT_IMAGE
            else (
                {
                    "version": self.CONTAINER_PYTHON_VERSION,
                    "abi": "cp312",
                    "image": self.image,
                },
            )
        )
        last_error = "No pip output."
        for target in targets:
            for old_file in Path(wheel_dir).glob("*"):
                try:
                    old_file.unlink()
                except OSError:
                    pass

            command = [
                sys.executable,
                "-m",
                "pip",
                "--isolated",
                "--disable-pip-version-check",
                "--no-input",
                "--no-cache-dir",
                "download",
                "--only-binary=:all:",
                "--no-deps",
                "--index-url",
                "https://pypi.org/simple",
                "--dest",
                wheel_dir,
            ]
            for wheel_platform in self.wheel_platforms:
                command.extend(["--platform", wheel_platform])
            command.extend([
                "--python-version",
                target["version"],
                "--implementation",
                "cp",
                "--abi",
                target["abi"],
                "--abi",
                "abi3",
                "--abi",
                "none",
                f"{package_name}=={version}",
            ])
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=min(self.timeout_seconds, 180),
                    check=False,
                    shell=False,
                )
            except (FileNotFoundError, OSError) as exc:
                raise DockerSandboxError(f"Could not download the pinned PyPI wheel: {exc}") from exc
            except subprocess.TimeoutExpired as exc:
                raise DockerSandboxError("Pinned PyPI wheel download timed out.") from exc

            if completed.returncode == 0:
                wheels = list(Path(wheel_dir).glob("*.whl"))
                if len(wheels) == 1:
                    try:
                        os.chmod(wheel_dir, 0o755)
                        os.chmod(wheels[0], 0o644)
                    except OSError:
                        pass
                    return wheels[0], target["image"]
            else:
                last_error = (completed.stderr or completed.stdout or "No pip output.")[-self.MAX_OUTPUT_CHARS:]

        raise DockerSandboxError(
            "Could not download a binary wheel for the exact PyPI pin: "
            f"{last_error.strip()}"
        )

    @staticmethod
    def _validate_wheel(wheel_path: Path, package_name: str, version: str) -> None:
        try:
            wheel_name, wheel_version, _, _ = parse_wheel_filename(wheel_path.name)
            requested_version = Version(version)
        except (InvalidVersion, ValueError) as exc:
            raise DockerSandboxError("Downloaded wheel filename is invalid.") from exc

        if canonicalize_name(str(wheel_name)) != canonicalize_name(package_name):
            raise DockerSandboxError("Downloaded wheel package name does not match the requested package.")
        if wheel_version != requested_version:
            raise DockerSandboxError("Downloaded wheel version does not match the exact pin.")

    @staticmethod
    def _validate_requirement(package_name: str, version: str) -> None:
        if not isinstance(package_name, str) or not isinstance(version, str):
            raise ValueError("Package name and pinned version must be strings.")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", package_name):
            raise ValueError("Package name contains unsupported characters.")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+!_-]{0,99}", version):
            raise ValueError("Version contains unsupported characters.")
        try:
            requirement = Requirement(f"{package_name}=={version}")
        except InvalidRequirement as exc:
            raise ValueError("The pinned package requirement is invalid.") from exc
        if requirement.url or requirement.marker:
            raise ValueError("URLs and environment markers are not allowed.")

    @staticmethod
    def _extract_result(stdout: str) -> dict[str, Any]:
        for line in reversed(stdout.splitlines()):
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(result, dict) and "ok" in result:
                return result
        raise DockerSandboxError("Docker returned no structured verification result.")

    def _remove_container(self, container_name: str) -> None:
        try:
            subprocess.run(
                [self.docker_command, "rm", "--force", container_name],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                shell=False,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            pass
