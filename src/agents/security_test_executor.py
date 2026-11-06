
"""
Controlled execution of approved, non-destructive dependency checks.

The supported check compares the exact dependency version declared in the
submitted scan with the supplied OSV affected ranges. It does not install or
execute project packages.
"""

from copy import deepcopy
from datetime import datetime, timezone
from collections.abc import Callable
from typing import Any

from packaging.version import InvalidVersion, Version

from src.agents.vulnerability_analyzer import version_in_affected_range


class SecurityTestExecutor:
    """Execute only explicitly approved and allowlisted security checks."""

    ALLOWED_TEST_TYPES = {"PACKAGE_VERSION_CHECK"}
    ALLOWED_CHECKS = {
        "WHEEL_INSTALLABLE",
        "METADATA_MATCHES_PIN",
        "OSV_RANGE_CLASSIFICATION",
    }

    def __init__(self, isolated_verifier: Any | None = None) -> None:
        self._isolated_verifier = isolated_verifier

    def execute(
        self,
        test_plan: dict,
        on_status_change: Callable[[dict], None] | None = None,
    ) -> dict:
        """Validate approval, execute safe checks, and return a result copy."""

        if not isinstance(test_plan, dict):
            raise ValueError("test_plan must be a dictionary.")

        if test_plan.get("approval_status") != "APPROVED":
            raise PermissionError(
                "Execution refused: the test plan is not APPROVED."
            )

        safety = test_plan.get("safety") or {}

        if (
            safety.get("automatic_execution") is not False
            or safety.get("requires_human_approval") is not True
            or safety.get("non_destructive") is not True
        ):
            raise PermissionError(
                "Execution refused: required safety settings are missing."
            )

        if test_plan.get("execution_status") != "NOT_STARTED":
            raise PermissionError(
                "Execution refused: this plan has already been processed."
            )

        tests = test_plan.get("tests")

        if not isinstance(tests, list) or not tests:
            raise ValueError("The test plan must contain at least one test.")

        for test in tests:
            if not isinstance(test, dict):
                raise ValueError("Each test must be a dictionary.")

            if test.get("approval_status") != "APPROVED":
                raise PermissionError(
                    "Execution refused: every test must be APPROVED."
                )

            if test.get("execution_status") != "NOT_STARTED":
                raise PermissionError(
                    "Execution refused: a test was already processed."
                )

            if test.get("safety") != "NON_DESTRUCTIVE":
                raise PermissionError(
                    "Execution refused: test is not marked NON_DESTRUCTIVE."
                )

            if test.get("test_type") not in self.ALLOWED_TEST_TYPES:
                raise PermissionError(
                    f"Unsupported test type: {test.get('test_type')}"
                )
            checks = test.get("checks", [])
            if (
                not isinstance(checks, list)
                or any(check not in self.ALLOWED_CHECKS for check in checks)
                or len(set(checks)) != len(checks)
            ):
                raise PermissionError(
                    "Execution refused: the plan contains unsupported declarative checks."
                )

        result_plan = deepcopy(test_plan)
        result_plan["execution_status"] = "RUNNING"
        result_plan["execution_started_at"] = datetime.now(
            timezone.utc
        ).isoformat()
        if on_status_change is not None:
            on_status_change(deepcopy(result_plan))

        results = []

        for test in result_plan["tests"]:
            try:
                result = self._execute_package_version_check(test)
            except Exception as exc:
                target = test.get("target") or {}
                result = {
                    "test_id": test.get("test_id"),
                    "cve_id": test.get("cve_id"),
                    "test_type": test.get("test_type"),
                    "package_name": target.get("package_name"),
                    "declared_version": target.get("installed_version"),
                    "installed_version": None,
                    "version_source": "NOT_VERIFIED",
                    "version_status": "UNKNOWN",
                    "execution_status": "FAILED",
                    "message": f"Check failed: {exc}",
                }
            test["execution_status"] = result["execution_status"]
            test["execution_result"] = result
            results.append(result)

        result_plan["execution_results"] = results
        result_plan["execution_timestamp"] = datetime.now(
            timezone.utc
        ).isoformat()

        result_plan["execution_status"] = (
            "FAILED"
            if any(r["execution_status"] == "FAILED" for r in results)
            else "COMPLETED"
        )
        result_plan["execution_finished_at"] = datetime.now(
            timezone.utc
        ).isoformat()
        if on_status_change is not None:
            on_status_change(deepcopy(result_plan))

        return result_plan

    def _execute_package_version_check(self, test: dict) -> dict:
        """Compare a scan-declared package version with supplied OSV ranges."""

        target = test.get("target") or {}
        package_name = target.get("package_name")
        ecosystem = target.get("ecosystem")
        declared_version = target.get("installed_version")

        base_result = {
            "test_id": test.get("test_id"),
            "cve_id": test.get("cve_id"),
            "test_type": test.get("test_type"),
            "package_name": package_name,
            "declared_version": declared_version,
            "installed_version": None,
            "version_source": "SCAN_DECLARED_DEPENDENCY",
            "version_status": "UNKNOWN",
        }

        if not package_name:
            return {
                **base_result,
                "execution_status": "SKIPPED",
                "message": "Package name is missing.",
            }

        if ecosystem != "PyPI":
            return {
                **base_result,
                "execution_status": "SKIPPED",
                "message": (
                    f"Unsupported ecosystem for this check: {ecosystem}."
                ),
            }

        if not isinstance(declared_version, str) or not declared_version.strip():
            return {
                **base_result,
                "execution_status": "SKIPPED",
                "message": "The scan did not include a declared package version.",
            }

        version_to_check = declared_version
        version_source = "SCAN_DECLARED_DEPENDENCY"
        sandbox_evidence = None
        if self._isolated_verifier is not None:
            sandbox_evidence = self._isolated_verifier.verify(
                package_name,
                declared_version,
            )
            version_to_check = sandbox_evidence.get("installed_version")
            version_source = sandbox_evidence.get(
                "version_source",
                "DOCKER_ISOLATED_WHEEL_INSTALL",
            )
            if not isinstance(version_to_check, str) or not version_to_check.strip():
                raise ValueError("The isolated environment returned no installed version.")

        evidence = test.get("evidence") or {}
        affected_ranges = evidence.get("affected_ranges") or []

        range_match = version_in_affected_range(
            version_to_check,
            affected_ranges,
        )

        if range_match is True:
            version_status = "AFFECTED"
            message = (
                "The version installed in the isolated Docker environment "
                "matches affected OSV data."
                if sandbox_evidence is not None
                else "The version declared in the scan matches affected OSV data."
            )
        elif range_match is False:
            version_status = "NOT_AFFECTED"
            message = (
                "The version installed in the isolated Docker environment is "
                "outside recognized affected OSV ranges."
                if sandbox_evidence is not None
                else "The version declared in the scan is outside recognized affected OSV ranges."
            )
        else:
            version_status = "UNKNOWN"
            message = (
                "Available OSV data is insufficient to determine the status "
                "of the isolated package version."
                if sandbox_evidence is not None
                else "Available OSV data is insufficient to determine the status of the declared version."
            )

        check_results = self._build_check_results(
            test.get("checks", []),
            sandbox_evidence,
            declared_version,
            version_to_check,
            range_match,
            version_status,
        )

        return {
            **base_result,
            "installed_version": version_to_check,
            "version_source": version_source,
            "version_status": version_status,
            "execution_status": "COMPLETED",
            "message": message,
            "isolated_environment": sandbox_evidence,
            "checks": check_results,
        }

    @staticmethod
    def _build_check_results(
        requested_checks: list[str],
        sandbox_evidence: dict | None,
        requested_version: str,
        installed_version: str,
        range_match: bool | None,
        version_status: str,
    ) -> list[dict[str, Any]]:
        results = []
        for check_id in requested_checks:
            if check_id == "WHEEL_INSTALLABLE":
                passed = bool(
                    sandbox_evidence
                    and sandbox_evidence.get("verification")
                    == "WHEEL_INSTALLED_METADATA_ONLY"
                    and sandbox_evidence.get("container_network_access") is False
                    and sandbox_evidence.get("project_code_executed") is False
                    and sandbox_evidence.get("package_code_executed") is False
                )
                detail = (
                    "The pinned binary wheel installed in the isolated container."
                    if passed
                    else "No isolated wheel installation was performed."
                )
            elif check_id == "METADATA_MATCHES_PIN":
                try:
                    passed = bool(
                        sandbox_evidence
                        and Version(installed_version) == Version(requested_version)
                    )
                except (InvalidVersion, TypeError):
                    passed = False
                detail = (
                    "Container distribution metadata matches the submitted pin."
                    if passed
                    else "Container metadata did not confirm the submitted pin."
                    if sandbox_evidence
                    else "No isolated distribution metadata was inspected."
                )
            else:  # OSV_RANGE_CLASSIFICATION; the allowlist is validated earlier.
                passed = range_match is not None
                detail = (
                    f"The supplied OSV ranges classify the version as {version_status}."
                    if passed
                    else "The supplied OSV ranges could not classify the version."
                )

            results.append({
                "check_id": check_id,
                "status": "PASSED" if passed else "NOT_PERFORMED",
                "passed": passed,
                "detail": detail,
            })
        return results
