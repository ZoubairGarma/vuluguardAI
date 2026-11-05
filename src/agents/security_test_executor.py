
"""
Controlled execution of approved, non-destructive dependency checks.

The supported check compares the exact dependency version declared in the
submitted scan with the supplied OSV affected ranges. It does not install or
execute project packages.
"""

from copy import deepcopy
from datetime import datetime, timezone
from collections.abc import Callable

from src.agents.vulnerability_analyzer import version_in_affected_range


class SecurityTestExecutor:
    """Execute only explicitly approved and allowlisted security checks."""

    ALLOWED_TEST_TYPES = {"PACKAGE_VERSION_CHECK"}

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
                result = {
                    "test_id": test.get("test_id"),
                    "cve_id": test.get("cve_id"),
                    "test_type": test.get("test_type"),
                    "package_name": (test.get("target") or {}).get("package_name"),
                    "installed_version": (test.get("target") or {}).get("installed_version"),
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
            "installed_version": declared_version,
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

        evidence = test.get("evidence") or {}
        affected_ranges = evidence.get("affected_ranges") or []

        range_match = version_in_affected_range(
            declared_version,
            affected_ranges,
        )

        if range_match is True:
            version_status = "AFFECTED"
            message = "The version declared in the scan matches affected OSV data."
        elif range_match is False:
            version_status = "NOT_AFFECTED"
            message = "The version declared in the scan is outside recognized affected OSV ranges."
        else:
            version_status = "UNKNOWN"
            message = "Available OSV data is insufficient to determine the status of the declared version."

        return {
            **base_result,
            "version_status": version_status,
            "execution_status": "COMPLETED",
            "message": message,
        }
