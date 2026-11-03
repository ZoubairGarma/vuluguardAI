
"""
Controlled execution of approved, non-destructive security checks.

The first supported check reads locally installed Python package metadata
and compares the installed version with the OSV affected ranges.
No package is installed, removed, modified, or executed.
"""

from copy import deepcopy
from datetime import datetime, timezone
from importlib import metadata

from src.agents.vulnerability_analyzer import version_in_affected_range


class SecurityTestExecutor:
    """Execute only explicitly approved and allowlisted security checks."""

    ALLOWED_TEST_TYPES = {"PACKAGE_VERSION_CHECK"}

    def execute(self, test_plan: dict) -> dict:
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

        if test_plan.get("execution_status") != "NOT_EXECUTED":
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

            if test.get("execution_status") != "NOT_EXECUTED":
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
        results = []

        for test in result_plan["tests"]:
            result = self._execute_package_version_check(test)
            test["execution_status"] = result["execution_status"]
            test["execution_result"] = result
            results.append(result)

        result_plan["execution_results"] = results
        result_plan["execution_timestamp"] = datetime.now(
            timezone.utc
        ).isoformat()

        if all(r["execution_status"] == "COMPLETED" for r in results):
            result_plan["execution_status"] = "COMPLETED"
        elif all(r["execution_status"] == "SKIPPED" for r in results):
            result_plan["execution_status"] = "SKIPPED"
        else:
            result_plan["execution_status"] = "PARTIAL"

        return result_plan

    def _execute_package_version_check(self, test: dict) -> dict:
        """Read installed package metadata and compare its version with OSV."""

        target = test.get("target") or {}
        package_name = target.get("package_name")
        ecosystem = target.get("ecosystem")

        base_result = {
            "test_id": test.get("test_id"),
            "cve_id": test.get("cve_id"),
            "test_type": test.get("test_type"),
            "package_name": package_name,
            "installed_version": None,
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
                    f"Unsupported ecosystem for local check: {ecosystem}."
                ),
            }

        try:
            installed_version = metadata.version(package_name)
        except metadata.PackageNotFoundError:
            return {
                **base_result,
                "execution_status": "COMPLETED",
                "version_status": "NOT_INSTALLED",
                "message": "Package is not installed in this Python environment.",
            }
        except Exception as exc:
            return {
                **base_result,
                "execution_status": "SKIPPED",
                "message": f"Could not read package metadata: {exc}",
            }

        evidence = test.get("evidence") or {}
        affected_ranges = evidence.get("affected_ranges") or []

        range_match = version_in_affected_range(
            installed_version,
            affected_ranges,
        )

        if range_match is True:
            version_status = "AFFECTED"
            message = "Installed version matches known affected OSV data."
        elif range_match is False:
            version_status = "NOT_AFFECTED"
            message = "Installed version is outside the recognized OSV ranges."
        else:
            version_status = "UNKNOWN"
            message = "Available OSV data is insufficient to determine the status."

        return {
            **base_result,
            "installed_version": installed_version,
            "version_status": version_status,
            "execution_status": "COMPLETED",
            "message": message,
        }
