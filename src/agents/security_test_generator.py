
from typing import Any, Dict, List


class SecurityTestGenerator:
    """
    Generates non-destructive security test scenarios
    from VulnerabilityAnalyzer results.

    This module only generates test plans.
    It does not execute commands or modify the environment.
    """

    SUPPORTED_VERSION_STATUSES = {
        "AFFECTED",
        "NOT_AFFECTED",
        "UNKNOWN",
        "NOT_CHECKED",
    }

    def generate(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate security test scenarios from a vulnerability analysis.

        Args:
            analysis: Result returned by VulnerabilityAnalyzer.analyze()

        Returns:
            A structured test plan awaiting human approval.
        """

        if not isinstance(analysis, dict):
            raise TypeError("analysis must be a dictionary")

        cve_id = analysis.get("cve_id")

        if not cve_id:
            raise ValueError("Analysis must contain a cve_id")

        affected_packages = analysis.get("affected_packages", [])

        if not isinstance(affected_packages, list):
            raise ValueError("affected_packages must be a list")

        generated_tests = []

        for index, package in enumerate(affected_packages, start=1):
            if not isinstance(package, dict):
                continue

            package_name = package.get("package_name")

            if not package_name:
                continue

            version_status = package.get("version_status", "UNKNOWN")

            if version_status not in self.SUPPORTED_VERSION_STATUSES:
                version_status = "UNKNOWN"

            test = self._generate_package_test(
                cve_id=cve_id,
                package=package,
                version_status=version_status,
                index=index,
            )

            generated_tests.append(test)

        return {
            "cve_id": cve_id,
            "total_tests": len(generated_tests),
            "tests": generated_tests,
            "approval_status": "PENDING_APPROVAL",
            "execution_status": "NOT_EXECUTED",
            "safety": {
                "non_destructive": True,
                "automatic_execution": False,
                "requires_human_approval": True,
            },
        }

    def _generate_package_test(
        self,
        cve_id: str,
        package: Dict[str, Any],
        version_status: str,
        index: int,
    ) -> Dict[str, Any]:

        package_name = package["package_name"]
        ecosystem = package.get("ecosystem")
        installed_version = package.get("installed_version")
        fixed_versions = package.get("fixed_versions", [])
        affected_ranges = package.get("affected_ranges", [])

        if version_status == "AFFECTED":
            title = "Confirm affected package version"
            objective = (
                "Verify that the installed package version matches "
                "an affected OSV version range."
            )

        elif version_status == "NOT_AFFECTED":
            title = "Verify non-affected package version"
            objective = (
                "Verify that the installed package version remains "
                "outside the affected OSV version ranges."
            )

        elif version_status == "NOT_CHECKED":
            title = "Check installed package version"
            objective = (
                "Identify the installed package version and compare it "
                "with the affected OSV version ranges."
            )

        else:
            title = "Review package version manually"
            objective = (
                "Inspect the package version and available OSV evidence "
                "to determine its vulnerability status."
            )

        return {
            "test_id": f"{cve_id}-TEST-{index:03d}",
            "cve_id": cve_id,
            "test_type": "PACKAGE_VERSION_CHECK",
            "title": title,
            "objective": objective,
            "target": {
                "package_name": package_name,
                "ecosystem": ecosystem,
                "installed_version": installed_version,
            },
            "evidence": {
                "version_status": version_status,
                "affected_ranges": affected_ranges,
                "fixed_versions": fixed_versions,
                "osv_ids": package.get("osv_ids", []),
                "purl": package.get("purl"),
            },
            "steps": [
                "Identify the package in the project dependency files.",
                "Determine its installed version.",
                "Compare the version with the supplied OSV affected ranges.",
                "Review the available fixed versions.",
            ],
            "expected_result": (
                "The installed package version is classified "
                "consistently with the OSV vulnerability data."
            ),
            "safety": "NON_DESTRUCTIVE",
            "approval_status": "PENDING_APPROVAL",
            "execution_status": "NOT_EXECUTED",
        }
