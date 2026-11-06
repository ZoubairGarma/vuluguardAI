
import pytest

from src.agents.security_test_executor import SecurityTestExecutor


@pytest.fixture
def executor():
    return SecurityTestExecutor()


@pytest.fixture
def approved_plan():
    return {
        "cve_id": "CVE-2023-0297",
        "approval_status": "APPROVED",
        "execution_status": "NOT_STARTED",
        "safety": {
            "non_destructive": True,
            "automatic_execution": False,
            "requires_human_approval": True,
        },
        "tests": [
            {
                "test_id": "CVE-2023-0297-TEST-001",
                "cve_id": "CVE-2023-0297",
                "test_type": "PACKAGE_VERSION_CHECK",
                "target": {
                    "package_name": "pip",
                    "ecosystem": "PyPI",
                    "installed_version": "1.0.0",
                },
                "evidence": {
                    "affected_ranges": [],
                    "fixed_versions": [],
                },
                "safety": "NON_DESTRUCTIVE",
                "approval_status": "APPROVED",
                "execution_status": "NOT_STARTED",
            }
        ],
    }


def test_rejects_pending_approval_plan(executor, approved_plan):
    approved_plan["approval_status"] = "PENDING_APPROVAL"

    with pytest.raises(PermissionError):
        executor.execute(approved_plan)


def test_rejects_rejected_plan(executor, approved_plan):
    approved_plan["approval_status"] = "REJECTED"

    with pytest.raises(PermissionError):
        executor.execute(approved_plan)


def test_rejects_unapproved_individual_test(executor, approved_plan):
    approved_plan["tests"][0]["approval_status"] = "PENDING_APPROVAL"

    with pytest.raises(PermissionError):
        executor.execute(approved_plan)


def test_rejects_unsupported_test_type(executor, approved_plan):
    approved_plan["tests"][0]["test_type"] = "COMMAND_EXECUTION"

    with pytest.raises(PermissionError):
        executor.execute(approved_plan)


def test_rejects_unsafe_plan(executor, approved_plan):
    approved_plan["safety"]["non_destructive"] = False

    with pytest.raises(PermissionError):
        executor.execute(approved_plan)


def test_rejects_already_processed_plan(executor, approved_plan):
    approved_plan["execution_status"] = "COMPLETED"

    with pytest.raises(PermissionError):
        executor.execute(approved_plan)


def test_execution_does_not_modify_original_plan(executor, approved_plan):
    original_status = approved_plan["execution_status"]

    executor.execute(approved_plan)

    assert approved_plan["execution_status"] == original_status
    assert "execution_results" not in approved_plan
    assert approved_plan["tests"][0]["execution_status"] == "NOT_STARTED"


def test_successful_execution_returns_results(executor, approved_plan):
    result = executor.execute(approved_plan)

    assert result["execution_status"] == "COMPLETED"
    assert len(result["execution_results"]) == 1
    assert result["tests"][0]["execution_status"] == "COMPLETED"
    assert result["execution_results"][0]["package_name"] == "pip"



def test_detects_affected_scan_declared_version(executor, approved_plan):
    approved_plan["tests"][0]["evidence"]["affected_ranges"] = [
        {
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "0"},
                {"fixed": "2.0.0"},
            ],
        }
    ]

    result = executor.execute(approved_plan)

    assert result["execution_results"][0]["version_status"] == "AFFECTED"


def test_detects_fixed_scan_declared_version(executor, approved_plan):
    approved_plan["tests"][0]["target"]["installed_version"] = "2.0.0"
    approved_plan["tests"][0]["evidence"]["affected_ranges"] = [
        {
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "0"},
                {"fixed": "2.0.0"},
            ],
        }
    ]

    result = executor.execute(approved_plan)

    assert result["execution_results"][0]["version_status"] == "NOT_AFFECTED"


def test_returns_unknown_for_unrecognized_ranges(
    executor, approved_plan
):
    approved_plan["tests"][0]["target"]["installed_version"] = "1.5.0"
    approved_plan["tests"][0]["evidence"]["affected_ranges"] = [
        {
            "type": "GIT",
            "events": [
                {"introduced": "abc123"},
            ],
        }
    ]

    result = executor.execute(approved_plan)

    assert result["execution_results"][0]["version_status"] == "UNKNOWN"


def test_missing_scan_version_is_skipped(executor, approved_plan):
    approved_plan["tests"][0]["target"]["installed_version"] = None
    result = executor.execute(approved_plan)

    assert result["execution_results"][0]["version_status"] == "UNKNOWN"
    assert result["execution_results"][0]["execution_status"] == "SKIPPED"


def test_uses_version_from_scan_not_local_environment(executor, approved_plan):
    approved_plan["tests"][0]["target"]["installed_version"] = "1.0.0"
    approved_plan["tests"][0]["evidence"]["affected_ranges"] = [
        {
            "type": "ECOSYSTEM",
            "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
        }
    ]

    result = executor.execute(approved_plan)

    assert result["execution_results"][0]["installed_version"] == "1.0.0"
    assert result["execution_results"][0]["version_source"] == "SCAN_DECLARED_DEPENDENCY"
    assert result["execution_results"][0]["version_status"] == "AFFECTED"


def test_reports_running_and_final_states(executor, approved_plan):
    observed_states = []

    result = executor.execute(
        approved_plan,
        on_status_change=lambda plan: observed_states.append(
            plan["execution_status"]
        ),
    )

    assert observed_states == ["RUNNING", "COMPLETED"]
    assert result["execution_status"] == "COMPLETED"


def test_uses_isolated_installed_version_for_osv_comparison(approved_plan):
    class IsolatedVerifier:
        def verify(self, package_name, version):
            assert package_name == "pip"
            assert version == "1.0.0"
            return {
                "installed_version": "1.0.0",
                "version_source": "DOCKER_ISOLATED_WHEEL_INSTALL",
                "verification": "WHEEL_INSTALLED_METADATA_ONLY",
                "container_network_access": False,
                "project_code_executed": False,
                "package_code_executed": False,
            }

    approved_plan["tests"][0]["evidence"]["affected_ranges"] = [
        {
            "type": "ECOSYSTEM",
            "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
        }
    ]
    approved_plan["tests"][0]["checks"] = [
        "WHEEL_INSTALLABLE",
        "METADATA_MATCHES_PIN",
        "OSV_RANGE_CLASSIFICATION",
    ]
    executor = SecurityTestExecutor(isolated_verifier=IsolatedVerifier())

    result = executor.execute(approved_plan)

    checked = result["execution_results"][0]
    assert checked["version_status"] == "AFFECTED"
    assert checked["version_source"] == "DOCKER_ISOLATED_WHEEL_INSTALL"
    assert checked["isolated_environment"]["project_code_executed"] is False
    assert [item["status"] for item in checked["checks"]] == [
        "PASSED",
        "PASSED",
        "PASSED",
    ]


def test_isolated_verification_failure_fails_the_plan(approved_plan):
    class FailingVerifier:
        def verify(self, package_name, version):
            raise RuntimeError("Docker daemon unavailable")

    executor = SecurityTestExecutor(isolated_verifier=FailingVerifier())

    result = executor.execute(approved_plan)

    assert result["execution_status"] == "FAILED"
    assert result["execution_results"][0]["execution_status"] == "FAILED"
    assert result["execution_results"][0]["declared_version"] == "1.0.0"
    assert result["execution_results"][0]["installed_version"] is None
    assert result["execution_results"][0]["version_source"] == "NOT_VERIFIED"
    assert "Docker daemon unavailable" in result["execution_results"][0]["message"]
