
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
        "execution_status": "NOT_EXECUTED",
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
                },
                "evidence": {
                    "affected_ranges": [],
                    "fixed_versions": [],
                },
                "safety": "NON_DESTRUCTIVE",
                "approval_status": "APPROVED",
                "execution_status": "NOT_EXECUTED",
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
    assert approved_plan["tests"][0]["execution_status"] == "NOT_EXECUTED"


def test_successful_execution_returns_results(executor, approved_plan):
    result = executor.execute(approved_plan)

    assert result["execution_status"] == "COMPLETED"
    assert len(result["execution_results"]) == 1
    assert result["tests"][0]["execution_status"] == "COMPLETED"
    assert result["execution_results"][0]["package_name"] == "pip"
