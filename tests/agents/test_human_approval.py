
import pytest

from src.agents.human_approval import HumanApprovalManager


@pytest.fixture
def manager():
    return HumanApprovalManager()


@pytest.fixture
def test_plan():
    return {
        "cve_id": "CVE-2023-0297",
        "total_tests": 1,
        "approval_status": "PENDING_APPROVAL",
        "execution_status": "NOT_STARTED",
        "safety": {
            "non_destructive": True,
            "automatic_execution": False,
            "requires_human_approval": True,
        },
        "tests": [
            {
                "test_id": "CVE-2023-0297-TEST-001",
                "checks": [
                    "WHEEL_INSTALLABLE",
                    "METADATA_MATCHES_PIN",
                    "OSV_RANGE_CLASSIFICATION",
                ],
                "approval_status": "PENDING_APPROVAL",
                "execution_status": "NOT_STARTED",
            }
        ],
    }


def test_approve_pending_plan(manager, test_plan):
    result = manager.approve(test_plan, "security_reviewer")

    assert result["approval_status"] == "APPROVED"
    assert result["approval"]["decision"] == "APPROVED"
    assert result["approval"]["reviewer"] == "security_reviewer"
    assert result["tests"][0]["approval_status"] == "APPROVED"
    assert result["execution_status"] == "NOT_STARTED"


def test_reject_pending_plan(manager, test_plan):
    result = manager.reject(
        test_plan,
        "security_reviewer",
        "Test scenario needs revision",
    )

    assert result["approval_status"] == "REJECTED"
    assert result["approval"]["decision"] == "REJECTED"
    assert result["approval"]["reason"] == "Test scenario needs revision"
    assert result["tests"][0]["approval_status"] == "REJECTED"
    assert result["execution_status"] == "NOT_STARTED"


def test_cannot_approve_already_approved_plan(manager, test_plan):
    approved = manager.approve(test_plan, "reviewer")

    with pytest.raises(ValueError, match="Only pending"):
        manager.approve(approved, "reviewer")


def test_rejection_requires_reason(manager, test_plan):
    with pytest.raises(ValueError, match="reason"):
        manager.reject(test_plan, "reviewer", "  ")


def test_reviewer_is_required(manager, test_plan):
    with pytest.raises(ValueError, match="reviewer"):
        manager.approve(test_plan, "  ")


def test_original_plan_is_not_modified(manager, test_plan):
    original_status = test_plan["approval_status"]
    original_test_status = test_plan["tests"][0]["approval_status"]

    manager.approve(test_plan, "reviewer")

    assert test_plan["approval_status"] == original_status
    assert test_plan["tests"][0]["approval_status"] == original_test_status


def test_invalid_safety_configuration_is_rejected(manager, test_plan):
    test_plan["safety"]["automatic_execution"] = True

    with pytest.raises(ValueError, match="safety"):
        manager.approve(test_plan, "reviewer")
