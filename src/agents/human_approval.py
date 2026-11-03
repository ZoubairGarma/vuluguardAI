
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict


class HumanApprovalManager:
    """
    Manages human approval or rejection of generated security test plans.

    This module does not execute security tests.
    """

    def approve(
        self,
        test_plan: Dict[str, Any],
        reviewer: str,
    ) -> Dict[str, Any]:
        """Approve a pending security test plan."""

        result = self._validate_and_copy(test_plan, reviewer)

        if result["approval_status"] != "PENDING_APPROVAL":
            raise ValueError("Only pending test plans can be approved")

        result["approval_status"] = "APPROVED"
        result["approval"] = {
            "decision": "APPROVED",
            "reviewer": reviewer.strip(),
            "timestamp": self._timestamp(),
            "reason": None,
        }

        for test in result["tests"]:
            if test["approval_status"] != "PENDING_APPROVAL":
                raise ValueError("All tests must be pending approval")

            test["approval_status"] = "APPROVED"

        return result

    def reject(
        self,
        test_plan: Dict[str, Any],
        reviewer: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Reject a pending security test plan."""

        result = self._validate_and_copy(test_plan, reviewer)

        if result["approval_status"] != "PENDING_APPROVAL":
            raise ValueError("Only pending test plans can be rejected")

        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("A rejection reason is required")

        result["approval_status"] = "REJECTED"
        result["approval"] = {
            "decision": "REJECTED",
            "reviewer": reviewer.strip(),
            "timestamp": self._timestamp(),
            "reason": reason.strip(),
        }

        for test in result["tests"]:
            if test["approval_status"] != "PENDING_APPROVAL":
                raise ValueError("All tests must be pending approval")

            test["approval_status"] = "REJECTED"

        return result

    def _validate_and_copy(
        self,
        test_plan: Dict[str, Any],
        reviewer: str,
    ) -> Dict[str, Any]:

        if not isinstance(test_plan, dict):
            raise TypeError("test_plan must be a dictionary")

        if not isinstance(reviewer, str) or not reviewer.strip():
            raise ValueError("A reviewer is required")

        if not isinstance(test_plan.get("tests"), list):
            raise ValueError("test_plan must contain a tests list")

        safety = test_plan.get("safety", {})

        if (
            safety.get("automatic_execution") is not False
            or safety.get("requires_human_approval") is not True
        ):
            raise ValueError("Test plan does not satisfy approval safety rules")

        if test_plan.get("execution_status") != "NOT_EXECUTED":
            raise ValueError("Test plan must not have been executed")

        return deepcopy(test_plan)

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()
