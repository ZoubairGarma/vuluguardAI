"""Second workflow agent: execute only approved, allowlisted checks."""

from collections.abc import Callable
from typing import Any

from src.agents.docker_sandbox_verifier import DockerSandboxVerifier
from src.agents.security_test_executor import SecurityTestExecutor


class ApprovedTestAgent:
    """Run the existing non-destructive checker after human approval."""

    def __init__(self, executor: Any | None = None):
        self._executor = executor or SecurityTestExecutor(
            isolated_verifier=DockerSandboxVerifier()
        )

    def run(
        self,
        approved_plan: dict,
        on_status_change: Callable[[dict], None] | None = None,
    ) -> dict:
        if not isinstance(approved_plan, dict):
            raise TypeError("approved_plan must be a dictionary.")
        if approved_plan.get("approval_status") != "APPROVED":
            raise PermissionError("The execution agent requires an approved plan.")

        return self._executor.execute(
            approved_plan,
            on_status_change=on_status_change,
        )
