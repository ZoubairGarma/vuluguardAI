"""Coordinate enrichment and optional risk/ML components."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from src.services.enrichment_adapter import (
    Dependency,
    EnrichmentAdapter,
    Vulnerability,
)


AnalysisComponent = Callable[[Sequence[Vulnerability]], dict[str, Any]]


@dataclass(frozen=True)
class AnalysisResult:
    """Structured result of one scan analysis attempt."""

    scan_id: str
    vulnerabilities: list[Vulnerability]
    risk_assessment: dict[str, Any] | None = None
    ml_prediction: dict[str, Any] | None = None
    unresolved: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable mapping for later persistence/API use."""
        return {
            "scan_id": self.scan_id,
            "vulnerabilities": self.vulnerabilities,
            "risk_assessment": self.risk_assessment,
            "ml_prediction": self.ml_prediction,
            "unresolved": self.unresolved,
        }


class AnalysisService:
    """Coordinate enrichment without implementing scoring or ML itself."""

    def __init__(
        self,
        enrichment_adapter: EnrichmentAdapter,
        risk_scorer: AnalysisComponent | None = None,
        ml_predictor: AnalysisComponent | None = None,
    ) -> None:
        self._enrichment_adapter = enrichment_adapter
        self._risk_scorer = risk_scorer
        self._ml_predictor = ml_predictor

    def analyze(
        self,
        scan_id: str,
        dependencies: Sequence[Dependency],
    ) -> AnalysisResult:
        """Analyze a scan and return findings without persisting them."""
        normalized_scan_id = self._validate_scan(scan_id, dependencies)
        dependency_snapshot = [dict(item) for item in dependencies]

        enrichment = self._enrichment_adapter.enrich_dependencies(
            dependency_snapshot
        )
        vulnerabilities = enrichment["findings"]
        unresolved = enrichment["unresolved"]

        risk_assessment = self._run_component(
            self._risk_scorer,
            vulnerabilities,
            "risk scorer",
        )
        ml_prediction = self._run_component(
            self._ml_predictor,
            vulnerabilities,
            "ML predictor",
        )

        return AnalysisResult(
            scan_id=normalized_scan_id,
            vulnerabilities=vulnerabilities,
            risk_assessment=risk_assessment,
            ml_prediction=ml_prediction,
            unresolved=unresolved,
        )

    @staticmethod
    def _validate_scan(
        scan_id: str,
        dependencies: Sequence[Dependency],
    ) -> str:
        if not isinstance(scan_id, str) or not scan_id.strip():
            raise ValueError("scan_id must be a non-empty string.")

        if (
            isinstance(dependencies, (str, bytes))
            or not isinstance(dependencies, Sequence)
            or not dependencies
        ):
            raise ValueError("At least one dependency is required.")

        required_fields = ("ecosystem", "name", "version")

        for index, dependency in enumerate(dependencies):
            if not isinstance(dependency, dict):
                raise ValueError(
                    f"Dependency at index {index} must be a dictionary."
                )

            for field_name in required_fields:
                value = dependency.get(field_name)
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(
                        f"Dependency at index {index} has an invalid "
                        f"{field_name}."
                    )

        return scan_id.strip()

    @staticmethod
    def _run_component(
        component: AnalysisComponent | None,
        vulnerabilities: Sequence[Vulnerability],
        component_name: str,
    ) -> dict[str, Any] | None:
        if component is None:
            return None

        result = component(vulnerabilities)
        if not isinstance(result, dict):
            raise TypeError(
                f"The {component_name} must return a dictionary."
            )

        return result