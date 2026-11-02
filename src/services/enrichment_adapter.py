"""Adapter connecting the Analysis Service to vulnerability enrichment."""

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from src.services.vulnerability_matcher import VulnerabilityMatcher


Dependency = dict[str, str]
Vulnerability = dict[str, Any]
EnrichmentData = dict[str, list[dict[str, Any]]]
Enricher = Callable[
    [Sequence[Dependency]],
    list[Vulnerability] | EnrichmentData,
]


class EnrichmentNotConfiguredError(RuntimeError):
    """Raised when analysis is requested before an enricher is connected."""


class EnrichmentAdapter:
    """Expose one stable interface for mocked or real enrichment."""

    def __init__(self, enricher: Enricher | None = None) -> None:
        self._enricher = enricher

    @classmethod
    def from_processed_data(
        cls,
        processed_dir: Path | str | None = None,
    ) -> "EnrichmentAdapter":
        """Build an adapter backed by the prepared OSV/EPSS/KEV CSV files."""
        matcher = VulnerabilityMatcher(processed_dir=processed_dir)
        return cls(enricher=matcher.match_dependencies)

    def enrich_dependencies(
        self,
        dependencies: Sequence[Dependency],
    ) -> EnrichmentData:
        """Return confirmed findings and any unresolved OSV matches."""
        if self._enricher is None:
            raise EnrichmentNotConfiguredError(
                "Vulnerability enrichment is not configured."
            )

        result = self._enricher(dependencies)

        # Keep compatibility with existing mocked enrichers that return a list.
        if isinstance(result, list):
            enrichment = {"findings": result, "unresolved": []}
        elif isinstance(result, dict):
            findings = result.get("findings")
            unresolved = result.get("unresolved")

            if not isinstance(findings, list) or not isinstance(unresolved, list):
                raise TypeError(
                    "The enricher must return a list of findings "
                    "and a list of unresolved entries."
                )

            enrichment = {
                "findings": findings,
                "unresolved": unresolved,
            }
        else:
            raise TypeError(
                "The enricher must return a findings list or an enrichment "
                "dictionary."
            )

        for key in ("findings", "unresolved"):
            if not isinstance(enrichment[key], list):
                raise TypeError(f"Enrichment field {key!r} must be a list.")
            if any(not isinstance(item, dict) for item in enrichment[key]):
                raise TypeError(
                    f"Every entry in enrichment field {key!r} must be a dictionary."
                )

        return enrichment