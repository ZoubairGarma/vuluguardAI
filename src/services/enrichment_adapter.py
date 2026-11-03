"""Adapter connecting the Analysis Service to vulnerability enrichment."""

import re
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pandas as pd
from packaging.utils import canonicalize_name

from src.agents.vulnerability_analyzer import VulnerabilityAnalyzer
from src.agents.vulnerability_context import (
    VulnerabilityContextBuilder,
    parse_json_list,
)
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
        """Build the legacy matcher adapter for comparison tests."""
        matcher = VulnerabilityMatcher(processed_dir=processed_dir)
        return cls(enricher=matcher.match_dependencies)

    @classmethod
    def from_intelligence_engine(
        cls,
        processed_dir: Path | str | None = None,
    ) -> "EnrichmentAdapter":
        """Use Person A's analyzer as the authoritative version evaluator.

        OSV package/advisory relationships identify candidate CVEs. The
        VulnerabilityAnalyzer then checks installed versions and supplies
        risk, explanations, and remediation recommendations.
        """
        if processed_dir is None:
            processed_dir = (
                Path(__file__).resolve().parents[2]
                / "data"
                / "processed"
            )

        data_dir = Path(processed_dir)
        context_builder = VulnerabilityContextBuilder(data_dir=data_dir)
        analyzer = VulnerabilityAnalyzer()
        package_data = context_builder.packages_df
        records_by_id = {
            str(row["osv_id"]): row
            for _, row in context_builder.osv_df.iterrows()
        }
        cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

        def analyze_dependencies(
            dependencies: Sequence[Dependency],
        ) -> EnrichmentData:
            findings: list[dict[str, Any]] = []
            unresolved: list[dict[str, Any]] = []
            supported_dependencies: dict[str, Dependency] = {}

            for dependency in dependencies:
                ecosystem = dependency["ecosystem"].strip()
                package_name = dependency["name"].strip()
                version = dependency["version"].strip()

                if ecosystem.casefold() != "pypi":
                    unresolved.append({
                        "package": package_name,
                        "version": version,
                        "ecosystem": ecosystem,
                        "reason": "The integrated analyzer currently "
                        "supports PyPI dependencies only.",
                    })
                    continue

                normalized_name = canonicalize_name(package_name)
                previous = supported_dependencies.get(normalized_name)
                if previous and previous["version"] != version:
                    unresolved.append({
                        "package": package_name,
                        "version": version,
                        "ecosystem": ecosystem,
                        "reason": "The scan contains conflicting versions "
                        "for the same normalized package name.",
                    })
                    supported_dependencies.pop(normalized_name, None)
                    continue

                supported_dependencies[normalized_name] = {
                    "ecosystem": "PyPI",
                    "name": package_name,
                    "version": version,
                }

            if not supported_dependencies:
                return {"findings": findings, "unresolved": unresolved}

            package_names = package_data["package_name"].fillna("").astype(str)
            normalized_package_names = package_names.map(canonicalize_name)
            pypi_mask = (
                package_data["ecosystem"]
                .fillna("")
                .astype(str)
                .str.casefold()
                .eq("pypi")
            )

            candidate_osv_ids: set[str] = set()
            for normalized_name in supported_dependencies:
                matches = package_data[
                    pypi_mask
                    & normalized_package_names.eq(normalized_name)
                ]
                candidate_osv_ids.update(
                    matches["osv_id"].dropna().astype(str)
                )

            candidate_cves: set[str] = set()
            advisories_without_cve: set[str] = set()
            for osv_id in candidate_osv_ids:
                record = records_by_id.get(osv_id)
                if record is None:
                    advisories_without_cve.add(osv_id)
                    continue

                identifiers = (
                    parse_json_list(record.get("cve_ids"))
                    + parse_json_list(record.get("aliases"))
                )
                linked_cves = {
                    identifier.strip().upper()
                    for identifier in identifiers
                    if isinstance(identifier, str)
                    and cve_pattern.fullmatch(identifier.strip())
                }
                candidate_cves.update(linked_cves)
                if not linked_cves:
                    advisories_without_cve.add(osv_id)

            for osv_id in sorted(advisories_without_cve):
                unresolved.append({
                    "osv_id": osv_id,
                    "reason": "The OSV advisory is not linked to a CVE; "
                    "Person A's analyzer currently analyzes by CVE ID.",
                })

            for cve_id in sorted(candidate_cves):
                context = context_builder.build(cve_id)

                # The analyzer keys installed versions by the exact package
                # names stored in OSV, so map normalized names back to them.
                installed_packages: dict[str, str] = {}
                for affected_package in context["affected_packages"]:
                    if str(affected_package.get("ecosystem", "")).casefold() != "pypi":
                        continue

                    affected_name = affected_package.get("package_name")
                    if not affected_name:
                        continue

                    dependency = supported_dependencies.get(
                        canonicalize_name(str(affected_name))
                    )
                    if dependency is not None:
                        installed_packages[str(affected_name)] = dependency["version"]

                analysis = analyzer.analyze_context(
                    context,
                    installed_packages=installed_packages,
                )

                matching_packages = [
                    package
                    for package in analysis["affected_packages"]
                    if str(package.get("ecosystem", "")).casefold() == "pypi"
                    and canonicalize_name(
                        str(package.get("package_name", ""))
                    ) in supported_dependencies
                ]
                affected = [
                    package
                    for package in matching_packages
                    if package["version_status"] == "AFFECTED"
                ]

                if affected:
                    findings.append(analysis)
                else:
                    for package in matching_packages:
                        if package["version_status"] == "UNKNOWN":
                            unresolved.append({
                                "cve_id": cve_id,
                                "package": package["package_name"],
                                "version": package.get("installed_version"),
                                "reason": "The analyzer could not determine "
                                "whether the installed version is affected.",
                            })

            return {"findings": findings, "unresolved": unresolved}

        return cls(enricher=analyze_dependencies)

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