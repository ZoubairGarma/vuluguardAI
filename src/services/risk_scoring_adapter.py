
"""Adapter for attaching precomputed risk assessments to scan findings."""

from pathlib import Path
from typing import Any

import pandas as pd

from src.services.enrichment_adapter import Vulnerability


class RiskScoringAdapter:
    """Attach precomputed CVE risk scores to vulnerability findings."""

    REQUIRED_COLUMNS = {
        "cve_id",
        "risk_score",
        "risk_level",
        "cvss_score_used",
        "cvss_severity_used",
        "cvss_source",
        "cvss_provider",
        "cvss_version_used",
        "epss_score_used",
        "epss_percentile",
        "is_kev",
        "scoring_basis",
        "risk_explanation",
    }

    def __init__(self, risk_file: Path | str | None = None) -> None:
        if risk_file is None:
            project_root = Path(__file__).resolve().parents[2]
            risk_file = (
                project_root
                / "data"
                / "processed"
                / "risk"
                / "risk_assessment.csv"
            )

        self.risk_file = Path(risk_file)

        if not self.risk_file.exists():
            raise FileNotFoundError(self.risk_file)

        df = pd.read_csv(self.risk_file)

        missing = self.REQUIRED_COLUMNS - set(df.columns)
        if missing:
            raise ValueError(
                "Missing columns in risk assessment: "
                f"{sorted(missing)}. Rebuild the derived files with "
                "`python -m src.preprocessing.calculate_cvss_scores` then "
                "`python -m src.agents.risk_scoring`."
            )

        if df["cve_id"].isna().any():
            raise ValueError("Risk assessment contains missing CVE IDs.")

        if df["cve_id"].duplicated().any():
            raise ValueError("Risk assessment contains duplicate CVE IDs.")

        self._risk_lookup = (
            {
                cve_id: {
                    column: (
                        None
                        if pd.isna(value)
                        else value.item() if hasattr(value, "item") else value
                    )
                    for column, value in row.items()
                }
                for cve_id, row in df.set_index("cve_id").iterrows()
            }
        )

    def __call__(
        self,
        vulnerabilities: list[Vulnerability] | tuple[Vulnerability, ...],
    ) -> dict[str, Any]:
        """Return risk assessments for the supplied findings."""

        assessments = []
        missing_cves = []

        for vulnerability in vulnerabilities:
            cve_id = str(vulnerability.get("cve_id", "")).strip().upper()

            if not cve_id:
                missing_cves.append({
                    "reason": "Finding has no CVE ID."
                })
                continue

            assessment = self._risk_lookup.get(cve_id)

            if assessment is None:
                missing_cves.append({
                    "cve_id": cve_id,
                    "reason": "No precomputed risk assessment found."
                })
                continue

            assessments.append({
                "cve_id": cve_id,
                **assessment,
            })

        return {
            "assessments": assessments,
            "unmatched": missing_cves,
            "total_findings": len(vulnerabilities),
            "matched_count": len(assessments),
            "unmatched_count": len(missing_cves),
        }
