
import json

from src.agents.llm.ollama_provider import OllamaProvider


class LLMExplanationAgent:
    """
    Generates developer-friendly explanations from the deterministic
    results produced by VulnerabilityAnalyzer.
    """

    def __init__(self, provider=None):
        self.provider = provider or OllamaProvider()

    def _validate_analysis(self, analysis: dict) -> None:
        if not isinstance(analysis, dict):
            raise ValueError("Analysis must be a dictionary.")

        if not analysis.get("cve_id"):
            raise ValueError("Analysis must contain a CVE ID.")

        required_fields = [
            "risk",
            "affected_packages",
            "recommendations",
        ]

        for field in required_fields:
            if field not in analysis:
                raise ValueError(
                    f"Analysis is missing required field: {field}"
                )

        if not isinstance(analysis["risk"], dict):
            raise ValueError("Risk information must be a dictionary.")

        if not isinstance(analysis["affected_packages"], list):
            raise ValueError("Affected packages must be a list.")

        if not isinstance(analysis["recommendations"], list):
            raise ValueError("Recommendations must be a list.")


    def _build_prompt(self, analysis: dict) -> str:
        # Keep only the information needed to explain the vulnerability.
        packages = []

        for package in analysis.get("affected_packages", []):
            packages.append({
                "ecosystem": package.get("ecosystem"),
                "package_name": package.get("package_name"),
                "purl": package.get("purl"),
                "osv_ids": package.get("osv_ids", []),
                "affected_ranges": package.get("affected_ranges", []),
                "introduced_versions": package.get("introduced_versions", []),
                "fixed_versions": package.get("fixed_versions", []),
                "installed_version": package.get("installed_version"),
                "version_status": package.get("version_status"),
            })

        risk = analysis.get("risk", {})

        context = {
            "cve_id": analysis.get("cve_id"),
            "description": analysis.get("description"),
            "advisories": analysis.get("advisories", []),
            "risk": {
                "score": risk.get("score"),
                "level": risk.get("level"),
                "is_kev": risk.get("is_kev"),
                "cvss_score": risk.get("cvss_score"),
                "cvss_severity": risk.get("cvss_severity"),
                "epss_score": risk.get("epss_score"),
                "epss_percentile": risk.get("epss_percentile"),
                "scoring_basis": risk.get("scoring_basis"),
            },
            "affected_packages": packages,
            "installed_package_check_performed": analysis.get(
                "installed_package_check_performed", False
            ),
            "analysis": analysis.get("analysis", []),
            "recommendations": analysis.get("recommendations", []),
        }

        context_json = json.dumps(
            context,
            ensure_ascii=False,
            indent=2,
            default=str,
        )


        return f"""
You are the explanation component of VulnGuard AI.

Explain the vulnerability using only the supplied JSON data.

STRICT VERSION RULES:
- Never invent, normalize, reformat, or infer version numbers.
- Preserve version strings exactly as supplied.
- An introduced version of "0" must remain "0".
- Do not transform "0" into "0.0.0-0" or another format.
- Distinguish affected ranges from installed versions.
- A fixed version is not an installed version.
- If installed_version is null, say no installed version was provided.
- NOT_CHECKED means the installed version was not checked.
- Never claim the project is vulnerable without an AFFECTED
  installed version status.

STRICT SECURITY RULES:
- Report the exact CVE identifier.
- Report supplied OSV identifiers.
- Report the exact package name and ecosystem.
- Report the exact CVSS score and severity.
- Report the exact EPSS score and percentile.
- Explain KEV status using is_kev:
  true means listed in the supplied CISA KEV snapshot.
  false means not listed in that snapshot.
- Report the exact VulnGuard risk score and risk level.
- The VulnGuard score is a prioritization score, not a probability.
- EPSS is an estimated exploitation probability, not severity.
- Do not invent impact details not supported by the description
  or advisory data.

Write professional, concise English for software developers.

Use exactly these six sections:

1. Vulnerability Summary
2. Potential Impact
3. Risk Assessment
4. Affected Packages
5. Recommended Actions
6. Analysis Limitations

The Affected Packages section must state:
- Package name and ecosystem.
- OSV identifiers.
- Supplied introduced and fixed versions, exactly as written.
- Whether an installed version was checked.
- Never invent an installed version.

The Risk Assessment section must include:
- CVSS and severity.
- EPSS and percentile.
- KEV status.
- VulnGuard score and risk level.

If the supplied data does not establish a fact, explicitly say
that the information is unavailable.

Do not explain the JSON structure. Explain the vulnerability itself.

VULNERABILITY DATA:
{context_json}
"""



    def explain(self, analysis: dict) -> dict:
        """
        Generate a human-readable explanation.
        """

        self._validate_analysis(analysis)

        prompt = self._build_prompt(analysis)
        explanation = self.provider.generate(prompt)

        return {
            "cve_id": analysis["cve_id"],
            "explanation": explanation,
            "risk": analysis["risk"],
            "affected_packages": analysis["affected_packages"],
            "recommendations": analysis["recommendations"],
            "metadata": {
                "provider": self.provider.__class__.__name__,
                "model": getattr(
                    self.provider,
                    "model",
                    "unknown",
                ),
            },
        }
