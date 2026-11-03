
import copy
import json
import re

from src.agents.llm.ollama_provider import OllamaProvider


class LLMExplanationAgent:
    """
    Generates a human-readable vulnerability explanation using an LLM.

    The LLM explains the analysis, while verified source data
    remains independently available in verified_facts.
    """

    def __init__(self, provider=None):
        self.provider = provider or OllamaProvider()

    @staticmethod
    def _validate_analysis(analysis: dict) -> None:
        """Validate the structure received from VulnerabilityAnalyzer."""

        if not isinstance(analysis, dict):
            raise ValueError("analysis must be a dictionary")

        if not analysis.get("cve_id"):
            raise ValueError("CVE ID is required")

        required_fields = [
            "risk",
            "description",
            "affected_packages",
            "recommendations",
        ]

        missing_fields = [
            field for field in required_fields
            if field not in analysis
        ]

        if missing_fields:
            raise ValueError(
                f"Missing required analysis fields: {missing_fields}"
            )

        if not isinstance(analysis["risk"], dict):
            raise TypeError("analysis['risk'] must be a dictionary")

        if not isinstance(analysis["affected_packages"], list):
            raise TypeError(
                "analysis['affected_packages'] must be a list"
            )

        if not isinstance(analysis["recommendations"], list):
            raise TypeError(
                "analysis['recommendations'] must be a list"
            )

    @staticmethod
    def _build_package_context(package: dict) -> dict:
        """
        Provide package identity and installation status to the LLM.

        Full OSV ranges remain available in verified_facts.
        They are excluded from the prompt to avoid misinterpretation
        of aggregated vulnerability ranges.
        """

        return {
            "package_name": package.get("package_name"),
            "ecosystem": package.get("ecosystem"),
            "purl": package.get("purl"),
            "osv_ids": package.get("osv_ids", []),
            "installed_version": package.get("installed_version"),
            "version_status": package.get("version_status"),
        }

    def _build_prompt(self, analysis: dict) -> str:
        """Build a strict prompt using the analyzer's verified data."""

        packages = [
            self._build_package_context(package)
            for package in analysis["affected_packages"]
        ]

        prompt_data = {
            "cve_id": analysis["cve_id"],
            "description": analysis.get("description"),
            "risk": analysis.get("risk", {}),
            "advisories": analysis.get("advisories", []),
            "affected_packages": packages,
            "installed_package_check_performed": analysis.get(
                "installed_package_check_performed",
                False,
            ),
            "recommendations": analysis.get("recommendations", []),
        }

        serialized_data = json.dumps(
            prompt_data,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

        return f"""
You are a cybersecurity vulnerability analyst.

Your task is to explain the vulnerability using ONLY the supplied
analysis data.

STRICT DATA INTEGRITY RULES:

1. Never invent or modify CVE identifiers, package names, versions,
   CVSS scores, EPSS scores, percentiles, risk scores, or dates.

2. Treat all supplied values as authoritative.
   If a value is null or missing, say that it is unavailable.
   Never replace missing values with estimates.

3. Do not calculate or reconstruct vulnerability version ranges.
   The complete OSV ranges are deliberately not included in this prompt.
   Never invent introduced versions, fixed versions, or affected intervals.

4. Keep affected packages separate.
   Never combine information from different packages.

5. Do not claim that an installed package is vulnerable unless its
   version_status is explicitly "AFFECTED".

6. Interpret version_status as follows:
   - AFFECTED: the installed version is within a known affected range.
   - NOT_AFFECTED: the installed version is outside known affected ranges.
   - UNKNOWN: the available data cannot establish the status.
   - NOT_CHECKED: no installed-version check was performed.


7. Interpret the is_kev field as an authoritative boolean value.
   You MUST follow these exact rules:

   - If is_kev is true:
     State: "The CVE is listed in the supplied KEV catalog snapshot."

   - If is_kev is false:
     State: "The CVE is not listed in the supplied KEV catalog snapshot."

   - If is_kev is null or missing:
     State: "KEV status is unavailable in the supplied data."

   IMPORTANT:
   - Never describe false as unavailable, unknown, or missing.
   - Never describe false as listed, included, present, or affected in KEV.
   - Never describe true as absent or not listed.
   - Do not contradict the KEV status elsewhere in the explanation.
   - Do not infer exploitation status from a missing KEV entry.
   - Use only the supplied is_kev value. Do not guess.

8. A risk level of UNKNOWN or a scoring basis of NO_DATA does not mean
   that the CVE is rejected, invalid, or harmless.
   Only describe a CVE as rejected if the supplied description or
   advisory explicitly says so.

9. Do not claim that a package has a fixed version unless that
   information is explicitly present in the supplied data.

10. Do not add external facts, references, exploit details, or
    remediation steps that are not supported by the supplied data.

11. If the source data contains contradictory or incomplete information,
    clearly state that limitation instead of resolving it yourself.

12. Do not omit any affected package from the explanation.

SOURCE DATA:

{serialized_data}

Write the explanation using exactly these six sections:

1. Vulnerability Overview
Explain what the vulnerability is, using the supplied description.
If the description is missing, state that it is unavailable.

2. Risk Assessment
Report the supplied risk level, risk score, CVSS information,
EPSS score, EPSS percentile, and KEV status when available.
Do not calculate or alter these values.
Explain when information is unavailable.

3. Affected Packages
List every affected package separately.
For each package, report its ecosystem and installed version status
when available.
Do not reconstruct or invent version ranges.

4. Installed Version Analysis
Explain whether an installed version was checked.
Only describe a package as affected when its status is AFFECTED.
If no installed-version check was performed, say so.

5. Recommendations
Use only the recommendations supplied in the source data.
Do not invent fixed versions or claim that a remediation is available
when the data does not establish this.

6. Data Limitations
Mention relevant missing or incomplete information.
In particular, distinguish unavailable risk data from evidence
that a vulnerability is rejected or harmless.

Be precise, cautious, and technically accurate.
Return a readable explanation, not JSON.
"""

 
    @staticmethod
    def _validate_generated_explanation(explanation: str, verified_facts: dict) -> list:
        """
        Detects a small set of contradictions between the LLM explanation
        and verified source facts. It does not rewrite the explanation.
        """
        warnings = []

        if not isinstance(explanation, str) or not isinstance(verified_facts, dict):
            return warnings

        risk = verified_facts.get("risk", {})
        if not isinstance(risk, dict):
            return warnings

        text = explanation.lower()

        # Split the explanation into individual sentences.
        sentences = re.split(r"(?<=[.!?])\s+", text)

        kev_positive = False
        kev_negative = False
        kev_unavailable = False

        unavailable_pattern = re.compile(
            r"\b(?:unavailable|not available|missing|unknown|not provided)\b"
        )
        kev_status_unavailable_pattern = re.compile(
            r"\b(?:kev|known exploited vulnerabilities)\b"
            r".{0,30}\bstatus\b.{0,20}"
            r"\b(?:unavailable|not available|missing|unknown|not provided|null)\b"
            r"|"
            r"\bstatus\b.{0,20}"
            r"\b(?:kev|known exploited vulnerabilities)\b"
            r".{0,30}"
            r"\b(?:unavailable|not available|missing|unknown|not provided|null)\b"
        )        

        negative_pattern = re.compile(
            r"\b(?:not\s+(?:listed|included|present|in)|"
            r"does\s+not\s+(?:appear|exist|feature)|"
            r"never\s+(?:listed|included|exploited)|"
            r"absent|excluded|not\s+present)\b"
        )

        positive_pattern = re.compile(
            r"\b(?:listed|included|present|appears)\b"
        )

        for sentence in sentences:
            mentions_kev = (
                "kev" in sentence
                or "known exploited vulnerabilities" in sentence
            )

            if not mentions_kev:
                continue

            if kev_status_unavailable_pattern.search(sentence):
                kev_unavailable = True

            negative_match = negative_pattern.search(sentence)
            positive_match = positive_pattern.search(sentence)

            if negative_match:
                kev_negative = True

            # Do not interpret "not listed" as a positive KEV claim.
            elif positive_match:
                kev_positive = True

        is_kev = risk.get("is_kev")

        if is_kev is True and (kev_negative or kev_unavailable):
            warnings.append(
                "KEV contradiction: the source indicates that the CVE is in KEV, "
                "but the explanation denies this or says the status is unavailable."
            )

        elif is_kev is False and (kev_positive or kev_unavailable):
            warnings.append(
                "KEV contradiction: the source indicates that the CVE is not "
                "in KEV, but the explanation claims it is listed or says the status is unavailable."
            )

        # Check EPSS percentile contradictions sentence by sentence.
        percentile = risk.get("epss_percentile")

        if percentile is not None:
            for sentence in sentences:
                mentions_percentile = (
                    "percentile" in sentence
                )

                says_unavailable = unavailable_pattern.search(sentence)

                if mentions_percentile and says_unavailable:
                    warnings.append(
                        "EPSS percentile contradiction: a percentile value exists "
                        "in the source data, but the explanation says it is unavailable."
                    )
                    break

        return warnings


    def explain(self, analysis: dict) -> dict:
        """
        Generate an explanation while preserving the original
        analyzer output as independently verifiable facts.
        """

        self._validate_analysis(analysis)

        verified_facts = {
            "description": copy.deepcopy(
                analysis.get("description")
            ),
            "advisories": copy.deepcopy(
                analysis.get("advisories", [])
            ),
            "risk": copy.deepcopy(
                analysis.get("risk", {})
            ),
            "affected_packages": copy.deepcopy(
                analysis.get("affected_packages", [])
            ),
            "recommendations": copy.deepcopy(
                analysis.get("recommendations", [])
            ),
            "installed_package_check_performed": copy.deepcopy(
                analysis.get(
                    "installed_package_check_performed",
                    False,
                )
            ),
        }

        prompt = self._build_prompt(analysis)

        explanation = self.provider.generate(prompt)

        if not isinstance(explanation, str):
            raise TypeError(
                "The LLM provider must return a string"
            )

        if not explanation.strip():
            raise ValueError(
                "The LLM provider returned an empty explanation"
            )
        validation_warnings = self._validate_generated_explanation(
            explanation,
            verified_facts,
        )
        return {
            "cve_id": analysis["cve_id"],
            "explanation": explanation.strip(),
            "risk": copy.deepcopy(analysis.get("risk", {})),
            "affected_packages": copy.deepcopy(
                analysis.get("affected_packages", [])
            ),
            "recommendations": copy.deepcopy(
                analysis.get("recommendations", [])
            ),
            "verified_facts": verified_facts,
            "validation_warnings": validation_warnings,
            "metadata": {
                "provider": self.provider.__class__.__name__,
                "llm_generated": True,
                "source_data_preserved": True,
            },
        }
