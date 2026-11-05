
import copy
import json
import re
from decimal import Decimal, InvalidOperation

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

        risk = analysis.get("risk") or {}
        if not isinstance(risk, dict):
            risk = {}

        advisories = [
            {
                "osv_id": advisory.get("osv_id"),
                "summary": advisory.get("summary"),
                "details": advisory.get("details"),
                "published": advisory.get("published"),
                "modified": advisory.get("modified"),
            }
            for advisory in analysis.get("advisories", [])
        ]

        prompt_data = {
            "cve_id": analysis["cve_id"],
            "description": analysis.get("description"),
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
            "advisories": advisories,
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

STRICT VERSION RULES:
- Never invent, normalize, reformat, or infer version numbers.
- Preserve version strings exactly as supplied.
- An introduced version of "0" must remain "0".
- Do not transform "0" into "0.0.0-0" or another format.
- Explain "introduced: 0" only as the supplied OSV range boundary; do not
  describe it as a literal released package version or release date.
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
- Describe impact only when the supplied description or advisory explicitly
  supports it. A vulnerability title or class alone is not enough to infer
  data theft, code execution, privilege escalation, or other consequences.
- Do not add generic claims about what an attacker "may" do. If impact is
  not explicitly established by the supplied text, say it is unavailable.
- Keep Potential Impact and Analysis Limitations consistent: do not claim a
  specific impact in one section and say it is unavailable in another.
- If the supplied description/advisory contains only a title or a short
  summary, keep Potential Impact limited to what that text explicitly states.

Do not explain the JSON structure. Explain the vulnerability itself.

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
Write the entire explanation in English only; do not mix languages.
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
            risk = {}

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

        # Require key source facts to be represented exactly enough to
        # detect omissions or conflicting values in the generated report.
        cve_id = verified_facts.get("cve_id")
        if cve_id and str(cve_id).lower() not in text:
            warnings.append(
                f"CVE identifier missing: the explanation does not include {cve_id}."
            )

        numeric_fields = (
            "score",
            "cvss_score",
            "epss_score",
            "epss_percentile",
        )
        numeric_tokens = set()
        for token in re.findall(r"(?<![\w.])-?\d+(?:\.\d+)?", text):
            try:
                numeric_tokens.add(Decimal(token).normalize())
            except InvalidOperation:
                continue

        for field in numeric_fields:
            expected = risk.get(field)
            if expected is None:
                continue
            try:
                expected_number = Decimal(str(expected)).normalize()
            except InvalidOperation:
                continue
            if expected_number not in numeric_tokens:
                warnings.append(
                    f"Risk metric missing or mismatched: the supplied {field} "
                    "value is not stated accurately in the explanation."
                )

        level = risk.get("level")
        if level and str(level).lower() not in text:
            warnings.append(
                "Risk level missing or mismatched: the explanation does not "
                "state the supplied risk level."
            )

        package_records = verified_facts.get("affected_packages", [])
        if isinstance(package_records, list):
            for package in package_records:
                if not isinstance(package, dict):
                    continue
                package_name = package.get("package_name")
                if package_name and str(package_name).lower() not in text:
                    warnings.append(
                        f"Affected package missing: {package_name} is not mentioned."
                    )
                    continue

                installed_version = package.get("installed_version")
                if installed_version and str(installed_version).lower() not in text:
                    warnings.append(
                        f"Installed version missing: the supplied version for "
                        f"{package_name} ({installed_version}) is not mentioned."
                    )

                status = str(package.get("version_status") or "").upper()
                package_sentences = [
                    sentence for sentence in sentences
                    if package_name and str(package_name).lower() in sentence
                ]
                package_context = " ".join(package_sentences)
                if status == "AFFECTED" and re.search(
                    r"\b(?:not affected|unaffected|not vulnerable|outside the affected)\b",
                    package_context,
                ):
                    warnings.append(
                        f"Package status contradiction: {package_name} is AFFECTED "
                        "in the source data but described as not affected."
                    )
                elif status == "NOT_AFFECTED" and re.search(
                    r"\b(?:affected|vulnerable)\b", package_context
                ) and not re.search(
                    r"\b(?:not affected|unaffected|not vulnerable)\b",
                    package_context,
                ):
                    warnings.append(
                        f"Package status contradiction: {package_name} is NOT_AFFECTED "
                        "in the source data but described as affected."
                    )

                for fixed_version in package.get("fixed_versions", []) or []:
                    version_pattern = re.compile(
                        rf"(?<![\w.]){re.escape(str(fixed_version))}(?![\w.])",
                        re.IGNORECASE,
                    )
                    if not version_pattern.search(package_context):
                        warnings.append(
                            f"Fixed version missing: the OSV-supplied version "
                            f"{fixed_version} for {package_name} is not mentioned."
                        )

        # Avoid repeating the same warning when multiple checks detect it.
        return list(dict.fromkeys(warnings))


    def explain(self, analysis: dict) -> dict:
        """
        Generate an explanation while preserving the original
        analyzer output as independently verifiable facts.
        """

        self._validate_analysis(analysis)

        verified_facts = {
            "cve_id": copy.deepcopy(analysis.get("cve_id")),
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
