import json
import sqlite3

import pytest

from src.agents.evaluate_llm import evaluate_model, load_findings_from_db, main


def finding(cve_id="CVE-2025-1"):
    return {
        "cve_id": cve_id,
        "risk": {"score": 40.0, "level": "MEDIUM", "is_kev": False},
        "description": "A path traversal issue.",
        "advisories": [],
        "affected_packages": [],
        "recommendations": ["Review the OSV advisory."],
    }


class FakeProvider:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.model = "fake"

    def generate(self, prompt):
        return self.outputs.pop(0)


GOOD = json.dumps({
    "summary": "A path traversal issue.",
    "impact_stated_in_source": False,
    "impact": "",
    "exposure_conditions": [],
    "limitations": [],
})


def test_evaluate_model_summarizes_outcomes():
    findings = [finding("CVE-2025-1"), finding("CVE-2025-2")]
    outputs = [GOOD, "not json", "still not json"]

    report = evaluate_model("fake", findings, provider_factory=lambda _: FakeProvider(outputs))

    summary = report["summary"]
    assert summary["findings"] == 2
    assert summary["accepted_pct"] == 50.0
    assert summary["withheld_pct"] == 50.0
    assert summary["needed_repair_pct"] == 50.0
    assert summary["withheld_reasons"] == {"Narrative format error": 1}


def test_provider_errors_are_counted_not_raised():
    class Down:
        model = "down"

        def generate(self, prompt):
            raise RuntimeError("Cannot connect to Ollama.")

    report = evaluate_model("down", [finding()], provider_factory=lambda _: Down())

    assert report["summary"]["errors"] == 1


def test_loads_unique_findings_from_database(tmp_path):
    db = tmp_path / "vulnguard.db"
    connection = sqlite3.connect(db)
    connection.execute(
        "CREATE TABLE scan_analysis_results (scan_id TEXT, result_json TEXT, analyzed_at TEXT)"
    )
    result = {
        "llm_explanations": [{"verified_facts": finding("CVE-2025-1")}],
        "vulnerabilities": [finding("CVE-2025-1"), finding("CVE-2025-2"), {"cve_id": "x"}],
    }
    connection.execute(
        "INSERT INTO scan_analysis_results VALUES (?, ?, ?)",
        ("scan-1", json.dumps(result), "2026-01-01"),
    )
    connection.commit()
    connection.close()

    findings = load_findings_from_db(db)

    assert sorted(item["cve_id"] for item in findings) == ["CVE-2025-1", "CVE-2025-2"]


def test_main_rejects_findings_file_without_findings(tmp_path):
    empty = tmp_path / "findings.json"
    empty.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="no finding"):
        main(["--findings", str(empty)])
