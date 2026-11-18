"""Compare Ollama models on real VulnGuard findings.

For every model the script runs each finding through LLMExplanationAgent and
reports how often the AI narrative is accepted, how often it needed the repair
attempt, how often it was withheld and why, and how long each explanation took.

Findings come from earlier scans stored in SQLite (default) or from a JSON file
containing a list of analyzer findings.

Examples:
    python -m src.agents.evaluate_llm --models llama3.2:3b,qwen2.5:3b
    python -m src.agents.evaluate_llm --models qwen2.5:7b --limit 10
    python -m src.agents.evaluate_llm --findings my_findings.json --models qwen2.5:3b
"""

import argparse
import json
import sqlite3
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from src.agents.llm.ollama_provider import OllamaProvider
from src.agents.llm_explanation import LLMExplanationAgent


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = PROJECT_ROOT / "data" / "vulnguard.db"
REPORTS_DIR = PROJECT_ROOT / "reports"
REQUIRED_FIELDS = ("cve_id", "risk", "description", "affected_packages", "recommendations")


def _is_finding(item) -> bool:
    return isinstance(item, dict) and all(field in item for field in REQUIRED_FIELDS)


def load_findings_from_db(db_path: Path = DEFAULT_DB) -> list[dict]:
    """Read explanation inputs saved by earlier scans, one per CVE."""

    if not db_path.exists():
        raise FileNotFoundError(
            f"No database at {db_path}. Run a scan first or pass --findings."
        )

    connection = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        rows = connection.execute(
            "SELECT result_json FROM scan_analysis_results ORDER BY analyzed_at DESC"
        ).fetchall()
    finally:
        connection.close()

    findings: dict[str, dict] = {}
    for (result_json,) in rows:
        result = json.loads(result_json)
        # verified_facts holds exactly the input the explanation agent received.
        candidates = [
            item.get("verified_facts")
            for item in result.get("llm_explanations", [])
            if isinstance(item, dict)
        ]
        candidates.extend(result.get("vulnerabilities", []))
        for candidate in candidates:
            if _is_finding(candidate) and candidate["cve_id"] not in findings:
                findings[candidate["cve_id"]] = candidate
    return list(findings.values())


def load_findings_from_file(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = [data]
    findings = [item for item in data if _is_finding(item)]
    if not findings:
        raise ValueError(f"{path} contains no finding with the fields {REQUIRED_FIELDS}.")
    return findings


def _error_type(error: str) -> str:
    return error.split(":", 1)[0]


def evaluate_model(
    model: str,
    findings: list[dict],
    provider_factory: Callable[[str], object] = lambda model: OllamaProvider(model=model),
) -> dict:
    agent = LLMExplanationAgent(provider=provider_factory(model))
    results = []

    for finding in findings:
        started = time.perf_counter()
        try:
            output = agent.explain(finding)
        except Exception as exc:  # Keep evaluating the remaining findings.
            results.append({
                "cve_id": finding.get("cve_id"),
                "status": "ERROR",
                "error": str(exc),
                "seconds": round(time.perf_counter() - started, 2),
            })
            continue

        calls = output["metadata"].get("llm_calls", [])
        results.append({
            "cve_id": finding.get("cve_id"),
            "status": output["narrative_status"],
            "repair_attempts": output["repair_attempts"],
            "narrative_errors": output["narrative_errors"],
            "validation_errors": output["validation_errors"],
            "context_may_be_truncated": output["metadata"].get("context_may_be_truncated"),
            "prompt_tokens": max(
                (call.get("prompt_tokens") or 0 for call in calls), default=None
            ),
            "seconds": round(time.perf_counter() - started, 2),
            "narrative": output["narrative"],
        })

    return {"model": model, "summary": summarize(results), "results": results}


def summarize(results: list[dict]) -> dict:
    total = len(results)

    def share(count: int) -> float:
        return round(100 * count / total, 1) if total else 0.0

    statuses = Counter(item["status"] for item in results)
    completed = [item for item in results if item["status"] != "ERROR"]
    repaired = sum(1 for item in completed if item.get("repair_attempts"))
    error_types = Counter(
        _error_type(error)
        for item in completed
        if item["status"] == "WITHHELD"
        for error in item.get("narrative_errors", [])
    )
    seconds = [item["seconds"] for item in completed]
    tokens = [item["prompt_tokens"] for item in completed if item.get("prompt_tokens")]

    return {
        "findings": total,
        "accepted_pct": share(statuses["ACCEPTED"]),
        "accepted_first_try_pct": share(
            sum(1 for item in completed
                if item["status"] == "ACCEPTED" and not item.get("repair_attempts"))
        ),
        "needed_repair_pct": share(repaired),
        "withheld_pct": share(statuses["WITHHELD"]),
        "errors": statuses["ERROR"],
        "full_text_validation_errors": sum(
            1 for item in completed if item.get("validation_errors")
        ),
        "possibly_truncated": sum(
            1 for item in completed if item.get("context_may_be_truncated")
        ),
        "avg_seconds": round(sum(seconds) / len(seconds), 1) if seconds else None,
        "max_prompt_tokens": max(tokens) if tokens else None,
        "withheld_reasons": dict(error_types.most_common()),
    }


def print_table(reports: list[dict]) -> None:
    columns = [
        ("model", "Model"),
        ("findings", "Findings"),
        ("accepted_pct", "Accepted %"),
        ("accepted_first_try_pct", "1st try %"),
        ("withheld_pct", "Withheld %"),
        ("errors", "Errors"),
        ("avg_seconds", "Avg s"),
        ("possibly_truncated", "Truncated"),
    ]
    rows = [
        [str(report["model"])] + [str(report["summary"][key]) for key, _ in columns[1:]]
        for report in reports
    ]
    widths = [
        max(len(title), *(len(row[index]) for row in rows))
        for index, (_, title) in enumerate(columns)
    ]
    print("  ".join(title.ljust(widths[i]) for i, (_, title) in enumerate(columns)))
    for row in rows:
        print("  ".join(value.ljust(widths[i]) for i, value in enumerate(row)))
    for report in reports:
        reasons = report["summary"]["withheld_reasons"]
        if reasons:
            print(f"\n{report['model']} withheld because of: {reasons}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--models",
        default=None,
        help="Comma-separated Ollama models. Default: OLLAMA_MODEL or llama3.2:3b.",
    )
    parser.add_argument("--findings", type=Path, help="JSON file with findings.")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite database path.")
    parser.add_argument("--limit", type=int, default=20, help="Maximum findings to use.")
    args = parser.parse_args(argv)

    findings = (
        load_findings_from_file(args.findings)
        if args.findings
        else load_findings_from_db(args.db)
    )[: args.limit]
    if not findings:
        print("No findings to evaluate. Run a scan first or pass --findings.")
        return 1

    models = (
        [model.strip() for model in args.models.split(",") if model.strip()]
        if args.models
        else [OllamaProvider().model]
    )

    print(f"Evaluating {len(models)} model(s) on {len(findings)} finding(s).\n")
    reports = []
    for model in models:
        print(f"Running {model}...")
        reports.append(evaluate_model(model, findings))

    print()
    print_table(reports)

    REPORTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = REPORTS_DIR / f"llm_eval_{stamp}.json"
    output_path.write_text(json.dumps(reports, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nFull results: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
