"""Runtime validation for the public scan and workflow JSON contracts."""

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


_SCHEMA_DIR = Path(__file__).with_name("schemas")
_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}


def _load_schema(name: str) -> dict[str, Any]:
    if name not in _SCHEMA_CACHE:
        path = _SCHEMA_DIR / f"{name}.schema.json"
        with path.open("r", encoding="utf-8") as schema_file:
            schema = json.load(schema_file)
        Draft202012Validator.check_schema(schema)
        _SCHEMA_CACHE[name] = schema
    return _SCHEMA_CACHE[name]


def validate_contract(
    document: Any,
    schema_name: str,
    *,
    label: str | None = None,
) -> Any:
    """Validate one document and raise a concise error with its JSON path."""
    schema = _load_schema(schema_name)
    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        details = []
        for error in errors[:5]:
            location = "/".join(str(part) for part in error.absolute_path) or "$"
            details.append(f"{location}: {error.message}")
        prefix = label or schema_name.replace("_", " ")
        raise ValueError(f"Invalid {prefix}: " + "; ".join(details))
    return document


def validate_scan_request(event: Any) -> dict:
    return validate_contract(event, "scan_request", label="scan request")


def validate_scan_error(event: Any) -> dict:
    return validate_contract(event, "scan_error", label="scan error event")


def validate_analysis_result(result: Any) -> dict:
    validated = validate_contract(
        result,
        "analysis_result",
        label="analysis result",
    )
    plans = validated.get("security_test_plans", [])
    for index, plan in enumerate(plans):
        try:
            validate_test_plan(plan)
        except ValueError as exc:
            raise ValueError(
                f"Invalid analysis result: security_test_plans/{index}: {exc}"
            ) from exc
    return validated


def validate_test_plan(plan: Any) -> dict:
    return validate_contract(plan, "test_plan", label="test plan")
