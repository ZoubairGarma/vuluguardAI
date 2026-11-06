# Local scan contracts

The scan workflow uses JSON schema version `1.0` for scan requests, scan errors,
analysis results, and declarative test plans. The schemas live in
`src/contracts/schemas/` and are validated by the producer, SQLite persistence
boundary, analysis result serializer, plan generator, and human approval gate.

## Scan request

A request contains a UUID `scan_id`, `event_type: "scan_request"`,
`schema_version: "1.0"`, a non-empty `project_name`, an ISO 8601
`submitted_at`, and at least one dependency. Each dependency contains non-empty
`ecosystem`, `name`, and exact `version` strings. The integrated analyzer
currently supports PyPI only; other ecosystems are reported as unresolved.

## Analysis result

An analysis result contains `scan_id`, `vulnerabilities`, and `unresolved`.
Risk, ML, LLM, test plan, and final report sections are optional so older
persisted results remain readable. New results carry `schema_version: "1.0"`.
Each included security test plan is validated against its own schema.

## Declarative test plan

Plans identify a CVE and contain tests with approval and execution statuses.
The only accepted test type is `PACKAGE_VERSION_CHECK`. Its checks are a fixed
allowlist: wheel installability, package metadata matching the exact pin, and
OSV range classification. The host downloads a single pinned PyPI wheel with
binary-only pip options. The constrained Docker container installs only that
local wheel with `--no-index` and `--network=none`, then reads distribution
metadata without importing the package. The three check results must all pass
before the workflow reports verification success. Plans contain no shell
commands or package-provided test code. A reviewer must approve the plan before
the executor runs it.

## Local end-to-end path

`tests/test_local_workflow_e2e.py` covers event construction, SQLite scan
ingestion, analysis and plan generation, human approval, allowlisted execution,
result verification, and report persistence. It replaces only the external
LLM and Docker boundaries; Kafka transport is bypassed by calling the consumer's
local event handler directly. The production Docker verifier performs the
offline wheel inspection described above.
