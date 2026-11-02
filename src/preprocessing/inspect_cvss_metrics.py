
import json
from pathlib import Path
from collections import Counter, defaultdict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OSV_DIR = PROJECT_ROOT / "data" / "raw" / "osv"

# Metrics shared by CVSS v3 and v4, plus version-specific metrics.
METRICS = {
    "CVSS_V3": [
        "AV", "AC", "PR", "UI", "S", "C", "I", "A"
    ],
    "CVSS_V4": [
        "AV", "AC", "AT", "PR", "UI",
        "VC", "VI", "VA", "SC", "SI", "SA", "E"
    ],
}


def parse_vector(vector):
    """Convert a CVSS vector string into a dictionary."""
    metrics = {}

    if not isinstance(vector, str):
        return metrics

    parts = vector.split("/")

    for part in parts[1:]:
        if ":" not in part:
            continue

        key, value = part.split(":", 1)
        metrics[key] = value

    return metrics


def inspect_cvss_metrics():
    value_counts = {
        version: defaultdict(Counter)
        for version in METRICS
    }

    vector_counts = Counter()
    records_with_both = 0
    records_with_v3 = 0
    records_with_v4 = 0
    invalid_vectors = []

    total_records = 0

    for path in OSV_DIR.glob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as file:
                record = json.load(file)
        except (OSError, json.JSONDecodeError) as error:
            print(f"Could not read {path.name}: {error}")
            continue

        total_records += 1

        found_versions = set()

        for severity in record.get("severity", []):
            version = severity.get("type")
            vector = severity.get("score")

            if version not in METRICS:
                continue

            if not isinstance(vector, str) or not vector.startswith("CVSS:"):
                invalid_vectors.append({
                    "osv_id": record.get("id"),
                    "type": version,
                    "score": vector,
                })
                continue

            found_versions.add(version)
            vector_counts[version] += 1

            parsed = parse_vector(vector)

            for metric in METRICS[version]:
                value = parsed.get(metric)

                if value is not None:
                    value_counts[version][metric][value] += 1

        if "CVSS_V3" in found_versions:
            records_with_v3 += 1

        if "CVSS_V4" in found_versions:
            records_with_v4 += 1

        if len(found_versions) == 2:
            records_with_both += 1

    print("\n========== CVSS METRIC INSPECTION ==========")

    print("Total OSV records inspected:", total_records)
    print("Records with CVSS v3:", records_with_v3)
    print("Records with CVSS v4:", records_with_v4)
    print("Records with both versions:", records_with_both)

    for version in METRICS:
        print(f"\n========== {version} ==========")
        print("Vector entries:", vector_counts[version])

        for metric in METRICS[version]:
            counts = value_counts[version][metric]

            if counts:
                print(f"\n{metric}:")

                for value, count in counts.most_common():
                    print(f"  {value}: {count}")

    print("\nInvalid or unexpected vectors:", len(invalid_vectors))

    for item in invalid_vectors[:10]:
        print(item)

    print("\nCVSS METRIC INSPECTION COMPLETE")


if __name__ == "__main__":
    inspect_cvss_metrics()
