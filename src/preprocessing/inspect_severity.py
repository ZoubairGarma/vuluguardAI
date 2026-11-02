
import json
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OSV_DIR = PROJECT_ROOT / "data" / "raw" / "osv"


def inspect_severity():

    total_records = 0
    records_with_severity = 0

    severity_types = Counter()
    severity_scores = Counter()

    examples = []

    for path in OSV_DIR.glob("*.json"):

        with path.open("r", encoding="utf-8") as file:
            record = json.load(file)

        total_records += 1

        severity = record.get("severity", [])

        if severity:

            records_with_severity += 1

            for item in severity:

                severity_type = item.get("type", "UNKNOWN")
                score = item.get("score")

                severity_types[severity_type] += 1

                if score:
                    severity_scores[severity_type] += 1

                if len(examples) < 10:
                    examples.append({
                        "osv_id": record.get("id"),
                        "summary": record.get("summary"),
                        "severity_type": severity_type,
                        "score": score
                    })

    print("\n========== SEVERITY INSPECTION ==========")

    print("Total OSV records:", total_records)

    print("Records with severity:", records_with_severity)

    print(
        "Records without severity:",
        total_records - records_with_severity
    )

    print("\nSeverity types:")

    for severity_type, count in severity_types.most_common():
        print(f"{severity_type}: {count}")

    print("\nSeverity scores by type:")

    for severity_type, count in severity_scores.most_common():
        print(f"{severity_type}: {count}")

    print("\nSample severity records:")

    for example in examples:
        print("\nOSV ID:", example["osv_id"])
        print("Summary:", example["summary"])
        print("Type:", example["severity_type"])
        print("Score:", example["score"])

    print("\nSEVERITY INSPECTION COMPLETE")


if __name__ == "__main__":
    inspect_severity()
