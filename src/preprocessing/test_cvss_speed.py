import json
from pathlib import Path
from collections import Counter
import time

OSV_DIR = Path("data/raw/osv")

start = time.time()

files = list(OSV_DIR.glob("*.json"))

print("Files found:", len(files), flush=True)

counts = Counter()

for index, path in enumerate(files):

    with path.open("r", encoding="utf-8") as file:
        record = json.load(file)

    for severity in record.get("severity", []):
        counts[severity.get("type", "UNKNOWN")] += 1

    if (index + 1) % 1000 == 0:
        print(
            f"Processed {index + 1}/{len(files)} files",
            flush=True
        )

print("\nResults:", counts)
print("Elapsed seconds:", round(time.time() - start, 2))