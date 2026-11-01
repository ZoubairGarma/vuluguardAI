import json
from pathlib import Path

OSV_DIR = Path(__file__).resolve().parent / "data" / "raw" / "osv"

files = list(OSV_DIR.glob("*.json"))

total = len(files)
readable = 0
with_affected = 0
invalid_json = []
unreadable = []

print("OSV DATASET VERIFICATION")
print("=" * 40)
print("Total JSON files:", total)

for index, path in enumerate(files, start=1):
    try:
        with path.open("r", encoding="utf-8") as file:
            vulnerability = json.load(file)

        readable += 1

        if vulnerability.get("affected"):
            with_affected += 1

    except json.JSONDecodeError as error:
        invalid_json.append((path.name, str(error)))

    except OSError as error:
        unreadable.append((path.name, str(error)))

    if index % 2000 == 0:
        print(f"Checked {index}/{total} files...")

print("\nFINAL RESULTS")
print("=" * 40)
print("Total files:", total)
print("Successfully readable:", readable)
print("Records with affected packages:", with_affected)
print("Invalid JSON:", len(invalid_json))
print("Unreadable files:", len(unreadable))

if invalid_json:
    print("\nFirst invalid JSON files:")
    for name, error in invalid_json[:10]:
        print(name, ":", error)

if unreadable:
    print("\nFirst unreadable files:")
    for name, error in unreadable[:10]:
        print(name, ":", error)