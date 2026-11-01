
import json
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[2]

OUTPUT_DIR = PROJECT_ROOT / "data" / "raw" / "kev"

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def download_kev_dataset():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    output_file = OUTPUT_DIR / "known_exploited_vulnerabilities.json"

    print("Downloading CISA KEV dataset...")

    response = requests.get(KEV_URL, timeout=120)
    response.raise_for_status()

    data = response.json()

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)

    vulnerabilities = data.get("vulnerabilities", [])

    print("\nCISA KEV download completed!")
    print("Total vulnerabilities:", len(vulnerabilities))
    print("Catalog version:", data.get("catalogVersion"))
    print("Date released:", data.get("dateReleased"))
    print("Saved to:", output_file)


if __name__ == "__main__":
    download_kev_dataset()
