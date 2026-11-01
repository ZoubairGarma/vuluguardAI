
import io
import json
import zipfile
from pathlib import Path

import requests


# Project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Where raw OSV data will be stored
OUTPUT_DIR = PROJECT_ROOT / "data" / "raw" / "osv"

# Official OSV PyPI vulnerability archive
OSV_URL = (
    "https://osv-vulnerabilities.storage.googleapis.com/"
    "PyPI/all.zip"
)


def download_osv_dataset():
    """
    Download the complete OSV vulnerability archive for PyPI
    and extract individual JSON vulnerability records.
    """

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Downloading OSV PyPI vulnerability dataset...")

    response = requests.get(OSV_URL, timeout=120)
    response.raise_for_status()

    print("Download completed.")

    # Open the ZIP archive directly from memory
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:

        json_files = [
            name for name in archive.namelist()
            if name.endswith(".json")
        ]

        print(f"Found {len(json_files)} JSON files.")

        saved_count = 0

        for filename in json_files:

            try:
                content = archive.read(filename)
                vulnerability = json.loads(content)

                vulnerability_id = vulnerability.get("id")

                if not vulnerability_id:
                    continue

                output_file = OUTPUT_DIR / f"{vulnerability_id}.json"

                with open(output_file, "w", encoding="utf-8") as file:
                    json.dump(
                        vulnerability,
                        file,
                        indent=2,
                        ensure_ascii=False
                    )

                saved_count += 1

            except (json.JSONDecodeError, KeyError) as error:
                print(f"Skipping {filename}: {error}")

    print(f"Successfully saved {saved_count} vulnerability records.")
    print(f"Location: {OUTPUT_DIR}")


if __name__ == "__main__":
    download_osv_dataset()
