
from pathlib import Path
import requests


PROJECT_ROOT = Path(__file__).resolve().parents[2]

OUTPUT_DIR = PROJECT_ROOT / "data" / "raw" / "epss"

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def download_epss_dataset():

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    output_file = OUTPUT_DIR / "epss_scores-current.csv.gz"

    print("Downloading EPSS dataset...")

    response = requests.get(EPSS_URL, timeout=120)
    response.raise_for_status()

    with open(output_file, "wb") as file:
        file.write(response.content)

    print("EPSS download completed!")
    print("Saved to:", output_file)
    print("File size:", round(output_file.stat().st_size / (1024 * 1024), 2), "MB")


if __name__ == "__main__":
    download_epss_dataset()
