import subprocess
import json
from pathlib import Path


def run_trivy(app_path, output_file):
    app_path = Path(app_path)
    output_file = Path(output_file)

    command = [
        "trivy",
        "fs",
	"--skip-db-update",
        "--offline-scan",
        "--format", "json",
        "--output", str(output_file),
        str(app_path)
    ]

    print("[3/5] Running Trivy...")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode != 0:
        print("Trivy failed:")
        print(result.stderr)
        return None

    if not output_file.exists():
        print("Trivy did not create an output file.")
        return None

    with open(output_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    print("Trivy completed.")

    return data