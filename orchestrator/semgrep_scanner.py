import subprocess
import json
from pathlib import Path


SEMGREP_TIMEOUT_SECONDS = 120


def run_semgrep(app_path, output_file):
    app_path = Path(app_path)
    output_file = Path(output_file)

    # Use only the locally stored Semgrep rules.
    #
    # IMPORTANT:
    # The installed Semgrep version does not support --offline.
    # Network-related checks are therefore disabled through:
    #   --disable-version-check
    #   --metrics=off
    #
    # The --config path points directly to our local rule directory,
    # so we do not use "auto" or a remote Semgrep registry.
    command = [
        "semgrep",
        "--disable-version-check",
        "--metrics=off",
        "--config",
        r"C:\airgap-security\rules\semgrep",
        "--json",
        "--output",
        str(output_file),
        str(app_path)
    ]

    print("[2/5] Running Semgrep...")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=SEMGREP_TIMEOUT_SECONDS
        )

    except subprocess.TimeoutExpired:
        print(
            "Semgrep timed out after "
            f"{SEMGREP_TIMEOUT_SECONDS} seconds."
        )
        return None

    # Semgrep normally returns:
    #   0 -> scan completed with no findings
    #   1 -> scan completed with findings
    #
    # Both are successful scan results.
    if result.returncode not in [0, 1]:
        print("Semgrep failed:")

        if result.stderr:
            print(result.stderr)

        if result.stdout:
            print(result.stdout)

        return None

    if not output_file.exists():
        print("Semgrep did not create an output file.")
        return None

    try:
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)

    except json.JSONDecodeError as e:
        print("Semgrep produced invalid JSON:")
        print(e)
        return None

    print("Semgrep completed.")

    return data