import subprocess
import json
import time
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

    start_time = time.time()
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

    duration = round(time.time() - start_time, 3)

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

    meta = {
        "command": command,
        "rule_dir": r"C:\airgap-security\rules\semgrep",
        "returncode": result.returncode,
        "execution_time_seconds": duration,
        "output_file": str(output_file),
    }
    meta_path = output_file.parent / f"{output_file.stem}_meta.json"
    try:
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    except Exception:
        pass

    if isinstance(data, dict):
        data["_execution_metadata"] = meta

    print(f"Semgrep completed in {duration}s.")

    return data