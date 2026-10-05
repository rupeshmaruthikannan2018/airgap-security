import subprocess
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def get_trivy_version_info() -> Dict[str, str]:
    """Retrieves cached or dynamic version and database information from trivy."""
    info = {
        "scanner_version": "unknown",
        "vulnerability_db_version": "unknown",
        "vulnerability_db_updated_at": "unknown",
        "java_db_version": "unknown",
    }
    try:
        res = subprocess.run(
            ["trivy", "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10
        )
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                line_str = line.strip()
                if line_str.startswith("Version:"):
                    info["scanner_version"] = line_str.replace("Version:", "").strip()
                elif "UpdatedAt:" in line_str and info["vulnerability_db_updated_at"] == "unknown":
                    info["vulnerability_db_updated_at"] = line_str.replace("UpdatedAt:", "").strip()
                elif line_str.startswith("Version:") and "Vulnerability DB" in res.stdout:
                    pass
    except Exception:
        pass
    return info


def run_trivy(
    app_path: Path | str,
    output_file: Path | str,
    scanners: Optional[List[str]] = None
) -> Optional[Dict[str, Any]]:
    """
    Run Trivy filesystem scanner with configured scanner modules.

    Supports:
        scanners = ["vuln", "secret"] (default)
        scanners = ["vuln", "secret", "misconfig"] (when infra/config present)
        scanners = ["vuln", "secret", "misconfig", "license"] (when license scans requested)

    Captures:
        - command
        - exit code
        - stdout/stderr
        - execution time
        - output JSON path
        - scanner version
        - database metadata
    """
    app_path = Path(app_path).resolve()
    output_file = Path(output_file).resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Clean and validate requested scanners
    allowed_scanners = {"vuln", "secret", "misconfig", "license"}
    if scanners:
        chosen_scanners = [s.strip().lower() for s in scanners if s.strip().lower() in allowed_scanners]
    else:
        chosen_scanners = ["vuln", "secret"]

    if not chosen_scanners:
        chosen_scanners = ["vuln", "secret"]

    command = [
        "trivy",
        "fs",
        "--skip-db-update",
        "--offline-scan",
        "--scanners",
        ",".join(chosen_scanners),
        "--format", "json",
        "--output", str(output_file),
        str(app_path)
    ]

    print(f"[Trivy] Running filesystem scan with scanners: {','.join(chosen_scanners)}...")

    start_time = time.time()
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300
        )
    except subprocess.TimeoutExpired as e:
        print(f"Trivy timed out after 300 seconds.")
        return None
    except Exception as e:
        print(f"Trivy execution error: {e}")
        return None

    duration = round(time.time() - start_time, 3)
    version_info = get_trivy_version_info()

    execution_meta = {
        "command": command,
        "scanners": chosen_scanners,
        "returncode": result.returncode,
        "execution_time_seconds": duration,
        "output_file": str(output_file),
        "scanner_version": version_info.get("scanner_version"),
        "vulnerability_db_version": version_info.get("vulnerability_db_version"),
        "vulnerability_db_updated_at": version_info.get("vulnerability_db_updated_at"),
        "stdout": result.stdout[:2000] if result.stdout else "",
        "stderr": result.stderr[:2000] if result.stderr else "",
    }

    # Save execution meta alongside output file
    meta_path = output_file.parent / f"{output_file.stem}_meta.json"
    try:
        meta_path.write_text(json.dumps(execution_meta, indent=2), encoding="utf-8")
    except Exception:
        pass

    if result.returncode != 0:
        print("Trivy failed with non-zero exit code:")
        print(result.stderr)
        return None

    if not output_file.exists():
        print("Trivy did not create an output file.")
        return None

    try:
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as err:
        print(f"Trivy output invalid JSON: {err}")
        return None

    # Attach execution metadata to returned dict
    if isinstance(data, dict):
        data["_execution_metadata"] = execution_meta

    print(f"Trivy completed in {duration}s.")
    return data