"""
Dedicated Nuclei Scanner Module for Air-Gapped Security Orchestrator.

Strict Requirements:
1. Runs Nuclei strictly against the running HTTP endpoint (e.g. http://localhost:8081),
   NEVER against the Docker container itself through an arbitrary shell target.
2. Treated as a separate discovery source: scanner = "nuclei".
3. Operates in strict air-gapped / offline mode:
   - -duc (disable automatic update check)
   - -ni (disable interactsh server)
   - -no-stdin (prevent terminal hang)
   - -jsonl (structured JSON lines output)
4. Preserves complete Nuclei evidence (template ID, name, severity, matched URL,
   matcher information, extracted results, curl command, references, CVE/CWE).
5. Preserves evaluation distinctions:
   - detected_by_scanner
   - applicable
   - prerequisite_satisfied
   - confirmed_exploitable
"""
from __future__ import annotations

import argparse
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple, Set
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_NUCLEI_BIN = Path(r"C:\airgap-security\tools\nuclei\nuclei.exe")
DEFAULT_TEMPLATES_DIR = Path(r"C:\Users\M Rupesh\nuclei-templates")


def find_nuclei_binary() -> Path:
    """Locate nuclei executable in project tools or system PATH."""
    if DEFAULT_NUCLEI_BIN.exists():
        return DEFAULT_NUCLEI_BIN

    which_path = shutil.which("nuclei")
    if which_path:
        return Path(which_path)

    local_appdata = os.environ.get("LOCALAPPDATA", "")
    if local_appdata:
        p = Path(local_appdata) / "nuclei" / "nuclei.exe"
        if p.exists():
            return p

    raise FileNotFoundError(
        f"Nuclei executable not found at '{DEFAULT_NUCLEI_BIN}' or in PATH."
    )


def get_default_tomcat_templates() -> list[str]:
    """
    Returns curated list of Tomcat-specific templates for rapid, reliable offline scans.
    """
    candidates = [
        DEFAULT_TEMPLATES_DIR / "http" / "technologies" / "apache" / "tomcat-detect.yaml",
        DEFAULT_TEMPLATES_DIR / "http" / "exposed-panels" / "apache" / "apache-tomcat-exposed.yaml",
        DEFAULT_TEMPLATES_DIR / "http" / "misconfiguration" / "tomcat-directory-listing.yaml",
        DEFAULT_TEMPLATES_DIR / "http" / "misconfiguration" / "tomcat-stacktraces.yaml",
        DEFAULT_TEMPLATES_DIR / "http" / "misconfiguration" / "tomcat-cookie-exposed.yaml",
        DEFAULT_TEMPLATES_DIR / "http" / "misconfiguration" / "tomcat-scripts.yaml",
        DEFAULT_TEMPLATES_DIR / "http" / "misconfiguration" / "apache" / "apache-tomcat-manager-panel.yaml",
        DEFAULT_TEMPLATES_DIR / "http" / "default-logins" / "apache" / "tomcat-default-login.yaml",
        DEFAULT_TEMPLATES_DIR / "http" / "cves" / "2025" / "CVE-2025-24813.yaml",
    ]
    return [str(p) for p in candidates if p.exists()]


def sanitize_target_url(target_url: str) -> str:
    """
    Ensures URL uses 127.0.0.1 rather than 'localhost' if running on Windows
    to guarantee Go's internal resolver succeeds in air-gapped / offline environments.
    """
    url = target_url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    
    # Replace localhost with 127.0.0.1 for Go network resolution safety
    url = re.sub(r"://localhost(?=[:/])", "://127.0.0.1", url)
    return url


def run_nuclei(
    target_url: str,
    output_file: str | Path,
    templates: list[str] | None = None,
    tags: str | None = None,
    extra_args: list[str] | None = None
) -> list[dict]:
    """
    Execute Nuclei against the specified live HTTP endpoint.

    Args:
        target_url: Live HTTP/web-service URL (e.g. http://localhost:8081).
        output_file: Path to write the raw JSONL output.
        templates: Optional list of specific template file or folder paths.
        tags: Optional comma-separated tags filter (e.g. 'tomcat').
        extra_args: Additional command line flags.

    Returns:
        List of raw Nuclei finding dictionaries parsed from JSONL.
    """
    nuclei_bin = find_nuclei_binary()
    resolved_url = sanitize_target_url(target_url)
    output_path = Path(output_file).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        str(nuclei_bin),
        "-u", resolved_url,
        "-duc",          # Disable automatic update check (air-gap constraint)
        "-ni",           # Disable interactsh server (air-gap constraint)
        "-no-stdin",     # Prevent stdin blocking on Windows
        "-jsonl",        # JSON lines format
        "-o", str(output_path)
    ]

    # Select templates
    if templates:
        for t in templates:
            command.extend(["-t", str(t)])
    elif tags:
        command.extend(["-tags", str(tags)])
    else:
        # Default to curated Tomcat suite for fast and targeted assessment
        tomcat_templates = get_default_tomcat_templates()
        if tomcat_templates:
            for t in tomcat_templates:
                command.extend(["-t", str(t)])
        elif DEFAULT_TEMPLATES_DIR.exists():
            command.extend(["-t", str(DEFAULT_TEMPLATES_DIR)])

    if extra_args:
        command.extend(extra_args)

    print(f"[NUCLEI] Scanning live HTTP endpoint: {resolved_url}")
    print(f"[NUCLEI] Executing: {' '.join(command[:6])} ... [flags]")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode != 0 and not output_path.exists():
        print(f"[NUCLEI] Execution returned code {result.returncode}:")
        if result.stderr:
            print(result.stderr.strip())

    raw_findings = []
    if output_path.exists():
        with output_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        raw_findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    print(f"[NUCLEI] Scan finished. Discovered raw template matches: {len(raw_findings)}")
    return raw_findings


def normalize_nuclei(raw_results: list[dict] | str | Path) -> list[dict]:
    """
    Normalize Nuclei findings into the project's canonical finding schema.
    
    Preserves:
    - template ID, template name, severity, matched URL
    - matcher & evidence information (curl command, extracted results, response snippet)
    - references
    - CVE & CWE identifiers where provided
    - Explicit evaluation distinction (detected_by_scanner vs applicable vs confirmed_exploitable)
    """
    if isinstance(raw_results, (str, Path)):
        p = Path(raw_results)
        if not p.exists():
            return []
        items = []
        with p.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        raw_results = items

    normalized = []
    for counter, item in enumerate(raw_results, start=1):
        info = item.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        metadata = info.get("metadata", {}) or {}

        # Extract CVE / CWE
        cve_id = classification.get("cve-id")
        if isinstance(cve_id, list):
            cve_id = cve_id[0] if cve_id else None
        elif not cve_id:
            # Check tags for cve pattern
            for tag in info.get("tags", []):
                m = re.match(r"(cve-\d{4}-\d{4,7})", str(tag), re.IGNORECASE)
                if m:
                    cve_id = m.group(1).upper()
                    break

        cwe_id = classification.get("cwe-id")
        if isinstance(cwe_id, list):
            cwe_id = cwe_id[0] if cwe_id else None
        elif isinstance(cwe_id, str) and "," in cwe_id:
            cwe_id = cwe_id.split(",")[0].strip()

        template_id = item.get("template-id") or item.get("templateID") or "unknown-template"
        template_name = info.get("name") or template_id
        severity = str(info.get("severity", "info")).upper()
        matched_url = item.get("matched-at") or item.get("url") or item.get("host")
        extracted_results = item.get("extracted-results", [])
        matcher_name = item.get("matcher-name")
        curl_command = item.get("curl-command")
        references = info.get("reference", [])
        if isinstance(references, str):
            references = [references]

        detected_product = metadata.get("product") or "Apache Tomcat"
        detected_version = extracted_results[0] if extracted_results else None

        # Build clean description
        description = info.get("description") or f"Nuclei template {template_id} triggered on {matched_url}."
        description = description.strip()

        # Preserve the distinction: detected != applicable != confirmed exploitable
        is_exploit_cve = bool(cve_id)
        evaluation_state = {
            "detected_by_nuclei": True,
            "applicable": True if "tomcat" in detected_product.lower() else None,
            "prerequisite_satisfied": False,
            "confirmed_exploitable": False,
            "requires_deterministic_evaluation": is_exploit_cve
        }

        finding = {
            "id": f"NUCLEI-TOMCAT-{counter:03d}",
            "scanner": "nuclei",
            "type": "live_service_vulnerability" if severity not in ("INFO", "UNKNOWN") else "service_detection",
            "title": template_name,
            "severity": severity,
            "confidence": "HIGH" if severity in ("CRITICAL", "HIGH") else "MEDIUM",
            "cve": cve_id,
            "cwe": cwe_id,
            "package": detected_product,
            "installed_version": detected_version,
            "fixed_version": None,
            "target": matched_url,
            "matched_at": matched_url,
            "template_id": template_id,
            "template_name": template_name,
            "matcher_name": matcher_name,
            "extracted_results": extracted_results,
            "curl_command": curl_command,
            "references": references,
            "description": description,
            "scanner_evidence": {
                "source": "Nuclei live HTTP scan",
                "template_id": template_id,
                "template_name": template_name,
                "severity": severity,
                "matched_at": matched_url,
                "matcher_name": matcher_name,
                "extracted_results": extracted_results,
                "curl_command": curl_command,
                "references": references,
                "cve": cve_id,
                "cwe": cwe_id,
                "description": description
            },
            "evaluation_state": evaluation_state
        }
        normalized.append(finding)

    return normalized


def save_nuclei_findings(findings: list[dict], output_file: str | Path) -> dict:
    """Save normalized Nuclei findings to JSON report."""
    output_path = Path(output_file).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "scanner": "nuclei",
        "total_findings": len(findings),
        "findings": findings
    }
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return report


# ======================================================================
# Targeted CVE Template Discovery & Single-Command Dynamic Validation
# ======================================================================

def resolve_templates_dir(custom_path: Optional[Path | str] = None) -> Path:
    """Resolve local Nuclei templates directory adhering to air-gap policies."""
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return p

    candidates = [
        DEFAULT_TEMPLATES_DIR,
        Path(__file__).resolve().parent.parent / "nuclei-templates",
        Path(__file__).resolve().parent / "nuclei-templates",
        Path(os.environ.get("USERPROFILE", "")) / "nuclei-templates",
    ]
    for c in candidates:
        if c.exists():
            return c

    return DEFAULT_TEMPLATES_DIR


def build_template_index(templates_dir: Optional[Path | str] = None) -> dict[str, list[str]]:
    """
    Build in-memory mapping of CVE IDs to local template file paths.
    Strictly offline: reads local .templates-index, cves.json, or file headers.
    """
    tdir = resolve_templates_dir(templates_dir)
    cve_map: dict[str, list[str]] = {}

    if not tdir.exists():
        return cve_map

    # 1. Fast path: .templates-index file (standard in Nuclei template releases)
    index_file = tdir / ".templates-index"
    if index_file.exists():
        try:
            with open(index_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.strip().split(",", 1)
                    if len(parts) == 2:
                        tid, p_str = parts[0].strip(), parts[1].strip()
                        m = re.match(r"^(CVE-\d{4}-\d{4,7})$", tid, re.IGNORECASE)
                        if m:
                            cid = m.group(1).upper()
                            cve_map.setdefault(cid, []).append(p_str)
        except Exception as e:
            print(f"[NUCLEI] Warning reading .templates-index: {e}")

    # 2. Check cves.json if available
    cves_json = tdir / "cves.json"
    if cves_json.exists():
        try:
            with open(cves_json, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        cid = record.get("ID")
                        rel_path = record.get("file_path")
                        if cid and rel_path and cid.upper().startswith("CVE-"):
                            full_path = str(tdir / rel_path)
                            cve_clean = cid.upper().strip()
                            if full_path not in cve_map.get(cve_clean, []):
                                cve_map.setdefault(cve_clean, []).append(full_path)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"[NUCLEI] Warning reading cves.json: {e}")

    return cve_map


def discover_template_for_cve(
    cve_id: str,
    templates_dir: Optional[Path | str] = None,
    template_index: Optional[dict[str, list[str]]] = None
) -> dict[str, Any]:
    """
    Locates appropriate local Nuclei template(s) for a given CVE ID.

    Lookup Procedure:
    1. Primary Lookup: direct path under nuclei-templates/http/cves/<year>/<CVE-ID>.yaml
    2. Fallback Lookup: local index / metadata / tag search (e.g. network/cves, cves.json)
    3. If neither found: returns template_found = False, nuclei_status = "no_dynamic_test_available"

    Returns dictionary with discovery metadata.
    """
    clean_cve = str(cve_id or "").strip().upper()
    tdir = resolve_templates_dir(templates_dir)

    m = re.match(r"^CVE-(\d{4})-\d+$", clean_cve)
    if not m:
        return {
            "cve_id": clean_cve,
            "template_found": False,
            "template_path": None,
            "template_paths": [],
            "discovery_method": None,
            "nuclei_ran": False,
            "nuclei_confirmed": False,
            "nuclei_status": "no_dynamic_test_available"
        }

    year = m.group(1)

    # 1. PRIMARY LOOKUP: Direct path in http/cves/<year>/<CVE-ID>.yaml (or .yml)
    direct_candidates = [
        tdir / "http" / "cves" / year / f"{clean_cve}.yaml",
        tdir / "http" / "cves" / year / f"{clean_cve}.yml",
        tdir / "http" / "cves" / year / f"{clean_cve.lower()}.yaml",
        tdir / "http" / "cves" / year / f"{clean_cve.lower()}.yml",
    ]

    for p in direct_candidates:
        if p.exists():
            return {
                "cve_id": clean_cve,
                "template_found": True,
                "template_path": str(p.resolve()),
                "template_paths": [str(p.resolve())],
                "discovery_method": "direct_path",
                "nuclei_ran": False,
                "nuclei_confirmed": False,
                "nuclei_status": "not_run"
            }

    # 2. FALLBACK LOOKUP: Local index / tag search (strictly offline, no internet calls)
    if template_index is None:
        template_index = build_template_index(tdir)

    matched_paths = template_index.get(clean_cve, [])
    valid_paths = []
    for p_str in matched_paths:
        p = Path(p_str)
        if p.exists():
            valid_paths.append(str(p.resolve()))

    # If still not found, check category subdirectories for filename match (e.g. network/cves, etc.)
    if not valid_paths and tdir.exists():
        for proto in ["network", "dns", "ssl", "dast", "cloud", "javascript"]:
            proto_cve = tdir / proto / "cves" / year / f"{clean_cve}.yaml"
            if proto_cve.exists():
                valid_paths.append(str(proto_cve.resolve()))

    if valid_paths:
        return {
            "cve_id": clean_cve,
            "template_found": True,
            "template_path": valid_paths[0],
            "template_paths": valid_paths,
            "discovery_method": "index_tag_search",
            "nuclei_ran": False,
            "nuclei_confirmed": False,
            "nuclei_status": "not_run"
        }

    # 3. Neither found: No dynamic test available
    return {
        "cve_id": clean_cve,
        "template_found": False,
        "template_path": None,
        "template_paths": [],
        "discovery_method": None,
        "nuclei_ran": False,
        "nuclei_confirmed": False,
        "nuclei_status": "no_dynamic_test_available"
    }


def discover_templates_for_cves(
    cve_ids: list[str],
    templates_dir: Optional[Path | str] = None
) -> dict[str, dict[str, Any]]:
    """
    Discover local Nuclei templates for a batch of CVE IDs.
    Builds the local index once for maximum performance.
    """
    tdir = resolve_templates_dir(templates_dir)
    template_index = build_template_index(tdir)
    results = {}
    for cve in cve_ids:
        results[cve] = discover_template_for_cve(cve, tdir, template_index)
    return results


def validate_cves_dynamically(
    target_url: str,
    cve_ids: list[str],
    templates_dir: Optional[Path | str] = None,
    output_file: Optional[Path | str] = None,
    extra_args: Optional[list[str]] = None
) -> dict[str, dict[str, Any]]:
    """
    Execute single-command Nuclei validation for a list of CVE IDs.

    Strict Requirements:
    1. Collects all matched local templates first.
    2. Builds ONE single Nuclei command using repeated -t <template_path>.
    3. Never launches one Nuclei process per CVE.
    4. Only passes matched templates, never the entire directory.
    5. Returns a structured result for EVERY input CVE, even when no template exists.
    6. Distinguishes confirmed, not_detected, execution_error, and no_dynamic_test_available.
    """
    resolved_target = sanitize_target_url(target_url)
    discoveries = discover_templates_for_cves(cve_ids, templates_dir)

    # Collect unique template paths
    unique_templates: list[str] = []
    template_to_cves: dict[str, list[str]] = {}

    for cve, disc in discoveries.items():
        if disc["template_found"] and disc["template_paths"]:
            for tpath in disc["template_paths"]:
                if tpath not in unique_templates:
                    unique_templates.append(tpath)
                template_to_cves.setdefault(tpath, []).append(cve)

    final_results: dict[str, dict[str, Any]] = {}

    # Case A: No templates discovered for any input CVE
    if not unique_templates:
        for cve in cve_ids:
            final_results[cve] = {
                "cve_id": cve,
                "template_found": False,
                "template_path": None,
                "discovery_method": None,
                "nuclei_ran": False,
                "nuclei_confirmed": False,
                "nuclei_status": "no_dynamic_test_available",
                "matched_at": None,
                "extracted_results": [],
                "curl_command": None,
                "detection_details": None
            }
        return final_results

    # Case B: Execute ONE Nuclei command with all matched templates
    out_path = Path(output_file).resolve() if output_file else (
        Path(r"C:\airgap-security\workspace\nuclei-dynamic-validation.jsonl")
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        try:
            out_path.unlink()
        except Exception:
            pass

    nuclei_bin = find_nuclei_binary()
    command = [
        str(nuclei_bin),
        "-u", resolved_target,
        "-duc",          # Disable automatic update check (air-gap constraint)
        "-ni",           # Disable interactsh server (air-gap constraint)
        "-no-stdin",     # Prevent terminal hang on Windows
        "-jsonl",        # JSON lines output format
        "-o", str(out_path)
    ]

    for t in sorted(unique_templates):
        command.extend(["-t", str(t)])

    if extra_args:
        command.extend(extra_args)

    print(f"[NUCLEI] Dynamic validation for {len(cve_ids)} CVEs using {len(unique_templates)} templates.")
    print(f"[NUCLEI] Executing single batched command against: {resolved_target}")

    try:
        proc_result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        execution_success = (proc_result.returncode == 0) or out_path.exists()
        error_msg = proc_result.stderr.strip() if proc_result.returncode != 0 else None
    except Exception as ex:
        execution_success = False
        error_msg = str(ex)

    # Parse JSONL output
    detections: list[dict] = []
    if out_path.exists():
        with open(out_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        detections.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    # Map detections to CVEs
    confirmed_cves: dict[str, dict[str, Any]] = {}
    for item in detections:
        info = item.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        matched_cve = None

        # Check classification cve-id
        cve_val = classification.get("cve-id")
        if isinstance(cve_val, list) and cve_val:
            matched_cve = str(cve_val[0]).strip().upper()
        elif isinstance(cve_val, str) and cve_val.strip():
            matched_cve = cve_val.strip().upper()

        # Check tags or template ID
        if not matched_cve:
            tid = str(item.get("template-id") or item.get("templateID") or "")
            m_tid = re.search(r"(CVE-\d{4}-\d{4,7})", tid, re.IGNORECASE)
            if m_tid:
                matched_cve = m_tid.group(1).upper()

        if not matched_cve:
            for tag in info.get("tags", []):
                m_tag = re.search(r"(CVE-\d{4}-\d{4,7})", str(tag), re.IGNORECASE)
                if m_tag:
                    matched_cve = m_tag.group(1).upper()
                    break

        # Check template path mapping fallback
        if not matched_cve:
            t_path_used = item.get("template-path") or item.get("template")
            if t_path_used and t_path_used in template_to_cves:
                matched_cve = template_to_cves[t_path_used][0]

        if matched_cve:
            confirmed_cves[matched_cve] = {
                "matched_at": item.get("matched-at") or item.get("url") or item.get("host"),
                "extracted_results": item.get("extracted-results", []),
                "curl_command": item.get("curl-command"),
                "template_id": item.get("template-id") or item.get("templateID"),
                "raw_finding": item
            }

    # Synthesize per-CVE results
    for cve in cve_ids:
        disc = discoveries.get(cve, {})
        has_template = disc.get("template_found", False)
        t_path = disc.get("template_path")
        method = disc.get("discovery_method")

        if not has_template:
            final_results[cve] = {
                "cve_id": cve,
                "template_found": False,
                "template_path": None,
                "discovery_method": None,
                "nuclei_ran": False,
                "nuclei_confirmed": False,
                "nuclei_status": "no_dynamic_test_available",
                "matched_at": None,
                "extracted_results": [],
                "curl_command": None,
                "detection_details": None
            }
        elif not execution_success:
            final_results[cve] = {
                "cve_id": cve,
                "template_found": True,
                "template_path": t_path,
                "discovery_method": method,
                "nuclei_ran": False,
                "nuclei_confirmed": False,
                "nuclei_status": "execution_error",
                "error_message": error_msg,
                "matched_at": None,
                "extracted_results": [],
                "curl_command": None,
                "detection_details": None
            }
        elif cve in confirmed_cves:
            det = confirmed_cves[cve]
            final_results[cve] = {
                "cve_id": cve,
                "template_found": True,
                "template_path": t_path,
                "discovery_method": method,
                "nuclei_ran": True,
                "nuclei_confirmed": True,
                "nuclei_status": "confirmed",
                "matched_at": det.get("matched_at"),
                "extracted_results": det.get("extracted_results", []),
                "curl_command": det.get("curl_command"),
                "detection_details": det
            }
        else:
            final_results[cve] = {
                "cve_id": cve,
                "template_found": True,
                "template_path": t_path,
                "discovery_method": method,
                "nuclei_ran": True,
                "nuclei_confirmed": False,
                "nuclei_status": "not_detected",
                "matched_at": None,
                "extracted_results": [],
                "curl_command": None,
                "detection_details": None
            }

    return final_results


def main():
    parser = argparse.ArgumentParser(description="Air-Gapped Nuclei Scanner for Tomcat")
    parser.add_argument("--target", "-u", default="http://localhost:8081", help="Target HTTP URL")
    parser.add_argument("--output", "-o", default=None, help="Output JSON report path")
    parser.add_argument("--templates", "-t", nargs="*", help="Specific template paths")
    parser.add_argument("--tags", help="Tags filter")
    args = parser.parse_args()

    out_file = Path(args.output) if args.output else Path(r"C:\airgap-security\workspace\nuclei-findings.json")
    raw_jsonl = out_file.with_suffix(".jsonl")

    raw_items = run_nuclei(args.target, raw_jsonl, templates=args.templates, tags=args.tags)
    normalized = normalize_nuclei(raw_items)
    save_nuclei_findings(normalized, out_file)
    print(f"[NUCLEI] Saved {len(normalized)} normalized findings to {out_file}")


if __name__ == "__main__":
    main()
