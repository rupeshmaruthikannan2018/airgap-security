"""Autonomous Tool-Calling Security Agent.

This module inspects arbitrary inputs (zip files, directories, code files, or network targets),
uses the LLM to autonomously determine which tools (Semgrep, Trivy, Nmap) to call, executes them,
and compiles the findings into remediation plans.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import zipfile
from pathlib import Path

from semgrep_scanner import run_semgrep
from trivy_scanner import run_trivy
from nmap_scanner import run_nmap
from scanner_manager import normalize_semgrep, normalize_trivy
from remediation_planner import build_remediation_plan
from local_llm import generate_response


def inspect_target(target_input: str | Path, workspace_root: Path = Path(r"C:\airgap-security\workspace")) -> dict:
    """
    Inspect the target input and prepare the inspection metadata for the LLM.
    """
    workspace_root.mkdir(parents=True, exist_ok=True)
    target_str = str(target_input).strip()

    # Check if target is a network host / IP address
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    hostname_pattern = r"^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$"
    if re.match(ip_pattern, target_str) or re.match(hostname_pattern, target_str) or target_str == "localhost":
        return {
            "type": "network_target",
            "target": target_str,
            "target_path": None,
            "files": [],
            "extensions": [],
            "manifests": [],
            "description": f"Target is a network host/IP address: {target_str}"
        }

    target_path = Path(target_str)
    
    # Check if target is a zip archive
    if target_path.is_file() and target_path.suffix.lower() == ".zip":
        extract_dir = workspace_root / f"extracted_{target_path.stem}"
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"[*] Extracting archive {target_path.name} to {extract_dir}...")
        with zipfile.ZipFile(target_path, "r") as z:
            z.extractall(extract_dir)
        target_path = extract_dir

    if target_path.is_dir():
        all_files = [f for f in target_path.rglob("*") if f.is_file()]
        rel_files = [str(f.relative_to(target_path)) for f in all_files]
        extensions = sorted(list({f.suffix.lower() for f in all_files if f.suffix}))
        manifest_names = {"requirements.txt", "package.json", "pom.xml", "go.mod", "gemfile", "cargo.toml"}
        manifests = [f for f in rel_files if Path(f).name.lower() in manifest_names]

        # Read sample snippets
        sample_code = []
        for f in all_files[:3]:
            try:
                content = f.read_text(encoding="utf-8", errors="replace")[:400]
                sample_code.append(f"File: {f.name}\n{content}")
            except Exception:
                pass

        return {
            "type": "filesystem_target",
            "target": str(target_path),
            "target_path": target_path,
            "file_count": len(all_files),
            "files": rel_files[:20],
            "extensions": extensions,
            "manifests": manifests,
            "sample_snippets": sample_code,
            "description": f"Directory target with {len(all_files)} files. Extensions: {extensions}. Manifests: {manifests}"
        }

    if target_path.is_file():
        return {
            "type": "file_target",
            "target": str(target_path),
            "target_path": target_path,
            "files": [target_path.name],
            "extensions": [target_path.suffix.lower()],
            "manifests": [target_path.name] if target_path.name.lower() in {"requirements.txt", "package.json"} else [],
            "description": f"Single file target: {target_path.name}"
        }

    return {
        "type": "unknown",
        "target": target_str,
        "target_path": None,
        "files": [],
        "extensions": [],
        "manifests": [],
        "description": f"Target could not be mapped to existing file, dir, or host: {target_str}"
    }


def select_tools_autonomously(metadata: dict) -> dict:
    """
    Query the LLM to autonomously select which tools (Semgrep, Trivy, Nmap) to run.
    """
    prompt = (
        f"Target Type: {metadata.get('type')}\n"
        f"Target Identifier: {metadata.get('target')}\n"
        f"Target Summary: {metadata.get('description')}\n"
        f"Discovered Files: {json.dumps(metadata.get('files', []))}\n"
        f"File Extensions: {json.dumps(metadata.get('extensions', []))}\n"
        f"Dependency Manifests: {json.dumps(metadata.get('manifests', []))}\n\n"
        "Available Tools:\n"
        "1. 'semgrep' -> Source code vulnerability scanner (Python, JS, Go, Java, etc.)\n"
        "2. 'trivy' -> Dependency & package vulnerability scanner (requirements.txt, package.json, etc.)\n"
        "3. 'nmap' -> Network service & open port scanner (for IP addresses and hostnames)\n\n"
        "Select the required tool(s) and explain the reason for each choice."
    )

    print("\n" + "=" * 60)
    print("[*] CONSULTING LLM FOR AUTONOMOUS TOOL SELECTION...")
    print("=" * 60)

    try:
        selection = generate_response(prompt, task="tool_selection")
        print(f"[+] LLM Autonomous Decision: {json.dumps(selection, indent=2)}")
        return selection
    except Exception as e:
        print(f"[-] LLM call encountered error or offline mode: {e}")
        print("[*] Falling back to intelligent heuristic tool selector...")
        return heuristic_tool_fallback(metadata)


def heuristic_tool_fallback(metadata: dict) -> dict:
    """
    Intelligent fallback tool selection when offline LLM backend is unavailable.
    """
    target_type = metadata.get("type")
    selected_tools = []

    if target_type == "network_target":
        selected_tools.append({
            "tool": "nmap",
            "reason": "Target is a network host/IP address requiring port and service audit.",
            "target_spec": metadata.get("target")
        })
        return {
            "target_type": "network_host",
            "selected_tools": selected_tools,
            "analysis_strategy": "Run Nmap network service scan against host."
        }

    extensions = set(metadata.get("extensions", []))
    manifests = set(metadata.get("manifests", []))
    code_extensions = {".py", ".js", ".ts", ".go", ".java", ".php", ".c", ".cpp", ".cs", ".rb"}

    if extensions & code_extensions:
        selected_tools.append({
            "tool": "semgrep",
            "reason": f"Source code files detected with extensions {list(extensions & code_extensions)}.",
            "target_spec": metadata.get("target")
        })

    if manifests or (extensions & {".txt", ".json", ".lock"}):
        selected_tools.append({
            "tool": "trivy",
            "reason": f"Dependency manifests detected: {list(manifests) if manifests else 'filesystem'}.",
            "target_spec": metadata.get("target")
        })

    if not selected_tools:
        selected_tools.append({
            "tool": "semgrep",
            "reason": "Defaulting to static source code analysis for directory.",
            "target_spec": metadata.get("target")
        })

    return {
        "target_type": "mixed_application" if len(selected_tools) > 1 else "source_code",
        "selected_tools": selected_tools,
        "analysis_strategy": "Execute all selected static and dependency vulnerability scanners.",
    }


def execute_autonomous_pipeline(target_input: str | Path) -> dict:
    """
    End-to-end autonomous analysis pipeline:
    1. Ingest & Inspect
    2. Autonomous LLM Tool Selection
    3. Tool Execution
    4. Normalization & Correlation
    5. Remediation Planning
    """
    workspace = Path(r"C:\airgap-security\workspace")
    metadata = inspect_target(target_input, workspace_root=workspace)
    
    print("\n" + "=" * 60)
    print(f"[*] AUTONOMOUS SECURITY AGENT INGESTION")
    print(f"[*] Target: {target_input}")
    print(f"[*] Identified Type: {metadata['type']}")
    print("=" * 60)

    # 1. LLM Tool Selection
    decision = select_tools_autonomously(metadata)
    raw_selected = decision.get("selected_tools", [])
    tools_to_run = []
    normalized_tool_items = []
    for item in raw_selected:
        if isinstance(item, dict):
            t_name = str(item.get("tool", "")).lower()
            t_reason = item.get("reason", decision.get("reasoning", ""))
            tools_to_run.append(t_name)
            normalized_tool_items.append({"tool": t_name, "reason": t_reason})
        elif isinstance(item, str):
            t_name = str(item).lower()
            t_reason = decision.get("reasoning", "")
            tools_to_run.append(t_name)
            normalized_tool_items.append({"tool": t_name, "reason": t_reason})
    
    all_findings = []
    
    # 2. Run chosen tools
    for tool_item in normalized_tool_items:
        tool_name = tool_item["tool"]
        reason = tool_item.get("reason", "")
        print(f"\n[>] Executing Tool: '{tool_name.upper()}' (Reason: {reason})")

        if tool_name == "semgrep":
            scan_target = metadata["target_path"] or Path(metadata["target"])
            semgrep_out = workspace / "semgrep_autonomous_out.json"
            semgrep_res = run_semgrep(scan_target, semgrep_out)
            if semgrep_res:
                norm_findings = normalize_semgrep(semgrep_res)
                print(f"[+] Semgrep found {len(norm_findings)} potential vulnerabilities.")
                all_findings.extend(norm_findings)

        elif tool_name == "trivy":
            scan_target = metadata["target_path"] or Path(metadata["target"])
            trivy_out = workspace / "trivy_autonomous_out.json"
            trivy_res = run_trivy(scan_target, trivy_out)
            if trivy_res:
                norm_findings = normalize_trivy(trivy_res)
                print(f"[+] Trivy found {len(norm_findings)} dependency vulnerabilities.")
                all_findings.extend(norm_findings)

        elif tool_name == "nmap":
            target_host = metadata["target"]
            nmap_out = workspace / "nmap_autonomous_out.xml"
            nmap_res = run_nmap(target_host, nmap_out)
            if nmap_res and "findings" in nmap_res:
                print(f"[+] Nmap identified {len(nmap_res['findings'])} exposed service findings.")
                all_findings.extend(nmap_res["findings"])

    print("\n" + "=" * 60)
    print(f"[*] AGGREGATING FINDINGS & BUILDING REMEDIATION PLANS")
    print(f"[*] Total Raw Findings: {len(all_findings)}")
    print("=" * 60)

    # 3. Build Remediation Plan for every finding
    remediated_findings = []
    for finding in all_findings:
        plan = build_remediation_plan(finding)
        finding["remediation_plan"] = plan
        remediated_findings.append(finding)

    final_report = {
        "target": str(target_input),
        "target_type": decision.get("target_type"),
        "autonomous_decision": decision,
        "tools_executed": tools_to_run,
        "total_findings": len(remediated_findings),
        "findings": remediated_findings
    }

    report_path = workspace / "autonomous_security_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=2)

    print(f"\n[+] Autonomous Security Run Complete! Report saved to: {report_path}")
    return final_report
