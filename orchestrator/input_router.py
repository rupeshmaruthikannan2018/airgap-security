"""Safe input classification and analysis routing for the security console.

The router deliberately chooses from an allow-list of local analyzers.  An LLM
may explain the results, but it never receives permission to construct or run a
shell command from uploaded content.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from report import generate_html_report
from remediation_planner import build_remediation_plan
from scanner_manager import normalize_trivy, save_findings
from trivy_scanner import run_trivy


SOURCE_SUFFIXES = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".c", ".cpp", ".cs"}
LOG_SUFFIXES = {".log", ".txt", ".evtx", ".pcap", ".jsonl"}


def classify_input(target: Path) -> dict:
    """Return a bounded analysis plan based on the actual uploaded artifact."""
    target = Path(target)
    if target.is_dir():
        names = {item.name.lower() for item in target.rglob("*") if item.is_file()}
        suffixes = {item.suffix.lower() for item in target.rglob("*") if item.is_file()}
        if {"server.xml", "nginx.conf", "httpd.conf", "docker-compose.yml"} & names:
            return _plan("application_server", ["server_configuration", "trivy_filesystem"],
                         "Server configuration markers were found in the extracted artifact.")
        if suffixes & SOURCE_SUFFIXES or {"package.json", "requirements.txt", "pom.xml", "go.mod"} & names:
            return _plan("source_code", ["semgrep", "trivy_filesystem"],
                         "Source files or dependency manifests were found in the extracted artifact.")
        return _plan("unknown", [], "No supported source, server, or log markers were found.")

    if target.suffix.lower() in LOG_SUFFIXES:
        return _plan("network_log", ["network_log_rules"], "The uploaded file has a log-like extension.")
    return _plan("unknown", [], "The artifact type is not supported by the local tool policy.")


def _plan(target_type: str, tools: list[str], reason: str) -> dict:
    return {"target_type": target_type, "selected_tools": tools, "selection_reason": reason,
            "execution_policy": "Only allow-listed local analyzers may run; uploaded data is never executed."}


def analyze_network_log(log_path: Path) -> list[dict]:
    """Analyze common text log indicators without executing or parsing log content as code."""
    try:
        lines = Path(log_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        raise RuntimeError(f"Could not read network log: {error}") from error

    rules = [
        ("NET-001", re.compile(r"failed password|authentication failure|invalid user", re.I), "HIGH",
         "Authentication failure detected", "Rate-limit or block the source if failures repeat, investigate the account, and enforce MFA or key-based authentication."),
        ("NET-002", re.compile(r"port scan|nmap|masscan|scan detected", re.I), "MEDIUM",
         "Possible reconnaissance or port scan", "Verify the source is authorized; otherwise block it and restrict exposed services with firewall rules."),
        ("NET-003", re.compile(r"sql injection|union select|/etc/passwd|\.\./", re.I), "HIGH",
         "Possible web exploitation attempt", "Review the affected request and application logs, patch input handling, and deploy WAF rules as a temporary control."),
        ("NET-004", re.compile(r"malware|c2 |command and control|beacon", re.I), "CRITICAL",
         "Possible malware command-and-control indicator", "Isolate the affected host, preserve evidence, block the indicator, and begin incident-response triage."),
    ]
    findings = []
    for finding_id, pattern, severity, title, remedy in rules:
        matches = [(number, line[:500]) for number, line in enumerate(lines, 1) if pattern.search(line)]
        if not matches:
            continue
        findings.append({
            "id": finding_id, "scanner": "network_log_rules", "type": "Network Log Indicator",
            "title": title, "severity": severity, "file": str(log_path),
            "line_start": matches[0][0], "line_end": matches[-1][0],
            "description": f"Detected {len(matches)} matching log entr{'y' if len(matches) == 1 else 'ies'}.",
            "evidence": [f"Line {number}: {line}" for number, line in matches[:5]],
            "remediation_plan": {"status": "requires_review", "action": "investigate_and_contain",
                                 "recommended_fix": remedy, "requires_patch_validation": False},
        })
    return findings


def analyze_server_configuration(server_path: Path) -> list[dict]:
    """Check a small, transparent baseline for commonly uploaded server configs."""
    findings = []
    checks = [
        ("server.xml", re.compile(r"<Connector[^>]+port=\"8080\"", re.I), "MEDIUM", "Tomcat HTTP connector exposed",
         "Put the connector behind TLS and a reverse proxy, restrict network access, and disable it if it is not required."),
        ("nginx.conf", re.compile(r"listen\s+80\b", re.I), "MEDIUM", "Nginx clear-text HTTP listener",
         "Redirect HTTP to HTTPS and configure a TLS listener with current protocols and ciphers."),
        ("docker-compose.yml", re.compile(r"privileged:\s*true", re.I), "HIGH", "Privileged container configuration",
         "Remove privileged mode and grant only the specific capabilities and mounts the service needs."),
    ]
    for expected_name, pattern, severity, title, remedy in checks:
        for file_path in server_path.rglob(expected_name):
            text = file_path.read_text(encoding="utf-8", errors="replace")
            matches = [(index, line) for index, line in enumerate(text.splitlines(), 1) if pattern.search(line)]
            if matches:
                findings.append({"id": f"CFG-{len(findings)+1:03d}", "scanner": "server_configuration",
                    "type": "Application Server Configuration", "title": title, "severity": severity,
                    "file": str(file_path.relative_to(server_path)), "line_start": matches[0][0], "line_end": matches[-1][0],
                    "description": "A configuration setting matches a local hardening rule.",
                    "evidence": [f"Line {number}: {line.strip()}" for number, line in matches[:5]],
                    "remediation_plan": {"status": "requires_review", "action": "harden_configuration",
                        "recommended_fix": remedy, "requires_patch_validation": True}})
    return findings


def run_routed_scan(target: Path, workspace: Path, application_scan) -> dict:
    """Run the preselected analyzer(s) and create a uniform report."""
    plan = classify_input(target)
    workspace.mkdir(parents=True, exist_ok=True)
    if plan["target_type"] == "source_code":
        result = application_scan(target, workspace)
        result["routing"] = plan
        return result
    if plan["target_type"] == "network_log":
        findings = analyze_network_log(target)
    elif plan["target_type"] == "application_server":
        findings = analyze_server_configuration(target)
        trivy_results = run_trivy(target, workspace / "trivy-results.json")
        if trivy_results is not None:
            findings.extend(normalize_trivy(trivy_results))
    else:
        raise ValueError(plan["selection_reason"])

    for finding in findings:
        finding.setdefault("remediation_plan", build_remediation_plan(finding))

    findings_file = workspace / "findings.json"
    report_file = workspace / "report.html"
    report = save_findings(findings, findings_file)
    report["routing"] = plan
    findings_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    generate_html_report(findings, target.name, report_file)
    return {"status": "completed", "target_type": plan["target_type"], "total_findings": len(findings),
            "findings_file": str(findings_file), "report_file": str(report_file), "findings": findings, "routing": plan}
