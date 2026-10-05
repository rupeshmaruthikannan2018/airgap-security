import json
from pathlib import Path


def normalize_semgrep(results):
    findings = []

    for index, result in enumerate(results.get("results", []), start=1):

        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        cwe = metadata.get("cwe", [])
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None

        cve = metadata.get("cve", [])
        if isinstance(cve, list):
            cve = cve[0] if cve else None

        line_start = result.get("start", {}).get("line")
        line_end = result.get("end", {}).get("line")
        code_lines = extra.get("lines", "")
        confidence = str(metadata.get("confidence") or "MEDIUM").upper()

        finding_id = f"SEM-{index:03d}"
        finding = {
            # Legacy fields
            "id": finding_id,
            "scanner": "semgrep",
            "type": "Source Code Vulnerability",
            "title": result.get("check_id", "Unknown"),
            "severity": extra.get("severity", "UNKNOWN"),
            "file": result.get("path"),
            "line_start": line_start,
            "line_end": line_end,
            "cwe": cwe,
            "cve": cve,
            "description": extra.get("message", ""),
            "confidence": confidence,
            "fix": extra.get("fix"),
            "code_context": code_lines,

            # Standard pipeline fields
            "finding_id": finding_id,
            "finding_type": "Source Code Vulnerability",
            "cve_id": cve,
            "package": None,
            "installed_version": None,
            "fixed_version": None,
            "cvss": None,
            "line": line_start,
            "message": extra.get("message", ""),
            "evidence": [code_lines] if code_lines else [],
            "source": "semgrep",
        }

        findings.append(finding)

    return findings


def normalize_trivy(results):
    findings = []
    counter = 1

    for result in results.get("Results", []):
        target = result.get("Target")

        # 1. Dependency Vulnerabilities
        for vulnerability in result.get("Vulnerabilities", []):
            finding_id = f"TRIVY-{counter:03d}"
            cve = vulnerability.get("VulnerabilityID")
            severity = vulnerability.get("Severity", "UNKNOWN")
            cwe_list = vulnerability.get("CweIDs", [])
            cwe = cwe_list[0] if cwe_list else None
            cvss_val = (
                vulnerability.get("CVSS", {}).get("nvd", {}).get("V3Score")
                or vulnerability.get("CVSS", {}).get("redhat", {}).get("V3Score")
            )

            finding = {
                # Legacy fields
                "id": finding_id,
                "scanner": "trivy",
                "type": "Dependency Vulnerability",
                "title": vulnerability.get("Title") or vulnerability.get("VulnerabilityID"),
                "severity": severity,
                "file": target,
                "package": vulnerability.get("PkgName"),
                "installed_version": vulnerability.get("InstalledVersion"),
                "fixed_version": vulnerability.get("FixedVersion"),
                "cve": cve,
                "cwe": cwe,
                "description": vulnerability.get("Description", ""),
                "cvss": cvss_val,

                # Standard pipeline fields
                "finding_id": finding_id,
                "finding_type": "Dependency Vulnerability",
                "cve_id": cve,
                "line": None,
                "line_start": None,
                "line_end": None,
                "message": vulnerability.get("Description", "") or vulnerability.get("Title", ""),
                "evidence": [f"Package: {vulnerability.get('PkgName')}@{vulnerability.get('InstalledVersion')}"],
                "source": "trivy",
                "confidence": "HIGH",
            }

            findings.append(finding)
            counter += 1

        # 2. Infrastructure Misconfigurations
        for misconfig in result.get("Misconfigurations", []):
            finding_id = f"TRIVY-CFG-{counter:03d}"
            cause_meta = misconfig.get("CauseMetadata", {})
            start_line = cause_meta.get("StartLine")
            end_line = cause_meta.get("EndLine")
            code_lines = cause_meta.get("Code", {}).get("Lines", [])
            code_evidence = [l.get("Content", "") for l in code_lines] if code_lines else []

            finding = {
                # Legacy fields
                "id": finding_id,
                "scanner": "trivy",
                "type": "Infrastructure Misconfiguration",
                "title": misconfig.get("Title") or misconfig.get("ID", "Misconfiguration"),
                "severity": misconfig.get("Severity", "UNKNOWN"),
                "file": target,
                "package": None,
                "installed_version": None,
                "fixed_version": None,
                "cve": None,
                "cwe": None,
                "description": misconfig.get("Description") or misconfig.get("Message", ""),
                "line_start": start_line,
                "line_end": end_line,
                "cvss": None,

                # Standard pipeline fields
                "finding_id": finding_id,
                "finding_type": "Infrastructure Misconfiguration",
                "cve_id": None,
                "line": start_line,
                "message": misconfig.get("Description") or misconfig.get("Message", ""),
                "evidence": code_evidence or [misconfig.get("Resolution", "")],
                "source": "trivy_misconfig",
                "confidence": "HIGH",
            }

            findings.append(finding)
            counter += 1

        # 3. Secret Leaks
        for secret in result.get("Secrets", []):
            finding_id = f"TRIVY-SEC-{counter:03d}"
            start_line = secret.get("StartLine")
            end_line = secret.get("EndLine")

            finding = {
                # Legacy fields
                "id": finding_id,
                "scanner": "trivy",
                "type": "Secret Finding",
                "title": secret.get("Title") or secret.get("RuleID", "Exposed Secret"),
                "severity": secret.get("Severity", "HIGH"),
                "file": target,
                "package": None,
                "installed_version": None,
                "fixed_version": None,
                "cve": None,
                "cwe": "CWE-798",
                "description": f"Exposed secret ({secret.get('Category', 'credential')}) detected in file.",
                "line_start": start_line,
                "line_end": end_line,
                "cvss": 7.5,

                # Standard pipeline fields
                "finding_id": finding_id,
                "finding_type": "Secret Finding",
                "cve_id": None,
                "line": start_line,
                "message": secret.get("Title", "Exposed Secret"),
                "evidence": [f"Matched rule: {secret.get('RuleID')}"],
                "source": "trivy_secret",
                "confidence": "HIGH",
            }

            findings.append(finding)
            counter += 1

    return findings


def normalize_nuclei(results):
    from nuclei_scanner import normalize_nuclei as norm_nuc
    findings = norm_nuc(results)
    for f in findings:
        f.setdefault("finding_id", f.get("id"))
        f.setdefault("finding_type", f.get("type", "Dynamic Validation Finding"))
        f.setdefault("cve_id", f.get("cve"))
        f.setdefault("line", f.get("line_start"))
        f.setdefault("message", f.get("description", ""))
        f.setdefault("evidence", [f.get("scanner_evidence")] if f.get("scanner_evidence") else [])
        f.setdefault("source", "nuclei")
        f.setdefault("confidence", "HIGH")
    return findings


def combine_findings(semgrep_results=None, trivy_results=None, nuclei_results=None):
    findings = []
    if semgrep_results:
        findings.extend(normalize_semgrep(semgrep_results))
    if trivy_results:
        findings.extend(normalize_trivy(trivy_results))
    if nuclei_results:
        findings.extend(normalize_nuclei(nuclei_results))
    return findings


def ranges_overlap(start1, end1, start2, end2):
    return start1 <= end2 and start2 <= end1


def correlate_findings(findings):

    correlated = []
    semgrep_groups = []
    cve_to_index = {}

    for finding in findings:

        # Semgrep findings are grouped by file and CWE
        if finding.get("scanner") == "semgrep":
            placed = False
            for group in semgrep_groups:
                representative = group[0]
                same_file = (
                    finding.get("file") ==
                    representative.get("file")
                )
                same_cwe = (
                    finding.get("cwe") is not None
                    and finding.get("cwe") ==
                    representative.get("cwe")
                )
                if not same_file or not same_cwe:
                    continue
                if ranges_overlap(
                    finding.get("line_start") or 0,
                    finding.get("line_end") or 0,
                    representative.get("line_start") or 0,
                    representative.get("line_end") or 0
                ):
                    group.append(finding)
                    placed = True
                    break
            if not placed:
                semgrep_groups.append([finding])
            continue

        # For dependency / live findings: deduplicate by CVE if present
        cve_raw = finding.get("cve") or finding.get("VulnerabilityID") or finding.get("cve_id")
        clean_cve = str(cve_raw).strip().upper() if cve_raw and str(cve_raw).strip().upper().startswith("CVE-") else None

        if clean_cve and clean_cve in cve_to_index:
            existing = correlated[cve_to_index[clean_cve]]
            existing.setdefault("related_findings", [existing["id"]]).append(finding["id"])

            # Merge Nuclei dynamic detection into existing finding
            if finding.get("scanner") == "nuclei":
                existing["nuclei_confirmed"] = True
                existing["nuclei_status"] = "confirmed"
                existing["validation_status"] = "CONFIRMED"
                existing["nuclei_matched_at"] = finding.get("matched_at")
                existing["nuclei_extracted_results"] = finding.get("extracted_results")
                existing["nuclei_curl_command"] = finding.get("curl_command")
                existing["template_found"] = True
                existing["template_id"] = finding.get("template_id")
                existing["template_name"] = finding.get("template_name")
                ev_list = existing.setdefault("nuclei_evidence", [])
                if finding.get("scanner_evidence") and finding["scanner_evidence"] not in ev_list:
                    ev_list.append(finding["scanner_evidence"])
                existing["scanner"] = f"{existing.get('scanner', 'trivy')}+nuclei"

            elif existing.get("scanner") == "nuclei" and finding.get("scanner") == "trivy":
                for field in ("package", "installed_version", "fixed_version", "cvss", "description", "title"):
                    if finding.get(field):
                        existing[field] = finding[field]
                existing["nuclei_confirmed"] = True
                existing["nuclei_status"] = "confirmed"
                existing["validation_status"] = "CONFIRMED"
                existing["scanner"] = f"trivy+{existing.get('scanner', 'nuclei')}"
            else:
                for k, v in finding.items():
                    if v and k not in existing:
                        existing[k] = v
        else:
            finding_copy = dict(finding)
            finding_copy["related_findings"] = [finding_copy["id"]]
            correlated.append(finding_copy)
            if clean_cve:
                cve_to_index[clean_cve] = len(correlated) - 1

    # Convert each Semgrep group into one representative finding.
    for group in semgrep_groups:

        representative = dict(group[0])

        representative["related_findings"] = [
            item["id"] for item in group
        ]

        representative["correlation_count"] = len(group)

        correlated.append(representative)

    return correlated


def save_findings(findings, output_file):

    output_file = Path(output_file)

    report = {
        "total_findings": len(findings),
        "findings": findings
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report