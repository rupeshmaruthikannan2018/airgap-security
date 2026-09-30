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

        finding = {
            "id": f"SEM-{index:03d}",
            "scanner": "semgrep",
            "type": "Source Code Vulnerability",
            "title": result.get("check_id", "Unknown"),
            "severity": extra.get("severity", "UNKNOWN"),
            "file": result.get("path"),
            "line_start": result.get("start", {}).get("line"),
            "line_end": result.get("end", {}).get("line"),
            "cwe": cwe,
            "description": extra.get("message", ""),
            "confidence": metadata.get("confidence"),
            "fix": extra.get("fix")
        }

        findings.append(finding)

    return findings


def normalize_trivy(results):
    findings = []

    counter = 1

    for result in results.get("Results", []):

        target = result.get("Target")

        for vulnerability in result.get("Vulnerabilities", []):

            finding = {
                "id": f"TRIVY-{counter:03d}",
                "scanner": "trivy",
                "type": "Dependency Vulnerability",
                "title": vulnerability.get("Title"),
                "severity": vulnerability.get("Severity", "UNKNOWN"),
                "file": target,
                "package": vulnerability.get("PkgName"),
                "installed_version": vulnerability.get("InstalledVersion"),
                "fixed_version": vulnerability.get("FixedVersion"),
                "cve": vulnerability.get("VulnerabilityID"),
                "cwe": (
                    vulnerability.get("CweIDs", [None])[0]
                    if vulnerability.get("CweIDs")
                    else None
                ),
                "description": vulnerability.get("Description", "")
            }

            findings.append(finding)

            counter += 1

    return findings


def normalize_nuclei(results):
    from nuclei_scanner import normalize_nuclei as norm_nuc
    return norm_nuc(results)


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

    for finding in findings:

        # Trivy CVEs are normally independent dependency findings.
        if finding["scanner"] != "semgrep":
            finding["related_findings"] = [finding["id"]]
            correlated.append(finding)
            continue

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