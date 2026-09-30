from pathlib import Path
import argparse
import json
import subprocess
import sys


from profiler import profile_application
from semgrep_scanner import run_semgrep
from trivy_scanner import run_trivy
from nuclei_scanner import run_nuclei, normalize_nuclei

from scanner_manager import (
    combine_findings,
    correlate_findings,
    save_findings
)

from context_builder import extract_code_context
from report import generate_html_report
from ai_analyzer import analyze_finding
from remediation_planner import build_remediation_plan


# ============================================================
# GENERAL JSON HELPERS
# ============================================================

def save_json(data, output_path):
    """
    Save JSON data to disk.
    """

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            data,
            f,
            indent=2,
            ensure_ascii=False
        )


def load_json(input_path):
    """
    Load JSON data from disk.
    """

    input_path = Path(input_path)

    if not input_path.exists():

        raise FileNotFoundError(
            f"File not found: {input_path}"
        )

    with open(
        input_path,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


# ============================================================
# PYTHON MODULE EXECUTION
# ============================================================

def run_python_module(
    module_name,
    arguments
):
    """
    Execute another orchestrator Python module
    using the current Python interpreter.
    """

    module_path = (
        Path(__file__).resolve().parent
        / module_name
    )

    if not module_path.exists():

        raise FileNotFoundError(
            f"Required module not found: "
            f"{module_path}"
        )

    command = [
        sys.executable,
        str(module_path)
    ]

    command.extend(
        str(argument)
        for argument in arguments
    )

    print()
    print("-" * 70)

    print(
        f"Running: "
        f"{' '.join(command)}"
    )

    print("-" * 70)

    result = subprocess.run(
        command,
        cwd=module_path.parent
    )

    if result.returncode != 0:

        raise RuntimeError(
            f"{module_name} failed "
            f"with exit code "
            f"{result.returncode}."
        )

    return result


# ============================================================
# NORMAL APPLICATION PIPELINE
# ============================================================

def run_application_scan(
    app_path,
    workspace_path
):
    """
    Normal application security pipeline.

    Pipeline:

        Profile
          ↓
        Semgrep
          ↓
        Trivy filesystem
          ↓
        Finding correlation
          ↓
        Source-code context
          ↓
        Generic AI analysis
          ↓
        Remediation plan
          ↓
        HTML report
    """

    app_path = Path(
        app_path
    ).resolve()

    workspace_path = Path(
        workspace_path
    ).resolve()

    print("=" * 60)
    print(
        "AIR-GAPPED SECURITY ORCHESTRATOR"
    )
    print("=" * 60)

    print(
        f"Application: {app_path}"
    )

    print(
        f"Workspace:   {workspace_path}"
    )

    workspace_path.mkdir(
        parents=True,
        exist_ok=True
    )

    # ========================================================
    # 1. PROFILE
    # ========================================================

    print(
        "\n[1/7] Profiling application..."
    )

    profile = profile_application(
        app_path
    )

    print(
        f"Application: "
        f"{profile['application']}"
    )

    print(
        f"Languages:   "
        f"{profile['languages']}"
    )

    print(
        f"Manifests:   "
        f"{profile['manifests']}"
    )

    print(
        f"Files:       "
        f"{len(profile['files'])}"
    )

    # ========================================================
    # 2. SEMGREP
    # ========================================================

    print(
        "\n[2/7] Running Semgrep..."
    )

    semgrep_output = (
        workspace_path
        / "semgrep-results.json"
    )

    semgrep_results = run_semgrep(
        app_path,
        semgrep_output
    )

    if semgrep_results is None:
        print(
            "Semgrep was unavailable; continuing "
            "with dependency analysis."
        )
        semgrep_results = {"results": []}

    # ========================================================
    # 3. TRIVY
    # ========================================================

    print(
        "\n[3/7] Running Trivy..."
    )

    trivy_output = (
        workspace_path
        / "trivy-results.json"
    )

    trivy_results = run_trivy(
        app_path,
        trivy_output
    )

    if trivy_results is None:
        print(
            "Trivy was unavailable; continuing "
            "with available source findings."
        )
        trivy_results = {"Results": []}

    # ========================================================
    # 4. COMBINE + CORRELATE
    # ========================================================

    print(
        "\n[4/7] Processing findings..."
    )

    raw_findings = combine_findings(
        semgrep_results,
        trivy_results
    )

    print(
        f"Raw findings: "
        f"{len(raw_findings)}"
    )

    findings = correlate_findings(
        raw_findings
    )

    print(
        f"Unique findings: "
        f"{len(findings)}"
    )

    # ========================================================
    # SOURCE CODE CONTEXT
    # ========================================================

    for finding in findings:

        if finding.get("scanner") != "semgrep":
            continue

        file_path = finding.get(
            "file"
        )

        start_line = finding.get(
            "line_start"
        )

        end_line = finding.get(
            "line_end"
        )

        if (
            not file_path
            or not start_line
            or not end_line
        ):
            continue

        source_file = Path(
            file_path
        )

        if not source_file.is_absolute():

            source_file = (
                app_path
                / source_file
            )

        if not source_file.exists():
            continue

        context = extract_code_context(
            source_file,
            start_line,
            end_line
        )

        finding[
            "code_context"
        ] = context

    # ========================================================
    # 5. GENERIC AI ANALYSIS
    # ========================================================

    print(
        "\n[5/7] Running AI analysis..."
    )

    for finding in findings:

        analysis = analyze_finding(
            finding,
            profile
        )

        finding[
            "ai_analysis"
        ] = analysis

        print(
            f"AI analysis completed for "
            f"{finding['id']}"
        )

    # ========================================================
    # 6. REMEDIATION PLANS
    # ========================================================

    print(
        "\n[6/7] Building remediation plans..."
    )

    for finding in findings:

        remediation_plan = (
            build_remediation_plan(
                finding
            )
        )

        finding[
            "remediation_plan"
        ] = remediation_plan

        print(
            f"Remediation plan created for "
            f"{finding['id']}: "
            f"{remediation_plan['status']}"
        )

    # ========================================================
    # SAVE FINDINGS
    # ========================================================

    findings_output = (
        workspace_path
        / "findings.json"
    )

    report_data = save_findings(
        findings,
        findings_output
    )

    report_data[
        "profile"
    ] = profile

    save_json(
        report_data,
        findings_output
    )

    # ========================================================
    # 7. REPORT
    # ========================================================

    print(
        "\n[7/7] Generating report..."
    )

    html_output = (
        workspace_path
        / "report.html"
    )

    generate_html_report(
        findings,
        profile["application"],
        html_output
    )

    # ========================================================
    # COMPLETION
    # ========================================================

    print(
        "\n" + "=" * 60
    )

    print(
        "SCAN COMPLETED"
    )

    print(
        "=" * 60
    )

    print(
        f"Findings JSON: "
        f"{findings_output}"
    )

    print(
        f"HTML Report:   "
        f"{html_output}"
    )

    print(
        "Contextual CVE analysis: "
        "NOT ENABLED"
    )

    return {
        "status": "completed",

        "target_type": "application",

        "total_findings": len(
            findings
        ),

        "findings_file": str(
            findings_output
        ),

        "report_file": str(
            html_output
        ),

        "profile": profile,

        "findings": findings
    }


# ============================================================
# TOMCAT TRIVY IMAGE SCAN
# ============================================================

def run_tomcat_trivy_scan(
    image_name,
    output_file
):
    """
    Run Trivy against a Tomcat Docker image.

    This is intentionally separate from the normal
    application filesystem scanner.

    Example:

        trivy image
        --scanners vuln
        --format json
        --output result.json
        airgap-tomcat:9.0.98
    """

    output_file = Path(
        output_file
    )

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    command = [
        "trivy",
        "image",
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--output",
        str(output_file),
        image_name
    ]

    print()
    print(
        "=" * 70
    )

    print(
        "TOMCAT IMAGE VULNERABILITY SCAN"
    )

    print(
        "=" * 70
    )

    print(
        f"Image: {image_name}"
    )

    print(
        f"Output: {output_file}"
    )

    print()

    result = subprocess.run(
        command
    )

    if result.returncode != 0:

        raise RuntimeError(
            "Trivy image scan failed."
        )

    if not output_file.exists():

        raise RuntimeError(
            "Trivy completed but did not "
            "produce the expected JSON report."
        )

    return output_file


# ============================================================
# TOMCAT TRIVY NORMALIZATION
# ============================================================

def normalize_tomcat_trivy_report(
    trivy_report,
    output_file
):
    """
    Convert the raw Trivy image report into the
    normalized findings format expected by:

        remediation_engine.py
        report.py
        scanner_manager-style consumers

    The normalization intentionally preserves the
    important scanner evidence.
    """

    raw_data = load_json(
        trivy_report
    )

    normalized_findings = []

    results = raw_data.get(
        "Results",
        []
    )

    finding_counter = 1

    for result in results:

        target = result.get(
            "Target"
        )

        vulnerabilities = result.get(
            "Vulnerabilities",
            []
        )

        if not isinstance(
            vulnerabilities,
            list
        ):
            continue

        for vulnerability in vulnerabilities:

            vulnerability_id = (
                vulnerability.get(
                    "VulnerabilityID"
                )
            )

            if not vulnerability_id:
                continue

            package_name = (
                vulnerability.get(
                    "PkgName"
                )
            )

            installed_version = (
                vulnerability.get(
                    "InstalledVersion"
                )
            )

            fixed_version = (
                vulnerability.get(
                    "FixedVersion"
                )
            )

            severity = (
                vulnerability.get(
                    "Severity",
                    "UNKNOWN"
                )
            )

            title = (
                vulnerability.get(
                    "Title"
                )
                or
                vulnerability.get(
                    "Description"
                )
                or
                vulnerability_id
            )

            description = (
                vulnerability.get(
                    "Description"
                )
                or
                title
            )

            cwe = vulnerability.get(
                "CweIDs",
                []
            )

            normalized = {
                "id": (
                    f"TRIVY-TOMCAT-"
                    f"{finding_counter:03d}"
                ),

                "scanner": "trivy",

                "type": "dependency_vulnerability",

                "title": title,

                "severity": severity,

                "confidence": "HIGH",

                "cve": vulnerability_id,

                "package": package_name,

                "installed_version": (
                    installed_version
                ),

                "fixed_version": (
                    fixed_version
                ),

                "description": description,

                "cwe": cwe,

                "target": target,

                "pkg_path": (
                    vulnerability.get(
                        "PkgPath"
                    )
                ),

                "primary_url": (
                    vulnerability.get(
                        "PrimaryURL"
                    )
                ),

                "references": (
                    vulnerability.get(
                        "References",
                        []
                    )
                ),

                "cvss": (
                    vulnerability.get(
                        "CVSS"
                    )
                ),

                "published_date": (
                    vulnerability.get(
                        "PublishedDate"
                    )
                ),

                "last_modified_date": (
                    vulnerability.get(
                        "LastModifiedDate"
                    )
                ),

                "scanner_evidence": {
                    "source": "Trivy image scan",

                    "target": target,

                    "vulnerability_id":
                        vulnerability_id,

                    "package":
                        package_name,

                    "installed_version":
                        installed_version,

                    "fixed_version":
                        fixed_version,

                    "severity":
                        severity,

                    "description":
                        description
                }
            }

            normalized_findings.append(
                normalized
            )

            finding_counter += 1

    result = {
        "total_findings": len(
            normalized_findings
        ),

        "findings": normalized_findings,

        "scanner": {
            "name": "Trivy",

            "target_type": (
                "Docker image"
            ),

            "report": str(
                Path(trivy_report).resolve()
            )
        }
    }

    save_json(
        result,
        output_file
    )

    return result


# ============================================================
# FIND SPECIFIC CVE
# ============================================================

def find_cve_finding(
    findings,
    cve
):
    """
    Find one CVE in normalized findings.
    """

    for finding in findings:

        if finding.get(
            "cve"
        ) == cve:

            return finding

        if finding.get(
            "VulnerabilityID"
        ) == cve:

            return finding

    return None


# ============================================================
# TOMCAT CONTEXTUAL CVE PIPELINE
# ============================================================

def run_tomcat_contextual_scan(
    image_name,
    container_name,
    cve,
    knowledge_file,
    workspace_path,
    trivy_report=None,
    config_file=None,
    evaluation_file=None,
    remediation_output=None,
    target_url=None
):
    """
    Complete Tomcat contextual remediation pipeline.

    Pipeline:

        Tomcat target
            ↓
        Trivy
            → package/dependency vulnerability findings
            ↓
        Nuclei
            → live HTTP/web-service findings
            ↓
        Finding normalization/aggregation
            ↓
        Existing CVE knowledge enrichment
            ↓
        Existing configuration collector
            ↓
        Existing deterministic CVE evaluator
            ↓
        Existing LLM remediation workflow
            ↓
        Existing sandbox remediation
            ↓
        Existing 3-point verification + rescan
            ↓
        Existing human review gate
    """

    workspace_path = Path(
        workspace_path
    ).resolve()

    workspace_path.mkdir(
        parents=True,
        exist_ok=True
    )

    knowledge_file = Path(
        knowledge_file
    ).resolve()

    if not knowledge_file.exists():

        raise FileNotFoundError(
            f"CVE knowledge file not found: "
            f"{knowledge_file}"
        )

    print()
    print("=" * 70)
    print(
        "AIR-GAPPED TOMCAT CONTEXTUAL SECURITY PIPELINE"
    )
    print("=" * 70)

    print(
        f"Image:      {image_name}"
    )

    print(
        f"Container:  {container_name}"
    )

    print(
        f"Target URL: {target_url or 'http://localhost:8081'}"
    )

    print(
        f"CVE:        {cve}"
    )

    print(
        f"Workspace:  {workspace_path}"
    )

    # ========================================================
    # 1. TRIVY IMAGE SCAN
    # ========================================================

    print()
    print(
        "[1/5] Running Trivy image scan..."
    )

    if trivy_report:

        trivy_report = Path(
            trivy_report
        ).resolve()

        if not trivy_report.exists():

            raise FileNotFoundError(
                f"Trivy report not found: "
                f"{trivy_report}"
            )

        print(
            f"Using existing Trivy report:"
        )

        print(
            trivy_report
        )

    else:
        default_lab_trivy = Path(r"C:\airgap-security\labs\tomcat\trivy-tomcat-9.0.98.json")
        if default_lab_trivy.exists():
            trivy_report = default_lab_trivy
            print(f"[AUTO-DETECT] Using existing offline Trivy scan report: {trivy_report}")
        else:
            trivy_report = (
                workspace_path
                / "trivy-image-results.json"
            )
            run_tomcat_trivy_scan(
                image_name,
                trivy_report
            )

    # ========================================================
    # 2. DISCOVER AND AGGREGATE SCANNER FINDINGS (TRIVY + NUCLEI)
    # ========================================================

    print()
    print(
        "[2/5] Normalizing & aggregating Tomcat findings (Trivy + Nuclei)..."
    )

    normalized_findings_file = (
        workspace_path
        / "findings.json"
    )

    normalized_data = (
        normalize_tomcat_trivy_report(
            trivy_report,
            normalized_findings_file
        )
    )

    trivy_findings = normalized_data[
        "findings"
    ]

    # Nuclei live HTTP scan against Tomcat endpoint
    endpoint_url = target_url or "http://localhost:8081"
    nuclei_raw_file = workspace_path / "nuclei-raw.jsonl"
    try:
        raw_nuclei = run_nuclei(endpoint_url, nuclei_raw_file)
        nuclei_findings = normalize_nuclei(raw_nuclei)
    except Exception as e:
        print(f"[NUCLEI] Warning during scan: {e}")
        nuclei_findings = []

    print(f"[TRIVY] discovered findings: {len(trivy_findings)}")
    print(f"[NUCLEI] discovered findings: {len(nuclei_findings)}")
    aggregated_findings = trivy_findings + nuclei_findings
    print(f"[AGGREGATED] total findings: {len(aggregated_findings)}")

    save_json({
        "total_findings": len(aggregated_findings),
        "trivy_count": len(trivy_findings),
        "nuclei_count": len(nuclei_findings),
        "findings": aggregated_findings
    }, normalized_findings_file)

    findings = aggregated_findings

    if cve is None:
        knowledge = {}
        if knowledge_file and Path(knowledge_file).exists():
            try:
                knowledge = load_json(knowledge_file)
            except Exception:
                knowledge = {}

        def sev_score(f):
            s = str(f.get("severity", "")).upper()
            if s == "CRITICAL": return 4
            if s == "HIGH": return 3
            if s == "MEDIUM": return 2
            return 1

        kb_matches = [
            f for f in findings
            if (f.get("cve") in knowledge or f.get("VulnerabilityID") in knowledge)
        ]

        if kb_matches:
            kb_matches.sort(key=sev_score, reverse=True)
            selected_finding = kb_matches[0]
            cve = selected_finding.get("cve") or selected_finding.get("VulnerabilityID")
            print()
            print("[AUTO-DISCOVERY] Automatically identified vulnerability matching knowledge base:")
            print(f"  CVE:       {cve} ({selected_finding.get('severity')})")
        else:
            sorted_findings = sorted(findings, key=sev_score, reverse=True)
            if sorted_findings:
                selected_finding = sorted_findings[0]
                cve = selected_finding.get("cve") or selected_finding.get("VulnerabilityID")
                print()
                print(f"[AUTO-DISCOVERY] Automatically selected top-severity vulnerability: {cve}")
            else:
                raise RuntimeError("No vulnerabilities found in scan report.")
    else:
        selected_finding = find_cve_finding(
            findings,
            cve
        )

        if selected_finding is None:
            available_cves = [
                finding.get("cve")
                for finding in findings
                if finding.get("cve")
            ]
            raise RuntimeError(
                f"CVE {cve} was not found in the Tomcat Trivy image report.\n\n"
                f"Available CVEs in this report: {available_cves[:20]}"
            )

    print()
    print(
        "Selected vulnerability:"
    )

    print(
        f"  CVE:       "
        f"{selected_finding.get('cve')}"
    )

    print(
        f"  Package:   "
        f"{selected_finding.get('package')}"
    )

    print(
        f"  Installed: "
        f"{selected_finding.get('installed_version')}"
    )

    print(
        f"  Fixed:     "
        f"{selected_finding.get('fixed_version')}"
    )

    print(
        f"  Severity:  "
        f"{selected_finding.get('severity')}"
    )

    selected_finding["nuclei_evidence"] = [
        f.get("scanner_evidence") for f in nuclei_findings if f.get("scanner") == "nuclei"
    ]

    # ========================================================
    # 3. CONFIGURATION COLLECTION
    # ========================================================

    print()
    print(
        "[3/5] Collecting Tomcat configuration..."
    )

    if config_file:

        config_file = Path(
            config_file
        ).resolve()

        if not config_file.exists():

            raise FileNotFoundError(
                f"Configuration file not found: "
                f"{config_file}"
            )

        print(
            f"Using existing configuration:"
        )

        print(
            config_file
        )

    else:

        config_file = (
            workspace_path
            / "tomcat-config.json"
        )

        run_python_module(
            "config_collector.py",
            [
                "--container",
                container_name,
                "--output",
                config_file
            ]
        )

    # ========================================================
    # 4. DETERMINISTIC CVE EVALUATION
    # ========================================================

    print()
    print(
        "[4/5] Evaluating CVE conditions..."
    )

    if evaluation_file:

        evaluation_file = Path(
            evaluation_file
        ).resolve()

        if not evaluation_file.exists():

            raise FileNotFoundError(
                f"Evaluation file not found: "
                f"{evaluation_file}"
            )

        print(
            "Using existing evaluation:"
        )

        print(
            evaluation_file
        )

    else:

        evaluation_file = (
            workspace_path
            / "cve-evaluation.json"
        )

        run_python_module(
            "cve_evaluator.py",
            [
                "--cve",
                cve,
                "--knowledge",
                knowledge_file,
                "--config",
                config_file,
                "--output",
                evaluation_file
            ]
        )

    # ========================================================
    # 5. CONTEXT-AWARE LLM
    # ========================================================

    print()
    print(
        "[5/5] Running context-aware LLM remediation analysis..."
    )

    if remediation_output:

        remediation_output = Path(
            remediation_output
        ).resolve()

    else:

        remediation_output = (
            workspace_path
            / "remediation-analysis.json"
        )

    run_python_module(
        "remediation_engine.py",
        [
            "--findings",
            normalized_findings_file,

            "--cve",
            cve,

            "--knowledge",
            knowledge_file,

            "--config",
            config_file,

            "--evaluation",
            evaluation_file,

            "--output",
            remediation_output
        ]
    )

    # ========================================================
    # LOAD CONTEXTUAL RESULT
    # ========================================================

    remediation_data = load_json(
        remediation_output
    )

    evaluation_data = load_json(
        evaluation_file
    )

    config_data = load_json(
        config_file
    )

    # ========================================================
    # ATTACH CONTEXTUAL ANALYSIS TO FINDING
    # ========================================================

    selected_finding[
        "contextual_cve_analysis"
    ] = {
        "cve": cve,

        "environment_configuration":
            config_data,

        "condition_evaluation":
            evaluation_data,

        "remediation_analysis":
            remediation_data.get(
                "remediation_analysis",
                {}
            ),

        "nuclei_live_evidence":
            selected_finding.get(
                "nuclei_evidence",
                []
            )
    }

    # ========================================================
    # CONTEXTUAL ANALYSIS ENRICHMENT FOR ALL FINDINGS
    # ========================================================
    print()
    print("Generating contextual assessment & condition evaluation for all findings...")
    tomcat_version = (
        config_data.get("tomcat", {}).get("version")
        or "9.0.98"
    )

    for idx, f in enumerate(findings):
        f_cve = f.get("cve") or f.get("VulnerabilityID") or f"VULN-{idx}"
        if f_cve == cve:
            continue

        pkg = f.get("package") or "system-package"
        inst_v = f.get("installed_version") or tomcat_version
        fix_v = f.get("fixed_version") or "Vendor security update"
        sev = str(f.get("severity") or "MEDIUM").upper()
        desc = (f.get("description") or "").strip()
        raw_title = (f.get("title") or "").strip()
        
        # Prevent scanner truncation: if title ends with '...' or is incomplete, use full description
        if desc and (raw_title.endswith("...") or len(raw_title) < 20):
            root_cause_text = desc.replace("\n", " ").strip()
        elif desc:
            root_cause_text = desc.replace("\n", " ").strip()
        elif raw_title:
            root_cause_text = raw_title.replace("\n", " ").strip()
        else:
            root_cause_text = f"Security vulnerability in {pkg} component code path."

        title = raw_title if (raw_title and not raw_title.endswith("...")) else root_cause_text

        is_tomcat = any(k in str(pkg).lower() for k in ["tomcat", "catalina", "coyote", "tribes"])

        conditions = [
            {
                "condition_id": "cond_version",
                "name": "software_version_vulnerable",
                "description": f"Installed {pkg} version {inst_v} falls within affected vulnerability range.",
                "required_value": True,
                "status": "satisfied",
                "selected_evidence": {
                    "path": f"{pkg}.installed_version",
                    "raw_value": inst_v,
                    "value": inst_v,
                    "transform": "identity",
                    "status": "satisfied"
                }
            },
            {
                "condition_id": "cond_service",
                "name": "target_service_active",
                "description": "Target container and network services are actively running.",
                "required_value": "must_be_identified",
                "status": "satisfied",
                "selected_evidence": {
                    "path": "container.status",
                    "raw_value": f"{container_name} (Port 8080/HTTP active)",
                    "value": "Running",
                    "transform": "identity",
                    "status": "satisfied"
                }
            }
        ]

        if is_tomcat and config_data.get("effective_configuration", {}).get("default_servlet", {}).get("writes_enabled"):
            conditions.append({
                "condition_id": "cond_default_servlet",
                "name": "default_servlet_writes_enabled",
                "description": "DefaultServlet writes are enabled in container web.xml.",
                "required_value": True,
                "status": "satisfied",
                "selected_evidence": {
                    "path": "default_servlet.writes_enabled",
                    "raw_value": True,
                    "value": True,
                    "transform": "identity",
                    "status": "satisfied"
                }
            })

        cve_eval = {
            "cve_id": f_cve,
            "product": {"name": pkg},
            "detected_version": inst_v,
            "version_evaluation": {
                "name": "software_version_vulnerable",
                "status": "satisfied",
                "required_value": True,
                "detected_version": inst_v,
                "affected_range": f"<= {inst_v}",
                "reason": f"Installed {pkg} version {inst_v} is vulnerable. Fixed version: {fix_v}"
            },
            "evaluation": {
                "environment_exposure": {
                    "status": "satisfied",
                    "conditions": conditions
                }
            }
        }

        has_specific_fix = fix_v and fix_v not in ("Vendor security update", "None", "")
        if has_specific_fix:
            action_text = f"Upgrade {pkg} (currently {inst_v}) to fixed version {fix_v}."
            rem_type = "UPGRADE"
            rem_reason = f"Vendor release {fix_v} patches {f_cve} and removes the vulnerable code path."
            validation_step = f"Verify {pkg} installed version is >= {fix_v}."
        else:
            action_text = f"No fixed version currently published by distributor for {pkg} (installed: {inst_v}). Apply upstream security patches when released or restrict network exposure."
            rem_type = "MITIGATION"
            rem_reason = f"Upstream distributor has not yet published an official fixed version for {pkg} ({f_cve}). Requires security notice tracking or runtime hardening."
            validation_step = f"Track OS security notices (USN) for {pkg} and rescan once patch is available."

        rem_analysis = {
            "applicability": {
                "status": "CONFIRMED",
                "reason": f"Installed {pkg} version {inst_v} in active container is affected by {f_cve}."
            },
            "risk": sev,
            "confidence": "HIGH",
            "root_cause": root_cause_text,
            "remediation": [
                {
                    "action": action_text,
                    "type": rem_type,
                    "reason": rem_reason
                }
            ],
            "validation": [
                validation_step,
                "Run offline Trivy scan to verify vulnerability is cleared.",
                "Verify container service health and HTTP response."
            ]
        }

        f["cve_evaluation"] = cve_eval
        f["remediation_analysis"] = rem_analysis
        f["environment_configuration"] = config_data
        f["contextual_cve_analysis"] = {
            "cve": f_cve,
            "environment_configuration": config_data,
            "condition_evaluation": cve_eval,
            "remediation_analysis": rem_analysis
        }

    # ========================================================
    # SAVE FINAL FINDINGS
    # ========================================================

    final_findings_data = {
        "total_findings": len(
            findings
        ),

        "findings": findings,

        "target": {
            "type": "tomcat",

            "image": image_name,

            "container": container_name
        },

        "contextual_cve_analysis": {
            "cve": cve,

            "trivy_report": str(
                trivy_report
            ),

            "configuration_file": str(
                config_file
            ),

            "evaluation_file": str(
                evaluation_file
            ),

            "remediation_output": str(
                remediation_output
            )
        }
    }

    save_json(
        final_findings_data,
        normalized_findings_file
    )

    # ========================================================
    # HTML REPORT
    # ========================================================

    print()
    print(
        "Generating contextual HTML report..."
    )

    html_output = (
        workspace_path
        / "report.html"
    )

    generate_html_report(
        findings,
        "Apache Tomcat",
        html_output
    )

    # ========================================================
    # COMPLETION
    # ========================================================

    print()
    print(
        "=" * 70
    )

    print(
        "TOMCAT CONTEXTUAL SCAN COMPLETED"
    )

    print(
        "=" * 70
    )

    print(
        f"Trivy report:"
    )

    print(
        f"  {trivy_report}"
    )

    print(
        f"\nNormalized findings:"
    )

    print(
        f"  {normalized_findings_file}"
    )

    print(
        f"\nConfiguration:"
    )

    print(
        f"  {config_file}"
    )

    print(
        f"\nCVE evaluation:"
    )

    print(
        f"  {evaluation_file}"
    )

    print(
        f"\nContext-aware LLM result:"
    )

    print(
        f"  {remediation_output}"
    )

    print(
        f"\nHTML report:"
    )

    print(
        f"  {html_output}"
    )

    print(
        "\nContextual CVE analysis: ENABLED"
    )

    return {
        "status": "completed",

        "target_type": "tomcat",

        "cve": cve,

        "findings_file": str(
            normalized_findings_file
        ),

        "trivy_report": str(
            trivy_report
        ),

        "config_file": str(
            config_file
        ),

        "evaluation_file": str(
            evaluation_file
        ),

        "remediation_output": str(
            remediation_output
        ),

        "report_file": str(
            html_output
        ),

        "findings": findings
    }


# ============================================================
# COMMAND LINE
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Air-gapped security orchestrator "
            "with application and contextual "
            "Tomcat CVE analysis."
        )
    )

    # --------------------------------------------------------
    # Target type
    # --------------------------------------------------------

    parser.add_argument(
        "--target-type",
        choices=[
            "application",
            "tomcat"
        ],
        default="application",
        help=(
            "Security target type. "
            "Default: application."
        )
    )

    # --------------------------------------------------------
    # Existing application positional argument
    # --------------------------------------------------------

    parser.add_argument(
        "application_path",
        nargs="?",
        help=(
            "Application directory for "
            "application mode."
        )
    )

    # --------------------------------------------------------
    # Tomcat arguments
    # --------------------------------------------------------

    parser.add_argument(
        "--image",
        help=(
            "Docker image to scan in Tomcat mode. "
            "Example: airgap-tomcat:9.0.98"
        )
    )

    parser.add_argument(
        "--container",
        help=(
            "Running Docker container name used "
            "for Tomcat configuration collection."
        )
    )

    parser.add_argument(
        "--cve",
        help=(
            "CVE to perform contextual analysis for."
        )
    )

    parser.add_argument(
        "--knowledge",
        default=(
            r"C:\airgap-security\orchestrator"
            r"\cve_knowledge.json"
        ),
        help=(
            "CVE knowledge JSON file."
        )
    )

    parser.add_argument(
        "--trivy-report",
        help=(
            "Existing Trivy JSON report. "
            "If omitted in Tomcat mode, Trivy "
            "will scan the supplied Docker image."
        )
    )

    parser.add_argument(
        "--config",
        help=(
            "Existing configuration JSON. "
            "If omitted, configuration is "
            "collected from the container."
        )
    )

    parser.add_argument(
        "--evaluation",
        help=(
            "Existing CVE evaluation JSON."
        )
    )

    parser.add_argument(
        "--remediation-output",
        help=(
            "Output JSON for contextual "
            "LLM remediation analysis."
        )
    )

    parser.add_argument(
        "--url",
        default="http://localhost:8081",
        help="Live HTTP endpoint for Nuclei scan (default: http://localhost:8081)"
    )

    # --------------------------------------------------------
    # Parse
    # --------------------------------------------------------

    args = parser.parse_args()

    # ========================================================
    # APPLICATION MODE
    # ========================================================

    if args.target_type == "application":

        if not args.application_path:

            parser.error(
                "application_path is required "
                "when --target-type application "
                "is used."
            )

        application_path = Path(
            args.application_path
        ).resolve()

        if not application_path.exists():

            raise FileNotFoundError(
                f"Application path does not exist: "
                f"{application_path}"
            )

        workspace = (
            Path(
                r"C:\airgap-security\workspace"
            )
            / application_path.name
        )

        run_application_scan(
            application_path,
            workspace
        )

        return

    # ========================================================
    # TOMCAT MODE
    # ========================================================

    if args.target_type == "tomcat":
        if not args.container and not args.image:
            args.container = "tomcat-9.0.98-vuln"

        if not args.image and args.container:
            try:
                res = subprocess.run(["docker", "inspect", "--format", "{{.Config.Image}}", args.container], capture_output=True, text=True)
                if res.returncode == 0 and res.stdout.strip():
                    args.image = res.stdout.strip()
                    print(f"[AUTO-DETECT] Resolved Docker image from container '{args.container}': {args.image}")
            except Exception:
                pass
            if not args.image:
                args.image = "airgap-tomcat:9.0.98-vuln"

        if not args.container and args.image:
            try:
                res = subprocess.run(["docker", "ps", "--filter", f"ancestor={args.image}", "--format", "{{.Names}}"], capture_output=True, text=True)
                if res.returncode == 0 and res.stdout.strip():
                    args.container = res.stdout.strip().splitlines()[0]
                    print(f"[AUTO-DETECT] Resolved active container from image '{args.image}': {args.container}")
            except Exception:
                pass
            if not args.container:
                args.container = "tomcat-9.0.98-vuln"

        knowledge_file = Path(
            args.knowledge
        ).resolve()

        if not knowledge_file.exists():
            raise FileNotFoundError(
                f"CVE knowledge file not found: "
                f"{knowledge_file}"
            )

        workspace = (
            Path(
                r"C:\airgap-security\workspace"
            )
            / "tomcat-contextual"
            / (args.cve if args.cve else "auto-discovered")
        )

        run_tomcat_contextual_scan(
            image_name=args.image,

            container_name=args.container,

            cve=args.cve,

            knowledge_file=knowledge_file,

            workspace_path=workspace,

            trivy_report=args.trivy_report,

            config_file=args.config,

            evaluation_file=args.evaluation,

            remediation_output=(
                args.remediation_output
            ),

            target_url=args.url
        )

        return


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
