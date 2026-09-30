"""
Script to generate the complete project report as a Word document (.docx).
Covers the entire architecture, background, contextual evaluation,
sandbox remediation, 3-point verification, and operational guide.
"""

from pathlib import Path
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn


def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)


def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tcPr.append(tcMar)


def add_code_block(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.2)
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(4)
    
    # We create a single-cell table for shaded code background
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    table.columns[0].width = Inches(6.5)
    
    cell = table.cell(0, 0)
    set_cell_background(cell, "0F172A")  # Dark slate
    set_cell_margins(cell, top=140, bottom=140, left=200, right=200)
    
    cp = cell.paragraphs[0]
    cp.paragraph_format.space_before = Pt(0)
    cp.paragraph_format.space_after = Pt(0)
    run = cp.add_run(text)
    run.font.name = "Consolas"
    run.font.size = Pt(9.5)
    run.font.color.rgb = RGBColor(56, 189, 248)  # Cyan
    
    doc.add_paragraph().paragraph_format.space_after = Pt(4)


def add_callout(doc, title, text, bg_hex="EFF6FF", border_hex="3B82F6"):
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    table.columns[0].width = Inches(6.5)
    
    cell = table.cell(0, 0)
    set_cell_background(cell, bg_hex)
    set_cell_margins(cell, top=140, bottom=140, left=200, right=200)
    
    cp = cell.paragraphs[0]
    cp.paragraph_format.space_before = Pt(0)
    cp.paragraph_format.space_after = Pt(2)
    t_run = cp.add_run(f"📌 {title}\n")
    t_run.font.name = "Calibri"
    t_run.font.size = Pt(11)
    t_run.font.bold = True
    t_run.font.color.rgb = RGBColor(30, 64, 175)
    
    b_run = cp.add_run(text)
    b_run.font.name = "Calibri"
    b_run.font.size = Pt(10)
    b_run.font.color.rgb = RGBColor(31, 41, 55)
    
    doc.add_paragraph().paragraph_format.space_after = Pt(4)


def build_document(output_path):
    doc = docx.Document()
    
    # Page Margins
    for section in doc.sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(0.8)
        section.right_margin = Inches(0.8)
        
    # Styles
    styles = doc.styles
    normal_style = styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(10.5)
    normal_style.font.color.rgb = RGBColor(31, 41, 55)

    # ========================================================
    # COVER / TITLE
    # ========================================================
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(20)
    title_p.paragraph_format.space_after = Pt(6)
    title_run = title_p.add_run("Autonomous Air-Gapped Security & Remediation Platform")
    title_run.font.name = "Calibri"
    title_run.font.size = Pt(24)
    title_run.font.bold = True
    title_run.font.color.rgb = RGBColor(15, 23, 42)

    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_after = Pt(18)
    sub_run = sub_p.add_run("Comprehensive Technical Report: Contextual Vulnerability Evaluation, Autonomous Sandbox Remediation, Three-Point Verification, and Human Governance Workflow")
    sub_run.font.size = Pt(13)
    sub_run.font.color.rgb = RGBColor(75, 85, 99)

    # Metadata bar
    meta_table = doc.add_table(rows=2, cols=3)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_table.autofit = False
    col_widths = [Inches(2.1), Inches(2.2), Inches(2.2)]
    for row in meta_table.rows:
        for idx, width in enumerate(col_widths):
            row.cells[idx].width = width

    headers = [("Target Environment", "Apache Tomcat 9.0.98"), ("Primary Scanner", "Aqua Trivy (Offline)"), ("Governance", "Human-in-the-Loop Approval")]
    for idx, (label, val) in enumerate(headers):
        c = meta_table.cell(0, idx)
        set_cell_background(c, "F1F5F9")
        set_cell_margins(c, top=80, bottom=60, left=100, right=100)
        p = c.paragraphs[0]
        r1 = p.add_run(f"{label}\n")
        r1.font.size = Pt(9)
        r1.font.bold = True
        r1.font.color.rgb = RGBColor(100, 116, 139)
        r2 = p.add_run(val)
        r2.font.size = Pt(10)
        r2.font.bold = True
        r2.font.color.rgb = RGBColor(15, 23, 42)

    doc.add_paragraph().paragraph_format.space_after = Pt(16)

    # ========================================================
    # SECTION 1: EXECUTIVE SUMMARY
    # ========================================================
    h1 = doc.add_heading("1. Executive Summary & Core Philosophy", level=1)
    h1.paragraph_format.space_before = Pt(16)
    
    doc.add_paragraph(
        "Modern enterprise vulnerability scanners generate high-volume alert noise by solely matching software version numbers. "
        "In critical infrastructure and air-gapped secure enclaves, software upgrades cannot be applied blindly without validation. "
        "Furthermore, many reported vulnerabilities are completely mitigated or unexploitable due to the instance's active runtime configuration."
    )
    
    doc.add_paragraph(
        "This project establishes a resilient, end-to-end autonomous security architecture designed to operate 100% offline. "
        "Its purpose is to ingest vulnerability findings, evaluate actual runtime prerequisites against live configuration, "
        "safely generate and apply remediation in an isolated sandbox copy, independently verify that the fix works without regressions, "
        "and present verified evidence to a human administrator for explicit deployment authorization."
    )

    add_callout(
        doc,
        "Fundamental Architectural Tenet",
        "The system treats Trivy as the sole source of discovered vulnerability findings. "
        "Knowledge base definitions (cve_knowledge.json) must NEVER be treated as vulnerability findings on their own; "
        "they serve strictly to enrich findings actually detected by Trivy. Remediations are NEVER applied directly to live production servers."
    )

    # ========================================================
    # SECTION 2: END-TO-END SYSTEM ARCHITECTURE
    # ========================================================
    h1 = doc.add_heading("2. Multi-Stage Pipeline Architecture", level=1)
    h1.paragraph_format.space_before = Pt(16)

    doc.add_paragraph("The orchestrator executes a 6-tier defensive workflow across completely isolated boundaries:")

    # Table of Stages
    pipeline_table = doc.add_table(rows=7, cols=3)
    pipeline_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    pipeline_table.autofit = False
    p_widths = [Inches(1.2), Inches(2.2), Inches(3.1)]
    for row in pipeline_table.rows:
        for idx, width in enumerate(p_widths):
            row.cells[idx].width = width

    p_data = [
        ("Tier", "Pipeline Stage", "Responsibility & Air-Gap Boundary"),
        ("Tier 1", "Offline Discovery", "Trivy scans container images and software manifests offline; establishes the authoritative list of discovered CVEs."),
        ("Tier 2", "Configuration Collection", "config_collector.py introspects container web.xml, environment variables, connectors, and version scripts."),
        ("Tier 3", "Contextual Evaluation", "cve_evaluator.py checks whether software version + environmental prerequisites constitute a full exploitable match."),
        ("Tier 4", "Remediation Planning", "remediation_engine.py generates allowlisted, structured configuration actions with rollback safety."),
        ("Tier 5", "Sandbox Remediation & 3-Point Verification", "sandbox_remediator.py clones/modifies an isolated sandbox container, executes 3 verification tests, and rescans."),
        ("Tier 6", "Human Review & Governance", "Generates human_review_portal.html and human_review_package.json. Pipeline halts awaiting explicit authorization.")
    ]

    for r_idx, row in enumerate(pipeline_table.rows):
        for c_idx, text in enumerate(p_data[r_idx]):
            cell = row.cells[c_idx]
            set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
            p = cell.paragraphs[0]
            if r_idx == 0:
                set_cell_background(cell, "1E293B")
                run = p.add_run(text)
                run.font.bold = True
                run.font.color.rgb = RGBColor(255, 255, 255)
            else:
                set_cell_background(cell, "F8FAFC" if r_idx % 2 == 1 else "FFFFFF")
                run = p.add_run(text)
                run.font.size = Pt(9.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # ========================================================
    # SECTION 2.1: AUTONOMOUS TOOL SELECTION ENGINE
    # ========================================================
    h2 = doc.add_heading("2.1 Autonomous LLM Tool Selector & Ingestion Engine", level=2)
    doc.add_paragraph(
        "A foundational capability of this platform is the Autonomous Tool Selector (implemented in orchestrator/autonomous_agent.py). "
        "Instead of requiring human operators to manually configure scanners for every target, the system dynamically analyzes "
        "incoming artifacts and prompts the local LLM (Gemma 26B/24B via SGLang) to select the exact tools required."
    )
    
    doc.add_paragraph(
        "Key operational capabilities of the Autonomous Tool Selector:\n"
        "• Target Ingestion & Profiling: Recursively extracts ZIP archives and directories, analyzing file extensions (.py, .js, .java), "
        "dependency manifests (requirements.txt, package.json, pom.xml), or network addresses (IP/hostname).\n"
        "• Autonomous LLM Consultation: Constructs a structured prompt detailing the target profile and queries the local model. "
        "The model returns a JSON payload specifying which tools to trigger ('semgrep', 'trivy', 'nmap') with clear technical reasoning.\n"
        "• Intelligent Heuristic Fallback: If the local LLM server is unreachable or offline, the engine seamlessly engages a deterministic "
        "heuristic rule matrix, ensuring 100% operational uptime without stalling.\n"
        "• Unified Execution & Aggregation: Automatically runs the selected security scanners, maps findings into a standardized schema, "
        "and generates the comprehensive autonomous_security_report.json."
    )

    add_callout(
        doc,
        "Live Autonomous Tool Selection Proof",
        "When evaluated on 'test-app-offline.zip', the autonomous agent profiled the target (containing app.py and requirements.txt) "
        "and queried the local Gemma model. The LLM autonomously selected ['semgrep', 'trivy'], explaining that source code required static analysis "
        "and requirements.txt required dependency scanning. The agent executed both tools, detecting 1 command injection vulnerability and 2 Flask dependency CVEs."
    )

    # ========================================================
    # SECTION 3: DEEP-DIVE: CVE-2025-24813 VS CVE-2024-50379
    # ========================================================
    h1 = doc.add_heading("3. Contextual Vulnerability Analysis & The Trivy Ingestion Law", level=1)
    h1.paragraph_format.space_before = Pt(16)

    doc.add_heading("3.1 The Vulnerability Precondition Discrepancy", level=2)
    doc.add_paragraph(
        "A critical milestone of this project was determining why vulnerability scanners flag high-severity CVEs that cannot be fully exploited. "
        "In our test environment running Apache Tomcat 9.0.98, Trivy detected CVE-2025-24813 ('Potential RCE and/or arbitrary file write with partial PUT')."
    )
    doc.add_paragraph(
        "When our contextual prerequisite evaluator analyzed CVE-2025-24813 against the live container configuration, it identified two distinct threat models:"
    )

    # Attack chain breakdown table
    chain_table = doc.add_table(rows=6, cols=4)
    chain_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    chain_table.autofit = False
    c_widths = [Inches(1.8), Inches(1.8), Inches(1.4), Inches(1.5)]
    for row in chain_table.rows:
        for idx, width in enumerate(c_widths):
            row.cells[idx].width = width

    c_data = [
        ("Attack Vector", "Mandatory Precondition", "Instance State", "Match Status"),
        ("Arbitrary File Write", "Tomcat Version <= 9.0.98", "9.0.98 detected", "SATISFIED"),
        ("Arbitrary File Write", "DefaultServlet readonly = false", "false in web.xml", "SATISFIED (Exploitable)"),
        ("Arbitrary File Write", "Partial PUT enabled", "allowPartialPut = true", "SATISFIED"),
        ("Remote Code Execution", "File-based session persistence", "StandardManager", "SATISFIED"),
        ("Remote Code Execution", "Deserialization library in classpath", "No gadget library found", "NOT SATISFIED (Blocked)")
    ]

    for r_idx, row in enumerate(chain_table.rows):
        for c_idx, text in enumerate(c_data[r_idx]):
            cell = row.cells[c_idx]
            set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
            p = cell.paragraphs[0]
            if r_idx == 0:
                set_cell_background(cell, "1E293B")
                run = p.add_run(text)
                run.font.bold = True
                run.font.color.rgb = RGBColor(255, 255, 255)
            else:
                set_cell_background(cell, "FEF2F2" if "NOT SATISFIED" in text else ("F0FDF4" if "SATISFIED" in text else "FFFFFF"))
                run = p.add_run(text)
                run.font.size = Pt(9.5)
                if "SATISFIED (Exploitable)" in text or "NOT SATISFIED" in text:
                    run.font.bold = True

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    doc.add_heading("3.2 Why CVE-2024-50379 Was Not in the Report", level=2)
    doc.add_paragraph(
        "According to official Apache Tomcat and NVD records, CVE-2024-50379 affects versions 9.0.0.M1 through 9.0.97 and was officially patched in Tomcat 9.0.98. "
        "Therefore, Trivy adheres to the official vendor database and correctly did not report CVE-2024-50379 for Tomcat 9.0.98. "
        "Because the fix in 9.0.98 was found to be incomplete, the vulnerability in 9.0.98 was assigned new identifiers: CVE-2024-56337 and CVE-2025-24813 (fixed in 9.0.99)."
    )

    add_callout(
        doc,
        "The Sole Source of Truth Law",
        "We updated sandbox_remediator.py to guarantee that Trivy is the sole source of discovered findings. "
        "The system never loops over cve_knowledge.json to invent findings. "
        "Because CVE-2024-50379 was not in the Trivy scan report, it is strictly excluded from evaluation and reporting."
    )

    # ========================================================
    # SECTION 4: AUTONOMOUS SANDBOX REMEDIATION
    # ========================================================
    h1 = doc.add_heading("4. Autonomous Sandbox Remediation & Three-Point Verification", level=1)
    h1.paragraph_format.space_before = Pt(16)

    doc.add_paragraph(
        "When an exploitable full match is confirmed (such as the DefaultServlet arbitrary file write vulnerability on CVE-2025-24813), "
        "the orchestrator applies remediation under strict containment boundaries:"
    )

    doc.add_heading("4.1 Isolation Safeguards", level=2)
    doc.add_paragraph(
        "1. Live Target Preservation: The live server (e.g. tomcat-9.0.98) is marked READ-ONLY. No write commands or restarts are ever permitted against it.\n"
        "2. Sandbox Testbed: Modifications take place inside an isolated sandbox container copy (tomcat-9.0.98-vuln).\n"
        "3. Automated Rollback Backup: Before any configuration edit, a timestamped copy is generated (/opt/tomcat/conf/remediation-backups/web.xml.<timestamp>.bak).\n"
        "4. Allowlisted Mutation: Arbitrary shell commands are rejected. Only allowlisted, deterministic parameters (e.g. DefaultServlet readonly = true) are modified."
    )

    doc.add_heading("4.2 The Three Mandatory Verifications + Rescan", level=2)
    doc.add_paragraph(
        "After applying the fix and reloading the sandbox daemon, the engine executes three independent verification tests:"
    )

    # Verifications table
    v_table = doc.add_table(rows=4, cols=4)
    v_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    v_table.autofit = False
    v_widths = [Inches(1.5), Inches(1.8), Inches(1.8), Inches(1.4)]
    for row in v_table.rows:
        for idx, width in enumerate(v_widths):
            row.cells[idx].width = width

    v_data = [
        ("Verification Check", "Pre-Remediation Baseline", "Post-Remediation Sandbox", "Independent Proof"),
        ("1. Vulnerability Eliminated", "HTTP PUT /probe.txt -> 201 Created (Write allowed)", "HTTP PUT /probe.txt -> 405 Method Not Allowed", "PASS (Write capability neutralized)"),
        ("2. Zero Regressions", "Original vulnerable state", "Trivy offline rescan -> 0 new CVEs; clean XML diff", "PASS (No side-effects introduced)"),
        ("3. Application Healthy", "HTTP GET / -> 200 OK", "HTTP GET / -> 200 OK (11,210 bytes, daemon running)", "PASS (Service availability preserved)")
    ]

    for r_idx, row in enumerate(v_table.rows):
        for c_idx, text in enumerate(v_data[r_idx]):
            cell = row.cells[c_idx]
            set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
            p = cell.paragraphs[0]
            if r_idx == 0:
                set_cell_background(cell, "1E293B")
                run = p.add_run(text)
                run.font.bold = True
                run.font.color.rgb = RGBColor(255, 255, 255)
            else:
                set_cell_background(cell, "F0FDF4" if "PASS" in text else "FFFFFF")
                run = p.add_run(text)
                run.font.size = Pt(9.5)
                if "PASS" in text:
                    run.font.bold = True
                    run.font.color.rgb = RGBColor(22, 101, 52)

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    doc.add_heading("4.3 The Critical Halt & Governance Gate", level=2)
    doc.add_paragraph(
        "Upon successful completion of all three verifications, the pipeline immediately triggers an intentional halt:\n"
        "• Status marked: VALIDATED_SANDBOX_CONFIRMED_FIX.\n"
        "• Real Environment Protection: No commands are sent to the production target.\n"
        "• Human Dossier Generated: An interactive dashboard and JSON authorization package are generated."
    )

    # ========================================================
    # SECTION 5: OPERATIONAL GUIDE & HANDS-ON VERIFICATION
    # ========================================================
    h1 = doc.add_heading("5. Operational Hands-on Guide (End-to-End)", level=1)
    h1.paragraph_format.space_before = Pt(16)

    doc.add_paragraph("To run and verify the complete workflow end-to-end, execute the following commands in PowerShell from C:\\airgap-security:")

    doc.add_heading("Step 1: Set Sandbox to Vulnerable Baseline", level=2)
    doc.add_paragraph("Configure readonly=false in web.xml and restart the sandbox container:")
    add_code_block(doc, 'docker exec tomcat-9.0.98-vuln sed -i -E "/<param-name>\\s*readonly\\s*<\\/param-name>/{n;s/<param-value>\\s*true\\s*<\\/param-value>/<param-value>false<\\/param-value>/;}" /opt/tomcat/conf/web.xml; docker restart tomcat-9.0.98-vuln')

    doc.add_paragraph("Prove arbitrary file upload is actively exploitable (HTTP 201 Created):")
    add_code_block(doc, 'curl.exe -X PUT http://localhost:8081/baseline_test.txt -d "exploit_payload" -i')

    doc.add_heading("Step 2: Run Full Contextual Discovery Scan", level=2)
    doc.add_paragraph("Execute main.py in Tomcat mode to discover vulnerabilities via Trivy, gather configuration, and evaluate prerequisites:")
    add_code_block(doc, 'python orchestrator\\main.py --target-type tomcat --image airgap-tomcat:9.0.98-vuln --container tomcat-9.0.98-vuln')

    doc.add_heading("Step 3: Run Autonomous Sandbox Remediation", level=2)
    doc.add_paragraph("Launch the sandbox remediator to apply the fix, run the 3 verifications, rescan, and halt for human review:")
    add_code_block(doc, 'python orchestrator\\sandbox_remediator.py --live-target tomcat-9.0.98 --sandbox-container tomcat-9.0.98-vuln --sandbox-url http://localhost:8081')

    doc.add_heading("Step 4: Inspect Generated Human Review Portal", level=2)
    doc.add_paragraph("Open the interactive HTML dashboard in your browser:")
    add_code_block(doc, 'Start-Process "C:\\airgap-security\\workspace\\sandbox-validation\\human_review_portal.html"')

    doc.add_heading("Step 5: Direct Live Verification (curl)", level=2)
    doc.add_paragraph("Verify that HTTP PUT is now blocked (HTTP 405 Method Not Allowed):")
    add_code_block(doc, 'curl.exe -X PUT http://localhost:8081/sandbox_test.txt -d "test" -i')

    doc.add_paragraph("Verify that HTTP GET still works normally (HTTP 200 OK):")
    add_code_block(doc, 'curl.exe -I http://localhost:8081/')

    doc.add_heading("Step 6: Optional Human-Authorized Staged Deployment", level=2)
    doc.add_paragraph("If approved by the human security administrator, deploy the verified fix to the live server:")
    add_code_block(doc, 'python orchestrator\\remediation_executor.py --remediation workspace\\sandbox-validation\\sandbox_remediation_plan.json --container tomcat-9.0.98 --apply')

    # ========================================================
    # SECTION 6: DELIVERABLE ARTIFACTS & FILE STRUCTURE
    # ========================================================
    h1 = doc.add_heading("6. Key Project Deliverables & Artifact Inventory", level=1)
    h1.paragraph_format.space_before = Pt(16)

    doc.add_paragraph("The table below details the core components and artifacts developed in this project:")

    art_table = doc.add_table(rows=8, cols=3)
    art_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    art_table.autofit = False
    a_widths = [Inches(2.2), Inches(1.5), Inches(2.8)]
    for row in art_table.rows:
        for idx, width in enumerate(a_widths):
            row.cells[idx].width = width

    a_data = [
        ("File Path", "Role / Category", "Description"),
        ("orchestrator/sandbox_remediator.py", "Core Orchestration", "Autonomous sandbox remediation engine; enforces Trivy as sole source of findings and executes 3-point verifications."),
        ("orchestrator/remediation_executor.py", "Remediation Engine", "Controlled, allowlisted configuration executor; creates backups and applies in-place sed edits."),
        ("orchestrator/remediation_validator.py", "Validator", "Independent behavioral validator; executes HTTP PUT probes and inspects configuration."),
        ("orchestrator/cve_evaluator.py", "Contextual Evaluator", "Deterministic prerequisite engine evaluating live configuration against structured attack conditions."),
        ("orchestrator/config_collector.py", "Auditor", "CVE-agnostic container configuration extraction utility."),
        ("workspace/sandbox-validation/human_review_portal.html", "UI / Review Portal", "Executive dark-mode interactive portal displaying before/after proofs and governance status."),
        ("workspace/sandbox-validation/human_review_package.json", "Governance Package", "Structured JSON dossier containing complete cryptographic/behavioral audit trails.")
    ]

    for r_idx, row in enumerate(art_table.rows):
        for c_idx, text in enumerate(a_data[r_idx]):
            cell = row.cells[c_idx]
            set_cell_margins(cell, top=80, bottom=80, left=100, right=100)
            p = cell.paragraphs[0]
            if r_idx == 0:
                set_cell_background(cell, "1E293B")
                run = p.add_run(text)
                run.font.bold = True
                run.font.color.rgb = RGBColor(255, 255, 255)
            else:
                set_cell_background(cell, "F8FAFC" if r_idx % 2 == 1 else "FFFFFF")
                run = p.add_run(text)
                run.font.size = Pt(9.5)
                if c_idx == 0:
                    run.font.name = "Consolas"
                    run.font.size = Pt(8.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(16)

    # Save
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(output_path))
    print(f"Report successfully saved to: {output_path}")


if __name__ == "__main__":
    out_file = r"C:\airgap-security\AirGap_Security_Full_Project_Report.docx"
    build_document(out_file)
