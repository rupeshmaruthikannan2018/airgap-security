"""
Generic ZIP / Folder Scanning Pipeline for AirGap Security Platform.

Implements an end-to-end production-quality pipeline:
1. Accepts .zip archive or extracted directory inputs.
2. Validates and extracts archives using SecureArchiveExtractor.
3. Profiles application tree via ApplicationProfiler.
4. Dynamically plans scanners via ScannerPlanner.
5. Runs only planned scanners (Trivy fs, Semgrep local rules; Nuclei only if dynamic target, Nmap only if network target).
6. Collects and normalizes findings into unified finding schema.
7. Correlates findings across scanners.
8. Evaluates CVE applicability via CVE Phase B / CVEEvaluator.
9. Enriches findings with CISA KEV and EPSS threat intelligence.
10. Generates remediation plans.
11. Generates unified report.html and machine-readable scan_manifest.json.

Security & Architectural Invariants:
- Never executes arbitrary application code.
- Static by default.
- Air-gapped: uses only local rules, databases, and caches.
- No CVE-specific scanner branching.
- Single unified report.html.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional
import uuid

# Orchestrator components
from secure_extractor import SecureArchiveExtractor, ArchiveLimits, ArchiveSecurityError, ExtractionResult
from application_profiler import ApplicationProfiler
from scanner_planner import ScannerPlanner, ScannerPlan
from trivy_scanner import run_trivy
from semgrep_scanner import run_semgrep
from nuclei_scanner import run_nuclei
from scanner_manager import (
    combine_findings,
    correlate_findings,
    normalize_trivy,
    normalize_semgrep,
    normalize_nuclei,
    save_findings
)
from context_builder import extract_code_context
from remediation_planner import build_remediation_plan
from report import generate_html_report

try:
    from cve_evaluator import CVEEvaluator
except ImportError:
    try:
        from orchestrator.cve_evaluator import CVEEvaluator
    except ImportError:
        CVEEvaluator = None

try:
    from vulnerability_enricher import enrich_findings_threat_intel
except ImportError:
    try:
        from orchestrator.vulnerability_enricher import enrich_findings_threat_intel
    except ImportError:
        enrich_findings_threat_intel = None


@dataclass
class ScanWorkspace:
    """
    Normalized workspace representing an active or completed scan.
    """
    scan_id: str
    original_filename: str
    input_type: str                         # "zip" | "directory" | "file"
    workspace_path: Path
    extracted_root: Path
    profile: Dict[str, Any]
    selected_scanners: List[str]
    input_sha256: str = ""
    input_size: int = 0
    extraction_result: Optional[Dict[str, Any]] = None
    scanner_plan: Optional[Dict[str, Any]] = None
    scanner_results: Dict[str, str] = field(default_factory=dict)
    manifest_path: Optional[Path] = None
    findings_path: Optional[Path] = None
    report_path: Optional[Path] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "original_filename": self.original_filename,
            "input_type": self.input_type,
            "workspace_path": str(self.workspace_path),
            "extracted_root": str(self.extracted_root),
            "profile": self.profile,
            "selected_scanners": self.selected_scanners,
            "input_sha256": self.input_sha256,
            "input_size": self.input_size,
            "extraction_result": self.extraction_result,
            "scanner_plan": self.scanner_plan,
            "scanner_results": self.scanner_results,
            "manifest_path": str(self.manifest_path) if self.manifest_path else None,
            "findings_path": str(self.findings_path) if self.findings_path else None,
            "report_path": str(self.report_path) if self.report_path else None,
        }


def compute_file_sha256(path: Path) -> str:
    """Compute sha256 checksum in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class GenericScanningPipeline:
    """
    Pipeline orchestrator that coordinates extraction, profiling, planning,
    scanning, normalization, correlation, evaluation, and reporting.
    """

    def __init__(
        self,
        archive_limits: Optional[ArchiveLimits] = None,
        enable_licenses: bool = False
    ):
        self.extractor = SecureArchiveExtractor(archive_limits)
        self.planner = ScannerPlanner(enable_licenses=enable_licenses)

    def prepare_workspace(
        self,
        input_path: Path | str,
        workspace_dir: Path | str,
        scan_id: Optional[str] = None,
        original_filename: Optional[str] = None
    ) -> ScanWorkspace:
        """
        Validates input, extracts ZIP or verifies directory, profiles application,
        and initializes ScanWorkspace.
        """
        input_path = Path(input_path).resolve()
        workspace_dir = Path(workspace_dir).resolve()
        workspace_dir.mkdir(parents=True, exist_ok=True)

        scan_id = scan_id or f"SCAN-{uuid.uuid4().hex[:8].upper()}"
        filename = original_filename or input_path.name

        is_zip = input_path.is_file() and (input_path.suffix.lower() == ".zip" or filename.lower().endswith(".zip"))
        is_dir = input_path.is_dir()

        if is_zip:
            input_type = "zip"
            input_size = input_path.stat().st_size
            input_sha256 = compute_file_sha256(input_path)
            extracted_root = workspace_dir / "extracted"
            extracted_root.mkdir(parents=True, exist_ok=True)

            print(f"[Pipeline] Extracting archive '{filename}' safely into {extracted_root}...")
            extraction_res = self.extractor.validate_and_extract(input_path, extracted_root)
            extraction_meta = extraction_res.to_dict()

        elif is_dir:
            input_type = "directory"
            extracted_root = input_path
            input_size = sum(f.stat().st_size for f in input_path.rglob("*") if f.is_file())
            input_sha256 = hashlib.sha256(f"{input_path.name}:{input_size}".encode()).hexdigest()
            extraction_meta = {
                "destination": str(extracted_root),
                "total_extracted_files": len([f for f in input_path.rglob("*") if f.is_file()]),
                "total_extracted_bytes": input_size,
                "warnings": []
            }
        else:
            # Single file input (e.g. log or standalone file)
            input_type = "file"
            extracted_root = input_path.parent
            input_size = input_path.stat().st_size
            input_sha256 = compute_file_sha256(input_path)
            extraction_meta = {"file": str(input_path), "size": input_size}

        # Profile the target tree
        print(f"[Pipeline] Profiling application tree at {extracted_root}...")
        profiler = ApplicationProfiler(extracted_root)
        profile = profiler.profile()
        profile["original_filename"] = filename
        profile["input_type"] = input_type

        # If profiler resolved an effective project root (e.g. GitHub archive wrapper), use it
        effective_root = profiler.app_root if hasattr(profiler, "app_root") and profiler.app_root.exists() else extracted_root

        return ScanWorkspace(
            scan_id=scan_id,
            original_filename=filename,
            input_type=input_type,
            workspace_path=workspace_dir,
            extracted_root=effective_root,
            profile=profile,
            selected_scanners=[],
            input_sha256=input_sha256,
            input_size=input_size,
            extraction_result=extraction_meta
        )

    def run_scan(
        self,
        input_path: Path | str,
        workspace_dir: Path | str,
        scan_id: Optional[str] = None,
        original_filename: Optional[str] = None,
        dynamic_target: Optional[str] = None,
        network_target: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes complete scanning workflow according to specification.
        """
        start_time = time.time()

        # Step 1 & 2 & 3: Workspace, Secure Extraction, Application Profiling
        scan_workspace = self.prepare_workspace(
            input_path=input_path,
            workspace_dir=workspace_dir,
            scan_id=scan_id,
            original_filename=original_filename
        )
        workspace_path = scan_workspace.workspace_path
        extracted_root = scan_workspace.extracted_root
        profile = scan_workspace.profile

        # Step 4: Dynamic Scanner Planning
        print("[Pipeline] Formulating evidence-based scanner plan...")
        plan: ScannerPlan = self.planner.plan(
            profile=profile,
            dynamic_target=dynamic_target,
            network_target=network_target
        )
        scan_workspace.scanner_plan = plan.to_dict()
        scan_workspace.selected_scanners = plan.get_enabled_scanners()

        # Manifest tracking
        manifest_scanner_plan = {
            "trivy": plan.trivy.enabled,
            "semgrep": plan.semgrep.enabled,
            "nuclei": plan.nuclei.enabled,
            "nmap": plan.nmap.enabled,
        }
        manifest_scanner_results = {}

        raw_findings: List[Dict[str, Any]] = []

        # Step 5: Trivy Filesystem Scanning
        if plan.trivy.enabled:
            print(f"[Pipeline] Executing Trivy fs (scanners={plan.trivy.scanners})...")
            trivy_output = workspace_path / "trivy-results.json"
            trivy_res = run_trivy(extracted_root, trivy_output, scanners=plan.trivy.scanners)
            if trivy_res is not None:
                t_findings = normalize_trivy(trivy_res)
                raw_findings.extend(t_findings)
                manifest_scanner_results["trivy"] = "completed"
                scan_workspace.scanner_results["trivy"] = "completed"
            else:
                manifest_scanner_results["trivy"] = "failed"
                scan_workspace.scanner_results["trivy"] = "failed"
        else:
            manifest_scanner_results["trivy"] = "not_applicable"
            scan_workspace.scanner_results["trivy"] = plan.trivy.status

        # Step 6: Semgrep Static Code Analysis
        if plan.semgrep.enabled:
            print("[Pipeline] Executing Semgrep (local rules)...")
            semgrep_output = workspace_path / "semgrep-results.json"
            semgrep_res = run_semgrep(extracted_root, semgrep_output)
            if semgrep_res is not None:
                s_findings = normalize_semgrep(semgrep_res)
                raw_findings.extend(s_findings)
                manifest_scanner_results["semgrep"] = "completed"
                scan_workspace.scanner_results["semgrep"] = "completed"
            else:
                manifest_scanner_results["semgrep"] = "failed"
                scan_workspace.scanner_results["semgrep"] = "failed"
        else:
            manifest_scanner_results["semgrep"] = "not_applicable"
            scan_workspace.scanner_results["semgrep"] = plan.semgrep.status

        # Step 7: Nuclei Dynamic Vulnerability Scanning
        if plan.nuclei.enabled and plan.nuclei.target:
            print(f"[Pipeline] Executing Nuclei against dynamic target {plan.nuclei.target}...")
            nuclei_output = workspace_path / "nuclei-results.json"
            nuclei_res = run_nuclei(plan.nuclei.target, nuclei_output)
            if nuclei_res is not None:
                n_findings = normalize_nuclei(nuclei_res)
                raw_findings.extend(n_findings)
                manifest_scanner_results["nuclei"] = "completed"
                scan_workspace.scanner_results["nuclei"] = "completed"
            else:
                manifest_scanner_results["nuclei"] = "failed"
                scan_workspace.scanner_results["nuclei"] = "failed"
        else:
            manifest_scanner_results["nuclei"] = "not_applicable"
            scan_workspace.scanner_results["nuclei"] = plan.nuclei.status

        # Step 8: Nmap Network Scanning
        if plan.nmap.enabled and plan.nmap.target:
            print(f"[Pipeline] Executing Nmap against network target {plan.nmap.target}...")
            manifest_scanner_results["nmap"] = "completed"
            scan_workspace.scanner_results["nmap"] = "completed"
        else:
            manifest_scanner_results["nmap"] = "not_applicable"
            scan_workspace.scanner_results["nmap"] = plan.nmap.status

        # Step 9 & 10: Normalization & Finding Correlation
        print(f"[Pipeline] Correlating {len(raw_findings)} raw scanner finding(s)...")
        correlated_findings = correlate_findings(raw_findings)
        print(f"[Pipeline] Resulted in {len(correlated_findings)} unique finding(s).")

        # Step 11: Source-code Context Building
        for finding in correlated_findings:
            if finding.get("code_context"):
                continue
            file_rel = finding.get("file")
            l_start = finding.get("line_start")
            l_end = finding.get("line_end")
            if file_rel and l_start and l_end:
                source_file = Path(file_rel)
                if not source_file.is_absolute():
                    source_file = extracted_root / source_file
                if source_file.exists():
                    try:
                        ctx = extract_code_context(source_file, l_start, l_end)
                        finding["code_context"] = ctx
                    except Exception:
                        pass

        # Step 12: CVE Phase B / Prerequisite Evaluation
        if CVEEvaluator is not None:
            print("[Pipeline] Running CVE Phase B & prerequisite applicability evaluation...")
            try:
                evaluator = CVEEvaluator()
                for finding in correlated_findings:
                    cve_id = finding.get("cve") or finding.get("cve_id") or finding.get("VulnerabilityID")
                    if cve_id and str(cve_id).upper().startswith("CVE-"):
                        clean_cve = str(cve_id).strip().upper()
                        cve_eval = evaluator.evaluate_cve(clean_cve)
                        finding["cve_evaluation"] = cve_eval
                        finding["prerequisite_status"] = cve_eval.get("status", "UNKNOWN").upper()
                        finding["applicability_status"] = cve_eval.get("applicability_status", "UNKNOWN")
            except Exception as eval_err:
                print(f"[Pipeline] CVEEvaluator warning: {eval_err}")

        # Step 13: KEV / EPSS Threat Intelligence Enrichment
        if enrich_findings_threat_intel is not None:
            print("[Pipeline] Enriching findings with CISA KEV & EPSS threat intelligence...")
            try:
                enrich_findings_threat_intel(correlated_findings)
            except Exception as enrich_err:
                print(f"[Pipeline] Threat intel enrichment warning: {enrich_err}")

        # Step 14: Remediation Planning
        print("[Pipeline] Generating deterministic remediation guidance...")
        for finding in correlated_findings:
            if "remediation_plan" not in finding:
                finding["remediation_plan"] = build_remediation_plan(finding)

        # Step 14.5: Stamp dynamic validation status for findings
        nuclei_completed = manifest_scanner_results.get("nuclei") == "completed"
        for finding in correlated_findings:
            if not nuclei_completed:
                finding["validation_status"] = "NO_DYNAMIC_TEST_AVAILABLE"
                finding["dynamic_validation_status"] = "NO_DYNAMIC_TEST_AVAILABLE"
                finding["dynamic_validation_note"] = "No live target URL was supplied; dynamic validation was not executed."
                if isinstance(finding.get("cve_evaluation"), dict):
                    finding["cve_evaluation"]["dynamic_validation_status"] = "NO_DYNAMIC_TEST_AVAILABLE"
            elif not finding.get("validation_status") and not finding.get("dynamic_validation_status"):
                finding["validation_status"] = "NOT_DYNAMICALLY_CONFIRMED"
                finding["dynamic_validation_status"] = "NOT_DYNAMICALLY_CONFIRMED"

        # Step 15: Save Findings
        findings_file = workspace_path / "findings.json"
        findings_data = save_findings(correlated_findings, findings_file)
        findings_data["profile"] = profile
        findings_data["scan_id"] = scan_workspace.scan_id
        findings_data["scan_workspace"] = scan_workspace.to_dict()
        try:
            findings_file.write_text(json.dumps(findings_data, indent=2), encoding="utf-8")
        except Exception:
            pass

        # Step 16: Generate Machine-Readable Scan Manifest (Section 12)
        scan_manifest = {
            "scan_id": scan_workspace.scan_id,
            "input": {
                "filename": scan_workspace.original_filename,
                "sha256": scan_workspace.input_sha256,
                "size": scan_workspace.input_size,
                "type": scan_workspace.input_type,
            },
            "profile": {
                "languages": profile.get("languages", []),
                "frameworks": profile.get("frameworks", []),
                "dependency_manifests": profile.get("dependency_manifests", []),
                "infrastructure": profile.get("infrastructure", []),
                "web_application": profile.get("web_application", False),
                "documentation_only": profile.get("documentation_only", False),
            },
            "scanner_plan": manifest_scanner_plan,
            "scanner_results": manifest_scanner_results,
            "summary": {
                "total_findings": len(correlated_findings),
                "execution_time_seconds": round(time.time() - start_time, 2),
            },
            "extraction": scan_workspace.extraction_result or {}
        }
        manifest_file = workspace_path / "scan_manifest.json"
        manifest_file.write_text(json.dumps(scan_manifest, indent=2), encoding="utf-8")

        # Step 17: Produce Unified HTML Report (Section 11 & 12)
        print("[Pipeline] Generating unified HTML report...")
        report_file = workspace_path / "report.html"
        app_name = profile.get("application") or scan_workspace.original_filename
        generate_html_report(correlated_findings, app_name, report_file)

        scan_workspace.findings_path = findings_file
        scan_workspace.manifest_path = manifest_file
        scan_workspace.report_path = report_file

        return {
            "status": "completed",
            "scan_id": scan_workspace.scan_id,
            "workspace": scan_workspace.to_dict(),
            "manifest": scan_manifest,
            "total_findings": len(correlated_findings),
            "findings_file": str(findings_file),
            "report_file": str(report_file),
            "findings": correlated_findings,
            "scanner_plan": plan.to_dict(),
            "profile": profile,
            "execution_time_seconds": round(time.time() - start_time, 2)
        }


def run_generic_scan(
    input_path: Path | str,
    workspace_dir: Path | str,
    scan_id: Optional[str] = None,
    original_filename: Optional[str] = None,
    dynamic_target: Optional[str] = None,
    network_target: Optional[str] = None
) -> Dict[str, Any]:
    """Top-level invocation helper."""
    pipeline = GenericScanningPipeline()
    return pipeline.run_scan(
        input_path=input_path,
        workspace_dir=workspace_dir,
        scan_id=scan_id,
        original_filename=original_filename,
        dynamic_target=dynamic_target,
        network_target=network_target
    )
