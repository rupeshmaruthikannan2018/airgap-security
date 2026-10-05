"""
Dynamic Scanner Planner for AirGap Security Platform.

Inspects an ApplicationProfile and formulates an evidence-based ScannerPlan.
Ensures:
- Scanners are selected purely based on structured application evidence.
- No CVE-specific or hard-coded rules are used.
- Trivy filesystem scans source and dependencies, enabling misconfig only when
  infrastructure or configuration files are present.
- Semgrep runs only when source code evidence is present.
- Nuclei runs ONLY when an explicit dynamic target URL is provided.
  If not available, records NO_DYNAMIC_TARGET_AVAILABLE (never marked as SAFE or NOT_VULNERABLE).
- Nmap runs ONLY when an explicit network target host/IP is provided.
  If not available, records NO_NETWORK_TARGET_AVAILABLE.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ScannerConfig:
    enabled: bool
    status: str = "PENDING"
    reason: str = ""
    scanners: List[str] = field(default_factory=list)
    target: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "enabled": self.enabled,
            "status": self.status,
            "reason": self.reason,
        }
        if self.scanners:
            d["scanners"] = self.scanners
        if self.target:
            d["target"] = self.target
        if self.options:
            d["options"] = self.options
        return d


@dataclass
class ScannerPlan:
    trivy: ScannerConfig
    semgrep: ScannerConfig
    nuclei: ScannerConfig
    nmap: ScannerConfig
    profile_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trivy": self.trivy.to_dict(),
            "semgrep": self.semgrep.to_dict(),
            "nuclei": self.nuclei.to_dict(),
            "nmap": self.nmap.to_dict(),
            "profile_summary": self.profile_summary,
        }

    def get_enabled_scanners(self) -> List[str]:
        enabled = []
        if self.trivy.enabled:
            enabled.append("trivy")
        if self.semgrep.enabled:
            enabled.append("semgrep")
        if self.nuclei.enabled:
            enabled.append("nuclei")
        if self.nmap.enabled:
            enabled.append("nmap")
        return enabled


class ScannerPlanner:
    """
    Formulates a targeted scan plan based on ApplicationProfile evidence.
    """

    def __init__(
        self,
        enable_licenses: bool = False,
        default_trivy_scanners: Optional[List[str]] = None
    ):
        self.enable_licenses = enable_licenses
        self.default_trivy_scanners = default_trivy_scanners or ["vuln", "secret"]

    def plan(
        self,
        profile: Dict[str, Any],
        dynamic_target: Optional[str] = None,
        network_target: Optional[str] = None
    ) -> ScannerPlan:
        """
        Creates ScannerPlan from an ApplicationProfile dict.
        """
        languages = profile.get("languages", [])
        manifests = profile.get("dependency_manifests", []) or profile.get("manifests", [])
        infrastructure = profile.get("infrastructure", [])
        config_files = profile.get("config_files", [])
        doc_only = profile.get("documentation_only", False)
        total_files = profile.get("total_files", len(profile.get("files", [])))

        # ----------------------------------------------------
        # 1. TRIVY PLANNING
        # ----------------------------------------------------
        if doc_only or total_files == 0:
            trivy_config = ScannerConfig(
                enabled=False,
                status="SKIPPED",
                reason="Documentation-only or empty archive; no package or dependency manifests to scan."
            )
        else:
            trivy_scanners = list(self.default_trivy_scanners)

            # Enable misconfig when infrastructure or configuration files are present
            has_infra = bool(infrastructure)
            has_configs = bool(config_files)
            if has_infra or has_configs:
                if "misconfig" not in trivy_scanners:
                    trivy_scanners.append("misconfig")

            if self.enable_licenses and "license" not in trivy_scanners:
                trivy_scanners.append("license")

            reasons = []
            if manifests:
                reasons.append(f"Dependencies detected ({len(manifests)} manifest(s))")
            if has_infra:
                reasons.append(f"Infrastructure detected ({', '.join(infrastructure)})")
            if has_configs:
                reasons.append(f"Configurations detected ({len(config_files)} file(s))")
            if not reasons:
                reasons.append("Baseline filesystem vulnerability & secret inspection")

            trivy_config = ScannerConfig(
                enabled=True,
                status="PLANNED",
                scanners=trivy_scanners,
                reason="; ".join(reasons)
            )

        # ----------------------------------------------------
        # 2. SEMGREP PLANNING
        # ----------------------------------------------------
        if doc_only:
            semgrep_config = ScannerConfig(
                enabled=False,
                status="SKIPPED",
                reason="Documentation-only archive; no source code present."
            )
        elif languages:
            semgrep_config = ScannerConfig(
                enabled=True,
                status="PLANNED",
                reason=f"Source code evidence detected for language(s): {', '.join(languages)}."
            )
        elif any(f.endswith((".py", ".js", ".ts", ".java", ".go", ".rs", ".php", ".rb", ".c", ".cpp", ".cs"))
                 for f in profile.get("files", [])):
            semgrep_config = ScannerConfig(
                enabled=True,
                status="PLANNED",
                reason="Source code files present in workspace."
            )
        else:
            semgrep_config = ScannerConfig(
                enabled=False,
                status="SKIPPED",
                reason="No source code evidence detected in application tree."
            )

        # ----------------------------------------------------
        # 3. NUCLEI PLANNING
        # ----------------------------------------------------
        clean_dynamic = str(dynamic_target).strip() if dynamic_target else ""
        if clean_dynamic:
            nuclei_config = ScannerConfig(
                enabled=True,
                status="PLANNED",
                target=clean_dynamic,
                reason=f"Dynamic target available at {clean_dynamic}."
            )
        else:
            nuclei_config = ScannerConfig(
                enabled=False,
                status="NO_DYNAMIC_TARGET_AVAILABLE",
                reason="No runnable dynamic target available; static ZIP/folder scan only."
            )

        # ----------------------------------------------------
        # 4. NMAP PLANNING
        # ----------------------------------------------------
        clean_network = str(network_target).strip() if network_target else ""
        if clean_network:
            nmap_config = ScannerConfig(
                enabled=True,
                status="PLANNED",
                target=clean_network,
                reason=f"Network target supplied: {clean_network}."
            )
        else:
            nmap_config = ScannerConfig(
                enabled=False,
                status="NO_NETWORK_TARGET_AVAILABLE",
                reason="No network target supplied; network scanning disabled for static files."
            )

        profile_summary = {
            "languages": languages,
            "manifests": manifests,
            "infrastructure": infrastructure,
            "web_application": profile.get("web_application", "unknown"),
            "documentation_only": doc_only,
            "total_files": total_files,
        }

        return ScannerPlan(
            trivy=trivy_config,
            semgrep=semgrep_config,
            nuclei=nuclei_config,
            nmap=nmap_config,
            profile_summary=profile_summary
        )


def plan_scanners(
    profile: Dict[str, Any],
    dynamic_target: Optional[str] = None,
    network_target: Optional[str] = None
) -> ScannerPlan:
    """Convenience helper to create a ScannerPlan."""
    planner = ScannerPlanner()
    return planner.plan(profile, dynamic_target, network_target)
