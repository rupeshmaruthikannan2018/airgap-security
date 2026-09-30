

def split_fixed_versions(fixed_version):
    """
    Convert Trivy's fixed-version string into
    a clean list of versions.

    Example:

        "2.3.2, 2.2.5"

    becomes:

        ["2.3.2", "2.2.5"]
    """

    if not fixed_version:
        return []

    versions = []

    for version in str(fixed_version).split(","):

        version = version.strip()

        if version:
            versions.append(version)

    return versions


def build_trivy_remediation(finding):
    """
    Build a deterministic remediation plan for
    a Trivy dependency vulnerability.
    """

    package = finding.get("package")
    installed_version = finding.get(
        "installed_version"
    )
    fixed_version = finding.get(
        "fixed_version"
    )

    fixed_versions = split_fixed_versions(
        fixed_version
    )

    # ---------------------------------------------------------
    # Validate required information
    # ---------------------------------------------------------

    if not package:

        return {
            "status": "needs_review",
            "reason": (
                "Trivy finding does not contain "
                "a package name."
            )
        }

    if not installed_version:

        return {
            "status": "needs_review",
            "reason": (
                "Trivy finding does not contain "
                "an installed package version."
            )
        }

    if not fixed_versions:

        return {
            "status": "needs_review",
            "reason": (
                "Trivy finding does not provide "
                "a fixed package version."
            )
        }

    # ---------------------------------------------------------
    # Build deterministic remediation
    # ---------------------------------------------------------

    return {
        "status": "ready",

        "action": "upgrade_dependency",

        "package": package,

        "manifest": finding.get("file"),

        "installed_version": installed_version,

        "fixed_versions": fixed_versions,

        "cve": finding.get("cve"),

        "cwe": finding.get("cwe"),

        "source": "trivy",

        "requires_patch_validation": True
    }


def build_semgrep_remediation(finding):
    """
    Build a remediation plan for a Semgrep
    source-code vulnerability.

    The AI recommendation is preserved as advisory
    information only.

    No source-code modification is performed here.
    """

    file_path = finding.get("file")

    line_start = finding.get(
        "line_start"
    )

    line_end = finding.get(
        "line_end"
    )

    cwe = finding.get("cwe")

    ai_analysis = finding.get(
        "ai_analysis",
        {}
    )

    ai_assessment = ai_analysis.get(
        "ai_assessment",
        {}
    )

    recommended_fix = ai_assessment.get(
        "recommended_fix"
    )

    # ---------------------------------------------------------
    # Validate source location
    # ---------------------------------------------------------

    if not file_path:

        return {
            "status": "needs_review",
            "reason": (
                "Semgrep finding does not contain "
                "a source file."
            )
        }

    if not line_start or not line_end:

        return {
            "status": "needs_review",
            "reason": (
                "Semgrep finding does not contain "
                "a valid source-code location."
            )
        }

    # ---------------------------------------------------------
    # Build source-code remediation plan
    # ---------------------------------------------------------

    return {
        "status": "requires_patch_analysis",

        "action": "source_code_remediation",

        "file": file_path,

        "line_start": line_start,

        "line_end": line_end,

        "cwe": cwe,

        "source": "semgrep",

        "ai_recommended_fix": recommended_fix,

        "requires_patch_validation": True
    }



def build_nmap_remediation(finding):
    """
    Build a remediation plan for an Nmap
    network service / port exposure finding.
    """
    existing_plan = finding.get("remediation_plan")
    if existing_plan and isinstance(existing_plan, dict) and "action" in existing_plan:
        return existing_plan

    return {
        "status": "requires_review",
        "action": "restrict_network_access",
        "recommended_fix": (
            "Verify whether this port/service needs to be exposed. "
            "Restrict access via firewall rules or disable the unused service."
        ),
        "requires_patch_validation": False
    }


def build_remediation_plan(finding):
    """
    Build a remediation plan according to
    the scanner that produced the finding.
    """

    scanner = finding.get("scanner")

    # ---------------------------------------------------------
    # Trivy
    # ---------------------------------------------------------

    if scanner == "trivy":

        return build_trivy_remediation(
            finding
        )

    # ---------------------------------------------------------
    # Semgrep
    # ---------------------------------------------------------

    if scanner == "semgrep":

        return build_semgrep_remediation(
            finding
        )

    # ---------------------------------------------------------
    # Nmap
    # ---------------------------------------------------------

    if scanner == "nmap":

        return build_nmap_remediation(
            finding
        )

    # ---------------------------------------------------------
    # Unknown scanner
    # ---------------------------------------------------------

    return {
        "status": "needs_review",

        "reason": (
            f"Unsupported scanner: {scanner}"
        )
    }