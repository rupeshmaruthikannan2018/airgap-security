from remediation_planner import (
    build_remediation_plan
)


# ---------------------------------------------------------
# Test Trivy
# ---------------------------------------------------------

trivy_finding = {
    "id": "TRIVY-001",
    "scanner": "trivy",
    "file": "requirements.txt",
    "package": "Flask",
    "installed_version": "2.0.0",
    "fixed_version": "2.3.2, 2.2.5",
    "cve": "CVE-2023-30861",
    "cwe": "CWE-539"
}


trivy_plan = build_remediation_plan(
    trivy_finding
)


print("\nTRIVY REMEDIATION PLAN")
print("=" * 40)

for key, value in trivy_plan.items():

    print(f"{key}: {value}")


# ---------------------------------------------------------
# Test Semgrep
# ---------------------------------------------------------

semgrep_finding = {
    "id": "SEM-001",
    "scanner": "semgrep",
    "file": (
        r"C:\airgap-security\test-app\app.py"
    ),
    "line_start": 23,
    "line_end": 26,
    "cwe": "CWE-78",

    "ai_analysis": {
        "ai_assessment": {
            "recommended_fix": (
                "Remove shell=True and pass "
                "command arguments separately."
            )
        }
    }
}


semgrep_plan = build_remediation_plan(
    semgrep_finding
)


print("\nSEMGREP REMEDIATION PLAN")
print("=" * 40)

for key, value in semgrep_plan.items():

    print(f"{key}: {value}")