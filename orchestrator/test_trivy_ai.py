from ai_analyzer import analyze_finding


finding = {
    "id": "TRIVY-001",
    "scanner": "trivy",
    "type": "Dependency Vulnerability",
    "title": "Flask: improper handling of multipart form data",
    "severity": "HIGH",
    "confidence": None,
    "cwe": "CWE-539",
    "file": "requirements.txt",
    "cve": "CVE-2023-30861",
    "package": "Flask",
    "installed_version": "2.0.0",
    "fixed_version": "2.3.2",
    "description": (
        "Flask version 2.0.0 is affected by a known "
        "security vulnerability. A fixed version is available."
    )
}


profile = {
    "application": "test-app",
    "languages": ["python"],
    "manifests": ["requirements.txt"]
}


result = analyze_finding(
    finding,
    profile
)


print("\nTRIVY AI ANALYSIS")
print("=" * 40)

assessment = result["ai_assessment"]

for key, value in assessment.items():
    print(f"{key}: {value}")