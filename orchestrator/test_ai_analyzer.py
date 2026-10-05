from ai_analyzer import analyze_finding


finding = {
    "id": "SEM-001",
    "scanner": "semgrep",
    "type": "Source Code Vulnerability",
    "title": "local-python-command-injection",
    "severity": "ERROR",
    "confidence": "HIGH",
    "cwe": "CWE-78",
    "file": "app.py",
    "line_start": 17,
    "line_end": 20,
    "description": (
        "Potential command injection: "
        "subprocess is executed with shell=True."
    ),
    "code_context": """
17:     host = request.args.get("host")

18:     result = subprocess.check_output(
19:         "ping " + host,
20:         shell=True
21:     )
"""
}


profile = {
    "application": "test-app",
    "languages": ["python"],
    "manifests": ["requirements.txt"]
}


if __name__ == "__main__":
    result = analyze_finding(
        finding,
        profile
    )

    print("AI ANALYSIS RESULT")
    print("=" * 40)

    for key, value in result.items():
        print(f"{key}: {value}")