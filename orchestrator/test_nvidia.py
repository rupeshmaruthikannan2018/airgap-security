from local_llm import generate_response


if __name__ == "__main__":
    prompt = """
Analyze this security finding.

Finding:
- Scanner: Semgrep
- Vulnerability: Command Injection
- CWE: CWE-78
- File: app.py
- Lines: 23-26

Code:

result = subprocess.check_output(
    "ping " + host,
    shell=True
)

Return the required structured security assessment.
"""

    result = generate_response(prompt)

    print("\nNVIDIA TEST RESULT")
    print("=" * 60)

    for key, value in result.items():
        print(f"{key}: {value}")