from local_llm import generate_response


prompt = """
Analyze this vulnerability:

CWE-78
Command Injection

The application takes user-controlled input
and passes it to subprocess.check_output()
with shell=True.

Explain:
1. Whether this is a real vulnerability.
2. The security impact.
3. How it should be fixed.
"""


response = generate_response(prompt)


print("LOCAL LLM RESPONSE")
print("=" * 40)
print(response)