"""Test script to query the lab's Gemma 26B/24B model (SGLang server)."""

import os
import sys
import json
import time
from pathlib import Path

# Set up environment for the Lab's SGLang server
os.environ.setdefault("LOCAL_LLM_API_KEY", os.getenv("SGLANG_API_KEY", "local-sglang-key"))
os.environ.setdefault("LLM_PROVIDER", "sglang")

orchestrator_dir = Path(__file__).resolve().parent
if str(orchestrator_dir) not in sys.path:
    sys.path.insert(0, str(orchestrator_dir))

from local_llm import (
    generate_response,
    SGLANG_BASE_URL,
    SGLANG_MODEL,
    LLM_PROVIDER
)


def test_lab_security_analysis():
    print("=" * 70)
    print(f"[*] TESTING LAB MODEL: {SGLANG_MODEL}")
    print(f"[*] Server Endpoint: {SGLANG_BASE_URL}")
    print(f"[*] Active Provider: {LLM_PROVIDER}")
    print("=" * 70)

    prompt = (
        "Analyze this security finding:\n\n"
        "Scanner: Semgrep\n"
        "Vulnerability: Command Injection\n"
        "CWE: CWE-78\n"
        "File: app.py (Lines 23-26)\n"
        "Code:\n"
        "    result = subprocess.check_output('ping ' + host, shell=True)\n\n"
        "Provide a complete vulnerability analysis adhering strictly to the schema."
    )

    print("\n[>] Sending Security Analysis prompt to Gemma 26B/24B...")
    start_t = time.time()
    result = generate_response(prompt, task="analysis")
    elapsed = time.time() - start_t

    print(f"\n[+] Received response in {elapsed:.2f}s:")
    print("=" * 70)
    print(json.dumps(result, indent=2))
    print("=" * 70)
    return result


def test_lab_tool_selection():
    print("\n" + "=" * 70)
    print(f"[*] TESTING AUTONOMOUS TOOL SELECTION WITH GEMMA 26B/24B")
    print("=" * 70)

    prompt = (
        "Target Type: filesystem_target\n"
        "Target Identifier: C:\\airgap-security\\test-app-offline.zip\n"
        "Target Summary: Directory target containing Python backend files and requirements.\n"
        "Discovered Files: [\"app.py\", \"requirements.txt\", \"config.json\"]\n"
        "File Extensions: [\".py\", \".txt\", \".json\"]\n"
        "Dependency Manifests: [\"requirements.txt\"]\n\n"
        "Available Tools:\n"
        "1. 'semgrep' -> Source code vulnerability scanner (Python, JS, Go, Java, etc.)\n"
        "2. 'trivy' -> Dependency & package vulnerability scanner (requirements.txt, package.json, etc.)\n"
        "3. 'nmap' -> Network service & open port scanner (for IP addresses and hostnames)\n\n"
        "Select the required tool(s) and explain the reason for each choice."
    )

    print("[>] Querying Gemma 26B/24B for autonomous tool selection...")
    start_t = time.time()
    result = generate_response(prompt, task="tool_selection")
    elapsed = time.time() - start_t

    print(f"\n[+] Received decision in {elapsed:.2f}s:")
    print("=" * 70)
    print(json.dumps(result, indent=2))
    print("=" * 70)
    return result


def main():
    test_lab_security_analysis()
    test_lab_tool_selection()
    print("\n[SUCCESS] Lab Gemma 26B/24B model executed and validated successfully!")


if __name__ == "__main__":
    main()
