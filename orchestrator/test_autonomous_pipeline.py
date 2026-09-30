"""Test script for verifying autonomous tool calling on test-app-offline.zip."""

import sys
import argparse
import json
from pathlib import Path

# Add orchestrator to sys.path
orchestrator_dir = Path(__file__).resolve().parent
if str(orchestrator_dir) not in sys.path:
    sys.path.insert(0, str(orchestrator_dir))

from autonomous_agent import execute_autonomous_pipeline


def main():
    parser = argparse.ArgumentParser(description="Test Autonomous Tool Selection Pipeline")
    parser.add_argument(
        "--target",
        default=r"C:\airgap-security\test-app-offline.zip",
        help="Target zip archive, directory, or host to analyze"
    )
    args = parser.parse_args()

    target_path = Path(args.target)
    print("=" * 70)
    print("AUTONOMOUS SECURITY TOOL-CALLING TEST")
    print(f"Target: {target_path}")
    print("=" * 70)

    report = execute_autonomous_pipeline(target_path)

    print("\n" + "=" * 70)
    print("SUMMARY OF AUTONOMOUS ANALYSIS")
    print("=" * 70)
    print(f"Target Type: {report.get('target_type')}")
    print(f"Tools Chosen by Autonomous Agent: {report.get('tools_executed')}")
    print(f"Total Findings Detected: {report.get('total_findings')}")
    
    print("\n--- DETAILED FINDINGS & REMEDIATIONS ---")
    for idx, f in enumerate(report.get("findings", []), 1):
        print(f"\n[{idx}] Scanner: {f.get('scanner').upper()} | Severity: {f.get('severity')} | ID: {f.get('id')}")
        print(f"    Title: {f.get('title')}")
        print(f"    Target/File: {f.get('file')} (Lines {f.get('line_start')}-{f.get('line_end')})")
        remediation = f.get("remediation_plan", {})
        print(f"    Action: {remediation.get('action')}")
        remedy = remediation.get("recommended_fix") or remediation.get("ai_recommended_fix")
        if not remedy and remediation.get("fixed_versions"):
            remedy = f"Upgrade package '{remediation.get('package')}' to version {', '.join(remediation.get('fixed_versions', []))}"
        print(f"    Remedy: {remedy or 'Needs manual review'}")

    print("\n" + "=" * 70)
    print("[SUCCESS] Test pipeline finished successfully.")
    print("=" * 70)


if __name__ == "__main__":
    main()
