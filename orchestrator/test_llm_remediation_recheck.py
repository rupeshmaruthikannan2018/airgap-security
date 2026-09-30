from pathlib import Path
import json
from local_llm import generate_response


ORCHESTRATOR = Path(r"C:\airgap-security\orchestrator")

PROMPT_FILE = ORCHESTRATOR / "llm_remediation_recheck_prompt.txt"

DEMO_DIR = Path(r"C:\airgap-security\labs\tomcat\demo")
OUTPUT_DIR = DEMO_DIR / "02_LLM_REMEDIATION_ANALYSIS"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

PROMPT_OUTPUT = OUTPUT_DIR / "prompt.txt"
RESULT_OUTPUT = OUTPUT_DIR / "llm-remediation-assessment.json"


def main():
    print("=" * 70)
    print("LOCAL LLM REMEDIATION RECHECK")
    print("=" * 70)
    print()

    if not PROMPT_FILE.exists():
        raise FileNotFoundError(
            f"Prompt file not found:\n{PROMPT_FILE}"
        )

    prompt = PROMPT_FILE.read_text(encoding="utf-8")

    # Preserve the exact prompt used for this experiment.
    PROMPT_OUTPUT.write_text(prompt, encoding="utf-8")

    print("Prompt loaded:")
    print(PROMPT_FILE)
    print()

    print("Calling local LLM...")
    print()

    raw_result = generate_response(prompt)

    print("=" * 70)
    print("RAW LLM RESPONSE")
    print("=" * 70)
    print(raw_result)
    print("=" * 70)
    print()

    # generate_response() normally returns a parsed Python dictionary.
    # If it returns a string, try to parse JSON from it.
    if isinstance(raw_result, dict):
        result = raw_result

    elif isinstance(raw_result, str):
        cleaned = raw_result.strip()

        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]

        if cleaned.startswith("```"):
            cleaned = cleaned[3:]

        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]

        cleaned = cleaned.strip()

        try:
            result = json.loads(cleaned)
        except json.JSONDecodeError:
            result = {
                "raw_llm_response": raw_result
            }

    else:
        result = {
            "raw_llm_response": str(raw_result)
        }

    # Add experiment metadata without altering the LLM's reasoning.
    saved_result = {
        "experiment": {
            "name": "CVE-2025-24813 remediation recheck",
            "model_role": "Post-remediation evidence assessment",
            "server": "Apache Tomcat",
            "tomcat_before": "9.0.98",
            "tomcat_after": "9.0.98",
            "fixed_tomcat_9_version": "9.0.99"
        },
        "llm_assessment": result
    }

    RESULT_OUTPUT.write_text(
        json.dumps(
            saved_result,
            indent=4,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    print("LLM assessment saved to:")
    print(RESULT_OUTPUT)
    print()

    print("=" * 70)
    print("EXPERIMENT COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()