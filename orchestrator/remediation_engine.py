import argparse
import json
from pathlib import Path

from local_llm import generate_response


# ============================================================
# DEFAULT MODEL
# ============================================================

DEFAULT_MODEL = "gemma-4-26b-a4b-it"


# ============================================================
# JSON HELPERS
# ============================================================

def load_json(path):
    """
    Load a JSON file.
    """

    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(data, path):
    """
    Save JSON with readable formatting.
    """

    path = Path(path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            data,
            f,
            indent=2,
            ensure_ascii=False
        )


# ============================================================
# FINDING SELECTION
# ============================================================

def extract_findings(findings_data):
    """
    Accept:

        {
            "total_findings": ...,
            "findings": [...]
        }

    or a plain list.
    """

    if isinstance(findings_data, list):
        return findings_data

    if isinstance(findings_data, dict):

        findings = findings_data.get("findings")

        if isinstance(findings, list):
            return findings

    raise ValueError(
        "Invalid findings file. Expected a 'findings' list."
    )


def find_cve_finding(findings, cve):
    """
    Find the normalized finding corresponding
    to the requested CVE.
    """

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        # Normalized scanner_manager format.
        if finding.get("cve") == cve:
            return finding

        # Fallback formats.
        if finding.get("VulnerabilityID") == cve:
            return finding

        if finding.get("vulnerability_id") == cve:
            return finding

    return None


# ============================================================
# CONFIGURATION
# ============================================================

def get_effective_configuration(config):
    """
    Get compact effective configuration generated
    by config_collector.py.

    Falls back to the root configuration for
    older configuration files.
    """

    if not isinstance(config, dict):
        return {}

    effective = config.get(
        "effective_configuration"
    )

    if isinstance(effective, dict):
        return effective

    return config


# ============================================================
# EVIDENCE PACKAGE
# ============================================================

def build_evidence_package(
    finding,
    knowledge,
    config,
    evaluation
):
    """
    Build the evidence package supplied to the LLM.

    Evidence sources:

        1. Scanner finding
        2. CVE knowledge
        3. Environment configuration
        4. Deterministic CVE evaluation
    """

    effective_config = get_effective_configuration(
        config
    )

    return {
        "finding": finding,
        "vulnerability_knowledge": knowledge,
        "environment_configuration": effective_config,
        "condition_evaluation": evaluation
    }


# ============================================================
# PROMPT
# ============================================================

def build_prompt(evidence_package):

    evidence_json = json.dumps(
        evidence_package,
        indent=2,
        ensure_ascii=False
    )

    prompt = f"""
You are a cybersecurity vulnerability remediation analyst
operating inside a controlled security remediation platform.

Analyze ONE vulnerability using ONLY the supplied evidence.

Do NOT invent facts.

Do NOT assume exploitation merely because a scanner reports
a vulnerable software version.

Do NOT assume an application library, route, endpoint,
configuration, attacker capability, upload path, sensitive
file, or exploit behavior unless it is explicitly present
in the supplied evidence.

============================================================
CORE REASONING RULES
============================================================

1. Determine whether the installed component/version is affected.

2. Determine which CVE conditions are:

   - CONFIRMED
   - NOT_SATISFIED
   - NOT_ESTABLISHED
   - UNKNOWN

3. A condition marked NOT_SATISFIED must remain NOT_SATISFIED.

4. A condition marked UNKNOWN must remain UNKNOWN unless
   supplied evidence establishes it.

5. Do NOT claim successful exploitation unless supplied
   evidence proves exploitation.

6. Distinguish clearly between:

   - Vulnerable software version
   - Exploitation prerequisites
   - Confirmed exploitability
   - Potential impact

7. If the evidence does not prove RCE, do NOT claim RCE.

8. If the evidence does not prove information disclosure,
   do NOT claim information disclosure is confirmed.

9. Use supplied CVE knowledge and vendor remediation
   information when discussing upgrades.

10. Do not invent a fixed version.

11. Do not automatically execute remediation.

12. Do not provide destructive commands.

13. THE DETERMINISTIC CVE EVALUATION IS AUTHORITATIVE.

    The field "condition_evaluation" contains the result of a
    deterministic rules engine. Treat its evaluated statuses as
    ground truth for this analysis.

    Do NOT independently reconstruct, reinterpret, or override
    the evaluator's logic from raw configuration evidence.

    If the evaluator marks an overall condition as SATISFIED,
    NOT_SATISFIED, or UNKNOWN, preserve that status exactly.

14. DO NOT DERIVE NEW SUB-CONDITIONS.

    Do not claim that an overall condition is unsatisfied because
    you believe one of its internal fields should have a different
    value. The evaluator has already applied the condition logic.

    You may explain the evaluator's result, but the explanation
    must not contradict the supplied evaluated status.

15. RCE AND INFORMATION-DISCLOSURE ASSESSMENTS MUST FOLLOW
    THEIR DETERMINISTIC OVERALL STATUS.

    If the evaluator says remote_code_execution is NOT_SATISFIED,
    return RCE status NOT_SATISFIED. Explain the evaluator's stated
    blocking condition(s) without inventing additional blockers.

    If the evaluator says information_disclosure_or_content_injection
    is UNKNOWN, preserve that overall result and explain only the
    documented unknowns.

16. IF EVIDENCE AND EVALUATOR APPEAR TO CONFLICT, REPORT THE
    CONFLICT IN THE REASON FIELD.

    Do not silently resolve the conflict by changing the evaluator
    result. The deterministic result remains authoritative unless
    the evaluation file itself is corrected by the security team.

13. The deterministic CVE evaluation is AUTHORITATIVE for
condition status.

14. You MUST use each condition's evaluated status exactly
as supplied by the "condition_evaluation" evidence.

15. Do NOT change, reinterpret, downgrade, or upgrade a
condition status based on your own reasoning. In particular:

   - satisfied remains satisfied
   - not_satisfied remains not_satisfied
   - unknown remains unknown

16. The LLM may explain what an evaluated condition means,
but it must not replace the evaluator's status.

17. If scanner evidence, environment configuration, and the
deterministic evaluation appear inconsistent, explicitly
report the inconsistency as a CONFLICT/UNKNOWN rather than
silently changing the deterministic status.

18. Do not infer that a condition is NOT_SATISFIED merely
because the evidence does not establish a stronger exploit
path. "Not satisfied" and "unknown" are different states.

19. When discussing RCE or information disclosure, derive the
assessment from the deterministic evaluation and its logical
conditions. Do not substitute a separate model judgment for
the evaluator's result.

============================================================
REMEDIATION REASONING
============================================================

Determine appropriate remediation from the supplied evidence.

Consider:

- Vendor-supported upgrade
- Configuration hardening
- Disabling vulnerable functionality
- Removing unnecessary exposure
- Application-specific remediation
- Dependency updates

If multiple remediation actions are appropriate,
explain why each action is relevant.

Do not recommend a configuration change unless the supplied
evidence establishes that the configuration is related to
the vulnerability.

When a vendor fixed version is supplied, preserve it exactly.

============================================================
VALIDATION
============================================================

Describe how the security team can prove that remediation
worked.

Prefer validation such as:

- Recollecting configuration
- Verifying installed version
- Re-running the relevant scanner
- Re-running deterministic CVE evaluation
- Performing a controlled behavioral test
- Comparing before/after evidence

Do not claim that validation has already succeeded.

============================================================
IMPORTANT RISK RULE
============================================================

The "risk" field must contain ONLY one of:

LOW
MEDIUM
HIGH
CRITICAL

Do NOT put an explanation in the risk field.

============================================================
EVALUATION CONSISTENCY REQUIREMENT
============================================================

Before producing the JSON, compare every condition in your
"conditions" array with the supplied deterministic
"condition_evaluation". The status must match the evaluator.

For example, if the evidence says:

  file_based_session_persistence = satisfied

then the output condition for that same condition MUST use:

  "status": "CONFIRMED"

It MUST NOT say NOT_SATISFIED, NOT_ESTABLISHED, or UNKNOWN.

If a condition is evaluated as not_satisfied, the corresponding
LLM condition MUST be NOT_SATISFIED.

If a condition is evaluated as unknown, the corresponding LLM
condition MUST be UNKNOWN or NOT_ESTABLISHED only when the
evaluator explicitly represents the unresolved state that way;
do not invent a satisfied or not_satisfied result.

For RCE and information disclosure assessments, preserve the
logical outcome supplied by the deterministic evaluator.

============================================================
OUTPUT FORMAT
============================================================

Return ONLY valid JSON.

Use exactly this structure:

{{
  "applicability": {{
    "status": "",
    "reason": ""
  }},

  "risk": "",

  "conditions": [
    {{
      "condition": "",
      "status": "",
      "evidence": "",
      "reason": ""
    }}
  ],

  "rce_assessment": {{
    "status": "",
    "reason": ""
  }},

  "information_disclosure_assessment": {{
    "status": "",
    "reason": ""
  }},

  "root_cause": "",

  "remediation": [
    {{
      "action": "",
      "reason": "",
      "type": ""
    }}
  ],

  "validation": [
    ""
  ],

  "confidence": "",

  "unknowns": [
    ""
  ]
}}

============================================================
ALLOWED VALUES
============================================================

Applicability status:

- CONFIRMED
- NOT_ESTABLISHED
- UNKNOWN

Condition status:

- CONFIRMED
- NOT_SATISFIED
- NOT_ESTABLISHED
- UNKNOWN

RCE status:

- CONFIRMED
- NOT_SATISFIED
- NOT_ESTABLISHED
- UNKNOWN

Information disclosure status:

- CONFIRMED
- NOT_SATISFIED
- NOT_ESTABLISHED
- UNKNOWN

Risk:

- LOW
- MEDIUM
- HIGH
- CRITICAL

Confidence:

- LOW
- MEDIUM
- HIGH

Remediation type:

- UPGRADE
- CONFIGURATION
- HARDENING
- DEPENDENCY
- APPLICATION
- VALIDATION

============================================================
EVIDENCE
============================================================

{evidence_json}

============================================================
FINAL INSTRUCTION
============================================================

Return ONLY the JSON object.

Do not use Markdown.

Do not add explanations before or after the JSON.
""".strip()

    return prompt


# ============================================================
# RESPONSE VALIDATION
# ============================================================

def validate_remediation_result(result):
    """
    Validate the structured dictionary returned by local_llm.py.

    local_llm.py already parses the model response into a Python
    dictionary, so this function validates that dictionary
    directly.

    This checks structure and allowed values.
    It does NOT independently determine whether the model's
    cybersecurity reasoning is correct.
    """

    # --------------------------------------------------------
    # Root object
    # --------------------------------------------------------

    if not isinstance(result, dict):
        raise ValueError(
            "LLM result must be a JSON object/dictionary."
        )

    # --------------------------------------------------------
    # Required fields
    # --------------------------------------------------------

    required_fields = [
        "applicability",
        "risk",
        "conditions",
        "rce_assessment",
        "information_disclosure_assessment",
        "root_cause",
        "remediation",
        "validation",
        "confidence",
        "unknowns"
    ]

    missing = [
        field
        for field in required_fields
        if field not in result
    ]

    if missing:
        raise ValueError(
            "LLM result is missing required fields: "
            + ", ".join(missing)
        )

    # --------------------------------------------------------
    # Applicability
    # --------------------------------------------------------

    applicability = result["applicability"]

    if not isinstance(
        applicability,
        dict
    ):
        raise ValueError(
            "'applicability' must be an object."
        )

    if "status" not in applicability:
        raise ValueError(
            "'applicability.status' is missing."
        )

    allowed_applicability = {
        "CONFIRMED",
        "NOT_ESTABLISHED",
        "UNKNOWN"
    }

    if applicability["status"] not in allowed_applicability:
        raise ValueError(
            "Invalid applicability status: "
            f"{applicability['status']}"
        )

    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    allowed_risk = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }

    risk = result["risk"]

    if not isinstance(risk, str):
        raise ValueError(
            "'risk' must be a string."
        )

    if risk not in allowed_risk:
        raise ValueError(
            "Invalid risk value: "
            f"{risk}. "
            "Expected LOW, MEDIUM, HIGH, or CRITICAL."
        )

    # --------------------------------------------------------
    # Conditions
    # --------------------------------------------------------

    conditions = result["conditions"]

    if not isinstance(
        conditions,
        list
    ):
        raise ValueError(
            "'conditions' must be a list."
        )

    allowed_condition_status = {
        "CONFIRMED",
        "NOT_SATISFIED",
        "NOT_ESTABLISHED",
        "UNKNOWN"
    }

    for index, condition in enumerate(
        conditions
    ):

        if not isinstance(
            condition,
            dict
        ):
            raise ValueError(
                f"Condition {index} must be an object."
            )

        required_condition_fields = [
            "condition",
            "status",
            "evidence",
            "reason"
        ]

        missing_condition_fields = [
            field
            for field in required_condition_fields
            if field not in condition
        ]

        if missing_condition_fields:

            raise ValueError(
                f"Condition {index} is missing fields: "
                + ", ".join(missing_condition_fields)
            )

        if condition["status"] not in allowed_condition_status:

            raise ValueError(
                f"Invalid condition status at index {index}: "
                f"{condition['status']}"
            )

    # --------------------------------------------------------
    # RCE assessment
    # --------------------------------------------------------

    rce = result["rce_assessment"]

    if not isinstance(
        rce,
        dict
    ):
        raise ValueError(
            "'rce_assessment' must be an object."
        )

    if "status" not in rce:
        raise ValueError(
            "'rce_assessment.status' is missing."
        )

    if rce["status"] not in allowed_condition_status:

        raise ValueError(
            "Invalid RCE assessment status: "
            f"{rce['status']}"
        )

    # --------------------------------------------------------
    # Information disclosure assessment
    # --------------------------------------------------------

    information_disclosure = result[
        "information_disclosure_assessment"
    ]

    if not isinstance(
        information_disclosure,
        dict
    ):
        raise ValueError(
            "'information_disclosure_assessment' "
            "must be an object."
        )

    if "status" not in information_disclosure:
        raise ValueError(
            "'information_disclosure_assessment.status' "
            "is missing."
        )

    if information_disclosure[
        "status"
    ] not in allowed_condition_status:

        raise ValueError(
            "Invalid information disclosure status: "
            f"{information_disclosure['status']}"
        )

    # --------------------------------------------------------
    # Root cause
    # --------------------------------------------------------

    if not isinstance(
        result["root_cause"],
        str
    ):
        raise ValueError(
            "'root_cause' must be a string."
        )

    # --------------------------------------------------------
    # Remediation
    # --------------------------------------------------------

    remediation = result["remediation"]

    if not isinstance(
        remediation,
        list
    ):
        raise ValueError(
            "'remediation' must be a list."
        )

    for index, item in enumerate(
        remediation
    ):

        if not isinstance(
            item,
            dict
        ):
            raise ValueError(
                f"Remediation {index} must be an object."
            )

        required_remediation_fields = [
            "action",
            "reason",
            "type"
        ]

        missing_remediation_fields = [
            field
            for field in required_remediation_fields
            if field not in item
        ]

        if missing_remediation_fields:

            raise ValueError(
                f"Remediation {index} is missing fields: "
                + ", ".join(missing_remediation_fields)
            )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    validation = result["validation"]

    if not isinstance(
        validation,
        list
    ):
        raise ValueError(
            "'validation' must be a list."
        )

    for index, item in enumerate(
        validation
    ):

        if not isinstance(
            item,
            str
        ):
            raise ValueError(
                f"Validation item {index} must be a string."
            )

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    confidence = result["confidence"]

    allowed_confidence = {
        "LOW",
        "MEDIUM",
        "HIGH"
    }

    if confidence not in allowed_confidence:

        raise ValueError(
            "Invalid confidence value: "
            f"{confidence}"
        )

    # --------------------------------------------------------
    # Unknowns
    # --------------------------------------------------------

    unknowns = result["unknowns"]

    if not isinstance(
        unknowns,
        list
    ):
        raise ValueError(
            "'unknowns' must be a list."
        )

    for index, item in enumerate(
        unknowns
    ):

        if not isinstance(
            item,
            str
        ):
            raise ValueError(
                f"Unknown item {index} must be a string."
            )

    return True


# ============================================================
# MAIN REMEDIATION ENGINE
# ============================================================

def generate_remediation(
    findings_file,
    cve,
    knowledge_file,
    config_file,
    evaluation_file,
    output_file,
    model=DEFAULT_MODEL
):
    """
    Complete context-aware AI remediation pipeline.

    Pipeline:

        Scanner findings
             ↓
        CVE selection
             ↓
        CVE knowledge
             ↓
        Environment configuration
             ↓
        Deterministic evaluation
             ↓
        Evidence package
             ↓
        Prompt
             ↓
        local_llm.py
             ↓
        SGLang / Gemma
             ↓
        Parsed Python dictionary
             ↓
        Schema validation
             ↓
        Final JSON
    """

    print("=" * 70)
    print("AI REMEDIATION ENGINE")
    print("=" * 70)

    print(
        f"CVE:   {cve}"
    )

    print(
        f"Model: {model}"
    )

    # --------------------------------------------------------
    # 1. Load scanner findings
    # --------------------------------------------------------

    print(
        "\n[1/6] Loading scanner findings..."
    )

    findings_data = load_json(
        findings_file
    )

    findings = extract_findings(
        findings_data
    )

    print(
        f"Loaded {len(findings)} normalized findings."
    )

    # --------------------------------------------------------
    # 2. Select CVE
    # --------------------------------------------------------

    print(
        "\n[2/6] Selecting CVE finding..."
    )

    finding = find_cve_finding(
        findings,
        cve
    )

    if finding is None:

        raise RuntimeError(
            f"CVE {cve} was not found in "
            f"{findings_file}"
        )

    print(
        f"Selected finding: {finding.get('id')}"
    )

    print(
        f"Package:           "
        f"{finding.get('package')}"
    )

    print(
        f"Installed version: "
        f"{finding.get('installed_version')}"
    )

    print(
        f"Fixed version:     "
        f"{finding.get('fixed_version')}"
    )

    # --------------------------------------------------------
    # 3. Load CVE knowledge
    # --------------------------------------------------------

    print(
        "\n[3/6] Loading vulnerability knowledge..."
    )

    knowledge_data = load_json(
        knowledge_file
    )

    print(
        "Vulnerability knowledge loaded."
    )

    # --------------------------------------------------------
    # 4. Load environment evidence
    # --------------------------------------------------------

    print(
        "\n[4/6] Loading environment evidence..."
    )

    config_data = load_json(
        config_file
    )

    evaluation_data = load_json(
        evaluation_file
    )

    effective_config = get_effective_configuration(
        config_data
    )

    print(
        "Effective configuration loaded."
    )

    print(
        "CVE condition evaluation loaded."
    )

    # --------------------------------------------------------
    # Build evidence package
    # --------------------------------------------------------

    evidence_package = build_evidence_package(
        finding=finding,
        knowledge=knowledge_data,
        config=config_data,
        evaluation=evaluation_data
    )

    print(
        "Evidence package built."
    )

    # --------------------------------------------------------
    # Build prompt
    # --------------------------------------------------------

    prompt = build_prompt(
        evidence_package
    )

    print(
        "Remediation prompt built."
    )

    # --------------------------------------------------------
    # 5. Call local LLM
    # --------------------------------------------------------

    print(
        "\n[5/6] Sending evidence to local Gemma model..."
    )

    print(
        "Using local_llm.py with the configured LLM provider and remediation response schema."
    )

    print(
        "The model response will be parsed by "
        "local_llm.py."
    )

    print(
        "This may take some time depending on "
        "model inference latency."
    )

    # IMPORTANT:
    #
    # local_llm.generate_response() already:
    #
    #   1. Calls the SGLang server.
    #   2. Receives the model response.
    #   3. Parses the JSON.
    #   4. Returns a Python dictionary.
    #
    # Therefore we DO NOT perform another JSON parsing step.
    #

    remediation_result = generate_response(
        prompt,
        task="remediation"
    )

    print(
        "LLM response received."
    )

    # --------------------------------------------------------
    # 6. Validate LLM result
    # --------------------------------------------------------

    print(
        "\n[6/6] Validating LLM remediation..."
    )

    validate_remediation_result(
        remediation_result
    )

    print(
        "LLM remediation JSON validated successfully."
    )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    final_result = {

        "status": "completed",

        "cve": cve,

        "model": model,

        "scanner_finding": finding,

        "environment_configuration": effective_config,

        "condition_evaluation": evaluation_data,

        "remediation_analysis": remediation_result
    }

    # --------------------------------------------------------
    # Save result
    # --------------------------------------------------------

    save_json(
        final_result,
        output_file
    )

    print(
        f"\nResult saved to:"
    )

    print(
        output_file
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "REMEDIATION ANALYSIS COMPLETED"
    )

    print(
        "=" * 70
    )

    return final_result


# ============================================================
# COMMAND LINE
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Context-aware AI remediation engine "
            "using the configured LLM provider with a contextual remediation schema."
        )
    )

    parser.add_argument(
        "--findings",
        required=True,
        help=(
            "Existing normalized findings.json"
        )
    )

    parser.add_argument(
        "--cve",
        required=True,
        help=(
            "CVE to analyze, "
            "e.g. CVE-2025-24813"
        )
    )

    parser.add_argument(
        "--knowledge",
        required=True,
        help=(
            "CVE knowledge JSON file"
        )
    )

    parser.add_argument(
        "--config",
        required=True,
        help=(
            "Environment configuration JSON file"
        )
    )

    parser.add_argument(
        "--evaluation",
        required=True,
        help=(
            "Deterministic CVE condition "
            "evaluation JSON file"
        )
    )

    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=(
            "Model name used in the final report. "
            "The actual SGLang model configuration "
            "is controlled by local_llm.py."
        )
    )

    parser.add_argument(
        "--output",
        required=True,
        help=(
            "Output remediation JSON file"
        )
    )

    args = parser.parse_args()

    generate_remediation(
        findings_file=args.findings,
        cve=args.cve,
        knowledge_file=args.knowledge,
        config_file=args.config,
        evaluation_file=args.evaluation,
        output_file=args.output,
        model=args.model
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()