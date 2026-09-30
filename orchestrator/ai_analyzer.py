from local_llm import generate_response


def build_analysis_input(finding, profile):
    """
    Build the information that will be provided
    to the AI analyzer.
    """

    finding_input = {
        "id": finding.get("id"),
        "scanner": finding.get("scanner"),
        "type": finding.get("type"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "cwe": finding.get("cwe"),
        "file": finding.get("file"),
        "line_start": finding.get("line_start"),
        "line_end": finding.get("line_end"),
        "description": finding.get("description"),
        "code_context": finding.get("code_context")
    }

    # ---------------------------------------------------------
    # Trivy-specific information
    # ---------------------------------------------------------

    if finding.get("scanner") == "trivy":

        finding_input.update({
            "cve": finding.get("cve"),
            "package": finding.get("package"),
            "installed_version": finding.get(
                "installed_version"
            ),
            "fixed_version": finding.get(
                "fixed_version"
            )
        })

    return {
        "finding": finding_input,

        "application": {
            "name": profile.get("application"),
            "languages": profile.get("languages"),
            "manifests": profile.get("manifests")
        }
    }


def validate_ai_assessment(assessment):
    """
    Validate the structure and basic content
    returned by the local LLM.
    """

    # ---------------------------------------------------------
    # Required fields
    # ---------------------------------------------------------

    required_fields = [
        "validity",
        "risk",
        "confidence",
        "vulnerability_type",
        "evidence",
        "explanation",
        "impact",
        "attack_path",
        "recommended_fix",
        "patch_required"
    ]

    for field in required_fields:

        if field not in assessment:

            raise RuntimeError(
                f"AI assessment missing required field: {field}"
            )

    # ---------------------------------------------------------
    # Allowed values
    # ---------------------------------------------------------

    if assessment["validity"] not in [
        "confirmed",
        "false_positive",
        "needs_review"
    ]:

        raise RuntimeError(
            "AI assessment contains invalid validity value."
        )

    if assessment["risk"] not in [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]:

        raise RuntimeError(
            "AI assessment contains invalid risk value."
        )

    if assessment["confidence"] not in [
        "LOW",
        "MEDIUM",
        "HIGH"
    ]:

        raise RuntimeError(
            "AI assessment contains invalid confidence value."
        )

    # ---------------------------------------------------------
    # Data types
    # ---------------------------------------------------------

    if not isinstance(
        assessment["vulnerability_type"],
        str
    ):

        raise RuntimeError(
            "AI assessment vulnerability_type "
            "must be a string."
        )

    if not isinstance(
        assessment["evidence"],
        list
    ):

        raise RuntimeError(
            "AI assessment evidence must be a list."
        )

    if not isinstance(
        assessment["explanation"],
        str
    ):

        raise RuntimeError(
            "AI assessment explanation "
            "must be a string."
        )

    if not isinstance(
        assessment["impact"],
        str
    ):

        raise RuntimeError(
            "AI assessment impact "
            "must be a string."
        )

    if not isinstance(
        assessment["recommended_fix"],
        str
    ):

        raise RuntimeError(
            "AI assessment recommended_fix "
            "must be a string."
        )

    if not isinstance(
        assessment["attack_path"],
        list
    ):

        raise RuntimeError(
            "AI assessment attack_path "
            "must be a list."
        )

    if not isinstance(
        assessment["patch_required"],
        bool
    ):

        raise RuntimeError(
            "AI assessment patch_required "
            "must be true or false."
        )

    # ---------------------------------------------------------
    # Vulnerability type
    # ---------------------------------------------------------

    if not assessment["vulnerability_type"].strip():

        raise RuntimeError(
            "AI assessment vulnerability_type "
            "cannot be empty."
        )

    # ---------------------------------------------------------
    # Evidence
    # ---------------------------------------------------------

    if len(assessment["evidence"]) < 1:

        raise RuntimeError(
            "AI assessment evidence must contain "
            "at least one item."
        )

    for evidence_item in assessment["evidence"]:

        if not isinstance(
            evidence_item,
            str
        ):

            raise RuntimeError(
                "Each evidence item must be a string."
            )

        if not evidence_item.strip():

            raise RuntimeError(
                "AI assessment contains an empty "
                "evidence item."
            )

    # ---------------------------------------------------------
    # Long text fields
    # ---------------------------------------------------------

    long_text_fields = [
        "explanation",
        "impact",
        "recommended_fix"
    ]

    for field in long_text_fields:

        value = assessment[field].strip()

        if len(value) < 20:

            raise RuntimeError(
                f"AI assessment field '{field}' "
                "contains insufficient content."
            )

    # ---------------------------------------------------------
    # Attack path
    # ---------------------------------------------------------

    # An empty attack path is allowed.
    #
    # This is important for findings where the available
    # scanner evidence does not establish a concrete
    # exploitation path.

    for step in assessment["attack_path"]:

        if not isinstance(
            step,
            str
        ):

            raise RuntimeError(
                "Each attack_path step must be a string."
            )

        if len(step.strip()) < 10:

            raise RuntimeError(
                "AI assessment contains an incomplete "
                "attack_path step."
            )

    return True


def analyze_finding(finding, profile):
    """
    Analyze one security finding using the local LLM.

    Semgrep and Trivy findings are handled differently
    because they provide different types of evidence.
    """

    analysis_input = build_analysis_input(
        finding,
        profile
    )

    scanner = finding.get("scanner")

    # ---------------------------------------------------------
    # Determine evidence type
    # ---------------------------------------------------------

    if scanner == "semgrep":

        evidence_type = """
This is a Semgrep source-code finding.

The finding may contain:
- source file
- line numbers
- CWE
- scanner description
- source-code context

You may reason about the vulnerability using the
provided source-code context.

You may construct an attack path ONLY when the
provided source-code evidence supports it.
"""

    elif scanner == "trivy":

        evidence_type = """
This is a Trivy dependency vulnerability finding.

The finding may contain:
- CVE
- package
- installed version
- fixed version
- vulnerability description

The available evidence primarily establishes that
a dependency version is affected.

IMPORTANT:

Do NOT construct a concrete attacker exploitation
path from dependency metadata alone.

Do NOT invent:
- application endpoints
- HTTP requests
- attacker actions
- input validation behavior
- vulnerable application code
- successful exploitation
- arbitrary code execution
- denial of service

If the supplied evidence does not establish a concrete
exploitation path, return:

"attack_path": []

You may still explain the security significance
of the dependency vulnerability.

For remediation, prefer the fixed version supplied
by Trivy.
"""

    else:

        evidence_type = """
The scanner type is unknown.

Use only the evidence explicitly supplied.

Do not invent an attack path.

If a concrete attack path cannot be established,
return:

"attack_path": []
"""

    # ---------------------------------------------------------
    # Build AI prompt
    # ---------------------------------------------------------

    prompt = f"""
You are a cybersecurity vulnerability analysis engine.

Analyze ONLY the provided security finding.

The scanner output is the primary evidence.

{evidence_type}

IMPORTANT EVIDENCE RULES:

1. Treat scanner-provided facts as authoritative evidence.

2. Do not invent facts that are not present in the
   supplied finding or application information.

3. Do not invent application behavior.

4. Do not invent source-code behavior.

5. Do not invent package behavior.

6. Do not invent exploitability.

7. Do not claim arbitrary code execution, remote code
   execution, denial of service, data exposure, or other
   specific impacts unless supported by the supplied
   evidence.

8. If the available evidence is insufficient to determine
   validity, use:

   "needs_review"

9. Never invent source-code lines.

10. Never invent package versions.

EVIDENCE FIELD:

The evidence field must contain only facts directly
supported by the scanner finding and supplied application
context.

Do not add assumptions to the evidence field.

ATTACK PATH:

Only include an attack path when the supplied evidence
actually establishes the relevant exploitation steps.

If the evidence is insufficient, return:

"attack_path": []

Do not create an attack path merely to make the response
look complete.

RECOMMENDED FIX:

Prefer deterministic remediation information supplied
by the scanner.

For Trivy findings, if a fixed version is available,
use that fixed version when recommending the dependency
upgrade.

Do not invent a different version.

Determine:

1. Whether the finding is valid.
2. The security risk supported by the evidence.
3. Why the vulnerability exists according to the evidence.
4. The potential impact supported by the evidence.
5. The attack path supported by the evidence.
6. How the vulnerability should be remediated.
7. Whether a patch is required.

Keep explanations concise but complete.

Every string must be a complete sentence.

Application:
{analysis_input["application"]}

Finding:
{analysis_input["finding"]}

Return ONLY the required structured JSON.
"""

    # ---------------------------------------------------------
    # Generate AI assessment
    # ---------------------------------------------------------

    ai_assessment = generate_response(
        prompt
    )

    # ---------------------------------------------------------
    # Deterministic enforcement for Trivy
    # ---------------------------------------------------------

    if scanner == "trivy":

        # Trivy package metadata alone does not establish
        # a concrete application-level exploitation path.

        ai_assessment["attack_path"] = []

    # ---------------------------------------------------------
    # Validate AI response
    # ---------------------------------------------------------

    validate_ai_assessment(
        ai_assessment
    )

    # ---------------------------------------------------------
    # Return unified analysis result
    # ---------------------------------------------------------

    return {
        "finding_id": finding.get("id"),

        "scanner_assessment": {
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence")
        },

        "cwe": finding.get("cwe"),

        "ai_assessment": ai_assessment
    }