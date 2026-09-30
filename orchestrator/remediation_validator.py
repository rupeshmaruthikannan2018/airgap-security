import argparse
import json
import re
import subprocess
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path


# ============================================================
# AIR-GAPPED REMEDIATION VALIDATOR
# ============================================================
#
# Purpose:
#
# Independently validate whether a remediation changed the
# security posture of a target environment.
#
# Current laboratory:
#
#     Apache Tomcat 9.0.98
#     CVE-2025-24813
#
# Current remediation:
#
#     DISABLE_DEFAULT_SERVLET_WRITES
#
#
# Validation layers:
#
#     1. Container availability
#     2. Remediation execution evidence
#     3. Current configuration
#     4. HTTP service availability
#     5. Behavioral PUT validation
#     6. CVE evaluator integration
#     7. Installed software version
#     8. Before/after remediation assessment
#
#
# IMPORTANT:
#
# This validator does NOT trust the LLM.
#
# It independently checks the target environment.
#
# It also distinguishes:
#
#     MITIGATION
#
# from:
#
#     SOFTWARE PATCHING
#
# Therefore:
#
#     Tomcat 9.0.98
#     + readonly=true
#     + PUT=405
#
# is reported as:
#
#     MITIGATED_BUT_VERSION_STILL_AFFECTED
#
# and NOT:
#
#     PATCHED
#
# ============================================================


WEB_XML = "/opt/tomcat/conf/web.xml"

TARGET_CVE = "CVE-2025-24813"

FIXED_TOMCAT_9_VERSION = "9.0.99"


# ============================================================
# JSON UTILITIES
# ============================================================

def load_json(path):
    """
    Load JSON from disk.

    Returns None when the supplied path does not exist.
    """

    if not path:
        return None

    path = Path(path)

    if not path.exists():
        return None

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:

        return json.load(f)


def save_json(path, data):

    path = Path(path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            data,
            f,
            indent=2,
        )


# ============================================================
# COMMAND UTILITIES
# ============================================================

def run_command(
    command,
    check=False,
):

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if check and result.returncode != 0:

        raise RuntimeError(
            "Command failed.\n"
            f"Command: {' '.join(command)}\n"
            f"Exit code: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    return result


def docker_exec(
    container,
    command,
):

    return run_command(
        [
            "docker",
            "exec",
            container,
            "sh",
            "-c",
            command,
        ],
        check=True,
    )


# ============================================================
# DOCKER VALIDATION
# ============================================================

def container_exists(
    container,
):

    result = run_command(
        [
            "docker",
            "inspect",
            container,
        ],
        check=False,
    )

    return result.returncode == 0


def container_is_running(
    container,
):

    result = run_command(
        [
            "docker",
            "inspect",
            "-f",
            "{{.State.Running}}",
            container,
        ],
        check=False,
    )

    if result.returncode != 0:
        return False

    return (
        result.stdout.strip().lower()
        == "true"
    )


# ============================================================
# TOMCAT CONFIGURATION
# ============================================================

def read_web_xml(
    container,
):

    result = docker_exec(
        container,
        f"cat {WEB_XML}",
    )

    return result.stdout


def extract_readonly_value(
    web_xml,
):

    pattern = re.compile(
        r"<param-name>\s*readonly\s*</param-name>"
        r"\s*"
        r"<param-value>\s*(true|false)\s*</param-value>",
        re.IGNORECASE,
    )

    match = pattern.search(
        web_xml
    )

    if not match:
        return None

    return (
        match.group(1).lower()
        == "true"
    )


def extract_readonly_block(
    web_xml,
):

    pattern = re.compile(
        r"<init-param>\s*"
        r"<param-name>\s*readonly\s*</param-name>\s*"
        r"<param-value>\s*(true|false)\s*</param-value>\s*"
        r"</init-param>",
        re.IGNORECASE,
    )

    match = pattern.search(
        web_xml
    )

    if not match:
        return None

    return match.group(0)


def extract_partial_put_value(
    web_xml,
):

    pattern = re.compile(
        r"<param-name>\s*allowPartialPut\s*</param-name>"
        r"\s*"
        r"<param-value>\s*(true|false)\s*</param-value>",
        re.IGNORECASE,
    )

    match = pattern.search(
        web_xml
    )

    if not match:

        return {
            "value": True,
            "source": "Tomcat default",
        }

    return {
        "value": (
            match.group(1).lower()
            == "true"
        ),
        "source": "Explicit configuration",
    }


def collect_configuration(
    container,
):

    web_xml = read_web_xml(
        container
    )

    readonly = extract_readonly_value(
        web_xml
    )

    readonly_block = extract_readonly_block(
        web_xml
    )

    partial_put = extract_partial_put_value(
        web_xml
    )

    return {
        "readonly": readonly,

        "writes_enabled": (
            readonly is False
        ),

        "allowPartialPut": (
            partial_put["value"]
        ),

        "allowPartialPut_source": (
            partial_put["source"]
        ),

        "readonly_configuration": (
            readonly_block
        ),
    }


# ============================================================
# HTTP SERVICE VALIDATION
# ============================================================

def test_http_service(
    url,
):

    result = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "error": None,
    }

    request = urllib.request.Request(
        url,
        method="GET",
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=10,
        ) as response:

            result["reachable"] = True

            result["status_code"] = (
                response.status
            )

    except urllib.error.HTTPError as e:

        # An HTTP response proves that the service
        # is reachable even if the response itself is
        # an HTTP error.

        result["reachable"] = True

        result["status_code"] = e.code

        result["error"] = str(e)

    except Exception as e:

        result["error"] = str(e)

    return result


# ============================================================
# CONTROLLED PUT TEST
# ============================================================

def perform_put_test(
    base_url,
):

    test_url = (
        base_url.rstrip("/")
        + "/airgap-remediation-validation.txt"
    )

    body = (
        b"AIRGAP-REMEDIATION-VALIDATION"
    )

    result = {
        "url": test_url,
        "method": "PUT",
        "expected_after_remediation": 405,
        "actual_status": None,
        "behavior": "UNKNOWN",
        "passed": False,
        "error": None,
    }

    request = urllib.request.Request(
        test_url,
        data=body,
        method="PUT",
        headers={
            "Content-Type": "text/plain",
        },
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=10,
        ) as response:

            status = response.status

            result["actual_status"] = status

            if 200 <= status < 300:

                result["behavior"] = (
                    "WRITE_ACCEPTED"
                )

            else:

                result["behavior"] = (
                    "WRITE_NOT_ACCEPTED"
                )

    except urllib.error.HTTPError as e:

        result["actual_status"] = e.code

        if e.code == 405:

            result["behavior"] = (
                "WRITE_BLOCKED"
            )

            result["passed"] = True

        else:

            result["behavior"] = (
                "HTTP_ERROR"
            )

        result["error"] = str(e)

    except Exception as e:

        result["behavior"] = (
            "CONNECTION_ERROR"
        )

        result["error"] = str(e)

    return result


# ============================================================
# REMEDIATION EXECUTION RECORD
# ============================================================

def validate_execution_record(
    execution_path,
):

    if not execution_path:

        return {
            "available": False,
            "status": (
                "MANUAL_OR_EXTERNAL_REMEDIATION"
            ),
            "valid": False,
            "note": (
                "No remediation execution record "
                "was supplied. Independent environmental "
                "validation is being used."
            ),
        }

    path = Path(
        execution_path
    )

    if not path.exists():

        return {
            "available": False,
            "status": (
                "MANUAL_OR_EXTERNAL_REMEDIATION"
            ),
            "valid": False,
            "path": str(path),
            "note": (
                "The remediation execution record "
                "does not exist. Independent environmental "
                "validation is being used."
            ),
        }

    record = load_json(
        path
    )

    status = record.get(
        "status"
    )

    return {
        "available": True,
        "status": status,
        "action": record.get(
            "action"
        ),
        "changed": record.get(
            "changed"
        ),
        "restarted": record.get(
            "restarted"
        ),
        "valid": (
            status
            in {
                "SUCCESS",
                "NO_CHANGE_REQUIRED",
            }
        ),
        "record": record,
    }


# ============================================================
# CVE EVALUATOR HELPERS
# ============================================================

def normalize_status(
    value,
):
    """
    Convert evaluator status values into a standard form.

    Supported forms include:

        satisfied
        SATISFIED
        not_satisfied
        NOT_SATISFIED
        unknown
        UNKNOWN
    """

    if value is None:
        return None

    value = str(
        value
    ).strip().lower()

    value = value.replace(
        "-",
        "_",
    )

    value = value.replace(
        " ",
        "_",
    )

    mapping = {
        "satisfied": "SATISFIED",
        "confirmed": "SATISFIED",

        "not_satisfied": (
            "NOT_SATISFIED"
        ),

        "not_satisfied_": (
            "NOT_SATISFIED"
        ),

        "false": "NOT_SATISFIED",

        "unknown": "UNKNOWN",

        "needs_review": (
            "UNKNOWN"
        ),
    }

    return mapping.get(
        value,
        str(value).upper(),
    )


def recursive_find_status(
    obj,
    target_keywords,
    path="",
):

    """
    Recursively search a CVE evaluator JSON structure.

    This makes the validator tolerant of small schema
    differences between evaluator versions.

    It searches for objects whose names/keys contain
    relevant keywords and returns their status.
    """

    if isinstance(
        obj,
        dict,
    ):

        # ----------------------------------------------------
        # Determine current object's name
        # ----------------------------------------------------

        possible_names = []

        for key in [
            "name",
            "condition",
            "id",
            "title",
            "description",
        ]:

            value = obj.get(
                key
            )

            if isinstance(
                value,
                str,
            ):

                possible_names.append(
                    value
                )

        combined_name = " ".join(
            possible_names
        ).lower()

        # ----------------------------------------------------
        # Check whether this object represents our condition
        # ----------------------------------------------------

        if any(
            keyword.lower()
            in combined_name
            for keyword in target_keywords
        ):

            for status_key in [
                "status",
                "result",
                "state",
            ]:

                if status_key in obj:

                    status = normalize_status(
                        obj.get(
                            status_key
                        )
                    )

                    if status:

                        return {
                            "status": status,
                            "path": path,
                            "object": obj,
                        }

        # ----------------------------------------------------
        # Search child objects
        # ----------------------------------------------------

        for key, value in obj.items():

            child_path = (
                f"{path}.{key}"
                if path
                else key
            )

            found = recursive_find_status(
                value,
                target_keywords,
                child_path,
            )

            if found:
                return found

    elif isinstance(
        obj,
        list,
    ):

        for index, value in enumerate(
            obj
        ):

            child_path = (
                f"{path}[{index}]"
            )

            found = recursive_find_status(
                value,
                target_keywords,
                child_path,
            )

            if found:
                return found

    return None


# ============================================================
# CVE EVALUATION EXTRACTION
# ============================================================

def analyze_cve_evaluation(
    evaluation_path,
):

    if not evaluation_path:

        return {
            "available": False,
            "status": (
                "NO_CVE_EVALUATION_SUPPLIED"
            ),
        }

    path = Path(
        evaluation_path
    )

    if not path.exists():

        return {
            "available": False,
            "status": (
                "CVE_EVALUATION_FILE_NOT_FOUND"
            ),
            "path": str(path),
        }

    evaluation = load_json(
        path
    )

    # --------------------------------------------------------
    # CVE
    # --------------------------------------------------------

    cve = (
        evaluation.get(
            "cve"
        )
        or evaluation.get(
            "CVE"
        )
        or TARGET_CVE
    )

    # --------------------------------------------------------
    # Write condition
    # --------------------------------------------------------

    write_condition = (
        recursive_find_status(
            evaluation,
            [
                "writes enabled",
                "write enabled",
                "default servlet writes",
                "default_servlet_writes",
                "readonly",
            ],
        )
    )

    # --------------------------------------------------------
    # Partial PUT condition
    # --------------------------------------------------------

    partial_put_condition = (
        recursive_find_status(
            evaluation,
            [
                "partial put",
                "allowpartialput",
                "allow_partial_put",
            ],
        )
    )

    # --------------------------------------------------------
    # File-based session persistence
    # --------------------------------------------------------

    session_condition = (
        recursive_find_status(
            evaluation,
            [
                "file-based session",
                "file based session",
                "file_based_session",
                "session persistence",
                "session_persistence",
            ],
        )
    )

    # --------------------------------------------------------
    # Deserialization library
    # --------------------------------------------------------

    deserialization_condition = (
        recursive_find_status(
            evaluation,
            [
                "deserialization library",
                "deserialization_library",
                "deserialization",
            ],
        )
    )

    # --------------------------------------------------------
    # RCE group
    # --------------------------------------------------------

    rce_group = (
        recursive_find_status(
            evaluation,
            [
                "remote_code_execution",
                "remote code execution",
            ],
        )
    )

    # --------------------------------------------------------
    # Information disclosure group
    # --------------------------------------------------------

    disclosure_group = (
        recursive_find_status(
            evaluation,
            [
                "information_disclosure",
                "information disclosure",
                "content injection",
            ],
        )
    )

    # --------------------------------------------------------
    # Find a useful overall status if available
    # --------------------------------------------------------

    overall_status = None

    for key in [
        "overall_status",
        "overall",
        "status",
        "result",
    ]:

        value = evaluation.get(
            key
        )

        if isinstance(
            value,
            str,
        ):

            overall_status = normalize_status(
                value
            )

            break

    return {
        "available": True,

        "cve": cve,

        "overall_status": (
            overall_status
        ),

        "conditions": {
            "default_servlet_writes": (
                write_condition
            ),

            "partial_put": (
                partial_put_condition
            ),

            "file_based_session_persistence": (
                session_condition
            ),

            "deserialization_library": (
                deserialization_condition
            ),
        },

        "remote_code_execution": (
            rce_group
        ),

        "information_disclosure": (
            disclosure_group
        ),

        "raw_evaluation": evaluation,
    }


# ============================================================
# CURRENT CVE CONDITION RE-EVALUATION
# ============================================================

def evaluate_current_cve_conditions(
    configuration,
):

    readonly = configuration.get(
        "readonly"
    )

    partial_put = configuration.get(
        "allowPartialPut"
    )

    return {
        "cve": TARGET_CVE,

        "conditions": {

            "default_servlet_writes": {
                "status": (
                    "NOT_SATISFIED"
                    if readonly is True
                    else (
                        "SATISFIED"
                        if readonly is False
                        else "UNKNOWN"
                    )
                ),
                "evidence": (
                    f"readonly={readonly}"
                ),
            },

            "partial_put": {
                "status": (
                    "SATISFIED"
                    if partial_put is True
                    else (
                        "NOT_SATISFIED"
                        if partial_put is False
                        else "UNKNOWN"
                    )
                ),
                "evidence": (
                    f"allowPartialPut={partial_put}"
                ),
            },
        },
    }


# ============================================================
# TOMCAT VERSION
# ============================================================

def detect_tomcat_version(
    container,
):

    # --------------------------------------------------------
    # Method 1:
    # catalina.sh version
    # --------------------------------------------------------

    result = docker_exec(
        container,
        "/opt/tomcat/bin/catalina.sh version",
    )

    output = (
        result.stdout
        + "\n"
        + result.stderr
    )

    patterns = [
        r"Server version:\s*Apache Tomcat/([0-9.]+)",
        r"Apache Tomcat/([0-9.]+)",
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            output,
            re.IGNORECASE,
        )

        if match:

            return match.group(1)

    # --------------------------------------------------------
    # Method 2:
    # RELEASE-NOTES
    # --------------------------------------------------------

    result = docker_exec(
        container,
        (
            "grep -E "
            "'Apache Tomcat Version' "
            "/opt/tomcat/RELEASE-NOTES "
            "2>/dev/null | head -1"
        ),
    )

    match = re.search(
        r"Apache Tomcat Version\s*([0-9.]+)",
        result.stdout,
        re.IGNORECASE,
    )

    if match:

        return match.group(1)

    return None


# ============================================================
# VERSION COMPARISON
# ============================================================

def version_tuple(
    version,
):

    if not version:
        return None

    try:

        return tuple(
            int(part)
            for part in version.split(".")
        )

    except ValueError:

        return None


def is_tomcat_9_patched(
    version,
):

    parsed = version_tuple(
        version
    )

    if not parsed:
        return False

    if len(parsed) < 3:
        return False

    major = parsed[0]
    minor = parsed[1]
    patch = parsed[2]

    return (
        major == 9
        and minor == 0
        and patch >= 99
    )


# ============================================================
# BEFORE / AFTER COMPARISON
# ============================================================

def build_before_after(
    execution_result,
    configuration,
    behavioral_test,
):

    current_readonly = configuration.get(
        "readonly"
    )

    current_writes = configuration.get(
        "writes_enabled"
    )

    current_behavior = behavioral_test.get(
        "behavior"
    )

    # --------------------------------------------------------
    # Try to recover historical BEFORE value from the
    # execution record.
    # --------------------------------------------------------

    before_readonly = None

    if execution_result.get(
        "available"
    ):

        record = execution_result.get(
            "record",
            {},
        )

        before = record.get(
            "before",
            {},
        )

        if isinstance(
            before,
            dict,
        ):

            before_readonly = before.get(
                "readonly"
            )

    # --------------------------------------------------------
    # We don't have a successful execution record in the
    # current lab because remediation was applied manually.
    #
    # The previously established lab evidence was:
    #
    #     readonly=false
    #     PUT=201
    #
    # Therefore we preserve that fact but explicitly label
    # it as previous lab validation rather than pretending
    # this validator observed the historical state itself.
    # --------------------------------------------------------

    if before_readonly is None:

        before_readonly = False

        before_evidence_type = (
            "previous_lab_validation"
        )

    else:

        before_evidence_type = (
            "execution_record"
        )

    return {

        "before": {

            "readonly": (
                before_readonly
            ),

            "writes_enabled": (
                before_readonly is False
            ),

            "put_behavior": (
                "WRITE_ACCEPTED"
                if before_readonly is False
                else "UNKNOWN"
            ),

            "put_expected_status": (
                201
                if before_readonly is False
                else None
            ),

            "evidence_type": (
                before_evidence_type
            ),
        },

        "after": {

            "readonly": (
                current_readonly
            ),

            "writes_enabled": (
                current_writes
            ),

            "put_behavior": (
                current_behavior
            ),

            "put_status": (
                behavioral_test.get(
                    "actual_status"
                )
            ),

            "evidence_type": (
                "independent_current_validation"
            ),
        },

        "change": {

            "readonly_changed": (
                before_readonly
                != current_readonly
            ),

            "write_capability_changed": (
                before_readonly is False
                and current_writes is False
            ),

            "behavior_changed": (
                before_readonly is False
                and current_behavior
                == "WRITE_BLOCKED"
            ),
        },
    }


# ============================================================
# OVERALL ASSESSMENT
# ============================================================

def calculate_overall_assessment(
    configuration,
    service,
    behavioral_test,
    tomcat_version,
    cve_evaluation,
    current_cve_conditions,
):

    readonly = configuration.get(
        "readonly"
    )

    writes_enabled = configuration.get(
        "writes_enabled"
    )

    # --------------------------------------------------------
    # Configuration
    # --------------------------------------------------------

    configuration_pass = (
        readonly is True
        and writes_enabled is False
    )

    # --------------------------------------------------------
    # Behavioral
    # --------------------------------------------------------

    behavioral_pass = (
        behavioral_test.get(
            "behavior"
        )
        == "WRITE_BLOCKED"
        and behavioral_test.get(
            "actual_status"
        )
        == 405
    )

    # --------------------------------------------------------
    # Service
    # --------------------------------------------------------

    service_pass = (
        service.get(
            "reachable"
        )
        is True
    )

    # --------------------------------------------------------
    # Software patch
    # --------------------------------------------------------

    version_patched = (
        is_tomcat_9_patched(
            tomcat_version
        )
    )

    # --------------------------------------------------------
    # CVE write condition
    # --------------------------------------------------------

    current_write_condition = (
        current_cve_conditions[
            "conditions"
        ][
            "default_servlet_writes"
        ][
            "status"
        ]
    )

    cve_write_condition_mitigated = (
        current_write_condition
        == "NOT_SATISFIED"
    )

    # --------------------------------------------------------
    # Overall status
    # --------------------------------------------------------

    if (
        configuration_pass
        and behavioral_pass
        and service_pass
        and version_patched
    ):

        overall_status = (
            "PATCHED_AND_BEHAVIORALLY_VALIDATED"
        )

    elif (
        configuration_pass
        and behavioral_pass
        and service_pass
        and not version_patched
    ):

        overall_status = (
            "MITIGATED_BUT_VERSION_STILL_AFFECTED"
        )

    elif configuration_pass:

        overall_status = (
            "CONFIGURATION_MITIGATION_APPLIED_"
            "BUT_BEHAVIOR_NOT_FULLY_VALIDATED"
        )

    else:

        overall_status = (
            "REMEDIATION_NOT_VALIDATED"
        )

    # --------------------------------------------------------
    # Evidence
    # --------------------------------------------------------

    evidence = []

    if configuration_pass:

        evidence.append(
            "DefaultServlet readonly=true is "
            "currently configured."
        )

    else:

        evidence.append(
            "DefaultServlet readonly=true is "
            "not confirmed."
        )

    if behavioral_pass:

        evidence.append(
            "Controlled PUT request returned HTTP 405, "
            "demonstrating that the tested write operation "
            "is blocked."
        )

    else:

        evidence.append(
            "The controlled PUT test did not demonstrate "
            "the expected write blocking behavior."
        )

    if service_pass:

        evidence.append(
            "Tomcat remained reachable after remediation."
        )

    else:

        evidence.append(
            "Tomcat was not reachable after remediation."
        )

    if cve_write_condition_mitigated:

        evidence.append(
            "Current CVE condition evaluation indicates "
            "the DefaultServlet write condition is "
            "NOT_SATISFIED."
        )

    else:

        evidence.append(
            "Current CVE condition evaluation does not "
            "confirm that the DefaultServlet write condition "
            "is mitigated."
        )

    if tomcat_version:

        if version_patched:

            evidence.append(
                f"Tomcat {tomcat_version} is at or above "
                f"the fixed Tomcat 9 version "
                f"{FIXED_TOMCAT_9_VERSION}."
            )

        else:

            evidence.append(
                f"Tomcat remains at {tomcat_version}; "
                f"the fixed Tomcat 9 version is "
                f"{FIXED_TOMCAT_9_VERSION}."
            )

    return {

        "overall_status": overall_status,

        "configuration_validation": (
            "PASS"
            if configuration_pass
            else "FAIL"
        ),

        "behavioral_validation": (
            "PASS"
            if behavioral_pass
            else "FAIL"
        ),

        "service_validation": (
            "PASS"
            if service_pass
            else "FAIL"
        ),

        "cve_write_condition": (
            "MITIGATED"
            if cve_write_condition_mitigated
            else current_write_condition
        ),

        "software_version_status": (
            "PATCHED"
            if version_patched
            else "NOT_PATCHED"
        ),

        "tomcat_version": tomcat_version,

        "evidence_summary": evidence,
    }


# ============================================================
# MAIN VALIDATION PIPELINE
# ============================================================

def validate(
    container,
    service_url,
    execution_path=None,
    evaluation_path=None,
    config_path=None,
):

    print()
    print("=" * 70)
    print("AIR-GAPPED REMEDIATION VALIDATOR")
    print("=" * 70)
    print()

    # ========================================================
    # 1. Container
    # ========================================================

    print(
        "[1/7] Checking Docker container..."
    )

    if not container_exists(
        container
    ):

        raise RuntimeError(
            f"Docker container '{container}' "
            "does not exist."
        )

    running = container_is_running(
        container
    )

    print(
        "Container running:",
        running,
    )

    if not running:

        raise RuntimeError(
            f"Docker container '{container}' "
            "is not running."
        )

    # ========================================================
    # 2. Execution record
    # ========================================================

    print()
    print(
        "[2/7] Checking remediation execution record..."
    )

    execution_result = (
        validate_execution_record(
            execution_path
        )
    )

    if execution_result.get(
        "available"
    ):

        print(
            "Execution record: AVAILABLE"
        )

        print(
            "Execution status:",
            execution_result.get(
                "status"
            ),
        )

    else:

        print(
            "Execution record: NOT AVAILABLE"
        )

        print(
            "Using independent/manual remediation evidence."
        )

    # ========================================================
    # 3. Current configuration
    # ========================================================

    print()
    print(
        "[3/7] Checking current Tomcat configuration..."
    )

    configuration = collect_configuration(
        container
    )

    print(
        "DefaultServlet readonly:",
        configuration.get(
            "readonly"
        ),
    )

    print(
        "DefaultServlet writes enabled:",
        configuration.get(
            "writes_enabled"
        ),
    )

    print(
        "allowPartialPut:",
        configuration.get(
            "allowPartialPut"
        ),
    )

    print(
        "allowPartialPut source:",
        configuration.get(
            "allowPartialPut_source"
        ),
    )

    # ========================================================
    # 4. HTTP service
    # ========================================================

    print()
    print(
        "[4/7] Checking Tomcat HTTP service..."
    )

    service = test_http_service(
        service_url
    )

    print(
        "Service reachable:",
        service.get(
            "reachable"
        ),
    )

    print(
        "HTTP status:",
        service.get(
            "status_code"
        ),
    )

    # ========================================================
    # 5. Behavioral PUT
    # ========================================================

    print()
    print(
        "[5/7] Performing controlled PUT test..."
    )

    behavioral_test = perform_put_test(
        service_url
    )

    print(
        "PUT status:",
        behavioral_test.get(
            "actual_status"
        ),
    )

    print(
        "PUT behavior:",
        behavioral_test.get(
            "behavior"
        ),
    )

    # ========================================================
    # 6. CVE evaluator + current conditions + version
    # ========================================================

    print()
    print(
        "[6/7] Checking CVE evaluation..."
    )

    cve_evaluation = (
        analyze_cve_evaluation(
            evaluation_path
        )
    )

    if cve_evaluation.get(
        "available"
    ):

        print(
            "CVE:",
            cve_evaluation.get(
                "cve"
            ),
        )

        print(
            "Existing evaluator overall status:",
            cve_evaluation.get(
                "overall_status"
            ),
        )

        existing_write_condition = (
            cve_evaluation.get(
                "conditions",
                {}
            ).get(
                "default_servlet_writes"
            )
        )

        if existing_write_condition:

            print(
                "Existing evaluator write condition:",
                existing_write_condition.get(
                    "status"
                ),
            )

    else:

        print(
            "CVE evaluator result unavailable."
        )

    print()
    print(
        "Re-evaluating current CVE conditions "
        "from live configuration..."
    )

    current_cve_conditions = (
        evaluate_current_cve_conditions(
            configuration
        )
    )

    current_write_condition = (
        current_cve_conditions[
            "conditions"
        ][
            "default_servlet_writes"
        ]
    )

    print(
        "Current DefaultServlet write condition:",
        current_write_condition[
            "status"
        ],
    )

    print()
    print(
        "Detecting installed Tomcat version..."
    )

    tomcat_version = detect_tomcat_version(
        container
    )

    print(
        "Tomcat version:",
        tomcat_version,
    )

    # ========================================================
    # 7. Overall assessment
    # ========================================================

    print()
    print(
        "[7/7] Calculating remediation assessment..."
    )

    before_after = build_before_after(
        execution_result=execution_result,
        configuration=configuration,
        behavioral_test=behavioral_test,
    )

    assessment = (
        calculate_overall_assessment(
            configuration=configuration,
            service=service,
            behavioral_test=behavioral_test,
            tomcat_version=tomcat_version,
            cve_evaluation=cve_evaluation,
            current_cve_conditions=(
                current_cve_conditions
            ),
        )
    )

    # ========================================================
    # Final result
    # ========================================================

    result = {

        "validator": {
            "name": (
                "Air-Gapped Remediation Validator"
            ),
            "version": "2.0",
        },

        "timestamp": (
            datetime.now().isoformat()
        ),

        "target": {
            "container": container,
            "service_url": service_url,
        },

        "cve": {
            "id": TARGET_CVE,
            "fixed_tomcat_9_version": (
                FIXED_TOMCAT_9_VERSION
            ),
        },

        "remediation": {

            "action": (
                "DISABLE_DEFAULT_SERVLET_WRITES"
            ),

            "description": (
                "Disable Tomcat DefaultServlet "
                "write capability by setting "
                "readonly=true."
            ),
        },

        "execution_record": (
            execution_result
        ),

        "configuration": (
            configuration
        ),

        "service": (
            service
        ),

        "behavioral_test": (
            behavioral_test
        ),

        "cve_evaluation": (
            cve_evaluation
        ),

        "current_cve_conditions": (
            current_cve_conditions
        ),

        "software": {

            "product": (
                "Apache Tomcat"
            ),

            "version": (
                tomcat_version
            ),

            "fixed_version_tomcat_9": (
                FIXED_TOMCAT_9_VERSION
            ),

            "version_patch_status": (
                "PATCHED"
                if is_tomcat_9_patched(
                    tomcat_version
                )
                else "NOT_PATCHED"
            ),
        },

        "before_after": (
            before_after
        ),

        "assessment": (
            assessment
        ),
    }

    # ========================================================
    # Console output
    # ========================================================

    print()
    print("=" * 70)
    print("VALIDATION RESULT")
    print("=" * 70)
    print()

    print(
        "Overall status:",
        assessment[
            "overall_status"
        ],
    )

    print(
        "Configuration validation:",
        assessment[
            "configuration_validation"
        ],
    )

    print(
        "Behavioral validation:",
        assessment[
            "behavioral_validation"
        ],
    )

    print(
        "Service validation:",
        assessment[
            "service_validation"
        ],
    )

    print(
        "CVE write condition:",
        assessment[
            "cve_write_condition"
        ],
    )

    print(
        "Software version:",
        tomcat_version,
    )

    print(
        "Version patch status:",
        assessment[
            "software_version_status"
        ],
    )

    print()
    print(
        "BEFORE / AFTER:"
    )

    before = before_after[
        "before"
    ]

    after = before_after[
        "after"
    ]

    print(
        "  BEFORE readonly:",
        before[
            "readonly"
        ],
    )

    print(
        "  AFTER readonly:",
        after[
            "readonly"
        ],
    )

    print(
        "  BEFORE PUT:",
        before[
            "put_behavior"
        ],
    )

    print(
        "  AFTER PUT:",
        after[
            "put_behavior"
        ],
    )

    print()
    print(
        "Evidence:"
    )

    for item in assessment[
        "evidence_summary"
    ]:

        print(
            "  -",
            item,
        )

    print()
    print("=" * 70)

    return result


# ============================================================
# CLI
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Independent remediation validator "
            "for the air-gapped security platform."
        )
    )

    parser.add_argument(
        "--container",
        required=True,
        help="Docker container name.",
    )

    parser.add_argument(
        "--url",
        required=True,
        help=(
            "Tomcat base URL, for example "
            "http://localhost:8081"
        ),
    )

    parser.add_argument(
        "--execution",
        required=False,
        default=None,
        help=(
            "Optional remediation execution JSON."
        ),
    )

    parser.add_argument(
        "--evaluation",
        required=False,
        default=None,
        help=(
            "Optional CVE evaluator JSON."
        ),
    )

    parser.add_argument(
        "--config",
        required=False,
        default=None,
        help=(
            "Optional collected configuration JSON."
        ),
    )

    parser.add_argument(
        "--output",
        required=True,
        help=(
            "Output validation JSON."
        ),
    )

    args = parser.parse_args()

    result = validate(
        container=args.container,
        service_url=args.url,
        execution_path=args.execution,
        evaluation_path=args.evaluation,
        config_path=args.config,
    )

    save_json(
        args.output,
        result,
    )

    print()
    print(
        "Validation report saved to:"
    )

    print(
        args.output
    )


if __name__ == "__main__":
    main()