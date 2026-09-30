"""
Controlled remediation executor for the air-gapped security platform.

IMPORTANT:
- This module does NOT execute arbitrary commands supplied by an LLM.
- It accepts only structured, allowlisted remediation actions.
- It is designed for the controlled Tomcat lab used by this project.
- Default mode is DRY-RUN. Use --apply to make the change.
"""

import argparse
import json
import re
import subprocess
from datetime import datetime
from pathlib import Path


DEFAULT_CONTAINER = "tomcat-9.0.98-vuln"
TOMCAT_WEB_XML = "/opt/tomcat/conf/web.xml"
BACKUP_DIR = "/opt/tomcat/conf/remediation-backups"

# The executor can APPLY only allowlisted configuration actions.
# Other LLM recommendations (such as UPGRADE) are recorded as
# "unsupported_for_automatic_execution" rather than executed.
ALLOWED_ACTION_TYPES = {
    "CONFIGURATION",
}

ALLOWED_TARGETS = {
    "tomcat.default_servlet.readonly",
}

ALLOWED_VALUES = {
    "tomcat.default_servlet.readonly": {True, False},
}


def save_json(data, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def load_json(path):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def run_command(command, check=True):
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


def docker_exec(container, shell_command, check=True):
    return run_command(
        [
            "docker",
            "exec",
            container,
            "sh",
            "-c",
            shell_command,
        ],
        check=check,
    )


def validate_container_name(container):
    """
    Restrict the container identifier to a Docker-style name.

    This is an additional safety boundary: the container name is
    never interpreted as shell syntax.
    """
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", container):
        raise ValueError(
            f"Unsafe container name: {container!r}"
        )


def validate_action(action):
    if not isinstance(action, dict):
        raise ValueError("Each remediation action must be a JSON object.")

    action_type = action.get("type")

    # Not every valid LLM recommendation is an automatically executable
    # action. For example, UPGRADE is intentionally handled as a
    # recommendation-only action in this first executor.
    if action_type not in ALLOWED_ACTION_TYPES:
        return {
            "executable": False,
            "reason": (
                f"Remediation type {action_type!r} is not enabled for "
                "automatic execution. It is recorded for manual handling."
            ),
        }

    target = action.get("target")
    desired_value = action.get("desired_value")

    if target not in ALLOWED_TARGETS:
        raise ValueError(
            f"Unsupported remediation target: {target!r}. "
            f"Allowed: {sorted(ALLOWED_TARGETS)}"
        )

    if desired_value not in ALLOWED_VALUES[target]:
        raise ValueError(
            f"Unsupported desired value for {target}: {desired_value!r}"
        )

    return {
        "executable": True,
        "reason": "Action is allowlisted for automatic execution.",
    }


def extract_actions(remediation_analysis):
    """
    Accept either:

      {"remediation": [...]}

    or the complete remediation-analysis.json:

      {
        ...
        "remediation_analysis": {
          "remediation": [...]
        }
      }
    """
    if not isinstance(remediation_analysis, dict):
        raise ValueError("Remediation input must be a JSON object.")

    actions = remediation_analysis.get("remediation")

    if actions is None:
        nested = remediation_analysis.get("remediation_analysis")
        if isinstance(nested, dict):
            actions = nested.get("remediation")

    if not isinstance(actions, list):
        raise ValueError(
            "No valid 'remediation' action list was found."
        )

    return actions


def get_readonly_state(container):
    """
    Read the effective Default Servlet readonly value from web.xml.

    Returns:
        {
          "readonly": bool,
          "source": "explicit configuration" | "Tomcat default"
        }
    """
    result = docker_exec(
        container,
        (
            "if grep -q -A1 "
            "'<param-name>readonly</param-name>' "
            f"'{TOMCAT_WEB_XML}'; then "
            "  grep -A1 '<param-name>readonly</param-name>' "
            f"'{TOMCAT_WEB_XML}'; "
            "else "
            "  echo '__READONLY_NOT_EXPLICIT__'; "
            "fi"
        ),
        check=True,
    )

    output = result.stdout

    if "__READONLY_NOT_EXPLICIT__" in output:
        # Tomcat DefaultServlet readonly defaults to true.
        return {
            "readonly": True,
            "source": "Tomcat default",
        }

    match = re.search(
        r"<param-name>\s*readonly\s*</param-name>\s*"
        r"<param-value>\s*(true|false)\s*</param-value>",
        output,
        flags=re.IGNORECASE | re.DOTALL,
    )

    if not match:
        raise RuntimeError(
            "Could not determine the explicit Default Servlet "
            "readonly value from web.xml."
        )

    value = match.group(1).lower() == "true"

    return {
        "readonly": value,
        "source": "explicit configuration",
    }


def create_backup(container):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = f"{BACKUP_DIR}/web.xml.{timestamp}.bak"

    command = (
        f"mkdir -p '{BACKUP_DIR}' && "
        f"cp '{TOMCAT_WEB_XML}' '{backup_path}'"
    )

    docker_exec(container, command)

    return backup_path


def set_readonly(container, desired_value):
    """
    Apply the single allowlisted Tomcat configuration change.

    We deliberately modify only the value immediately following the
    readonly parameter name. No arbitrary path, command, or regex
    comes from the LLM.
    """
    replacement = "true" if desired_value else "false"

    cmd = (
        f"sed -i -E '/<param-name>\\s*readonly\\s*<\\/param-name>/{{n;s/<param-value>\\s*(true|false)\\s*<\\/param-value>/<param-value>{replacement}<\\/param-value>/;}}' '{TOMCAT_WEB_XML}'"
    )
    docker_exec(container, cmd)



def restart_container(container):
    run_command(["docker", "restart", container])


def get_container_status(container):
    result = run_command(
        [
            "docker",
            "inspect",
            "--format",
            "{{.State.Status}}",
            container,
        ],
        check=False,
    )

    if result.returncode != 0:
        return "unknown"

    return result.stdout.strip()


def execute_configuration_action(container, action, apply=False):
    validate_action(action)

    target = action["target"]
    desired_value = action["desired_value"]

    before = get_readonly_state(container)

    result = {
        "action": action,
        "target": target,
        "before": before,
        "applied": False,
        "backup": None,
        "restart": False,
        "after": None,
        "container_status": get_container_status(container),
    }

    if not apply:
        result["mode"] = "dry-run"
        result["message"] = (
            "Action validated but not applied. "
            "Use --apply to modify the controlled lab."
        )
        return result

    if before["readonly"] == desired_value:
        result["mode"] = "apply"
        result["applied"] = False
        result["message"] = (
            "Desired configuration is already present; "
            "no configuration change was necessary."
        )
        result["after"] = before
        return result

    backup = create_backup(container)
    result["backup"] = backup

    set_readonly(container, desired_value)
    result["applied"] = True

    restart_container(container)
    result["restart"] = True

    status = get_container_status(container)
    result["container_status"] = status

    if status != "running":
        raise RuntimeError(
            "Tomcat container did not return to the running state "
            f"after restart. Current status: {status}"
        )

    result["after"] = get_readonly_state(container)

    if result["after"]["readonly"] != desired_value:
        raise RuntimeError(
            "Remediation verification failed: the observed readonly "
            f"value is {result['after']['readonly']}, expected "
            f"{desired_value}."
        )

    result["mode"] = "apply"
    result["message"] = "Allowlisted configuration remediation applied and verified."

    return result


def execute_remediation(
    remediation_input,
    container=DEFAULT_CONTAINER,
    apply=False,
    output_file=None,
):
    validate_container_name(container)

    data = load_json(remediation_input)
    actions = extract_actions(data)

    if not actions:
        raise ValueError("Remediation action list is empty.")

    results = []

    for action in actions:
        validation = validate_action(action)

        if not validation["executable"]:
            results.append({
                "action": action,
                "mode": "manual_recommendation",
                "applied": False,
                "message": validation["reason"],
            })
            continue

        if action["type"] == "CONFIGURATION":
            result = execute_configuration_action(
                container=container,
                action=action,
                apply=apply,
            )
            results.append(result)
            continue

        raise ValueError(
            f"No executor exists for action type {action['type']!r}."
        )

    final = {
        "status": "applied" if apply else "dry_run",
        "container": container,
        "actions_requested": len(actions),
        "actions_processed": len(results),
        "results": results,
    }

    if output_file:
        save_json(final, output_file)

    return final


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Controlled allowlisted remediation executor "
            "for the air-gapped security platform."
        )
    )

    parser.add_argument(
        "--remediation",
        required=True,
        help="Path to remediation-analysis.json",
    )

    parser.add_argument(
        "--container",
        default=DEFAULT_CONTAINER,
        help=f"Target controlled Docker container (default: {DEFAULT_CONTAINER})",
    )

    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually apply the allowlisted remediation. "
             "Without this flag the executor performs a dry-run.",
    )

    parser.add_argument(
        "--output",
        help="Optional JSON file for executor results.",
    )

    args = parser.parse_args()

    print("=" * 70)
    print("CONTROLLED REMEDIATION EXECUTOR")
    print("=" * 70)
    print(f"Container:   {args.container}")
    print(f"Input:       {args.remediation}")
    print(f"Mode:        {'APPLY' if args.apply else 'DRY-RUN'}")

    result = execute_remediation(
        remediation_input=args.remediation,
        container=args.container,
        apply=args.apply,
        output_file=args.output,
    )

    print("\nRemediation execution result:")
    print(json.dumps(result, indent=2, ensure_ascii=False))

    print("\n" + "=" * 70)

    if args.apply:
        print("REMEDIATION APPLIED AND VERIFIED")
    else:
        print("DRY-RUN COMPLETED — NO CHANGES MADE")

    print("=" * 70)


if __name__ == "__main__":
    main()
