import json
import argparse
import re
from pathlib import Path
from packaging.version import parse as parse_version


def is_version_affected(detected_str, range_str, fixed_dict=None):
    """
    Deterministically check if a detected version falls within an affected range
    or is already patched.
    """
    if not detected_str or not range_str:
        return "unknown", "Missing version or range"

    m = re.search(r"(\d+(\.\d+)+([a-zA-Z0-9\.\-]+)?)", str(detected_str))
    if not m:
        return "unknown", f"Could not parse detected version: {detected_str}"
    detected_clean = m.group(1)

    try:
        det_v = parse_version(detected_clean)
    except Exception as e:
        return "unknown", f"Invalid semver: {e}"

    # 1. Check fixed versions first
    if fixed_dict:
        fixed_vals = fixed_dict.values() if isinstance(fixed_dict, dict) else (
            fixed_dict if isinstance(fixed_dict, list) else [fixed_dict]
        )
        for fv in fixed_vals:
            fm = re.search(r"(\d+(\.\d+)+)", str(fv))
            if fm:
                try:
                    fix_v = parse_version(fm.group(1))
                    if det_v.major == fix_v.major and det_v.minor == fix_v.minor:
                        if det_v >= fix_v:
                            return "not_satisfied", f"Installed version {detected_clean} is >= fixed version {fix_v} (PATCHED)"
                except Exception:
                    pass

    # 2. Check 'A through B' range
    through_m = re.match(r"(.+?)\s+through\s+(.+)", range_str, re.I)
    if through_m:
        sm = re.search(r"(\d+(\.\d+)+)", through_m.group(1))
        em = re.search(r"(\d+(\.\d+)+)", through_m.group(2))
        if sm and em:
            v_start = parse_version(sm.group(1))
            v_end = parse_version(em.group(1))
            if v_start <= det_v <= v_end:
                return "satisfied", f"Installed version {detected_clean} is within affected range {v_start} through {v_end}"
            else:
                return "not_satisfied", f"Installed version {detected_clean} is outside affected range {v_start} through {v_end}"

    # 3. Check '<= X' or '< X'
    lt_eq_m = re.match(r"<=\s*(\d+(\.\d+)+)", range_str)
    if lt_eq_m:
        v_limit = parse_version(lt_eq_m.group(1))
        if det_v <= v_limit:
            return "satisfied", f"Installed version {detected_clean} is <= {v_limit}"
        return "not_satisfied", f"Installed version {detected_clean} is > {v_limit}"

    lt_m = re.match(r"<\s*(\d+(\.\d+)+)", range_str)
    if lt_m:
        v_limit = parse_version(lt_m.group(1))
        if det_v < v_limit:
            return "satisfied", f"Installed version {detected_clean} is < {v_limit}"
        return "not_satisfied", f"Installed version {detected_clean} is >= {v_limit}"

    return "unknown", f"Unrecognized range format: {range_str}"


class CVEEvaluator:
    """
    Deterministic CVE prerequisite evaluator.

    The evaluator compares structured CVE knowledge against the
    effective environment configuration collected by config_collector.py.
    """

    def __init__(self, knowledge_file, config_file):
        self.knowledge_file = Path(knowledge_file)
        self.config_file = Path(config_file)

        self.knowledge = self.load_json(self.knowledge_file)
        self.raw_configuration = self.load_json(self.config_file)
        self.configuration = self.load_configuration(self.config_file)

    def get_detected_version(self):
        """
        Dynamically extract detected target software version from any config structure.
        """
        if isinstance(self.raw_configuration, dict):
            for key in ["tomcat_version", "version", "installed_version"]:
                val = self.raw_configuration.get(key)
                if val:
                    return str(val)

            t_block = self.raw_configuration.get("tomcat")
            if isinstance(t_block, dict) and t_block.get("version"):
                return str(t_block.get("version"))

        eff = self.configuration
        if isinstance(eff, dict):
            for key in ["version", "installed_version"]:
                if eff.get(key):
                    return str(eff.get(key))
            if isinstance(eff.get("tomcat"), dict) and eff["tomcat"].get("version"):
                return str(eff["tomcat"]["version"])

        return None

    def evaluate_version_condition(self, cve):
        """
        Evaluate whether the detected environment version is affected by the CVE.
        """
        detected_version = self.get_detected_version()
        affected_spec = cve.get("affected_versions", {})
        fixed_spec = cve.get("fixed_versions", {})
        range_str = affected_spec.get("range", "") if isinstance(affected_spec, dict) else str(affected_spec)

        if not detected_version:
            return {
                "name": "software_version_vulnerable",
                "status": "unknown",
                "required_value": True,
                "detected_version": None,
                "affected_range": range_str,
                "reason": "Target software version could not be detected from configuration"
            }

        status, reason = is_version_affected(detected_version, range_str, fixed_spec)
        return {
            "name": "software_version_vulnerable",
            "status": status,
            "required_value": True,
            "detected_version": detected_version,
            "affected_range": range_str,
            "reason": reason
        }

    # ---------------------------------------------------------
    # JSON loading
    # ---------------------------------------------------------

    def load_json(self, path):
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    # ---------------------------------------------------------
    # Configuration loading
    # ---------------------------------------------------------

    def load_configuration(self, path):
        data = self.load_json(path)

        if isinstance(data, dict):
            # Current config_collector format
            if "effective_configuration" in data:
                effective = data["effective_configuration"]

                if isinstance(effective, dict):
                    return effective

            # Older format where effective configuration was stored
            # directly at the top level.
            if "default_servlet" in data:
                return data

        return {}

    # ---------------------------------------------------------
    # Nested value lookup
    # ---------------------------------------------------------

    def get_value(self, data, path):
        current = data

        for part in path.split("."):
            if not isinstance(current, dict):
                return None, False

            if part not in current:
                return None, False

            current = current[part]

        return current, True

    # ---------------------------------------------------------
    # Evidence normalization
    # ---------------------------------------------------------

    def normalize_evidence_entry(self, entry):
        """
        Accept both legacy string evidence paths and the newer
        structured evidence format.

        Examples:

            "default_servlet.writes_enabled"

        or:

            {
                "path": "default_servlet.readonly",
                "transform": "boolean_not"
            }
        """

        if isinstance(entry, str):
            return {
                "path": entry,
                "transform": "identity"
            }

        if isinstance(entry, dict):
            path = entry.get("path")

            if not path:
                return None

            return {
                "path": path,
                "transform": entry.get("transform", "identity")
            }

        return None

    # ---------------------------------------------------------
    # Transform evidence value
    # ---------------------------------------------------------

    def transform_value(self, value, transform):
        """
        Convert raw configuration evidence into the semantic value
        required by the CVE condition.
        """

        if transform in (None, "", "identity", "none"):
            return value

        if transform in ("boolean_not", "not", "negate"):
            if isinstance(value, bool):
                return not value

            # A non-boolean value cannot safely be inverted.
            return None

        # Unknown transforms must not silently produce a result.
        return None

    # ---------------------------------------------------------
    # Determine whether evidence satisfies a requirement
    # ---------------------------------------------------------

    def check_evidence_value(self, value, required_value):
        # Missing / unresolved values
        if value is None:
            return "unknown"

        # Legacy collector value
        if value == "not_explicitly_configured":
            return "unknown"

        # Requirements that cannot be established from configuration
        # alone.
        if required_value == "must_be_established":
            return "unknown"

        # Requirement is that something must exist.
        if required_value == "must_be_identified":
            if isinstance(value, list):
                return "satisfied" if len(value) > 0 else "not_satisfied"

            if isinstance(value, dict):
                return "satisfied" if len(value) > 0 else "not_satisfied"

            if isinstance(value, str):
                return "satisfied" if value.strip() else "not_satisfied"

            return "satisfied" if bool(value) else "not_satisfied"

        # Normal exact comparison.
        if value == required_value:
            return "satisfied"

        return "not_satisfied"

    # ---------------------------------------------------------
    # Legacy semantic fallback
    # ---------------------------------------------------------

    def infer_legacy_transform(self, condition, path):
        """
        Preserve compatibility with the existing CVE knowledge file.

        Older knowledge may list:

            configuration_evidence:
              - default_servlet.writes_enabled
              - default_servlet.readonly

        while using:

            required_value: true

        Semantically, readonly is the inverse of writes_enabled.

        If the condition itself clearly requires writes to be enabled,
        automatically interpret readonly as boolean_not.

        New knowledge can avoid this fallback by explicitly specifying:

            {
                "path": "default_servlet.readonly",
                "transform": "boolean_not"
            }
        """

        condition_name = str(condition.get("name", "")).lower()
        normalized_path = str(path).lower()

        if (
            "writes_enabled" in condition_name
            and normalized_path.endswith(".readonly")
        ):
            return "boolean_not"

        return "identity"

    # ---------------------------------------------------------
    # Evaluate one CVE condition
    # ---------------------------------------------------------

    def evaluate_condition(self, condition):
        evidence_paths = condition.get("configuration_evidence", [])
        required_value = condition.get("required_value")

        evidence_results = []

        for raw_entry in evidence_paths:
            entry = self.normalize_evidence_entry(raw_entry)

            if entry is None:
                evidence_results.append(
                    {
                        "path": str(raw_entry),
                        "value": None,
                        "raw_value": None,
                        "transform": "invalid",
                        "status": "unknown"
                    }
                )
                continue

            path = entry["path"]
            transform = entry["transform"]

            # Compatibility with the existing knowledge file.
            if transform == "identity":
                transform = self.infer_legacy_transform(condition, path)

            raw_value, exists = self.get_value(
                self.configuration,
                path
            )

            if not exists:
                evidence_results.append(
                    {
                        "path": path,
                        "value": None,
                        "raw_value": None,
                        "transform": transform,
                        "status": "unknown"
                    }
                )
                continue

            transformed_value = self.transform_value(
                raw_value,
                transform
            )

            # If a transform was requested but could not be applied,
            # do not pretend the evidence proves anything.
            if transformed_value is None and raw_value is not None:
                status = "unknown"
            else:
                status = self.check_evidence_value(
                    transformed_value,
                    required_value
                )

            evidence_results.append(
                {
                    "path": path,
                    "value": transformed_value,
                    "raw_value": raw_value,
                    "transform": transform,
                    "status": status
                }
            )

        # -----------------------------------------------------
        # IMPORTANT:
        #
        # configuration_evidence entries are alternative ways
        # of proving the SAME condition.
        #
        # Example:
        #
        # writes_enabled = true
        #
        # OR
        #
        # readonly = false
        #
        # Either one is enough.
        # -----------------------------------------------------

        statuses = [
            item["status"]
            for item in evidence_results
        ]

        if "satisfied" in statuses:
            final_status = "satisfied"

        elif "unknown" in statuses:
            final_status = "unknown"

        else:
            final_status = "not_satisfied"

        # Select the strongest evidence.
        selected_evidence = None

        for item in evidence_results:
            if item["status"] == "satisfied":
                selected_evidence = item
                break

        if selected_evidence is None:
            for item in evidence_results:
                if item["status"] == "unknown":
                    selected_evidence = item
                    break

        if selected_evidence is None and evidence_results:
            selected_evidence = evidence_results[0]

        return {
            "condition_id": condition.get("id"),
            "name": condition.get("name"),
            "description": condition.get("description"),
            "required_value": required_value,
            "status": final_status,
            "selected_evidence": selected_evidence,
            "all_evidence": evidence_results
        }

    # ---------------------------------------------------------
    # Evaluate condition group
    # ---------------------------------------------------------

    def evaluate_condition_group(self, conditions, version_condition=None):
        results = []

        if version_condition:
            results.append(version_condition)

        for condition in conditions:
            result = self.evaluate_condition(condition)
            results.append(result)

        statuses = [
            result["status"]
            for result in results
        ]

        if "not_satisfied" in statuses:
            group_status = "not_satisfied"

        elif "unknown" in statuses:
            group_status = "unknown"

        else:
            group_status = "satisfied"

        return {
            "status": group_status,
            "conditions": results
        }

    # ---------------------------------------------------------
    # Evaluate CVE
    # ---------------------------------------------------------

    def evaluate_cve(self, cve_id):
        if cve_id not in self.knowledge:
            detected_v = self.get_detected_version()
            cve = {
                "cve_id": cve_id,
                "product": {
                    "vendor": "Target Environment",
                    "name": "Apache Tomcat" if detected_v else "Application",
                    "component": "Runtime Configuration"
                },
                "affected_versions": {
                    "range": f"<= {detected_v}" if detected_v else "unknown"
                },
                "fixed_versions": {},
                "severity": "DYNAMIC_CHECK",
                "description": f"Dynamic prerequisite evaluation for {cve_id} against live environment.",
                "vulnerability": {
                    "title": f"Dynamic Evaluation: {cve_id}",
                    "type": ["Contextual Verification"],
                    "cwe": []
                },
                "conditions": {
                    "environment_preconditions": [
                        {
                            "id": "dyn_cond_1",
                            "name": "network_connectors_active",
                            "description": "Active network listeners or connectors present in environment.",
                            "configuration_evidence": ["connectors"],
                            "required_value": "must_be_identified"
                        },
                        {
                            "id": "dyn_cond_2",
                            "name": "default_servlet_writes_enabled",
                            "description": "DefaultServlet writes enabled (readonly=false).",
                            "configuration_evidence": [
                                "default_servlet.writes_enabled",
                                "default_servlet.readonly"
                            ],
                            "required_value": True
                        }
                    ]
                }
            }
        else:
            cve = self.knowledge[cve_id]

        version_condition = self.evaluate_version_condition(cve)
        condition_groups = cve.get("conditions", {})

        evaluation = {}

        for group_name, conditions in condition_groups.items():
            evaluation[group_name] = self.evaluate_condition_group(
                conditions,
                version_condition=version_condition
            )

        return {
            "cve_id": cve_id,
            "product": cve.get("product"),
            "detected_version": self.get_detected_version(),
            "version_evaluation": version_condition,
            "affected_versions": cve.get("affected_versions"),
            "fixed_versions": cve.get("fixed_versions"),
            "vulnerability": cve.get("vulnerability"),
            "evaluation": evaluation,
            "remediation": cve.get("remediation"),
            "validation": cve.get("validation"),
            "source": cve.get("source")
        }

    # ---------------------------------------------------------
    # Print human-readable summary
    # ---------------------------------------------------------

    def print_summary(self, result):
        print()
        print("=" * 70)
        print("CVE CONFIGURATION & VERSION EVALUATION")
        print("=" * 70)

        print(f"CVE: {result['cve_id']}")
        v_eval = result.get("version_evaluation", {})
        print(f"Target Detected Version: {result.get('detected_version')} (Status: {v_eval.get('status', 'unknown').upper()})")
        if v_eval.get("reason"):
            print(f"Version Assessment: {v_eval.get('reason')}")
        print()

        for group_name, group in result["evaluation"].items():
            print(f"[{group_name}]")
            print(f"Overall status: {group['status']}")
            print()

            for condition in group["conditions"]:
                print(f"  {condition['name']}")
                print(f"    Status: {condition['status']}")
                print(f"    Required: {condition['required_value']}")

                selected = condition.get("selected_evidence")

                if selected:
                    print(
                        f"    Selected evidence: "
                        f"{selected['path']}"
                    )

                    print(
                        f"      Raw value: "
                        f"{selected.get('raw_value')}"
                    )

                    print(
                        f"      Evaluated value: "
                        f"{selected['value']}"
                    )

                    print(
                        f"      Transform: "
                        f"{selected.get('transform')}"
                    )

                    print(
                        f"      Status: "
                        f"{selected['status']}"
                    )

                print()

        print("=" * 70)


# =============================================================
# MAIN
# =============================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate CVE prerequisites against effective "
            "Tomcat configuration"
        )
    )

    parser.add_argument(
        "--cve",
        required=True,
        help="CVE ID"
    )

    parser.add_argument(
        "--knowledge",
        required=True,
        help="CVE knowledge JSON file"
    )

    parser.add_argument(
        "--config",
        required=True,
        help="Effective configuration JSON file"
    )

    parser.add_argument(
        "--output",
        default="cve-evaluation.json",
        help="Evaluation output JSON"
    )

    args = parser.parse_args()

    evaluator = CVEEvaluator(
        args.knowledge,
        args.config
    )

    result = evaluator.evaluate_cve(args.cve)

    evaluator.print_summary(result)

    output_path = Path(args.output)

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            result,
            f,
            indent=2,
            ensure_ascii=False
        )

    print()
    print(
        f"Full evaluation saved to: "
        f"{output_path}"
    )


if __name__ == "__main__":
    main()
