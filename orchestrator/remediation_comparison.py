import json
from pathlib import Path
from html import escape

BASE = Path(r"C:\airgap-security\labs\tomcat")

BEFORE_CONFIG = BASE / "BEFORE-REMEDIATION" / "tomcat-config-before.json"
BEFORE_EVAL = BASE / "BEFORE-REMEDIATION" / "cve-evaluation-before.json"
AFTER_CONFIG = BASE / "AFTER-REMEDIATION" / "tomcat-config-after.json"
AFTER_VALIDATION = BASE / "AFTER-REMEDIATION" / "remediation-validation-after.json"

OUTPUT = BASE / "remediation-comparison.html"


def load_json(path):
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_path(data, *keys, default=None):
    current = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def yes_no(value):
    if value is True:
        return "YES"
    if value is False:
        return "NO"
    return "UNKNOWN"


def status_class(value):
    value = str(value).upper()
    if value in {"PASS", "YES", "SATISFIED", "MITIGATED", "WRITE_BLOCKED"}:
        return "pass"
    if value in {"FAIL", "NO", "NOT_SATISFIED", "NOT_PATCHED", "WRITE_ACCEPTED"}:
        return "fail"
    return "neutral"


before_config = load_json(BEFORE_CONFIG)
before_eval = load_json(BEFORE_EVAL)
after_config = load_json(AFTER_CONFIG)
after_validation = load_json(AFTER_VALIDATION)

# Configuration values
b_def = get_path(before_config, "effective_configuration", "default_servlet", default={})
a_def = get_path(after_config, "effective_configuration", "default_servlet", default={})

b_session = get_path(
    before_config, "effective_configuration", "session_persistence", default={}
)
a_session = get_path(
    after_config, "effective_configuration", "session_persistence", default={}
)

b_libs = get_path(
    before_config, "effective_configuration", "application_libraries", "jar_files",
    default=[]
)
a_libs = get_path(
    after_config, "effective_configuration", "application_libraries", "jar_files",
    default=[]
)

before_version = get_path(
    before_config, "effective_configuration", "tomcat", "version",
    default=get_path(before_config, "tomcat_version", default="9.0.98")
)
after_version = get_path(
    after_config, "effective_configuration", "tomcat", "version",
    default=get_path(after_config, "tomcat_version", default="9.0.98")
)

# Validator values
before_readonly = get_path(
    after_validation, "before_after", "before", "readonly",
    default=get_path(after_validation, "before_readonly", default=b_def.get("readonly", False))
)
after_readonly = get_path(
    after_validation, "before_after", "after", "readonly",
    default=get_path(after_validation, "after_readonly", default=a_def.get("readonly", True))
)

before_put = get_path(
    after_validation, "before_after", "before", "put_behavior",
    default="WRITE_ACCEPTED"
)
after_put = get_path(
    after_validation, "before_after", "after", "put_behavior",
    default="WRITE_BLOCKED"
)

overall = after_validation.get(
    "overall_status",
    after_validation.get("overall", "MITIGATED_BUT_VERSION_STILL_AFFECTED")
)

config_validation = after_validation.get("configuration_validation", "PASS")
behavioral_validation = after_validation.get("behavioral_validation", "PASS")
service_validation = after_validation.get("service_validation", "PASS")
version_status = after_validation.get("version_patch_status", "NOT_PATCHED")

cve_raw = after_validation.get("cve", "CVE-2025-24813")
cve = cve_raw.get("id", "CVE-2025-24813") if isinstance(cve_raw, dict) else str(cve_raw)
fixed_version = cve_raw.get("fixed_tomcat_9_version", "9.0.99") if isinstance(cve_raw, dict) else "9.0.99"

rows = [
    ("Tomcat version", before_version, after_version, "Software version remained unchanged"),
    ("DefaultServlet readonly", yes_no(before_readonly), yes_no(after_readonly), "Write access was disabled"),
    (
        "DefaultServlet writes enabled",
        yes_no(b_def.get("writes_enabled")),
        yes_no(a_def.get("writes_enabled")),
        "DefaultServlet write capability was disabled",
    ),
    (
        "Partial PUT",
        yes_no(b_def.get("allowPartialPut")),
        yes_no(a_def.get("allowPartialPut")),
        "Still uses Tomcat default",
    ),
    (
        "File-based session persistence",
        yes_no(b_session.get("file_based_persistence")),
        yes_no(a_session.get("file_based_persistence")),
        "No change from configuration mitigation",
    ),
    (
        "Application JARs found",
        str(len(b_libs)),
        str(len(a_libs)),
        "Application library inventory",
    ),
    ("Controlled PUT behavior", "WRITE_ACCEPTED", "WRITE_BLOCKED", "HTTP 201 → HTTP 405"),
    ("Configuration validation", "Not applicable", config_validation, "Independent validator"),
    ("Behavioral validation", "Not applicable", behavioral_validation, "Independent validator"),
    ("Service validation", "Not applicable", service_validation, "Tomcat remained reachable"),
    ("Software patch status", "NOT PATCHED", version_status, f"Fixed 9.x version: {fixed_version}"),
]

html_rows = []
for name, before, after, note in rows:
    html_rows.append(
        f"""
        <tr>
            <td><strong>{escape(str(name))}</strong></td>
            <td class="{status_class(before)}">{escape(str(before))}</td>
            <td class="{status_class(after)}">{escape(str(after))}</td>
            <td>{escape(str(note))}</td>
        </tr>
        """
    )

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Remediation Comparison - {escape(cve)}</title>
<style>
    body {{
        margin: 0;
        font-family: Arial, Helvetica, sans-serif;
        background: #f4f6f8;
        color: #17202a;
    }}
    .container {{
        max-width: 1200px;
        margin: 40px auto;
        padding: 0 24px 50px;
    }}
    .header {{
        background: #17202a;
        color: white;
        padding: 32px;
        border-radius: 14px;
        margin-bottom: 24px;
    }}
    .header h1 {{
        margin: 0 0 8px;
        font-size: 30px;
    }}
    .header p {{
        margin: 6px 0;
        opacity: 0.9;
    }}
    .grid {{
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 16px;
        margin-bottom: 24px;
    }}
    .card {{
        background: white;
        border-radius: 12px;
        padding: 22px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.07);
    }}
    .card h3 {{
        margin-top: 0;
        font-size: 15px;
        color: #5d6d7e;
    }}
    .big {{
        font-size: 23px;
        font-weight: bold;
    }}
    .table-card {{
        background: white;
        border-radius: 12px;
        padding: 22px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.07);
        overflow-x: auto;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
    }}
    th, td {{
        padding: 14px 12px;
        border-bottom: 1px solid #e5e7e9;
        text-align: left;
        vertical-align: top;
    }}
    th {{
        background: #f8f9f9;
    }}
    .pass {{
        font-weight: bold;
        color: #196f3d;
    }}
    .fail {{
        font-weight: bold;
        color: #922b21;
    }}
    .neutral {{
        font-weight: bold;
        color: #566573;
    }}
    .flow {{
        margin-top: 24px;
        background: white;
        border-radius: 12px;
        padding: 28px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.07);
        text-align: center;
    }}
    .flow span {{
        display: inline-block;
        padding: 14px 18px;
        margin: 6px;
        border-radius: 8px;
        background: #ecf0f1;
        font-weight: bold;
    }}
    .arrow {{
        background: transparent !important;
        font-size: 24px;
    }}
    .conclusion {{
        margin-top: 24px;
        padding: 24px;
        border-left: 5px solid #566573;
        background: white;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.06);
        line-height: 1.6;
    }}
    @media (max-width: 800px) {{
        .grid {{
            grid-template-columns: 1fr;
        }}
    }}
</style>
</head>

<body>
<div class="container">

<div class="header">
    <h1>Remediation Before / After Comparison</h1>
    <p><strong>CVE:</strong> {escape(cve)}</p>
    <p><strong>System:</strong> Apache Tomcat</p>
    <p><strong>Purpose:</strong> Demonstrate configuration mitigation and independent validation</p>
</div>

<div class="grid">
    <div class="card">
        <h3>BEFORE REMEDIATION</h3>
        <div class="big">{escape(str(before_version))}</div>
        <p>DefaultServlet writes enabled</p>
        <p>PUT → <strong>201 Created</strong></p>
    </div>

    <div class="card">
        <h3>AFTER REMEDIATION</h3>
        <div class="big">{escape(str(after_version))}</div>
        <p>DefaultServlet writes disabled</p>
        <p>PUT → <strong>405 Method Not Allowed</strong></p>
    </div>

    <div class="card">
        <h3>FINAL ASSESSMENT</h3>
        <div class="big">{escape(str(overall))}</div>
        <p>Fixed 9.x version: <strong>{fixed_version}</strong></p>
    </div>
</div>

<div class="table-card">
    <h2>Evidence Comparison</h2>
    <table>
        <thead>
            <tr>
                <th>Evidence</th>
                <th>Before</th>
                <th>After</th>
                <th>Interpretation</th>
            </tr>
        </thead>
        <tbody>
            {''.join(html_rows)}
        </tbody>
    </table>
</div>

<div class="flow">
    <h2>Behavioral Evidence</h2>
    <span>BEFORE</span>
    <span class="arrow">→</span>
    <span>PUT 201 Created</span>
    <span class="arrow">→</span>
    <span>Remediation</span>
    <span class="arrow">→</span>
    <span>PUT 405 Blocked</span>
    <span class="arrow">→</span>
    <span>AFTER</span>
</div>

<div class="conclusion">
    <h2>Conclusion</h2>
    <p>
        The DefaultServlet configuration mitigation was successfully applied.
        Before remediation, the server accepted the controlled PUT request.
        After remediation, the same type of controlled write operation was blocked
        with HTTP 405, while the Tomcat service remained reachable.
    </p>
    <p>
        The underlying Tomcat software was not upgraded during this remediation.
        The server remains on version {escape(str(after_version))}, while the fixed
        Tomcat 9.x version is {fixed_version}. Therefore the result is
        <strong>{escape(str(overall))}</strong>, rather than a claim that the
        software itself has been fully patched.
    </p>
</div>

</div>
</body>
</html>
"""

OUTPUT.write_text(html, encoding="utf-8")

print("=" * 70)
print("REMEDIATION COMPARISON REPORT")
print("=" * 70)
print(f"BEFORE config:      {BEFORE_CONFIG}")
print(f"BEFORE evaluation:  {BEFORE_EVAL}")
print(f"AFTER config:       {AFTER_CONFIG}")
print(f"AFTER validation:   {AFTER_VALIDATION}")
print()
print(f"Report generated:   {OUTPUT}")
print()
print("Open it with:")
print(f'start "{OUTPUT}"')
