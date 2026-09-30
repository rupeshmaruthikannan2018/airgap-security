from flask import Flask, request, jsonify
from pathlib import Path
import zipfile
import uuid
import subprocess
import sys


app = Flask(__name__, static_folder='../frontend', static_url_path='/')

@app.route("/")
def index():
    return app.send_static_file('index.html')


BASE_DIR = Path(r"C:\airgap-security")
WORKSPACE = BASE_DIR / "workspace"
ORCHESTRATOR_DIR = BASE_DIR / "orchestrator"

sys.path.insert(0, str(ORCHESTRATOR_DIR))

import os
from main import run_application_scan
from input_router import classify_input, run_routed_scan
from cve_database_agent import CVEDatabaseAgent

WORKSPACE.mkdir(exist_ok=True)
CVE_AGENT = CVEDatabaseAgent()


@app.route("/api/cves/<cve_id>")
def get_cve(cve_id):
    try:
        result = CVE_AGENT.lookup(cve_id)
    except (ValueError, FileNotFoundError) as error:
        return jsonify({"error": str(error)}), 400

    if result is None:
        return jsonify({"error": f"{cve_id.upper()} is not in the local CVE database."}), 404

    return jsonify(result)


@app.route("/api/cves/search")
def search_cves():
    try:
        results = CVE_AGENT.search(request.args.get("q", ""))
    except (ValueError, FileNotFoundError) as error:
        return jsonify({"error": str(error)}), 400

    return jsonify({"count": len(results), "results": results})


def safe_extract(zip_file, destination):
    """
    Safely extract ZIP files and prevent Zip Slip attacks.
    """

    destination = destination.resolve()

    with zipfile.ZipFile(zip_file, "r") as z:

        for member in z.infolist():

            target = (destination / member.filename).resolve()

            if not target.is_relative_to(destination):
                raise ValueError(
                    "Unsafe ZIP entry detected."
                )

        z.extractall(destination)


@app.route("/upload", methods=["POST"])
def upload_application():

    if "file" not in request.files:
        return jsonify({
            "error": "No application file uploaded"
        }), 400

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":
        return jsonify({
            "error": "Empty filename"
        }), 400

    filename = Path(uploaded_file.filename).name
    if not filename.lower().endswith((".zip", ".log", ".txt", ".jsonl")):
        return jsonify({
            "error": "Upload a ZIP source/server bundle or a .log, .txt, or .jsonl network log."
        }), 400

    application_id = "APP-" + uuid.uuid4().hex[:8]

    application_workspace = (
        WORKSPACE / application_id
    )

    application_workspace.mkdir(
        parents=True,
        exist_ok=True
    )

    is_archive = filename.lower().endswith(".zip")
    target_path = application_workspace / ("application.zip" if is_archive else filename)
    uploaded_file.save(target_path)

    if is_archive:
        source_path = application_workspace / "source"
        source_path.mkdir()
        try:
            safe_extract(target_path, source_path)
        except Exception as e:
            return jsonify({"error": str(e)}), 400
        target_path = source_path

    routing = classify_input(target_path)

    return jsonify({
        "status": "uploaded",
        "application_id": application_id,
        "workspace": str(target_path),
        "routing": routing
    })
@app.route("/scan/<application_id>", methods=["POST"])
def scan_application(application_id):

    application_workspace = WORKSPACE / application_id
    source_path = application_workspace / "source"
    log_files = [path for path in application_workspace.iterdir()
                 if path.is_file() and path.suffix.lower() in {".log", ".txt", ".jsonl"}]
    target_path = source_path if source_path.exists() else (log_files[0] if log_files else None)

    # Check whether application exists
    if not application_workspace.exists():
        return jsonify({
            "error": "Application ID not found"
        }), 404

    # Check whether extracted source exists
    if target_path is None:
        return jsonify({
            "error": "Uploaded artifact not found"
        }), 404

    try:
        print(f"\nStarting security scan for {application_id}")
        
        import local_llm
        print(f"DEBUG: LLM_PROVIDER is {local_llm.LLM_PROVIDER}")
        
        result = run_routed_scan(target_path, application_workspace, run_application_scan)

        return jsonify({
            "status": "scan_completed",
            "application_id": application_id,
            "total_findings": result["total_findings"],
            "findings_file": result["findings_file"],
            "report_file": result["report_file"],
            "routing": result.get("routing"),
            "findings": result["findings"]
        })

    except Exception as e:

        print(f"Scan failed: {e}")

        return jsonify({
            "status": "scan_failed",
            "application_id": application_id,
            "error": str(e)
        }), 500

from flask import send_from_directory
from main import run_tomcat_contextual_scan
from sandbox_remediator import run_pipeline as run_sandbox_pipeline

@app.route("/report/<application_id>")
def view_report(application_id):
    application_workspace = WORKSPACE / application_id
    if not application_workspace.exists():
        return "Not found", 404
    return send_from_directory(application_workspace, "report.html")


@app.route("/api/tomcat/scan", methods=["POST"])
def scan_tomcat():
    data = request.get_json(silent=True) or {}
    container = data.get("container", "tomcat-9.0.98-vuln")
    url = data.get("url", "http://localhost:8081")
    cve = data.get("cve", None)
    
    workspace_path = WORKSPACE / "tomcat-contextual" / (cve if cve else "auto-discovered")
    workspace_path.mkdir(parents=True, exist_ok=True)
    knowledge_file = ORCHESTRATOR_DIR / "cve_knowledge.json"

    try:
        run_tomcat_contextual_scan(
            image_name="airgap-tomcat:9.0.98-vuln",
            container_name=container,
            cve=cve,
            knowledge_file=knowledge_file,
            workspace_path=workspace_path,
            target_url=url
        )

        findings_file = workspace_path / "findings.json"
        findings_data = {}
        if findings_file.exists():
            import json
            with findings_file.open("r", encoding="utf-8") as f:
                findings_data = json.load(f)

        findings = findings_data.get("findings", [])
        trivy_count = findings_data.get("trivy_count", len([f for f in findings if f.get("scanner") == "trivy"]))
        nuclei_count = findings_data.get("nuclei_count", len([f for f in findings if f.get("scanner") == "nuclei"]))
        nuclei_findings = [f for f in findings if f.get("scanner") == "nuclei"]

        rem_file = workspace_path / "remediation-analysis.json"
        rem_data = {}
        if rem_file.exists():
            import json
            with rem_file.open("r", encoding="utf-8") as f:
                rem_data = json.load(f)

        return jsonify({
            "status": "completed",
            "container": container,
            "url": url,
            "trivy_count": trivy_count,
            "nuclei_count": nuclei_count,
            "total_findings": len(findings),
            "nuclei_findings": nuclei_findings,
            "remediation_analysis": rem_data,
            "report_url": "/report/tomcat"
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "status": "failed",
            "error": str(e)
        }), 500


@app.route("/api/tomcat/remediate", methods=["POST"])
def remediate_tomcat():
    data = request.get_json(silent=True) or {}
    live_target = data.get("live_target", "tomcat-9.0.98")
    sandbox_container = data.get("sandbox_container", "tomcat-9.0.98-vuln")
    sandbox_url = data.get("sandbox_url", "http://localhost:8081")
    workspace_dir = WORKSPACE / "sandbox-validation"
    workspace_dir.mkdir(parents=True, exist_ok=True)

    try:
        pkg, html_path = run_sandbox_pipeline(
            live_target=live_target,
            sandbox_container=sandbox_container,
            sandbox_url=sandbox_url,
            workspace_dir=workspace_dir
        )

        if not pkg:
            return jsonify({
                "status": "failed",
                "error": "Sandbox remediation or verification checks failed"
            }), 400

        return jsonify({
            "status": "VALIDATED_SANDBOX_CONFIRMED_FIX",
            "package": pkg,
            "human_review_portal_url": "/api/tomcat/human-review"
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "status": "failed",
            "error": str(e)
        }), 500


@app.route("/report/tomcat")
def view_tomcat_report():
    report_path = WORKSPACE / "tomcat-contextual" / "auto-discovered" / "report.html"
    if not report_path.exists():
        return "Report not generated yet", 404
    return send_from_directory(report_path.parent, report_path.name)


@app.route("/api/tomcat/human-review")
def view_human_review_portal():
    portal_path = WORKSPACE / "sandbox-validation" / "human_review_portal.html"
    if not portal_path.exists():
        return "Human Review Portal not generated yet", 404
    return send_from_directory(portal_path.parent, portal_path.name)

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5000")),
        debug=False
    )
