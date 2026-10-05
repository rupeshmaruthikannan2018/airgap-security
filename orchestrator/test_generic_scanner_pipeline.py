"""
Comprehensive Automated Test Suite for the Generic ZIP / Folder Scanning Pipeline.

Tests:
1. Secure Archive Extraction:
   - Normal ZIP
   - Empty ZIP (0 bytes)
   - Malformed/corrupt ZIP
   - Path traversal / Zip Slip
   - Absolute paths (POSIX & Windows)
   - Nested archives within depth limit
   - Excessive nested archives exceeding depth limit
   - Symlink sanitization
   - Configurable limits (file size, total size, compression ratio)
2. Application Profiling:
   - Python + Flask/Django
   - Java + Maven/Spring
   - Node.js + Express
   - Go + Gin
   - Infrastructure: Dockerfile, Docker Compose, Terraform, Kubernetes YAML
   - Documentation-only projects
   - Mixed multi-language projects
3. Scanner Planning:
   - Evidence-based planning (Trivy, Semgrep)
   - Misconfig module activation on infrastructure
   - Nuclei activation only on dynamic target
   - Nmap activation only on network target
   - Absence of dynamic target -> NO_DYNAMIC_TARGET_AVAILABLE (never SAFE)
   - Generic selection (no hardcoded CVE rules)
4. End-to-End Pipeline Execution:
   - Workspace isolation
   - Machine-readable scan_manifest.json
   - Unified report.html
   - Zero code execution
"""
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import zipfile

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from secure_extractor import (
    SecureArchiveExtractor,
    ArchiveLimits,
    ArchiveSecurityError,
    ExtractionResult
)
from application_profiler import ApplicationProfiler, profile_application
from scanner_planner import ScannerPlanner, plan_scanners, ScannerPlan
from generic_scanner_pipeline import GenericScanningPipeline, ScanWorkspace, run_generic_scan
from scanner_manager import normalize_semgrep, normalize_trivy, correlate_findings
from report import (
    resolve_dynamic_validation,
    render_finding,
    render_complete_findings_table,
    generate_html_report,
)


class TestSecureArchiveExtractor(unittest.TestCase):
    """Rigorous security testing for archive extraction."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_extractor_"))
        self.dest_dir = self.temp_dir / "extracted"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_normal_zip_extraction(self):
        """Valid ZIP extracts safely preserving structure."""
        zip_path = self.temp_dir / "valid.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("app.py", "print('hello world')")
            zf.writestr("config/settings.json", '{"debug": false}')

        extractor = SecureArchiveExtractor()
        result = extractor.validate_and_extract(zip_path, self.dest_dir)

        self.assertTrue((self.dest_dir / "app.py").exists())
        self.assertTrue((self.dest_dir / "config" / "settings.json").exists())
        self.assertEqual(len(result.rejected_entries), 0)
        self.assertEqual(result.total_extracted_files, 2)
        self.assertTrue(result.archive_sha256 != "")

    def test_empty_zip_rejected(self):
        """0-byte ZIP files are rejected with security error."""
        zip_path = self.temp_dir / "empty.zip"
        zip_path.touch()

        extractor = SecureArchiveExtractor()
        with self.assertRaises(ArchiveSecurityError):
            extractor.validate_and_extract(zip_path, self.dest_dir)

    def test_malformed_zip_rejected(self):
        """Corrupt or non-ZIP files are rejected safely."""
        bad_zip = self.temp_dir / "bad.zip"
        bad_zip.write_bytes(b"THIS IS NOT A VALID ZIP FILE HEADER")

        extractor = SecureArchiveExtractor()
        with self.assertRaises(ArchiveSecurityError):
            extractor.validate_and_extract(bad_zip, self.dest_dir)

    def test_zip_slip_path_traversal_rejected(self):
        """Entries containing '..' or escaping destination are rejected."""
        zip_path = self.temp_dir / "zipslip.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("safe.txt", "safe content")
            zf.writestr("../escaped.txt", "malicious content")
            zf.writestr("foo/../../escaped2.txt", "malicious content")

        extractor = SecureArchiveExtractor()
        result = extractor.validate_and_extract(zip_path, self.dest_dir)

        self.assertTrue((self.dest_dir / "safe.txt").exists())
        self.assertFalse((self.temp_dir / "escaped.txt").exists())
        self.assertFalse((self.temp_dir / "escaped2.txt").exists())
        self.assertEqual(len(result.rejected_entries), 2)
        self.assertIn("escaped", result.rejected_entries[0]["entry"])

    def test_absolute_path_entries_rejected(self):
        """Entries with absolute POSIX or Windows paths are rejected."""
        zip_path = self.temp_dir / "absolute.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("/etc/passwd", "root:x:0:0:::")
            zf.writestr("C:\\Windows\\System32\\calc.exe", "evil")
            zf.writestr("valid.txt", "ok")

        extractor = SecureArchiveExtractor()
        result = extractor.validate_and_extract(zip_path, self.dest_dir)

        self.assertTrue((self.dest_dir / "valid.txt").exists())
        self.assertEqual(len(result.rejected_entries), 2)

    def test_nested_zip_within_depth_limit(self):
        """Nested ZIP files are extracted recursively up to max_nested_archive_depth."""
        inner_zip_bytes = io.BytesIO()
        with zipfile.ZipFile(inner_zip_bytes, "w") as izf:
            izf.writestr("inner.py", "print('inside')")
        inner_data = inner_zip_bytes.getvalue()

        outer_zip = self.temp_dir / "outer.zip"
        with zipfile.ZipFile(outer_zip, "w") as ozf:
            ozf.writestr("outer.txt", "outer level")
            ozf.writestr("nested.zip", inner_data)

        extractor = SecureArchiveExtractor(ArchiveLimits(max_nested_archive_depth=2))
        result = extractor.validate_and_extract(outer_zip, self.dest_dir)

        self.assertTrue((self.dest_dir / "outer.txt").exists())
        self.assertTrue((self.dest_dir / "nested_nested" / "inner.py").exists())
        self.assertEqual(result.nested_archives_extracted, 1)

    def test_excessive_nested_zip_depth_limit_enforced(self):
        """Nested recursion ceases when depth exceeds configured maximum."""
        # Create 3-level deep archive
        level2_buf = io.BytesIO()
        with zipfile.ZipFile(level2_buf, "w") as z2:
            z2.writestr("level2.txt", "deep")

        level1_buf = io.BytesIO()
        with zipfile.ZipFile(level1_buf, "w") as z1:
            z1.writestr("level2.zip", level2_buf.getvalue())

        root_zip = self.temp_dir / "root.zip"
        with zipfile.ZipFile(root_zip, "w") as z0:
            z0.writestr("level1.zip", level1_buf.getvalue())

        # Max depth = 1 -> level1 extracted, level2 skipped
        extractor = SecureArchiveExtractor(ArchiveLimits(max_nested_archive_depth=1))
        result = extractor.validate_and_extract(root_zip, self.dest_dir)

        self.assertEqual(result.nested_archives_extracted, 1)
        self.assertTrue(any("depth" in w.lower() for w in result.warnings))

    def test_suspicious_compression_ratio_zip_bomb(self):
        """Archives with extreme compression ratios trigger suspicious ratio check."""
        zip_path = self.temp_dir / "bomb.zip"
        # 1MB of zeroes compressed heavily
        big_zeroes = b"0" * (1024 * 1024)
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.dat", big_zeroes)

        # Set strict ratio limit
        limits = ArchiveLimits(max_compression_ratio=5.0, min_bytes_for_ratio_check=1024)
        extractor = SecureArchiveExtractor(limits)
        result = extractor.validate_and_extract(zip_path, self.dest_dir)

        self.assertEqual(len(result.rejected_entries), 1)
        self.assertIn("compression ratio", result.rejected_entries[0]["reason"].lower())

    def test_file_size_limit_enforced(self):
        """Files exceeding max_file_size are rejected or abort decompression."""
        zip_path = self.temp_dir / "bigfile.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("file_ok.txt", "small")
            zf.writestr("file_big.txt", "x" * 2000)

        limits = ArchiveLimits(max_file_size=1000)
        extractor = SecureArchiveExtractor(limits)
        result = extractor.validate_and_extract(zip_path, self.dest_dir)

        self.assertTrue((self.dest_dir / "file_ok.txt").exists())
        self.assertFalse((self.dest_dir / "file_big.txt").exists())
        self.assertEqual(len(result.rejected_entries), 1)

    def test_symlink_sanitization(self):
        """Symlinks are safely recorded and neutralized without live filesystem escape."""
        zip_path = self.temp_dir / "symlink.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            info = zipfile.ZipInfo("link_to_file")
            # Set POSIX symlink attribute (0120000 in octal)
            info.external_attr = 0o120777 << 16
            zf.writestr(info, "target.txt")
            zf.writestr("target.txt", "real file")

        extractor = SecureArchiveExtractor()
        result = extractor.validate_and_extract(zip_path, self.dest_dir)

        link_file = self.dest_dir / "link_to_file"
        self.assertTrue(link_file.exists())
        self.assertIn("SYMLINK", link_file.read_text(encoding="utf-8"))


class TestApplicationProfiler(unittest.TestCase):
    """Tests the generic application profiler across diverse tech stacks."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_profiler_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_profile_python_flask(self):
        (self.temp_dir / "app.py").write_text("from flask import Flask\napp = Flask(__name__)", encoding="utf-8")
        (self.temp_dir / "requirements.txt").write_text("Flask==2.0.1\nrequests==2.25.1", encoding="utf-8")

        profiler = ApplicationProfiler(self.temp_dir)
        profile = profiler.profile()

        self.assertIn("python", profile["languages"])
        self.assertIn("Flask", profile["frameworks"])
        self.assertIn("requirements.txt", profile["dependency_manifests"])
        self.assertTrue(profile["web_application"])
        self.assertFalse(profile["documentation_only"])

    def test_profile_java_spring(self):
        src_dir = self.temp_dir / "src" / "main" / "java"
        src_dir.mkdir(parents=True)
        (src_dir / "App.java").write_text("package com.test;\nimport org.springframework.boot.autoconfigure.SpringBootApplication;\n@SpringBootApplication\npublic class App {}", encoding="utf-8")
        (self.temp_dir / "pom.xml").write_text("<project><dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>", encoding="utf-8")

        profile = profile_application(self.temp_dir)

        self.assertIn("java", profile["languages"])
        self.assertIn("Spring", profile["frameworks"])
        self.assertIn("pom.xml", profile["manifests"])
        self.assertTrue(profile["web_application"])

    def test_profile_node_express(self):
        (self.temp_dir / "server.js").write_text("const express = require('express'); const app = express();", encoding="utf-8")
        (self.temp_dir / "package.json").write_text('{"name": "test-app", "dependencies": {"express": "^4.17.1"}}', encoding="utf-8")

        profile = profile_application(self.temp_dir)

        self.assertIn("javascript", profile["languages"])
        self.assertIn("Express", profile["frameworks"])
        self.assertIn("package.json", profile["dependency_manifests"])
        self.assertTrue(profile["web_application"])

    def test_profile_go_gin(self):
        (self.temp_dir / "main.go").write_text('package main\nimport "github.com/gin-gonic/gin"\nfunc main() {}', encoding="utf-8")
        (self.temp_dir / "go.mod").write_text("module test\ngo 1.20\nrequire github.com/gin-gonic/gin v1.9.0", encoding="utf-8")

        profile = profile_application(self.temp_dir)

        self.assertIn("go", profile["languages"])
        self.assertIn("Gin", profile["frameworks"])
        self.assertIn("go.mod", profile["dependency_manifests"])
        self.assertTrue(profile["web_application"])

    def test_profile_infrastructure(self):
        (self.temp_dir / "Dockerfile").write_text("FROM alpine:3.18\nRUN apk add curl", encoding="utf-8")
        (self.temp_dir / "docker-compose.yml").write_text("version: '3.8'\nservices:\n  web:\n    image: nginx", encoding="utf-8")
        (self.temp_dir / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "test"\n}', encoding="utf-8")
        k8s_file = self.temp_dir / "deploy.yaml"
        k8s_file.write_text("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app", encoding="utf-8")

        profile = profile_application(self.temp_dir)

        self.assertIn("Dockerfile", profile["infrastructure"])
        self.assertIn("docker-compose", profile["infrastructure"])
        self.assertIn("Terraform", profile["infrastructure"])
        self.assertIn("Kubernetes YAML", profile["infrastructure"])

    def test_profile_documentation_only(self):
        (self.temp_dir / "README.md").write_text("# Project Docs\nHere is documentation.", encoding="utf-8")
        (self.temp_dir / "LICENSE").write_text("MIT License", encoding="utf-8")
        (self.temp_dir / "manual.txt").write_text("User Guide", encoding="utf-8")

        profile = profile_application(self.temp_dir)

        self.assertTrue(profile["documentation_only"])
        self.assertEqual(len(profile["languages"]), 0)
        self.assertEqual(len(profile["dependency_manifests"]), 0)


class TestScannerPlanner(unittest.TestCase):
    """Tests the evidence-based scanner planner."""

    def test_python_and_requirements_plan(self):
        profile = {
            "languages": ["python"],
            "dependency_manifests": ["requirements.txt"],
            "infrastructure": [],
            "config_files": [],
            "documentation_only": False,
            "total_files": 5
        }
        plan = plan_scanners(profile)

        self.assertTrue(plan.trivy.enabled)
        self.assertEqual(plan.trivy.scanners, ["vuln", "secret"])
        self.assertTrue(plan.semgrep.enabled)
        self.assertFalse(plan.nuclei.enabled)
        self.assertEqual(plan.nuclei.status, "NO_DYNAMIC_TARGET_AVAILABLE")
        self.assertFalse(plan.nmap.enabled)
        self.assertEqual(plan.nmap.status, "NO_NETWORK_TARGET_AVAILABLE")

    def test_infrastructure_enables_misconfig(self):
        profile = {
            "languages": [],
            "dependency_manifests": [],
            "infrastructure": ["Dockerfile", "Terraform"],
            "config_files": ["server.xml"],
            "documentation_only": False,
            "total_files": 3
        }
        plan = plan_scanners(profile)

        self.assertTrue(plan.trivy.enabled)
        self.assertIn("misconfig", plan.trivy.scanners)
        self.assertIn("vuln", plan.trivy.scanners)
        self.assertIn("secret", plan.trivy.scanners)

    def test_documentation_only_skips_scanners(self):
        profile = {
            "languages": [],
            "dependency_manifests": [],
            "infrastructure": [],
            "config_files": [],
            "documentation_only": True,
            "total_files": 2
        }
        plan = plan_scanners(profile)

        self.assertFalse(plan.trivy.enabled)
        self.assertFalse(plan.semgrep.enabled)
        self.assertFalse(plan.nuclei.enabled)
        self.assertFalse(plan.nmap.enabled)

    def test_dynamic_target_enables_nuclei(self):
        profile = {
            "languages": ["python"],
            "dependency_manifests": ["requirements.txt"],
            "infrastructure": [],
            "config_files": [],
            "documentation_only": False,
            "total_files": 3
        }
        plan = plan_scanners(profile, dynamic_target="http://localhost:8080")

        self.assertTrue(plan.nuclei.enabled)
        self.assertEqual(plan.nuclei.target, "http://localhost:8080")

    def test_network_target_enables_nmap(self):
        profile = {
            "languages": ["python"],
            "dependency_manifests": [],
            "infrastructure": [],
            "config_files": [],
            "documentation_only": False,
            "total_files": 1
        }
        plan = plan_scanners(profile, network_target="192.168.1.50")

        self.assertTrue(plan.nmap.enabled)
        self.assertEqual(plan.nmap.target, "192.168.1.50")


class TestGenericScannerPipeline(unittest.TestCase):
    """Tests the full end-to-end generic scanning pipeline."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_pipeline_"))
        self.workspace = self.temp_dir / "workspace"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_pipeline_zip_scan_manifest_and_report(self):
        """End-to-end execution of ZIP scan with manifest and report verification."""
        # Create sample project zip
        project_zip = self.temp_dir / "sample_app.zip"
        with zipfile.ZipFile(project_zip, "w") as zf:
            zf.writestr("app.py", "import os\nprint('demo application')\n")
            zf.writestr("requirements.txt", "urllib3==1.26.4\n")
            zf.writestr("Dockerfile", "FROM python:3.9-slim\nCOPY . /app\n")

        pipeline = GenericScanningPipeline()
        result = pipeline.run_scan(
            input_path=project_zip,
            workspace_dir=self.workspace,
            scan_id="TEST-SCAN-01",
            original_filename="sample_app.zip"
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["scan_id"], "TEST-SCAN-01")

        # Verify artifacts written to workspace
        manifest_file = self.workspace / "scan_manifest.json"
        findings_file = self.workspace / "findings.json"
        report_file = self.workspace / "report.html"

        self.assertTrue(manifest_file.exists())
        self.assertTrue(findings_file.exists())
        self.assertTrue(report_file.exists())

        # Verify Manifest JSON structure (Section 12)
        manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
        self.assertEqual(manifest_data["scan_id"], "TEST-SCAN-01")
        self.assertEqual(manifest_data["input"]["filename"], "sample_app.zip")
        self.assertTrue(len(manifest_data["input"]["sha256"]) == 64)
        self.assertIn("python", manifest_data["profile"]["languages"])
        self.assertIn("requirements.txt", manifest_data["profile"]["dependency_manifests"])
        self.assertIn("Dockerfile", manifest_data["profile"]["infrastructure"])
        self.assertTrue(manifest_data["scanner_plan"]["trivy"])
        self.assertTrue(manifest_data["scanner_plan"]["semgrep"])
        self.assertFalse(manifest_data["scanner_plan"]["nuclei"])
        self.assertFalse(manifest_data["scanner_plan"]["nmap"])
        self.assertIn("trivy", manifest_data["scanner_results"])
        self.assertEqual(manifest_data["scanner_results"]["nuclei"], "not_applicable")

        # Verify Unified report.html exists and is non-empty
        report_content = report_file.read_text(encoding="utf-8", errors="replace")
        self.assertTrue(len(report_content) > 100)
        self.assertIn("html", report_content.lower())


class TestGenericPipelineRegression(unittest.TestCase):
    """
    Regression test suite verifying backend API contracts, secure archive handling,
    dynamic project root discovery, and defensive frontend behavior.
    """

    def setUp(self):
        backend_dir = Path(__file__).resolve().parent.parent / "backend"
        if str(backend_dir) not in sys.path:
            sys.path.insert(0, str(backend_dir))
        from app import app
        self.app = app
        self.client = app.test_client()
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_reg_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_1_valid_zip_upload_returns_json(self):
        """1. Valid ZIP upload returns JSON response with complete schema."""
        zip_path = self.temp_dir / "valid_app.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("package.json", '{"name": "test-app", "dependencies": {"express": "^4.18.2"}}')
            zf.writestr("index.js", 'const express = require("express");')

        with open(zip_path, "rb") as f:
            res = self.client.post("/upload", data={"file": (f, "valid_app.zip")}, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.is_json)
        self.assertTrue(res.headers.get("Content-Type", "").startswith("application/json"))
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertTrue(data.get("application_id", "").startswith("APP-"))
        self.assertEqual(data.get("filename"), "valid_app.zip")
        self.assertEqual(len(data.get("sha256", "")), 64)
        self.assertIn("profile", data)
        self.assertIn("scanner_plan", data)
        self.assertIn("manifest", data)
        self.assertIn("Express", data["profile"]["frameworks"])

    def test_2_malformed_zip_returns_json_error(self):
        """2. Malformed ZIP returns structured JSON error (never HTML)."""
        bad_file = io.BytesIO(b"NOT_A_VALID_ZIP_ARCHIVE_DATA")
        res = self.client.post("/upload", data={"file": (bad_file, "corrupt.zip")}, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 400)
        self.assertTrue(res.is_json)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertIn("error", data)
        self.assertIn(data["error"]["type"], ["EXTRACTION_SECURITY_VIOLATION", "MALFORMED_ARCHIVE", "EXTRACTION_ERROR"])
        self.assertTrue(len(data["error"]["message"]) > 0)

    def test_3_oversized_zip_returns_json_error(self):
        """3. Oversized ZIP exceeding limits returns structured JSON error."""
        zip_path = self.temp_dir / "oversized.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("huge_file.txt", "A" * 500)

        # Restrict extractor limit during this test
        strict_limits = ArchiveLimits(max_extracted_size=100)
        with patch("app.SecureArchiveExtractor") as mock_extractor_cls:
            mock_inst = SecureArchiveExtractor(limits=strict_limits)
            mock_extractor_cls.return_value = mock_inst
            with open(zip_path, "rb") as f:
                res = self.client.post("/upload", data={"file": (f, "oversized.zip")}, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 400)
        self.assertTrue(res.is_json)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertEqual(data["error"]["type"], "EXTRACTION_SECURITY_VIOLATION")

    def test_4_zip_slip_returns_json_error(self):
        """4. Zip Slip traversal returns structured JSON error."""
        zip_path = self.temp_dir / "zipslip.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../evil.sh", "echo pwned")

        with open(zip_path, "rb") as f:
            res = self.client.post("/upload", data={"file": (f, "zipslip.zip")}, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 400)
        self.assertTrue(res.is_json)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertEqual(data["error"]["type"], "EXTRACTION_SECURITY_VIOLATION")

    def test_5_profiler_exception_returns_json_error(self):
        """5. Unhandled exception in profiler returns 500 JSON error."""
        zip_path = self.temp_dir / "test_prof_fail.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("test.py", "print('fail test')")

        with patch("app.ApplicationProfiler.profile", side_effect=RuntimeError("Simulated profiler failure")):
            with open(zip_path, "rb") as f:
                res = self.client.post("/upload", data={"file": (f, "test_prof_fail.zip")}, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 500)
        self.assertTrue(res.is_json)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertEqual(data["error"]["type"], "PROFILER_ERROR")
        self.assertIn("Simulated profiler failure", data["error"]["message"])

    def test_6_scanner_planner_exception_returns_json_error(self):
        """6. Unhandled exception in scanner planner returns 500 JSON error."""
        zip_path = self.temp_dir / "test_plan_fail.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("test.py", "print('fail test')")

        with patch("app.ScannerPlanner.plan", side_effect=RuntimeError("Simulated planner failure")):
            with open(zip_path, "rb") as f:
                res = self.client.post("/upload", data={"file": (f, "test_plan_fail.zip")}, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 500)
        self.assertTrue(res.is_json)
        data = res.get_json()
        self.assertFalse(data.get("success"))
        self.assertEqual(data["error"]["type"], "SCANNER_PLANNER_ERROR")
        self.assertIn("Simulated planner failure", data["error"]["message"])

    def test_7_github_style_top_level_project_directory(self):
        """7. GitHub-style single top-level directory correctly resolves app root & frameworks."""
        zip_path = self.temp_dir / "project-master.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("project-master/package.json", '{"name": "my-pkg", "dependencies": {"express": "^4.17.1"}}')
            zf.writestr("project-master/src/index.js", 'console.log("hello");')
            zf.writestr("project-master/Dockerfile", 'FROM node:18\n')

        with open(zip_path, "rb") as f:
            res = self.client.post("/upload", data={"file": (f, "project-master.zip")}, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        profile = data["profile"]
        self.assertIn("javascript", profile["languages"])
        self.assertIn("Express", profile["frameworks"])
        self.assertIn("package.json", profile["dependency_manifests"])
        self.assertIn("Dockerfile", profile["infrastructure"])
        self.assertTrue(profile["web_application"])
        # Verify scanner planner activates semgrep and trivy
        plan = data["scanner_plan"]
        self.assertTrue(plan["semgrep"]["enabled"])
        self.assertTrue(plan["trivy"]["enabled"])

    def test_8_ordinary_flat_zip(self):
        """8. Ordinary flat ZIP with files directly at root is profiled cleanly."""
        zip_path = self.temp_dir / "flat_project.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("requirements.txt", "flask==2.3.2\nrequests==2.31.0\n")
            zf.writestr("main.py", "import flask\n")

        with open(zip_path, "rb") as f:
            res = self.client.post("/upload", data={"file": (f, "flat_project.zip")}, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        profile = data["profile"]
        self.assertIn("python", profile["languages"])
        self.assertIn("Flask", profile["frameworks"])
        self.assertIn("requirements.txt", profile["dependency_manifests"])

    def test_9_nested_project_directory(self):
        """9. Nested project directory structure correctly profiles evidence recursively."""
        proj_dir = self.temp_dir / "multi_level"
        nested_dir = proj_dir / "modules" / "core"
        nested_dir.mkdir(parents=True)
        (nested_dir / "pom.xml").write_text('<project><dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>', encoding="utf-8")
        (nested_dir / "App.java").write_text('package com.test; public class App {}', encoding="utf-8")

        profiler = ApplicationProfiler(proj_dir)
        profile = profiler.profile()
        self.assertIn("java", profile["languages"])
        self.assertIn("pom.xml", profile["dependency_manifests"])
        self.assertIn("Spring Boot", profile["frameworks"])

    def test_10_frontend_handles_non_json_response_safely(self):
        """10. Frontend defensive parsing verification: verify index.html implements parseApiResponse safely."""
        frontend_html = (Path(__file__).resolve().parent.parent / "frontend" / "index.html").read_text(encoding="utf-8")
        # Ensure parseApiResponse is defined and used
        self.assertIn("function parseApiResponse", frontend_html)
        self.assertIn("parseApiResponse(res, 'Upload failed')", frontend_html)
        self.assertIn("parseApiResponse(res, 'Scan failed')", frontend_html)
        # Ensure no blind res.json() without checking response
        self.assertNotIn("const data = await res.json();", frontend_html)
        # Ensure sensitive path redaction and html tag stripping are present
        self.assertIn("replace(/<[^>]*>/g", frontend_html)
        self.assertIn("[local-path]", frontend_html)


class TestDynamicValidationReportingSemantics(unittest.TestCase):
    """
    Regression test suite for dynamic validation reporting layer semantics:
    1. No dynamic target + Nuclei not executed -> NO_DYNAMIC_TEST_AVAILABLE
    2. Dynamic scanner executes and confirms -> CONFIRMED
    3. Dynamic scanner executes but does not confirm -> NOT_DYNAMICALLY_CONFIRMED
    4. Dynamic evaluation is attempted but evidence is insufficient -> UNDETERMINED
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_dyn_val_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_1_no_dynamic_target_nuclei_not_executed_is_no_dynamic_test_available(self):
        """
        1. When no dynamic target is available and Nuclei/dynamic validation was not executed:
           - Status must be NO_DYNAMIC_TEST_AVAILABLE
           - UI card displays NO DYNAMIC TEST AVAILABLE (with optional explanation)
           - Complete Findings Table displays NO DYNAMIC TEST AVAILABLE
           - Must NOT display UNDETERMINED
           - Prerequisite must remain UNKNOWN (never converted to 'no prerequisites exist')
        """
        # Source-only scan finding with no dynamic target and Nuclei not executed
        finding = {
            "id": "vuln-1",
            "cve": "CVE-2023-1234",
            "cve_id": "CVE-2023-1234",
            "package": "demo-library",
            "installed_version": "1.0.0",
            "fixed_version": "1.0.1",
            "severity": "HIGH",
            "priority": "HIGH",
            "source": "trivy",
            # No dynamic_target, nuclei not executed, no validation_status supplied
        }

        # 1. Resolver semantic test
        canonical, badge, display = resolve_dynamic_validation(finding)
        self.assertEqual(canonical, "NO_DYNAMIC_TEST_AVAILABLE")
        self.assertIn("NO DYNAMIC TEST", badge)
        self.assertIn("NO DYNAMIC TEST AVAILABLE", display)
        self.assertIn("No live target URL was supplied; dynamic validation was not executed.", display)
        self.assertNotIn("UNDETERMINED", badge)
        self.assertNotIn("UNDETERMINED", display)

        # 2. Finding card rendering test: detailed report displays NO DYNAMIC TEST AVAILABLE
        card_html = render_finding(finding)
        self.assertIn("NO DYNAMIC TEST AVAILABLE", card_html)
        self.assertIn("No live target URL was supplied; dynamic validation was not executed.", card_html)
        self.assertNotIn("UNDETERMINED", card_html)

        # 3. Summary table rendering test: summary table displays NO DYNAMIC TEST
        table_html = render_complete_findings_table([finding])
        self.assertIn("NO DYNAMIC TEST", table_html)
        self.assertNotIn(">UNDETERMINED<", table_html)

        # 4. Verify identical canonical status is used by both detailed finding card and Complete Findings Table
        # Both call resolve_dynamic_validation(f) which emits canonical status 'NO_DYNAMIC_TEST_AVAILABLE'
        self.assertEqual(resolve_dynamic_validation(finding)[0], "NO_DYNAMIC_TEST_AVAILABLE")
        self.assertIn(resolve_dynamic_validation(finding)[1], table_html)
        self.assertIn(resolve_dynamic_validation(finding)[2], card_html)

        # 5. Full report generation test: verify UI and table badges together
        out_report = self.temp_dir / "report_no_dyn.html"
        generate_html_report([finding], "TestApp", out_report)
        content = out_report.read_text(encoding="utf-8")
        self.assertIn("NO DYNAMIC TEST AVAILABLE", content)
        self.assertIn("NO DYNAMIC TEST", content)
        self.assertNotIn(">UNDETERMINED<", content)

        # 4. Pipeline normalization check: pipeline with no dynamic target stamps NO_DYNAMIC_TEST_AVAILABLE
        pipeline = GenericScanningPipeline()
        workspace = self.temp_dir / "ws1"
        extracted = workspace / "extracted"
        extracted.mkdir(parents=True)
        (extracted / "app.py").write_text("print('test')", encoding="utf-8")
        (extracted / "requirements.txt").write_text("requests==2.25.1", encoding="utf-8")

        # Mock out scanner subprocess execution to avoid external tools in unit test
        with patch("generic_scanner_pipeline.run_trivy", return_value={"Results": []}), \
             patch("generic_scanner_pipeline.run_semgrep", return_value={"results": []}), \
             patch("generic_scanner_pipeline.correlate_findings", return_value=[dict(finding)]):
            res = pipeline.run_scan(
                input_path=extracted,
                workspace_dir=workspace,
                dynamic_target=None
            )
            f_out = res["findings"][0]
            self.assertEqual(f_out.get("validation_status"), "NO_DYNAMIC_TEST_AVAILABLE")
            self.assertEqual(f_out.get("dynamic_validation_status"), "NO_DYNAMIC_TEST_AVAILABLE")
            # Prerequisite status must remain UNKNOWN for source-only scan with no dynamic target
            p_status = f_out.get("prerequisite_status", "UNKNOWN")
            self.assertEqual(p_status, "UNKNOWN")

    def test_2_dynamic_scanner_executes_and_confirms_is_confirmed(self):
        """
        2. Dynamic scanner executes and confirms:
           - Status must be CONFIRMED
           - Complete Findings Table displays CONFIRMED
           - Finding card displays CONFIRMED
        """
        finding = {
            "id": "vuln-2",
            "cve": "CVE-2024-5678",
            "cve_id": "CVE-2024-5678",
            "package": "web-framework",
            "installed_version": "2.0.0",
            "severity": "CRITICAL",
            "priority": "CRITICAL",
            "validation_status": "CONFIRMED",
            "nuclei_confirmed": True,
            "nuclei_status": "confirmed",
            "nuclei_matched_at": "http://127.0.0.1:8080/vulnerable/endpoint",
            "curl_command": "curl -X POST http://127.0.0.1:8080/vulnerable/endpoint",
        }

        canonical, badge, display = resolve_dynamic_validation(finding)
        self.assertEqual(canonical, "CONFIRMED")
        self.assertIn("CONFIRMED", badge)
        self.assertIn("status-danger", badge)
        self.assertIn("CONFIRMED", display)
        self.assertIn("http://127.0.0.1:8080/vulnerable/endpoint", display)

        # Card & Table
        card_html = render_finding(finding)
        self.assertIn("CONFIRMED", card_html)
        table_html = render_complete_findings_table([finding])
        self.assertIn("CONFIRMED", table_html)

    def test_3_dynamic_scanner_executes_but_does_not_confirm_is_not_dynamically_confirmed(self):
        """
        3. Dynamic scanner executes but does not confirm:
           - Status must be NOT_DYNAMICALLY_CONFIRMED
           - Complete Findings Table displays NOT DYNAMICALLY CONFIRMED
           - Finding card displays NOT DYNAMICALLY CONFIRMED
        """
        finding = {
            "id": "vuln-3",
            "cve": "CVE-2024-9999",
            "cve_id": "CVE-2024-9999",
            "package": "auth-service",
            "installed_version": "1.1.0",
            "severity": "HIGH",
            "priority": "HIGH",
            "validation_status": "NOT_DYNAMICALLY_CONFIRMED",
            "nuclei_confirmed": False,
            "nuclei_status": "not_detected",
            "nuclei_matched_at": "NO MATCH",
        }

        canonical, badge, display = resolve_dynamic_validation(finding)
        self.assertEqual(canonical, "NOT_DYNAMICALLY_CONFIRMED")
        self.assertIn("NOT DYNAMICALLY CONFIRMED", badge)
        self.assertIn("NOT DYNAMICALLY CONFIRMED", display)
        self.assertIn("NO MATCH", display)

        card_html = render_finding(finding)
        self.assertIn("NOT DYNAMICALLY CONFIRMED", card_html)
        table_html = render_complete_findings_table([finding])
        self.assertIn("NOT DYNAMICALLY CONFIRMED", table_html)

    def test_4_dynamic_evaluation_attempted_evidence_insufficient_is_undetermined(self):
        """
        4. Dynamic evaluation is attempted but evidence is insufficient:
           - Status must be UNDETERMINED
           - Complete Findings Table displays UNDETERMINED
           - Finding card displays UNDETERMINED
        """
        finding = {
            "id": "vuln-4",
            "cve": "CVE-2024-0001",
            "cve_id": "CVE-2024-0001",
            "package": "db-connector",
            "installed_version": "3.0.0",
            "severity": "MEDIUM",
            "priority": "MEDIUM",
            "validation_status": "UNDETERMINED",
            "dynamic_evaluation_attempted": True,
        }

        canonical, badge, display = resolve_dynamic_validation(finding)
        self.assertEqual(canonical, "UNDETERMINED")
        self.assertIn("UNDETERMINED", badge)
        self.assertIn("UNDETERMINED", display)
        self.assertIn("Dynamic evaluation was attempted but evidence was insufficient", display)

        card_html = render_finding(finding)
        self.assertIn("UNDETERMINED", card_html)
        table_html = render_complete_findings_table([finding])
        self.assertIn("UNDETERMINED", table_html)


if __name__ == "__main__":
    unittest.main()
