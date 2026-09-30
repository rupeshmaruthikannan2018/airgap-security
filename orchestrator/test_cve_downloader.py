"""Comprehensive test suite for CVE List V5 & NVD acquisition layer in cve_downloader.py.

Validates:
A. CVE List V5 URL/release resolution behavior using mocked HTTP responses.
B. Successful ZIP download using a small test ZIP fixture.
C. SHA-256 calculation.
D. Metadata generation.
E. Manifest contains the CVE List V5 artifact and distinguishes NVD.
F. Existing NVD downloader behavior remains working.
G. Zero network access performed by offline importer.
H. Invalid/non-ZIP CVE List V5 response is rejected.
I. HTTP failure and transient retries handled cleanly.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))
workspace_dir = current_dir.parent
if str(workspace_dir) not in sys.path:
    sys.path.insert(0, str(workspace_dir))

from cve_downloader import (
    CVEListV5Downloader,
    NVDDownloader,
    calculate_sha256,
    package_offline_update,
)
from cve_importer import CVEImporter


def _create_dummy_zip_bytes() -> bytes:
    """Create a minimal valid in-memory ZIP archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test_cve.json", json.dumps({"dataType": "CVE_RECORD", "cveMetadata": {"cveId": "CVE-2025-0001"}}))
    return buf.getvalue()


class CVEListV5DownloaderTests(unittest.TestCase):
    """Test suite for CVE List V5 downloader and packaging."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_cve_dl_"))

    def tearDown(self):
        try:
            shutil.rmtree(self.temp_dir)
        except OSError:
            pass

    # A. Release Resolution
    @patch("urllib.request.urlopen")
    def test_a_release_resolution_mocked(self, mock_urlopen):
        """Verify GitHub release resolution accurately detects the complete daily baseline asset."""
        mock_release_payload = {
            "tag_name": "cve_2026-09-28_1000Z",
            "published_at": "2026-09-28T10:05:00Z",
            "assets": [
                {
                    "name": "2026-09-28_delta_CVEs_at_1000Z.zip",
                    "browser_download_url": "https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-09-28_1000Z/2026-09-28_delta_CVEs_at_1000Z.zip",
                    "size": 50000,
                },
                {
                    "name": "2026-09-28_all_CVEs_at_midnight.zip.zip",
                    "browser_download_url": "https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-09-28_1000Z/2026-09-28_all_CVEs_at_midnight.zip.zip",
                    "size": 600000000,
                }
            ]
        }

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(mock_release_payload).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        downloader = CVEListV5Downloader(self.temp_dir)
        resolved = downloader.resolve_latest_baseline()

        self.assertEqual(resolved["release_tag"], "cve_2026-09-28_1000Z")
        self.assertEqual(resolved["asset_name"], "2026-09-28_all_CVEs_at_midnight.zip.zip")
        self.assertIn("all_CVEs_at_midnight", resolved["download_url"])
        self.assertEqual(resolved["classification"], "baseline")

    # B. Successful ZIP download
    @patch("urllib.request.urlopen")
    def test_b_successful_zip_download(self, mock_urlopen):
        """Verify baseline ZIP streams to disk, validates zipfile format, and returns metadata."""
        zip_bytes = _create_dummy_zip_bytes()

        mock_resp = MagicMock()
        mock_resp.read.side_effect = [zip_bytes, b""]
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        downloader = CVEListV5Downloader(self.temp_dir)
        asset_info = {
            "release_tag": "cve_2026-09-28_test",
            "asset_name": "2026-09-28_all_CVEs_at_midnight.zip",
            "download_url": "https://example.com/baseline.zip",
            "file_size_bytes": len(zip_bytes),
            "classification": "baseline",
        }

        metadata = downloader.download_baseline_zip(asset_info)
        downloaded_file = Path(metadata["target_path"])

        self.assertTrue(downloaded_file.exists())
        self.assertTrue(zipfile.is_zipfile(downloaded_file))
        self.assertEqual(metadata["file_size_bytes"], len(zip_bytes))
        self.assertEqual(metadata["classification"], "baseline")

    # C. SHA-256 Calculation
    def test_c_sha256_calculation(self):
        """Verify calculate_sha256 accurately hashes files."""
        zip_bytes = _create_dummy_zip_bytes()
        test_file = self.temp_dir / "test.zip"
        test_file.write_bytes(zip_bytes)

        import hashlib
        expected_sha = hashlib.sha256(zip_bytes).hexdigest()
        actual_sha = calculate_sha256(test_file)

        self.assertEqual(actual_sha, expected_sha)

    # D. Metadata Generation
    @patch("urllib.request.urlopen")
    def test_d_metadata_generation(self, mock_urlopen):
        """Verify metadata.json records all required provenance fields."""
        zip_bytes = _create_dummy_zip_bytes()
        mock_resp = MagicMock()
        mock_resp.read.side_effect = [zip_bytes, b""]
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        downloader = CVEListV5Downloader(self.temp_dir)
        asset_info = {
            "release_tag": "cve_2026-09-28_test",
            "asset_name": "2026-09-28_all_CVEs_at_midnight.zip",
            "download_url": "https://example.com/baseline.zip",
            "classification": "baseline",
        }
        meta = downloader.download_baseline_zip(asset_info)

        meta_file = self.temp_dir / "cve_list_v5" / "metadata.json"
        self.assertTrue(meta_file.exists())

        with open(meta_file, "r", encoding="utf-8") as f:
            saved_meta = json.load(f)

        self.assertEqual(saved_meta["source"], "CVE List V5")
        self.assertEqual(saved_meta["repository"], "CVEProject/cvelistV5")
        self.assertEqual(saved_meta["classification"], "baseline")
        self.assertEqual(saved_meta["release_tag"], "cve_2026-09-28_test")
        self.assertEqual(saved_meta["asset_filename"], "2026-09-28_all_CVEs_at_midnight.zip")
        self.assertEqual(saved_meta["sha256"], meta["sha256"])

    # E. Manifest packaging separates NVD and CVE List V5
    def test_e_manifest_packaging_distinguishes_sources(self):
        """Verify package manifest distinctly organizes NVD vs CVE List V5 artifacts."""
        # Create an NVD chunk
        nvd_file = self.temp_dir / "nvd_cve_chunk_0000000.json"
        nvd_file.write_text('{"vulnerabilities": []}', encoding="utf-8")

        # Create CVE List V5 zip and metadata
        cve_v5_dir = self.temp_dir / "cve_list_v5"
        cve_v5_dir.mkdir(parents=True, exist_ok=True)
        zip_file = cve_v5_dir / "2026-09-28_all_CVEs_at_midnight.zip"
        zip_file.write_bytes(_create_dummy_zip_bytes())

        meta_file = cve_v5_dir / "metadata.json"
        meta_file.write_text('{"source": "CVE List V5", "classification": "baseline"}', encoding="utf-8")

        package_offline_update(self.temp_dir, self.temp_dir)

        manifest_path = self.temp_dir / "manifest.json"
        self.assertTrue(manifest_path.exists())

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        # Check flat files mapping
        self.assertIn("nvd_cve_chunk_0000000.json", manifest["files"])
        self.assertIn("cve_list_v5/2026-09-28_all_CVEs_at_midnight.zip", manifest["files"])
        self.assertIn("cve_list_v5/metadata.json", manifest["files"])

        # Check distinct artifacts structure
        self.assertIn("artifacts", manifest)
        self.assertIn("nvd", manifest["artifacts"])
        self.assertIn("cve_list_v5", manifest["artifacts"])

        nvd_names = [a["filename"] for a in manifest["artifacts"]["nvd"]]
        cve_list_names = [a["filename"] for a in manifest["artifacts"]["cve_list_v5"]]

        self.assertIn("nvd_cve_chunk_0000000.json", nvd_names)
        self.assertIn("2026-09-28_all_CVEs_at_midnight.zip", cve_list_names)
        self.assertNotIn("nvd_cve_chunk_0000000.json", cve_list_names)

    # F. Existing NVD Downloader functionality
    @patch("urllib.request.urlopen")
    def test_f_nvd_downloader_remains_functional(self, mock_urlopen):
        """Verify NVDDownloader continues to fetch and serialize NVD pages."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "totalResults": 1,
            "vulnerabilities": [{"cve": {"id": "CVE-2025-9999", "vulnStatus": "Analyzed"}}]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        dl = NVDDownloader(self.temp_dir, page_size=1)
        page = dl.fetch_page(0)
        self.assertEqual(page["totalResults"], 1)
        self.assertEqual(page["vulnerabilities"][0]["cve"]["id"], "CVE-2025-9999")

    # G. Zero Network Access by Importer
    @patch("urllib.request.urlopen")
    def test_g_zero_network_access_by_importer(self, mock_urlopen):
        """Verify offline importer never makes any network calls during manifest verification or import."""
        mock_urlopen.side_effect = AssertionError("Network access attempted by offline importer!")

        fixture_dir = current_dir / "tests" / "fixtures"
        db_path = self.temp_dir / "offline_test.db"

        importer = CVEImporter(db_path)
        valid, _ = importer.verify_manifest(fixture_dir)
        self.assertTrue(valid)

        result = importer.import_package(fixture_dir)
        self.assertEqual(result["status"], "SUCCESS")
        self.assertEqual(mock_urlopen.call_count, 0)

    # H. Invalid / Non-ZIP CVE List V5 Rejected
    @patch("urllib.request.urlopen")
    def test_h_invalid_non_zip_rejected(self, mock_urlopen):
        """Verify corrupted or non-ZIP download is rejected and not accepted as valid."""
        corrupted_bytes = b"<html>404 Not Found or corrupted HTML</html>"
        mock_resp = MagicMock()
        mock_resp.read.side_effect = [corrupted_bytes, b""]
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        downloader = CVEListV5Downloader(self.temp_dir, max_retries=1)
        asset_info = {
            "release_tag": "test_tag",
            "asset_name": "corrupt.zip",
            "download_url": "https://example.com/corrupt.zip",
        }

        with self.assertRaises(ValueError) as ctx:
            downloader.download_baseline_zip(asset_info)

        self.assertIn("not a valid ZIP archive", str(ctx.exception))
        # Corrupted target file must be cleaned up
        self.assertFalse((self.temp_dir / "cve_list_v5" / "corrupt.zip").exists())

    # I. HTTP Failure Handled Cleanly
    @patch("urllib.request.urlopen")
    def test_i_http_failure_handled_cleanly(self, mock_urlopen):
        """Verify HTTP errors trigger retries and raise clean error upon exhaustion."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.github.com/...",
            code=503,
            msg="Service Unavailable",
            hdrs={},
            fp=None,
        )

        downloader = CVEListV5Downloader(self.temp_dir, max_retries=2, base_backoff=1.0)
        with self.assertRaises(RuntimeError) as ctx:
            downloader.resolve_latest_baseline()

        self.assertIn("Failed to resolve", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
