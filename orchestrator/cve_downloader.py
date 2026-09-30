"""Online CVE Acquisition and Packaging Tool.

Responsible for:
1. Fetching NVD 2.0 CVE records via NVD API 2.0 with pagination, retries, exponential backoff,
   and checkpointing for resumable downloads.
2. Resolving and acquiring official daily baseline ZIP releases from CVEProject/cvelistV5
   with verified TLS, streaming download, archive verification, and metadata generation.
3. Generating cryptographic SHA-256 manifest.json distinguishing NVD and CVE List V5 artifacts
   to prepare offline update packages for air-gapped data diode transfer.

SECURITY & ARCHITECTURAL BOUNDARY:
- Downloader must operate only on Internet-connected environments.
- Importer and runtime/offline lookup modules must NEVER import or invoke this file.
- NVD API credentials are read ONLY from the NVD_API_KEY environment variable.
- TLS certificate verification is ALWAYS strictly enforced using certifi.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import certifi

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cve_downloader")

NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API_RELEASES_LATEST = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
GITHUB_API_RELEASES = "https://api.github.com/repos/CVEProject/cvelistV5/releases"
DEFAULT_PAGE_SIZE = 2000
SCHEMA_VERSION = 1


def calculate_sha256(filepath: Path) -> str:
    """Compute SHA-256 checksum of a file in 64KB chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class NVDDownloader:
    """Downloader for NVD REST API 2.0 with rate-limiting, retries, and checkpointing."""

    def __init__(
        self,
        output_dir: Path,
        api_key: Optional[str] = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_retries: int = 5,
        base_backoff: float = 2.0,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # NVD API credentials must be read only from environment variable or explicit parameter
        self.api_key = api_key or os.environ.get("NVD_API_KEY", "").strip() or None
        self.page_size = page_size
        self.max_retries = max_retries
        self.base_backoff = base_backoff
        self.checkpoint_file = self.output_dir / ".nvd_checkpoint.json"

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": "AirGap-Security-CVE-Downloader/1.0",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _get_rate_limit_sleep(self) -> float:
        # NVD guidelines: 50 requests per 30 seconds with key (~0.6s),
        # 5 requests per 30 seconds without key (~6.0s)
        return 0.65 if self.api_key else 6.2

    def load_checkpoint(self) -> Dict[str, Any]:
        """Load download checkpoint if exists."""
        if self.checkpoint_file.exists():
            try:
                with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Could not read checkpoint file: {e}")
        return {"start_index": 0, "completed": False, "files": [], "total_results": None}

    def save_checkpoint(self, checkpoint_data: Dict[str, Any]) -> None:
        """Persist checkpoint data."""
        with open(self.checkpoint_file, "w", encoding="utf-8") as f:
            json.dump(checkpoint_data, f, indent=2)

    def fetch_page(self, start_index: int) -> Dict[str, Any]:
        """Fetch a single page from NVD API 2.0 with retry and exponential backoff."""
        url = f"{NVD_API_BASE_URL}?startIndex={start_index}&resultsPerPage={self.page_size}"
        req = urllib.request.Request(url, headers=self._get_headers())
        ssl_context = ssl.create_default_context(cafile=certifi.where())

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(f"Requesting NVD records startIndex={start_index} (attempt {attempt}/{self.max_retries})...")
                with urllib.request.urlopen(req, timeout=60, context=ssl_context) as resp:
                    if resp.status == 200:
                        raw = resp.read().decode("utf-8")
                        return json.loads(raw)
                    else:
                        logger.warning(f"NVD API returned HTTP status {resp.status}")
            except urllib.error.HTTPError as e:
                logger.warning(f"HTTPError {e.code}: {e.reason} on startIndex={start_index}")
                if e.code in (429, 503, 504):
                    # Rate limit or server busy
                    sleep_time = (self.base_backoff ** attempt) + random.uniform(0.5, 2.0)
                    logger.info(f"Backing off for {sleep_time:.2f}s due to HTTP {e.code}...")
                    time.sleep(sleep_time)
                else:
                    if attempt == self.max_retries:
                        raise
                    sleep_time = (self.base_backoff ** attempt)
                    time.sleep(sleep_time)
            except (urllib.error.URLError, TimeoutError) as e:
                logger.warning(f"Network error on startIndex={start_index}: {e}")
                if attempt == self.max_retries:
                    raise
                sleep_time = (self.base_backoff ** attempt) + random.uniform(1.0, 3.0)
                logger.info(f"Backing off for {sleep_time:.2f}s...")
                time.sleep(sleep_time)

        raise RuntimeError(f"Failed to fetch page at startIndex={start_index} after {self.max_retries} retries")

    def download_all(self, max_records: Optional[int] = None) -> List[Path]:
        """Download all NVD 2.0 CVE records in chunks, saving to JSON files."""
        checkpoint = self.load_checkpoint()
        if checkpoint.get("completed"):
            logger.info("Checkpoint indicates NVD download is already complete.")
            return [Path(p) for p in checkpoint.get("files", [])]

        start_index = checkpoint.get("start_index", 0)
        downloaded_files = [Path(p) for p in checkpoint.get("files", [])]
        total_results = checkpoint.get("total_results")

        while True:
            if max_records and start_index >= max_records:
                logger.info(f"Reached specified max records limit ({max_records}). Stopping.")
                break

            try:
                page_data = self.fetch_page(start_index)
            except Exception as e:
                logger.error(f"Fatal error fetching startIndex={start_index}: {e}")
                self.save_checkpoint({
                    "start_index": start_index,
                    "completed": False,
                    "files": [str(p) for p in downloaded_files],
                    "total_results": total_results,
                })
                raise

            total_results = page_data.get("totalResults", 0)
            vulnerabilities = page_data.get("vulnerabilities", [])
            num_in_page = len(vulnerabilities)

            if num_in_page == 0:
                logger.info("No more records returned. NVD download complete.")
                break

            out_file = self.output_dir / f"nvd_cve_chunk_{start_index:07d}.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(page_data, f, indent=2)

            downloaded_files.append(out_file)
            start_index += num_in_page

            checkpoint_data = {
                "start_index": start_index,
                "completed": (start_index >= total_results),
                "files": [str(p) for p in downloaded_files],
                "total_results": total_results,
            }
            self.save_checkpoint(checkpoint_data)
            logger.info(f"Saved {num_in_page} records to {out_file.name}. Progress: {start_index}/{total_results}")

            if start_index >= total_results:
                checkpoint_data["completed"] = True
                self.save_checkpoint(checkpoint_data)
                break

            time.sleep(self._get_rate_limit_sleep())

        return downloaded_files


class CVEListV5Downloader:
    """Acquires official daily baseline CVE List V5 ZIP releases from CVEProject/cvelistV5.

    Resolves the official complete daily baseline ZIP (matching '*all_CVEs_at_midnight*.zip*'),
    streams the archive directly to disk to preserve memory (< 50MB peak RAM),
    verifies archive integrity using zipfile, calculates SHA-256, and generates asset metadata.
    """

    def __init__(
        self,
        output_dir: Path,
        github_token: Optional[str] = None,
        max_retries: int = 5,
        base_backoff: float = 2.0,
    ):
        self.output_dir = Path(output_dir) / "cve_list_v5"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN", "").strip() or None
        self.max_retries = max_retries
        self.base_backoff = base_backoff
        # TLS certificate verification is always strictly enforced
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": "AirGap-Security-CVE-Downloader/1.0",
            "Accept": "application/vnd.github+json",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    def resolve_latest_baseline(self) -> Dict[str, Any]:
        """
        Query GitHub Releases API to identify the official complete daily baseline ZIP asset.
        Selects assets matching '*all_CVEs_at_midnight*.zip*' (not hourly deltas or main.zip).
        """
        logger.info("Resolving CVE List V5 baseline...")
        endpoints = [GITHUB_API_RELEASES_LATEST, f"{GITHUB_API_RELEASES}?per_page=5"]

        for endpoint in endpoints:
            req = urllib.request.Request(endpoint, headers=self._get_headers())
            data = None
            for attempt in range(1, self.max_retries + 1):
                try:
                    with urllib.request.urlopen(req, timeout=30, context=self.ssl_context) as resp:
                        if resp.status == 200:
                            data = json.loads(resp.read().decode("utf-8"))
                            break
                except urllib.error.HTTPError as e:
                    logger.warning(f"HTTPError {e.code}: {e.reason} querying {endpoint} (attempt {attempt}/{self.max_retries})")
                    if attempt == self.max_retries:
                        break
                    time.sleep((self.base_backoff ** attempt) + random.uniform(0.5, 1.5))
                except (urllib.error.URLError, TimeoutError) as e:
                    logger.warning(f"Network error querying {endpoint}: {e} (attempt {attempt}/{self.max_retries})")
                    if attempt == self.max_retries:
                        break
                    time.sleep((self.base_backoff ** attempt) + random.uniform(0.5, 1.5))

            if not data:
                continue

            releases = [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
            for rel in releases:
                tag = rel.get("tag_name")
                assets = rel.get("assets", [])
                for asset in assets:
                    name = asset.get("name", "")
                    if "all_cves_at_midnight" in name.lower() and (name.lower().endswith(".zip") or ".zip" in name.lower()):
                        download_url = asset.get("browser_download_url")
                        size = asset.get("size")
                        logger.info(f"Resolved release: {tag} ({name})")
                        return {
                            "release_tag": tag,
                            "asset_name": name,
                            "download_url": download_url,
                            "file_size_bytes": size,
                            "published_at": rel.get("published_at"),
                            "classification": "baseline",
                        }

        raise RuntimeError("Failed to resolve official CVE List V5 baseline ZIP from GitHub releases.")

    def download_baseline_zip(
        self,
        asset_info: Optional[Dict[str, Any]] = None,
        chunk_size: int = 65536,
    ) -> Dict[str, Any]:
        """
        Stream the baseline ZIP directly into file to preserve low memory footprint (< 50MB RAM).
        Verifies archive integrity, calculates SHA-256, writes metadata, and returns artifact details.
        """
        if not asset_info:
            asset_info = self.resolve_latest_baseline()

        asset_name = asset_info["asset_name"]
        download_url = asset_info["download_url"]
        tag = asset_info.get("release_tag", "unknown")

        target_file = self.output_dir / asset_name
        part_file = self.output_dir / f"{asset_name}.part"

        logger.info(f"Downloading CVE List V5 baseline from {download_url}...")
        req = urllib.request.Request(download_url, headers=self._get_headers())

        downloaded_bytes = 0
        last_logged_mb = 0

        for attempt in range(1, self.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=180, context=self.ssl_context) as resp, open(part_file, "wb") as out_f:
                    while True:
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        out_f.write(chunk)
                        downloaded_bytes += len(chunk)

                        mb = downloaded_bytes / (1024 * 1024)
                        if mb - last_logged_mb >= 50:
                            logger.info(f"Downloaded {mb:.1f} MB...")
                            last_logged_mb = mb
                break
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
                logger.warning(f"Download attempt {attempt}/{self.max_retries} failed: {e}")
                if attempt == self.max_retries:
                    if part_file.exists():
                        part_file.unlink()
                    raise
                time.sleep((self.base_backoff ** attempt) + random.uniform(1.0, 3.0))

        # Atomic rename to final target file
        if target_file.exists():
            target_file.unlink()
        part_file.rename(target_file)

        # Requirement 6: Verify archive is a valid ZIP
        if not zipfile.is_zipfile(target_file):
            target_file.unlink(missing_ok=True)
            raise ValueError(f"Downloaded asset {asset_name} is not a valid ZIP archive.")

        # Requirement 7: Calculate SHA-256
        sha256_hash = calculate_sha256(target_file)
        actual_size = target_file.stat().st_size
        logger.info(f"Downloaded {actual_size / (1024 * 1024):.1f} MB. SHA-256: {sha256_hash}")

        # Requirement 8: Record metadata
        metadata = {
            "source": "CVE List V5",
            "repository": "CVEProject/cvelistV5",
            "acquisition_method": "github_release_baseline_zip",
            "release_tag": tag,
            "asset_filename": asset_name,
            "source_url": download_url,
            "downloaded_at": datetime.now(timezone.utc).isoformat(),
            "sha256": sha256_hash,
            "file_size_bytes": actual_size,
            "classification": "baseline",
            "target_path": str(target_file),
        }

        meta_path = self.output_dir / "metadata.json"
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        logger.info("CVE List V5 acquisition complete.")
        return metadata


def package_offline_update(
    source_dir: Path,
    output_package_dir: Path,
    metadata_extra: Optional[Dict[str, Any]] = None,
) -> Path:
    """
    Prepare an offline update package for air-gap data diode transfer.
    Generates a cryptographic SHA-256 manifest.json containing hashes of all files,
    explicitly distinguishing NVD artifacts from CVE List V5 artifacts.
    """
    source_dir = Path(source_dir)
    output_package_dir = Path(output_package_dir)
    output_package_dir.mkdir(parents=True, exist_ok=True)

    manifest_entries: Dict[str, str] = {}
    nvd_artifacts: List[Dict[str, Any]] = []
    cve_list_artifacts: List[Dict[str, Any]] = []

    for file_path in sorted(source_dir.rglob("*")):
        if not file_path.is_file():
            continue
        if file_path.name in ("manifest.json", ".nvd_checkpoint.json") or file_path.suffix == ".part":
            continue

        rel_path = file_path.relative_to(source_dir).as_posix()
        dest_file = output_package_dir / file_path.relative_to(source_dir)
        dest_file.parent.mkdir(parents=True, exist_ok=True)

        if dest_file.resolve() != file_path.resolve():
            shutil.copy2(file_path, dest_file)

        sha = calculate_sha256(dest_file)
        manifest_entries[rel_path] = sha

        artifact_entry = {
            "path": rel_path,
            "filename": file_path.name,
            "sha256": sha,
            "size_bytes": dest_file.stat().st_size
        }

        if "cve_list_v5" in rel_path.split("/"):
            artifact_entry["source"] = "CVE List V5"
            artifact_entry["classification"] = "baseline" if dest_file.suffix == ".zip" or ".zip" in dest_file.name else "metadata"
            cve_list_artifacts.append(artifact_entry)
        else:
            artifact_entry["source"] = "NVD"
            nvd_artifacts.append(artifact_entry)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_files": len(manifest_entries),
        "files": manifest_entries,
        "artifacts": {
            "nvd": nvd_artifacts,
            "cve_list_v5": cve_list_artifacts,
        },
        "metadata": metadata_extra or {},
    }

    manifest_path = output_package_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    logger.info(f"Created manifest at {manifest_path} with {len(manifest_entries)} verified entries.")
    return output_package_dir


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Acquire NVD/CVE records and package for air-gapped transfer")
    parser.add_argument("--output-dir", required=True, help="Directory to store downloaded data and manifest")
    parser.add_argument("--max-records", type=int, default=None, help="Max NVD records to download (for testing)")
    parser.add_argument("--package-only", action="store_true", help="Only generate manifest for existing files")
    parser.add_argument("--skip-cve-list", action="store_true", help="Skip downloading CVE List V5 baseline")
    parser.add_argument("--skip-nvd", action="store_true", help="Skip downloading NVD records")
    parser.add_argument("--cve-list-only", action="store_true", help="Download only CVE List V5 baseline")
    parser.add_argument("--include-cve-list", action="store_true", help="Explicitly include full CVE List V5 baseline download when --max-records is set")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.package_only:
        package_offline_update(out_dir, out_dir)
    else:
        run_nvd = not args.cve_list_only and not args.skip_nvd
        # In test mode (--max-records set), skip the 600MB CVE list unless explicitly requested
        run_cve_list = (
            args.cve_list_only or
            (not args.skip_cve_list and (args.max_records is None or args.include_cve_list))
        )

        if run_nvd:
            dl_nvd = NVDDownloader(out_dir)
            dl_nvd.download_all(max_records=args.max_records)

        if run_cve_list:
            dl_cve_list = CVEListV5Downloader(out_dir)
            dl_cve_list.download_baseline_zip()

        package_offline_update(out_dir, out_dir)
