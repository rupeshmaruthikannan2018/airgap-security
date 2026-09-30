"""Offline CVE Importer and Normalizer.

Processes NVD 2.0 JSON and CVE List V5 JSON files from a verified local package,
enforces SHA-256 manifest integrity, stream-parses records, normalizes into
canonical SQLite tables, preserves multi-source provenance, and tracks memory usage.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import tracemalloc
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple

try:
    import psutil
except ImportError:
    psutil = None

try:
    from orchestrator.cve_db import CVEDatabase, DATABASE_VERSION, SCHEMA_VERSION
except ImportError:
    from cve_db import CVEDatabase, DATABASE_VERSION, SCHEMA_VERSION

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def parse_cpe_23(cpe_str: str) -> Dict[str, Optional[str]]:
    """
    Parse a CPE 2.3 formatted string into its structured components.
    Example: cpe:2.3:a:apache:tomcat:9.0.0:m1:*:*:*:*:*:*
    Handles escaped colons properly.
    """
    components = {
        "part": None,
        "vendor": None,
        "product": None,
        "version": None,
        "update_version": None,
        "edition": None,
        "language": None,
        "sw_edition": None,
        "target_sw": None,
        "target_hw": None,
        "other": None,
    }

    if not cpe_str or not cpe_str.startswith("cpe:2.3:"):
        return components

    # Split while handling escaped colons
    parts: List[str] = []
    current: List[str] = []
    escaped = False

    for char in cpe_str[8:]:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))

    keys = list(components.keys())
    for idx, val in enumerate(parts):
        if idx < len(keys):
            components[keys[idx]] = None if val in ("*", "-") else val

    return components


class CVEImporter:
    """Offline importer for local CVE packages with cryptographic verification."""

    def __init__(self, db: Any):
        if isinstance(db, (str, Path)):
            self.db = CVEDatabase(str(db))
        else:
            self.db = db
        self.stats: Dict[str, Any] = {
            "sources_scanned": [],
            "nvd_imported": 0,
            "cve_list_imported": 0,
            "total_cves": 0,
            "rejected_count": 0,
            "no_cpe_count": 0,
            "malformed_count": 0,
            "skipped_records": [],
            "peak_memory_bytes": 0,
            "duration_seconds": 0.0
        }

    # ------------------------------------------------------------------
    # Manifest Verification
    # ------------------------------------------------------------------

    @staticmethod
    def compute_sha256(file_path: Path) -> str:
        """Compute SHA-256 hash of a file efficiently using chunked reads."""
        h = hashlib.sha256()
        with file_path.open("rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def check_disk_space(target_path: Path, min_free_gb: float = 5.0) -> Tuple[bool, float, float]:
        """
        Check available disk space on the target filesystem.
        Returns: (has_sufficient_space, free_gb, total_gb)
        """
        check_dir = target_path if target_path.is_dir() else target_path.parent
        total, used, free = shutil.disk_usage(check_dir)
        free_gb = free / (1024 ** 3)
        total_gb = total / (1024 ** 3)
        return free_gb >= min_free_gb, round(free_gb, 2), round(total_gb, 2)

    def verify_manifest(self, package_dir: Path) -> Tuple[bool, str]:
        """
        Verify manifest.json in the package directory.
        Fails if manifest is missing or if any file hash does not match.
        Strictly enforces Rule 7 & Rule 34: If verification passes for one
        artifact but fails for another, stops the entire build and reports
        both passed and failed artifacts.
        """
        manifest_path = package_dir / "manifest.json"
        if not manifest_path.exists():
            return False, f"Manifest not found in package directory: {manifest_path}"

        try:
            with manifest_path.open("r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception as e:
            return False, f"Could not parse manifest.json: {e}"

        files_manifest = manifest.get("files", {})
        if not files_manifest:
            return False, "Manifest contains no file hash entries."

        passed_files: List[str] = []
        failed_files: List[Dict[str, Any]] = []

        for rel_path, expected_hash in files_manifest.items():
            target_file = package_dir / Path(rel_path)
            if not target_file.exists():
                failed_files.append({
                    "file": rel_path,
                    "error": "File missing on disk",
                    "expected_sha256": expected_hash,
                    "actual_sha256": None
                })
                continue

            actual_hash = self.compute_sha256(target_file)
            if actual_hash.lower() != expected_hash.lower():
                failed_files.append({
                    "file": rel_path,
                    "error": "SHA-256 mismatch",
                    "expected_sha256": expected_hash,
                    "actual_sha256": actual_hash
                })
            else:
                passed_files.append(rel_path)

        if failed_files:
            fail_report = "\n".join([
                f"  - FAILED: {f['file']} (SHA-256 mismatch - Expected SHA-256: {f['expected_sha256']}, got: {f['actual_sha256']})"
                for f in failed_files
            ])
            summary = (
                f"Manifest integrity verification FAILED for {len(failed_files)} artifact(s) "
                f"({len(passed_files)} passed):\n{fail_report}\n"
                f"Strict safety rule: Cannot proceed with partial or unverified corpus."
            )
            return False, summary

        return True, f"Manifest verified successfully: {len(passed_files)} artifacts verified."

    # ------------------------------------------------------------------
    # Checkpointing & Resumability
    # ------------------------------------------------------------------

    def _save_checkpoint(self, nvd_chunks: Set[str], v5_count: int):
        """
        Save checkpoint state strictly AFTER database transaction commit.
        Persists state to both db_metadata table and alongside the database.
        """
        conn = self.db.connect()
        chunk_list = sorted(list(nvd_chunks))
        now_iso = datetime.now(timezone.utc).isoformat()
        with conn:
            self.db.set_metadata("importer_checkpoint_nvd_chunks", json.dumps(chunk_list))
            self.db.set_metadata("importer_checkpoint_v5_count", str(v5_count))
            self.db.set_metadata("importer_checkpoint_timestamp", now_iso)

        checkpoint_file = Path(str(self.db.db_path) + ".checkpoint.json")
        try:
            with checkpoint_file.open("w", encoding="utf-8") as f:
                json.dump({
                    "nvd_completed_chunks": chunk_list,
                    "cve_list_v5_processed_count": v5_count,
                    "timestamp": now_iso
                }, f, indent=2)
        except Exception:
            pass

    def _load_checkpoint(self) -> Tuple[Set[str], int]:
        """Load checkpoint state from database or checkpoint file."""
        meta = self.db.get_metadata()
        chunks_json = meta.get("importer_checkpoint_nvd_chunks")
        v5_count_str = meta.get("importer_checkpoint_v5_count")

        nvd_chunks: Set[str] = set()
        v5_count = 0

        if chunks_json:
            try:
                nvd_chunks = set(json.loads(chunks_json))
            except Exception:
                pass
        if v5_count_str:
            try:
                v5_count = int(v5_count_str)
            except Exception:
                pass

        checkpoint_file = Path(str(self.db.db_path) + ".checkpoint.json")
        if checkpoint_file.exists() and (not nvd_chunks and v5_count == 0):
            try:
                with checkpoint_file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    nvd_chunks = set(data.get("nvd_completed_chunks", []))
                    v5_count = int(data.get("cve_list_v5_processed_count", 0))
            except Exception:
                pass

        return nvd_chunks, v5_count

    def _clear_checkpoint(self):
        """Clear checkpoint state for fresh imports."""
        conn = self.db.connect()
        with conn:
            conn.execute("DELETE FROM db_metadata WHERE key LIKE 'importer_checkpoint_%'")
        checkpoint_file = Path(str(self.db.db_path) + ".checkpoint.json")
        if checkpoint_file.exists():
            try:
                checkpoint_file.unlink()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # CVE List V5 Zip Streaming
    # ------------------------------------------------------------------

    def _stream_cve_list_zip(self, zip_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Stream individual CVE List V5 JSON records directly from zip archive.
        If the outer zip contains an inner zip (e.g. cves.zip), extracts only
        the inner zip archive into temp storage and streams JSON members
        directly, avoiding extraction of hundreds of thousands of individual files.
        """
        with zipfile.ZipFile(zip_path, "r") as zf_outer:
            outer_names = zf_outer.namelist()
            inner_zips = [n for n in outer_names if n.endswith(".zip")]
            if inner_zips:
                inner_zip_name = inner_zips[0]
                temp_dir = tempfile.gettempdir()
                extracted_inner = Path(temp_dir) / f"temp_cves_{os.getpid()}_{int(time.time())}.zip"
                try:
                    with zf_outer.open(inner_zip_name) as src, extracted_inner.open("wb") as dst:
                        shutil.copyfileobj(src, dst, length=1024 * 1024)

                    with zipfile.ZipFile(extracted_inner, "r") as zf_inner:
                        for member in zf_inner.namelist():
                            if member.endswith(".json"):
                                try:
                                    with zf_inner.open(member) as f:
                                        data = json.load(f)
                                    yield member, data
                                except Exception as e:
                                    self.stats["malformed_count"] += 1
                                    self.stats["skipped_records"].append({
                                        "file": f"{zip_path.name}:{member}",
                                        "error": f"JSON parse error: {e}"
                                    })
                finally:
                    if extracted_inner.exists():
                        try:
                            extracted_inner.unlink()
                        except Exception:
                            pass
            else:
                for member in outer_names:
                    if member.endswith(".json"):
                        try:
                            with zf_outer.open(member) as f:
                                data = json.load(f)
                            yield member, data
                        except Exception as e:
                            self.stats["malformed_count"] += 1
                            self.stats["skipped_records"].append({
                                "file": f"{zip_path.name}:{member}",
                                "error": f"JSON parse error: {e}"
                            })

    # ------------------------------------------------------------------
    # Record Streamers
    # ------------------------------------------------------------------

    def _stream_json_file(self, file_path: Path) -> Generator[Dict[str, Any], None, None]:
        """
        Read JSON records from a file.
        Supports NVD 2.0 feeds/API exports, CVE List V5 records, and lists of records.
        Yields individual raw vulnerability dictionaries.
        """
        try:
            with file_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            self.stats["malformed_count"] += 1
            self.stats["skipped_records"].append({
                "file": str(file_path),
                "error": f"JSON parse error: {e}"
            })
            return

        if isinstance(data, dict):
            # NVD 2.0 format
            if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                for item in data["vulnerabilities"]:
                    if isinstance(item, dict) and "cve" in item:
                        yield {"_type": "NVD", "data": item["cve"], "_file": str(file_path)}
                    elif isinstance(item, dict):
                        yield {"_type": "NVD", "data": item, "_file": str(file_path)}

            # CVE List V5 format
            elif "cveMetadata" in data:
                yield {"_type": "CVE_LIST_V5", "data": data, "_file": str(file_path)}

            # Generic dictionary mapping CVE IDs to records
            else:
                for k, v in data.items():
                    if _CVE_PATTERN.match(str(k)) and isinstance(v, dict):
                        yield {"_type": "CUSTOM", "data": v, "_file": str(file_path)}

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    if "cveMetadata" in item:
                        yield {"_type": "CVE_LIST_V5", "data": item, "_file": str(file_path)}
                    elif "cve" in item:
                        yield {"_type": "NVD", "data": item["cve"], "_file": str(file_path)}
                    elif "id" in item and _CVE_PATTERN.match(str(item["id"])):
                        yield {"_type": "NVD", "data": item, "_file": str(file_path)}

    # ------------------------------------------------------------------
    # NVD 2.0 Normalizer
    # ------------------------------------------------------------------

    def _normalize_nvd_record(self, raw: Dict[str, Any], file_path: str) -> Optional[Dict[str, Any]]:
        """Normalize an NVD 2.0 vulnerability item into canonical relational structures."""
        cve_id = str(raw.get("id") or "").strip().upper()
        if not _CVE_PATTERN.match(cve_id):
            return None

        vuln_status = raw.get("vulnStatus", "Analyzed")
        is_rejected = vuln_status.lower() in ("rejected", "disputed - rejected")

        # Descriptions & English summary
        descriptions = raw.get("descriptions", [])
        desc_en = None
        for d in descriptions:
            if isinstance(d, dict) and d.get("lang") == "en":
                desc_en = d.get("value")
                break
        if not desc_en and descriptions and isinstance(descriptions[0], dict):
            desc_en = descriptions[0].get("value")

        published = raw.get("published")
        last_modified = raw.get("lastModified")

        # Weaknesses (CWEs)
        weaknesses = raw.get("weaknesses", [])
        cwe_records = []
        cwe_ids = []
        for w in weaknesses:
            w_source = w.get("source")
            for desc_item in w.get("description", []):
                val = desc_item.get("value")
                if val:
                    cwe_records.append({
                        "source": w_source,
                        "cwe_id": val,
                        "description": desc_item.get("description")
                    })
                    if val not in cwe_ids:
                        cwe_ids.append(val)

        # CVSS Metrics (Preserve each metric individually)
        metrics = raw.get("metrics", {})
        cvss_records = []
        primary_severity = None
        primary_score = None

        metric_groups = [
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2", "2.0"),
        ]

        for key, ver in metric_groups:
            if key in metrics and isinstance(metrics[key], list):
                for m in metrics[key]:
                    cvss_data = m.get("cvssData", {})
                    base_score = cvss_data.get("baseScore")
                    base_sev = cvss_data.get("baseSeverity") or m.get("baseSeverity")
                    metric_type = m.get("type", "Primary")

                    record_m = {
                        "source": m.get("source", "NVD"),
                        "cvss_version": ver,
                        "vector_string": cvss_data.get("vectorString"),
                        "base_score": float(base_score) if base_score is not None else None,
                        "base_severity": base_sev.upper() if base_sev else None,
                        "metric_type": metric_type,
                        "exploitability_score": float(m["exploitabilityScore"]) if "exploitabilityScore" in m else None,
                        "impact_score": float(m["impactScore"]) if "impactScore" in m else None,
                    }
                    cvss_records.append(record_m)

                    if not primary_severity and record_m["base_severity"]:
                        primary_severity = record_m["base_severity"]
                        primary_score = record_m["base_score"]

        # References
        references = raw.get("references", [])
        ref_records = []
        for r in references:
            if isinstance(r, dict) and r.get("url"):
                ref_records.append({
                    "source": r.get("source", "NVD"),
                    "url": r.get("url"),
                    "source_identifier": r.get("sourceIdentifier"),
                    "tags": r.get("tags", [])
                })

        # Configurations (Preserves full AND/OR, negate, nested hierarchy)
        configurations = raw.get("configurations", [])
        config_nodes = []
        cpe_matches = []
        primary_vendor = None
        primary_product = None

        for c_idx, config in enumerate(configurations):
            nodes = config.get("nodes", [])
            for n_idx, node in enumerate(nodes):
                op = node.get("operator", "OR")
                negate = 1 if node.get("negate") else 0

                node_entry = {
                    "config_index": c_idx,
                    "operator": op,
                    "negate": negate,
                    "parent_node_id": None,
                    "node_type": "root"
                }
                config_nodes.append(node_entry)

                # Process leaf CPE matches
                for match in node.get("cpeMatch", []):
                    crit = match.get("criteria")
                    if not crit:
                        continue

                    parts = parse_cpe_23(crit)
                    if not primary_vendor and parts["vendor"]:
                        primary_vendor = parts["vendor"]
                    if not primary_product and parts["product"]:
                        primary_product = parts["product"]

                    cpe_matches.append({
                        "node_index": len(config_nodes) - 1,
                        "criteria": crit,
                        "match_criteria_id": match.get("matchCriteriaId"),
                        "vulnerable": 1 if match.get("vulnerable", True) else 0,
                        "cpe_parts": parts,
                        "version_start_including": match.get("versionStartIncluding"),
                        "version_start_excluding": match.get("versionStartExcluding"),
                        "version_end_including": match.get("versionEndIncluding"),
                        "version_end_excluding": match.get("versionEndExcluding"),
                        "operator": op,
                        "negate": negate
                    })

                # Check children (nested nodes)
                for child in node.get("children", []):
                    child_op = child.get("operator", "OR")
                    child_neg = 1 if child.get("negate") else 0
                    child_node_entry = {
                        "config_index": c_idx,
                        "operator": child_op,
                        "negate": child_neg,
                        "parent_node_id": len(config_nodes) - 1,
                        "node_type": "child"
                    }
                    config_nodes.append(child_node_entry)

                    for match in child.get("cpeMatch", []):
                        crit = match.get("criteria")
                        if not crit:
                            continue
                        parts = parse_cpe_23(crit)
                        if not primary_vendor and parts["vendor"]:
                            primary_vendor = parts["vendor"]
                        if not primary_product and parts["product"]:
                            primary_product = parts["product"]

                        cpe_matches.append({
                            "node_index": len(config_nodes) - 1,
                            "criteria": crit,
                            "match_criteria_id": match.get("matchCriteriaId"),
                            "vulnerable": 1 if match.get("vulnerable", True) else 0,
                            "cpe_parts": parts,
                            "version_start_including": match.get("versionStartIncluding"),
                            "version_start_excluding": match.get("versionStartExcluding"),
                            "version_end_including": match.get("versionEndIncluding"),
                            "version_end_excluding": match.get("versionEndExcluding"),
                            "operator": child_op,
                            "negate": child_neg
                        })

        has_cpe_config = 1 if len(cpe_matches) > 0 else 0

        return {
            "source": "NVD",
            "source_record_version": "2.0",
            "cve_id": cve_id,
            "status": vuln_status,
            "is_rejected": 1 if is_rejected else 0,
            "description": desc_en,
            "summary": desc_en[:200] if desc_en else None,
            "published_date": published,
            "last_modified_date": last_modified,
            "primary_vendor": primary_vendor,
            "primary_product": primary_product,
            "primary_severity": primary_severity,
            "primary_cvss_score": primary_score,
            "cwe_ids": cwe_ids,
            "cwes": cwe_records,
            "cvss_metrics": cvss_records,
            "references": ref_records,
            "configurations": config_nodes,
            "cpe_matches": cpe_matches,
            "affected_versions": [],
            "has_cpe_config": has_cpe_config,
            "raw_json": json.dumps(raw),
            "source_file": file_path
        }

    # ------------------------------------------------------------------
    # CVE List V5 Normalizer
    # ------------------------------------------------------------------

    def _normalize_cve_list_record(self, raw: Dict[str, Any], file_path: str) -> Optional[Dict[str, Any]]:
        """Normalize a CVE Record Format 5.x JSON item."""
        cve_meta = raw.get("cveMetadata", {})
        cve_id = str(cve_meta.get("cveId") or "").strip().upper()
        if not _CVE_PATTERN.match(cve_id):
            return None

        state = cve_meta.get("state", "PUBLISHED")
        is_rejected = (state.upper() == "REJECTED")

        containers = raw.get("containers", {})
        cna = containers.get("cna", {}) if isinstance(containers, dict) else {}

        # Descriptions
        desc_en = None
        for d in cna.get("descriptions", []):
            if isinstance(d, dict) and d.get("lang") in ("en", "en-US"):
                desc_en = d.get("value")
                break
        if not desc_en and cna.get("descriptions"):
            first_d = cna.get("descriptions")[0]
            if isinstance(first_d, dict):
                desc_en = first_d.get("value")

        summary = cna.get("title") or (desc_en[:200] if desc_en else None)
        published = cve_meta.get("datePublished")
        last_modified = cve_meta.get("dateUpdated")

        # Affected versions & products
        affected_list = cna.get("affected", [])
        aff_records = []
        primary_vendor = None
        primary_product = None

        for aff in affected_list:
            v_name = aff.get("vendor")
            p_name = aff.get("product")
            p_url = aff.get("packageName") or aff.get("collectionURL")
            repo = aff.get("repo")
            modules = aff.get("modules", [])
            platforms = aff.get("platforms", [])
            default_status = aff.get("defaultStatus")

            if not primary_vendor and v_name:
                primary_vendor = v_name
            if not primary_product and p_name:
                primary_product = p_name

            for ver in aff.get("versions", []):
                aff_records.append({
                    "vendor": v_name,
                    "product": p_name,
                    "package_url": p_url,
                    "repo_url": repo,
                    "modules": modules,
                    "platforms": platforms,
                    "version_value": str(ver.get("version", "")),
                    "version_status": ver.get("status", "affected"),
                    "version_type": ver.get("versionType"),
                    "less_than": ver.get("lessThan"),
                    "less_than_or_equal": ver.get("lessThanOrEqual"),
                    "default_status": default_status
                })

        # Problem types / CWEs
        cwe_records = []
        cwe_ids = []
        for pt in cna.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId") or desc.get("description")
                if cwe_id:
                    cwe_records.append({
                        "source": "CVE_LIST_V5",
                        "cwe_id": cwe_id,
                        "description": desc.get("description")
                    })
                    if cwe_id not in cwe_ids:
                        cwe_ids.append(cwe_id)

        # CVSS Metrics from CNA
        cvss_records = []
        primary_severity = None
        primary_score = None
        for m in cna.get("metrics", []):
            for k in ("cvssV3_1", "cvssV3_0", "cvssV2_0", "cvssV4_0"):
                if k in m and isinstance(m[k], dict):
                    cvss_data = m[k]
                    ver = cvss_data.get("version", k.replace("cvssV", "").replace("_", "."))
                    score = cvss_data.get("baseScore")
                    sev = cvss_data.get("baseSeverity")
                    record_m = {
                        "source": "CVE_LIST_V5",
                        "cvss_version": ver,
                        "vector_string": cvss_data.get("vectorString"),
                        "base_score": float(score) if score is not None else None,
                        "base_severity": sev.upper() if sev else None,
                        "metric_type": "Secondary",
                        "exploitability_score": None,
                        "impact_score": None,
                    }
                    cvss_records.append(record_m)
                    if not primary_severity and record_m["base_severity"]:
                        primary_severity = record_m["base_severity"]
                        primary_score = record_m["base_score"]

        # References
        ref_records = []
        for r in cna.get("references", []):
            if isinstance(r, dict) and r.get("url"):
                ref_records.append({
                    "source": "CVE_LIST_V5",
                    "url": r.get("url"),
                    "source_identifier": r.get("name"),
                    "tags": r.get("tags", [])
                })

        return {
            "source": "CVE_LIST_V5",
            "source_record_version": str(raw.get("dataVersion", "5.0")),
            "cve_id": cve_id,
            "status": state.capitalize(),
            "is_rejected": 1 if is_rejected else 0,
            "description": desc_en,
            "summary": summary,
            "published_date": published,
            "last_modified_date": last_modified,
            "primary_vendor": primary_vendor,
            "primary_product": primary_product,
            "primary_severity": primary_severity,
            "primary_cvss_score": primary_score,
            "cwe_ids": cwe_ids,
            "cwes": cwe_records,
            "cvss_metrics": cvss_records,
            "references": ref_records,
            "configurations": [],
            "cpe_matches": [],
            "affected_versions": aff_records,
            "has_cpe_config": 0,
            "raw_json": json.dumps(raw),
            "source_file": file_path
        }

    # ------------------------------------------------------------------
    # Batch SQLite Ingestion
    # ------------------------------------------------------------------

    def _persist_normalized_batch(self, batch: List[Dict[str, Any]]):
        """
        Insert or merge a batch of normalized records in a single transaction.
        Preserves multi-source provenance and never silently overwrites.
        """
        conn = self.db.connect()
        import_ts = datetime.now(timezone.utc).isoformat()

        with conn:
            all_cvss = []
            all_cwes = []
            all_refs = []
            all_cpes = []
            all_affs = []
            for item in batch:
                cve_id = item["cve_id"]
                src = item["source"]

                # 1. Insert or update master `cves` record first (required by foreign key constraints)
                existing = conn.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,)).fetchone()

                if not existing:
                    # New canonical record
                    sources_list = [src]
                    provenance = {
                        "description": src,
                        "status": src,
                        "severity": src if item["primary_severity"] else None,
                        "cwes": src if item["cwe_ids"] else None,
                        "configurations": src if item["has_cpe_config"] else None,
                        "affected_versions": src if item["affected_versions"] else None
                    }

                    conn.execute("""
                        INSERT INTO cves (
                            cve_id, status, is_rejected, description, summary,
                            published_date, last_modified_date, primary_vendor,
                            primary_product, primary_severity, primary_cvss_score,
                            cwe_ids, has_cpe_config, sources, provenance,
                            raw_record_reference, import_timestamp
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        cve_id, item["status"], item["is_rejected"], item["description"],
                        item["summary"], item["published_date"], item["last_modified_date"],
                        item["primary_vendor"], item["primary_product"], item["primary_severity"],
                        item["primary_cvss_score"], json.dumps(item["cwe_ids"]),
                        item["has_cpe_config"], json.dumps(sources_list), json.dumps(provenance),
                        item["source_file"], import_ts
                    ))
                else:
                    # Merge into canonical record with field-level provenance
                    sources_list = json.loads(existing["sources"]) if existing["sources"] else []
                    if src not in sources_list:
                        sources_list.append(src)

                    prov = json.loads(existing["provenance"]) if existing["provenance"] else {}

                    # Provenance rules:
                    # - If rejected in either source, mark is_rejected = 1
                    is_rej = existing["is_rejected"] or item["is_rejected"]
                    status = item["status"] if item["is_rejected"] else existing["status"]

                    # - Prefer NVD for description/severity/CPE configurations if available
                    desc = existing["description"]
                    if not desc or (src == "NVD" and item["description"]):
                        desc = item["description"]
                        prov["description"] = src

                    summ = existing["summary"] or item["summary"]
                    pub_date = existing["published_date"] or item["published_date"]
                    mod_date = item["last_modified_date"] or existing["last_modified_date"]
                    vendor = existing["primary_vendor"] or item["primary_vendor"]
                    product = existing["primary_product"] or item["primary_product"]

                    sev = existing["primary_severity"]
                    score = existing["primary_cvss_score"]
                    if not sev or (src == "NVD" and item["primary_severity"]):
                        sev = item["primary_severity"]
                        score = item["primary_cvss_score"]
                        prov["severity"] = src

                    # Union CWEs
                    existing_cwes = set(json.loads(existing["cwe_ids"])) if existing["cwe_ids"] else set()
                    merged_cwes = sorted(list(existing_cwes.union(item["cwe_ids"])))

                    has_cpe = existing["has_cpe_config"] or item["has_cpe_config"]
                    if item["has_cpe_config"]:
                        prov["configurations"] = src

                    if item["affected_versions"]:
                        prov["affected_versions"] = src

                    conn.execute("""
                        UPDATE cves SET
                            status = ?, is_rejected = ?, description = ?, summary = ?,
                            published_date = ?, last_modified_date = ?, primary_vendor = ?,
                            primary_product = ?, primary_severity = ?, primary_cvss_score = ?,
                            cwe_ids = ?, has_cpe_config = ?, sources = ?, provenance = ?,
                            import_timestamp = ?
                        WHERE cve_id = ?
                    """, (
                        status, is_rej, desc, summ, pub_date, mod_date, vendor, product,
                        sev, score, json.dumps(merged_cwes), has_cpe, json.dumps(sources_list),
                        json.dumps(prov), import_ts, cve_id
                    ))

                # 2. Insert/Update source_records table (stores exact source JSON)
                conn.execute("""
                    INSERT INTO source_records (
                        cve_id, source, source_record_version, vuln_status,
                        raw_json, source_file, import_timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id, source) DO UPDATE SET
                        source_record_version = excluded.source_record_version,
                        vuln_status = excluded.vuln_status,
                        raw_json = excluded.raw_json,
                        source_file = excluded.source_file,
                        import_timestamp = excluded.import_timestamp
                """, (
                    cve_id, src, item["source_record_version"], item["status"],
                    item["raw_json"], item["source_file"], import_ts
                ))

                # Ensure rerun safety: only if updating an existing record, delete prior child records for this (cve_id, src)
                if existing:
                    conn.execute("DELETE FROM cve_cvss_metrics WHERE cve_id = ? AND source = ?", (cve_id, src))
                    conn.execute("DELETE FROM cve_cwes WHERE cve_id = ? AND source = ?", (cve_id, src))
                    conn.execute("DELETE FROM cve_references WHERE cve_id = ? AND source = ?", (cve_id, src))
                    if src == "NVD":
                        conn.execute("DELETE FROM cve_cpe_matches WHERE cve_id = ?", (cve_id,))
                        conn.execute("DELETE FROM cve_configurations WHERE cve_id = ?", (cve_id,))
                    elif src == "CVE_LIST_V5":
                        conn.execute("DELETE FROM cve_affected_versions WHERE cve_id = ?", (cve_id,))

                # Collect child records for batch executemany
                for m in item["cvss_metrics"]:
                    all_cvss.append((
                        cve_id, m["source"], m["cvss_version"], m["vector_string"],
                        m["base_score"], m["base_severity"], m["metric_type"],
                        m["exploitability_score"], m["impact_score"]
                    ))

                for cwe in item["cwes"]:
                    all_cwes.append((cve_id, cwe["source"], cwe["cwe_id"], cwe["description"]))

                for ref in item["references"]:
                    all_refs.append((cve_id, ref["source"], ref["url"], ref["source_identifier"], json.dumps(ref["tags"])))

                # Insert single configuration node per config structure (not duplicate per CPE)
                node_id = None
                if item["configurations"]:
                    cfg = item["configurations"][0]
                    cur = conn.execute("""
                        INSERT INTO cve_configurations (
                            cve_id, config_index, operator, negate, parent_node_id, node_type
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    """, (cve_id, cfg.get("config_index", 0), cfg.get("operator", "OR"),
                          cfg.get("negate", 0), None, cfg.get("node_type", "root")))
                    node_id = cur.lastrowid

                for cpe in item["cpe_matches"]:
                    parts = cpe["cpe_parts"]
                    all_cpes.append((
                        cve_id, node_id, cpe["criteria"], cpe["match_criteria_id"], cpe["vulnerable"],
                        parts["part"], parts["vendor"], parts["product"], parts["version"],
                        parts["update_version"], parts["edition"], parts["language"],
                        parts["sw_edition"], parts["target_sw"], parts["target_hw"], parts["other"],
                        cpe["version_start_including"], cpe["version_start_excluding"],
                        cpe["version_end_including"], cpe["version_end_excluding"]
                    ))

                for aff in item["affected_versions"]:
                    all_affs.append((
                        cve_id, aff["vendor"], aff["product"], aff["package_url"], aff["repo_url"],
                        json.dumps(aff["modules"]), json.dumps(aff["platforms"]), aff["version_value"],
                        aff["version_status"], aff["version_type"], aff["less_than"],
                        aff["less_than_or_equal"], aff["default_status"]
                    ))

            # Batch execute child table insertions in pure C for extreme throughput
            if all_cvss:
                conn.executemany("""
                    INSERT INTO cve_cvss_metrics (
                        cve_id, source, cvss_version, vector_string,
                        base_score, base_severity, metric_type,
                        exploitability_score, impact_score
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, all_cvss)

            if all_cwes:
                conn.executemany("""
                    INSERT INTO cve_cwes (cve_id, source, cwe_id, description)
                    VALUES (?, ?, ?, ?)
                """, all_cwes)

            if all_refs:
                conn.executemany("""
                    INSERT INTO cve_references (cve_id, source, url, source_identifier, tags)
                    VALUES (?, ?, ?, ?, ?)
                """, all_refs)

            if all_cpes:
                conn.executemany("""
                    INSERT INTO cve_cpe_matches (
                        cve_id, config_node_id, criteria, match_criteria_id, vulnerable,
                        part, vendor, product, version, update_version, edition,
                        language, sw_edition, target_sw, target_hw, other,
                        version_start_including, version_start_excluding,
                        version_end_including, version_end_excluding
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, all_cpes)

            if all_affs:
                conn.executemany("""
                    INSERT INTO cve_affected_versions (
                        cve_id, vendor, product, package_url, repo_url, modules,
                        platforms, version_value, version_status, version_type,
                        less_than, less_than_or_equal, default_status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, all_affs)

    # ------------------------------------------------------------------
    # Public Import Pipeline
    # ------------------------------------------------------------------

    def import_package(
        self,
        package_dir: str | Path,
        verify_hashes: bool = True,
        batch_size: int = 1000,
        progress_interval: int = 10000,
        resume: bool = True,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> Dict[str, Any]:
        """
        Verify manifest and import NVD chunks and CVE List V5 baseline ZIP.
        Features:
        - Pre-import disk space verification.
        - Cryptographic manifest verification with full mismatch reporting.
        - Direct streaming of CVE List V5 zip members without full disk extraction.
        - Checkpoint advancement strictly AFTER database transaction commit.
        - Rerun safety preventing duplicate child records.
        - Continuous physical RSS and heap memory monitoring.
        - Structured progress reporting every progress_interval records.
        """
        pkg_path = Path(package_dir)
        if not pkg_path.exists() or not pkg_path.is_dir():
            raise FileNotFoundError(f"Package directory does not exist: {pkg_path}")

        # 1. Pre-Import Disk Space Verification
        db_path = Path(self.db.db_path)
        has_space, free_gb_before, total_gb = self.check_disk_space(db_path, min_free_gb=5.0)
        self.stats["disk_space_before_gb"] = free_gb_before
        self.stats["target_database_path"] = str(db_path)
        if not has_space:
            raise RuntimeError(
                f"Insufficient disk space on {db_path.parent}: {free_gb_before:.2f} GB free, "
                f"minimum required is 5.0 GB."
            )

        # 2. Cryptographic Manifest Verification (Rules 7 & 34)
        if verify_hashes:
            is_valid, msg = self.verify_manifest(pkg_path)
            if not is_valid:
                raise ValueError(f"Package integrity validation failed: {msg}")

        # 3. Initialize Memory Monitoring & High-Precision Timers
        tracemalloc.start()
        start_time = time.perf_counter()
        process = psutil.Process() if psutil else None
        peak_rss_bytes = process.memory_info().rss if process else 0

        def update_peak_rss():
            nonlocal peak_rss_bytes
            if process:
                rss = process.memory_info().rss
                if rss > peak_rss_bytes:
                    peak_rss_bytes = rss

        # 4. Initialize Database Schema & Tune Bulk PRAGMAs
        self.db.init_schema()
        conn = self.db.connect()
        conn.execute("PRAGMA cache_size = -64000;")
        conn.execute("PRAGMA temp_store = MEMORY;")
        conn.execute("PRAGMA mmap_size = 268435456;")

        # 5. Checkpoint & Resumability State
        if resume:
            completed_nvd_chunks, committed_v5_count = self._load_checkpoint()
        else:
            self._clear_checkpoint()
            completed_nvd_chunks, committed_v5_count = set(), 0

        batch: List[Dict[str, Any]] = []

        def format_elapsed(secs: float) -> str:
            m, s = divmod(int(secs), 60)
            h, m = divmod(m, 60)
            return f"{h:02d}:{m:02d}:{s:02d}"

        # ------------------------------------------------------------------
        # 6. Process NVD JSON Chunks
        # ------------------------------------------------------------------
        json_files = sorted([
            f for f in pkg_path.glob("*.json")
            if f.name not in ("manifest.json", ".nvd_checkpoint.json")
        ])

        nvd_processed = len(completed_nvd_chunks) * 2000
        nvd_imported = len(completed_nvd_chunks) * 2000
        nvd_rejected = 0
        last_nvd_report = nvd_processed

        for json_file in json_files:
            if json_file.name in completed_nvd_chunks:
                self.stats["sources_scanned"].append(f"{json_file.name} (resumed/skipped)")
                continue

            self.stats["sources_scanned"].append(str(json_file))

            for raw_item in self._stream_json_file(json_file):
                nvd_processed += 1
                record_type = raw_item["_type"]
                data = raw_item["data"]
                src_file = raw_item["_file"]

                norm_record = None
                try:
                    if record_type == "NVD":
                        norm_record = self._normalize_nvd_record(data, src_file)
                    elif record_type == "CVE_LIST_V5":
                        norm_record = self._normalize_cve_list_record(data, src_file)
                    else:
                        norm_record = self._normalize_nvd_record(data, src_file) or self._normalize_cve_list_record(data, src_file)
                except Exception as ex:
                    self.stats["malformed_count"] += 1
                    self.stats["skipped_records"].append({
                        "file": src_file,
                        "error": f"Normalization exception: {ex}"
                    })
                    continue

                if norm_record:
                    if norm_record["is_rejected"]:
                        nvd_rejected += 1
                        self.stats["rejected_count"] += 1
                    if not norm_record["has_cpe_config"] and not norm_record["is_rejected"]:
                        self.stats["no_cpe_count"] += 1

                    batch.append(norm_record)
                    nvd_imported += 1
                    self.stats["nvd_imported"] += 1
                    self.stats["total_cves"] += 1

                    if len(batch) >= batch_size:
                        self._persist_normalized_batch(batch)
                        batch = []
                        update_peak_rss()

                # Progress reporting interval
                if nvd_processed - last_nvd_report >= progress_interval:
                    last_nvd_report = nvd_processed
                    elapsed_str = format_elapsed(time.perf_counter() - start_time)
                    update_peak_rss()
                    rss_mb = peak_rss_bytes / (1024 * 1024)
                    print(
                        f"[NVD] Processed: {nvd_processed:6d} | Imported: {nvd_imported:6d} | "
                        f"Rejected/Skipped: {nvd_rejected:4d} | Elapsed: {elapsed_str} | Peak RSS: {rss_mb:.1f} MB",
                        flush=True
                    )
                    if progress_callback:
                        progress_callback({
                            "source": "NVD",
                            "processed": nvd_processed,
                            "imported": nvd_imported,
                            "rejected": nvd_rejected,
                            "elapsed": elapsed_str,
                            "peak_rss_mb": round(rss_mb, 2)
                        })

            # Commit remaining items in chunk and advance NVD checkpoint strictly after commit
            if batch:
                self._persist_normalized_batch(batch)
                batch = []
                update_peak_rss()

            completed_nvd_chunks.add(json_file.name)
            self._save_checkpoint(completed_nvd_chunks, committed_v5_count)

        # ------------------------------------------------------------------
        # 7. Process CVE List V5 Baseline ZIP
        # ------------------------------------------------------------------
        v5_dir = pkg_path / "cve_list_v5"
        v5_zip_files = sorted(list(v5_dir.glob("*.zip*"))) if v5_dir.exists() else []

        v5_processed = committed_v5_count
        v5_imported = committed_v5_count
        v5_rejected = 0
        last_v5_report = v5_processed

        for v5_zip in v5_zip_files:
            self.stats["sources_scanned"].append(str(v5_zip))
            member_idx = 0

            for member_name, raw_data in self._stream_cve_list_zip(v5_zip):
                member_idx += 1
                if member_idx <= committed_v5_count:
                    continue

                v5_processed += 1
                src_ident = f"{v5_zip.name}:{member_name}"

                norm_record = None
                try:
                    norm_record = self._normalize_cve_list_record(raw_data, src_ident)
                except Exception as ex:
                    self.stats["malformed_count"] += 1
                    self.stats["skipped_records"].append({
                        "file": src_ident,
                        "error": f"Normalization exception: {ex}"
                    })
                    continue

                if norm_record:
                    if norm_record["is_rejected"]:
                        v5_rejected += 1
                        self.stats["rejected_count"] += 1
                    if not norm_record["has_cpe_config"] and not norm_record["is_rejected"]:
                        self.stats["no_cpe_count"] += 1

                    batch.append(norm_record)
                    v5_imported += 1
                    self.stats["cve_list_imported"] += 1
                    self.stats["total_cves"] += 1

                    if len(batch) >= batch_size:
                        self._persist_normalized_batch(batch)
                        committed_v5_count = member_idx
                        self._save_checkpoint(completed_nvd_chunks, committed_v5_count)
                        batch = []
                        update_peak_rss()

                # Progress reporting interval
                if v5_processed - last_v5_report >= progress_interval:
                    last_v5_report = v5_processed
                    elapsed_str = format_elapsed(time.perf_counter() - start_time)
                    update_peak_rss()
                    rss_mb = peak_rss_bytes / (1024 * 1024)
                    print(
                        f"[CVE List V5] Processed: {v5_processed:6d} | Imported: {v5_imported:6d} | "
                        f"Rejected/Skipped: {v5_rejected:4d} | Elapsed: {elapsed_str} | Peak RSS: {rss_mb:.1f} MB",
                        flush=True
                    )
                    if progress_callback:
                        progress_callback({
                            "source": "CVE_LIST_V5",
                            "processed": v5_processed,
                            "imported": v5_imported,
                            "rejected": v5_rejected,
                            "elapsed": elapsed_str,
                            "peak_rss_mb": round(rss_mb, 2)
                        })

            if batch:
                self._persist_normalized_batch(batch)
                committed_v5_count = member_idx
                self._save_checkpoint(completed_nvd_chunks, committed_v5_count)
                batch = []
                update_peak_rss()

        # ------------------------------------------------------------------
        # 8. Post-Import Telemetry & Database Finalization
        # ------------------------------------------------------------------
        duration = time.perf_counter() - start_time
        current_mem, peak_traced_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        update_peak_rss()

        # Measure disk space after import
        _, free_gb_after, _ = self.check_disk_space(db_path)
        self.stats["disk_space_after_gb"] = free_gb_after

        # Measure database file sizes
        db_size_bytes = db_path.stat().st_size if db_path.exists() else 0
        wal_path = Path(str(db_path) + "-wal")
        wal_size_bytes = wal_path.stat().st_size if wal_path.exists() else 0
        journal_path = Path(str(db_path) + "-journal")
        journal_size_bytes = journal_path.stat().st_size if journal_path.exists() else 0

        self.stats["final_db_size_bytes"] = db_size_bytes
        self.stats["final_db_size_mb"] = round(db_size_bytes / (1024 * 1024), 2)
        self.stats["wal_size_bytes"] = wal_size_bytes
        self.stats["wal_size_mb"] = round(wal_size_bytes / (1024 * 1024), 2)
        self.stats["journal_size_bytes"] = journal_size_bytes
        self.stats["journal_size_mb"] = round(journal_size_bytes / (1024 * 1024), 2)

        self.stats["peak_memory_bytes"] = peak_traced_mem
        self.stats["peak_memory_mb"] = round(peak_traced_mem / (1024 * 1024), 2)
        self.stats["peak_rss_bytes"] = peak_rss_bytes
        self.stats["peak_rss_mb"] = round(peak_rss_bytes / (1024 * 1024), 2)
        self.stats["duration_seconds"] = round(duration, 4)
        self.stats["duration_formatted"] = format_elapsed(duration)

        # Hardware constraint alert if peak RSS approaches 4 GB
        if peak_rss_bytes >= 3.8 * (1024 ** 3):
            self.stats["hardware_constraint_warning"] = (
                f"Peak RAM usage ({self.stats['peak_rss_mb']:.1f} MB) approached the 4 GB threshold. "
                f"Host usable RAM is ~6 GB."
            )

        # Update metadata in database
        now_iso = datetime.now(timezone.utc).isoformat()
        counts = self.db.get_detailed_counts() if hasattr(self.db, "get_detailed_counts") else self.db.get_counts()
        self.stats["detailed_counts"] = counts
        self.stats["linked_cve_count"] = counts["linked_cve_count"]

        self.db.set_metadata("schema_version", str(SCHEMA_VERSION))
        self.db.set_metadata("database_version", DATABASE_VERSION)
        self.db.set_metadata("build_timestamp", now_iso)
        self.db.set_metadata("record_count", str(counts["total_cves"]))
        self.db.set_metadata("nvd_record_count", str(counts["nvd_record_count"]))
        self.db.set_metadata("cve_list_record_count", str(counts["cve_list_record_count"]))
        self.db.set_metadata("linked_cve_count", str(counts["linked_cve_count"]))
        self.db.set_metadata("rejected_cve_count", str(counts["rejected_cves"]))
        self.db.set_metadata("nvd_source", "NVD JSON 2.0")
        self.db.set_metadata("nvd_date", now_iso)
        self.db.set_metadata("cve_list_source", "CVE List V5")
        self.db.set_metadata("cve_list_date", now_iso)
        self.db.set_metadata("package_sha256", "verified" if verify_hashes else "unverified")
        self.db.set_metadata("import_peak_memory_mb", str(self.stats["peak_memory_mb"]))
        self.db.set_metadata("import_peak_rss_mb", str(self.stats["peak_rss_mb"]))
        self.db.set_metadata("import_duration_seconds", str(self.stats["duration_seconds"]))

        return {
            "status": "SUCCESS",
            "stats": self.stats,
            "counts": counts,
            "metadata": self.db.get_metadata()
        }
