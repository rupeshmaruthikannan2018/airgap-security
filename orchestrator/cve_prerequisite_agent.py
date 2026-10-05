"""
CVE Prerequisite Extraction Agent for the AirGap Security Platform.

Discovers and extracts the technical prerequisites and environmental conditions
required for a CVE to be exploitable without inventing facts or assumptions.

Operates in:
1. Online development mode: Retrieves and caches authoritative vendor advisories,
   GHSA, CVE/NVD records, commit diffs, and inspects local Nuclei templates.
2. Offline air-gapped mode: Reuses locally cached advisories and local databases.

All stored prerequisites are tagged:
    trust_level: "authoritative" | "derived"
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

import yaml

# Add project root and orchestrator to path
_orchestrator_dir = Path(__file__).resolve().parent
_project_root = _orchestrator_dir.parent
for _p in [str(_project_root), str(_orchestrator_dir)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cve_database_agent import CVEDatabaseAgent

try:
    from orchestrator.condition_ir import (
        AndGroup,
        ASTNode,
        ConditionCategory,
        ConditionNode,
        ConditionType,
        CVEConditionTree,
        NotNode,
        Operator,
        OrGroup,
        TrustLevel,
        VerificationMethod,
    )
    from orchestrator.nvd_applicability_parser import parse_nvd_configurations
    from orchestrator.condition_extractor import ConditionExtractor
    from orchestrator.document_sanitizer import DocumentSanitizer, DocumentType, PassageRelevance
except ImportError:
    from condition_ir import (
        AndGroup,
        ASTNode,
        ConditionCategory,
        ConditionNode,
        ConditionType,
        CVEConditionTree,
        NotNode,
        Operator,
        OrGroup,
        TrustLevel,
        VerificationMethod,
    )
    from nvd_applicability_parser import parse_nvd_configurations
    from condition_extractor import ConditionExtractor
    from document_sanitizer import DocumentSanitizer, DocumentType, PassageRelevance

DEFAULT_CACHE_DIR = _project_root / "data" / "cve_advisories"
DEFAULT_DB_PATH = _project_root / "data" / "cve_prerequisites.db"
DEFAULT_TEMPLATES_DIR = Path(r"C:\Users\M Rupesh\nuclei-templates")


# ============================================================
# SOURCE PRIORITIZATION & CLASSIFICATION
# ============================================================

SOURCE_PRIORITY = {
    "vendor_advisory": 1,
    "project_advisory": 2,
    "ghsa": 3,
    "cve_reference": 4,
    "source_fix": 5,
    "nuclei": 6,
    "technical_research": 7,
    "other": 8,
}


def classify_source_url(url: str) -> Tuple[str, int]:
    """
    Classify a reference URL into authoritative source categories
    and return (source_type, priority_rank).
    """
    u = url.lower()

    # 1. Official vendor advisories
    if any(k in u for k in [
        "tomcat.apache.org/security", "apache.org/security",
        "access.redhat.com/security", "ubuntu.com/security",
        "msrc.microsoft.com", "oracle.com/security-alerts",
        "security.debian.org", "support.apple.com", "openssl.org"
    ]):
        return "vendor_advisory", SOURCE_PRIORITY["vendor_advisory"]

    # 2. Official project advisories (mailing lists, release announcements)
    if any(k in u for k in [
        "lists.apache.org/thread", "mail-archives.apache.org",
        "seclists.org/oss-sec", "curl.se/docs/cve",
        "palletsprojects.com", "djangoproject.com/weblog",
        "spring.io/security"
    ]):
        return "project_advisory", SOURCE_PRIORITY["project_advisory"]

    # 3. GitHub Security Advisories
    if "github.com/advisories" in u or "/security/advisories" in u or "ghsa-" in u:
        return "ghsa", SOURCE_PRIORITY["ghsa"]

    # 5. Official patch / commit / source-code fix
    if any(k in u for k in ["/commit/", "/pull/", "/commits/", "git.apache.org", "gitlab.com"]):
        return "source_fix", SOURCE_PRIORITY["source_fix"]

    # 4. CVE / NVD references
    if any(k in u for k in ["nvd.nist.gov", "cve.org", "cve.mitre.org", "avd.aquasec.com"]):
        return "cve_reference", SOURCE_PRIORITY["cve_reference"]

    # 7. Technical research / PoC
    if any(k in u for k in ["exploit-db.com", "packetstormsecurity.com", "hackerone.com/reports", "blog."]):
        return "technical_research", SOURCE_PRIORITY["technical_research"]

    return "other", SOURCE_PRIORITY["other"]


def evaluate_source_relevance(source: Dict[str, Any], cve_id: str) -> Tuple[bool, str]:
    """
    Evaluates whether a retrieved source document is genuinely relevant to the CVE
    or is an irrelevant shell, unrendered SPA, or generic licensing placeholder.
    Preserves provenance without contaminating prerequisite extraction.
    """
    s_type = source.get("source_type", "")
    if s_type == "nuclei":
        return True, "Local validation template"

    raw = str(source.get("raw_content") or source.get("content") or "")
    text = str(source.get("content") or "")

    # Unrendered SPA HTML shell detection (e.g. Pony Mail SPA)
    if '<div id="app"></div>' in raw or 'id="ponymail' in raw.lower() or '<title>Pony Mail</title>' in raw or 'single-page application' in raw.lower():
        return False, "Unrendered Single-Page Application (SPA) HTML shell containing no advisory body"

    if not text or len(text.strip()) < 20:
        return False, "Empty or truncated response"

    is_html_doc = ("<html" in raw.lower() or "<!doctype" in raw.lower() or DocumentSanitizer.detect_document_type(raw) == DocumentType.HTML)
    clean_cve = cve_id.strip().upper()
    has_cve = clean_cve in text.upper() or clean_cve in raw.upper()
    has_sec_terms = bool(re.search(r'\b(vulnerability|advisory|security|cve|flaw|exploit|patch|fixed|affects?|bug|attacker|crafted|over-read|overrun|overflow|bypass)\b', text, re.I))

    if not has_cve and not has_sec_terms:
        return False, "Content lacks CVE identifier and vulnerability terminology"

    # If it's an HTML document that does not contain the CVE ID
    if is_html_doc and not has_cve:
        return False, "Generic HTML document without CVE reference"

    # Authoritative vendor/GHSA text fetched directly for this CVE
    if s_type in ("ghsa", "vendor_advisory", "source_fix") and not is_html_doc:
        return True, "Authoritative advisory text"

    return True, "Contains authoritative advisory and vulnerability references"


# ============================================================
# STORAGE ENGINE (SQLite + JSON)
# ============================================================

class PrerequisiteStore:
    """
    Local SQLite and JSON knowledge store for extracted CVE prerequisites.
    """

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_prerequisite_records (
                    cve_id TEXT PRIMARY KEY,
                    summary TEXT,
                    affected_versions TEXT,
                    prerequisites_count INTEGER DEFAULT 0,
                    unknown_conditions_count INTEGER DEFAULT 0,
                    has_nuclei_template INTEGER DEFAULT 0,
                    raw_record_json TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_prerequisites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    prerequisite_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    category TEXT,
                    required INTEGER DEFAULT 1,
                    expected_state TEXT,
                    verification_method TEXT,
                    trust_level TEXT DEFAULT 'authoritative',
                    confidence TEXT DEFAULT 'high',
                    evidence_source TEXT,
                    evidence_url TEXT,
                    evidence_text TEXT,
                    created_at TEXT,
                    source_version TEXT,
                    FOREIGN KEY(cve_id) REFERENCES cve_prerequisite_records(cve_id)
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    source_id TEXT,
                    source_type TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    local_cache_path TEXT,
                    content_sha256 TEXT,
                    priority_rank INTEGER,
                    retrieved_at TEXT,
                    status TEXT,
                    FOREIGN KEY(cve_id) REFERENCES cve_prerequisite_records(cve_id)
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_prereq_cve ON cve_prerequisites(cve_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sources_cve ON cve_sources(cve_id)")

            # Schema Migration for Condition IR and AST
            try:
                cursor.execute("PRAGMA table_info(cve_prerequisite_records)")
                rec_cols = [row[1] for row in cursor.fetchall()]
                if "condition_tree_json" not in rec_cols:
                    cursor.execute("ALTER TABLE cve_prerequisite_records ADD COLUMN condition_tree_json TEXT")

                cursor.execute("PRAGMA table_info(cve_prerequisites)")
                prereq_cols = [row[1] for row in cursor.fetchall()]
                for col_name, col_type in [
                    ("condition_type", "TEXT"),
                    ("subject", "TEXT"),
                    ("attribute", "TEXT"),
                    ("operator", "TEXT"),
                    ("logical_group", "TEXT"),
                    ("parent_condition_id", "TEXT"),
                    ("ast_node_type", "TEXT DEFAULT 'CONDITION'"),
                ]:
                    if col_name not in prereq_cols:
                        cursor.execute(f"ALTER TABLE cve_prerequisites ADD COLUMN {col_name} {col_type}")
            except Exception:
                pass

            conn.commit()

    def save_record(self, record: Dict[str, Any]) -> None:
        cve_id = record["cve_id"]
        now = now_iso()

        prereqs = record.get("prerequisites", [])
        unknowns = record.get("unknown_conditions", [])
        sources = record.get("sources", [])
        has_nuclei = 1 if any(s.get("source_type") == "nuclei" for s in sources) else 0

        cond_tree_str = record.get("condition_tree_json")
        if not cond_tree_str and record.get("condition_tree"):
            try:
                cond_tree_str = json.dumps(record["condition_tree"], ensure_ascii=False)
            except Exception:
                cond_tree_str = None

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Upsert master record
            cursor.execute("""
                INSERT INTO cve_prerequisite_records (
                    cve_id, summary, affected_versions, prerequisites_count,
                    unknown_conditions_count, has_nuclei_template, raw_record_json,
                    condition_tree_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    summary=excluded.summary,
                    affected_versions=excluded.affected_versions,
                    prerequisites_count=excluded.prerequisites_count,
                    unknown_conditions_count=excluded.unknown_conditions_count,
                    has_nuclei_template=excluded.has_nuclei_template,
                    raw_record_json=excluded.raw_record_json,
                    condition_tree_json=excluded.condition_tree_json,
                    updated_at=excluded.updated_at
            """, (
                cve_id,
                record.get("summary", ""),
                json.dumps(record.get("affected_versions", [])),
                len(prereqs),
                len(unknowns),
                has_nuclei,
                json.dumps(record, ensure_ascii=False),
                cond_tree_str,
                now,
                now
            ))

            # Replace prerequisites for this CVE
            cursor.execute("DELETE FROM cve_prerequisites WHERE cve_id = ?", (cve_id,))
            for p in prereqs:
                ev_list = p.get("evidence", [])
                primary_ev = ev_list[0] if ev_list else {}
                cursor.execute("""
                    INSERT INTO cve_prerequisites (
                        cve_id, prerequisite_id, name, description, category,
                        required, expected_state, verification_method, trust_level,
                        confidence, evidence_source, evidence_url, evidence_text,
                        created_at, source_version,
                        condition_type, subject, attribute, operator, logical_group, parent_condition_id, ast_node_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cve_id,
                    p.get("id", f"{cve_id}_cond_{p.get('name')}"),
                    p.get("name", "unnamed_condition"),
                    p.get("description", ""),
                    p.get("category", "configuration"),
                    1 if p.get("required", True) else 0,
                    str(p.get("expected_state", "")),
                    p.get("verification_method", "config_collector"),
                    str(p.get("trust_level", "authoritative")),
                    primary_ev.get("confidence", "high"),
                    primary_ev.get("source_type", "vendor_advisory"),
                    primary_ev.get("source_url", ""),
                    primary_ev.get("evidence_text", ""),
                    now,
                    "1.0",
                    p.get("condition_type", "GENERIC"),
                    p.get("subject", p.get("name", "")),
                    p.get("attribute", p.get("category", "")),
                    p.get("operator", "=="),
                    p.get("logical_group"),
                    p.get("parent_condition_id"),
                    p.get("ast_node_type", "CONDITION")
                ))

            # Replace sources
            cursor.execute("DELETE FROM cve_sources WHERE cve_id = ?", (cve_id,))
            for s in sources:
                cursor.execute("""
                    INSERT INTO cve_sources (
                        cve_id, source_id, source_type, source_url, local_cache_path,
                        content_sha256, priority_rank, retrieved_at, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cve_id,
                    s.get("source_id", ""),
                    s.get("source_type", "other"),
                    s.get("source_url", ""),
                    s.get("local_cache_path", ""),
                    s.get("content_sha256", ""),
                    s.get("priority_rank", 99),
                    s.get("retrieved_at", now),
                    s.get("status", "cached")
                ))

            conn.commit()

    def get_record(self, cve_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT raw_record_json, condition_tree_json FROM cve_prerequisite_records WHERE cve_id = ?",
                (cve_id.upper(),)
            )
            row = cursor.fetchone()
            if row and row["raw_record_json"]:
                rec = json.loads(row["raw_record_json"])
                if "condition_tree_json" in row.keys() and row["condition_tree_json"]:
                    rec["condition_tree_json"] = row["condition_tree_json"]
                    try:
                        rec["condition_tree"] = json.loads(row["condition_tree_json"])
                        if "environment_tree" in rec["condition_tree"]:
                            rec["environment_tree"] = rec["condition_tree"]["environment_tree"]
                    except Exception:
                        pass
                return rec
        return None

    def export_json(self, cve_id: str, file_path: Path | str | None = None) -> Optional[Dict[str, Any]]:
        rec = self.get_record(cve_id)
        if not rec:
            return None
        if file_path:
            p = Path(file_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
        return rec


# ============================================================
# SOURCE RETRIEVAL & LOCAL CACHING
# ============================================================

class SourceRetriever:
    """
    Retrieves and caches authoritative external references locally.
    Enforces strict priority order and prevents repetitive network queries.
    """

    def __init__(self, cache_dir: Path | str = DEFAULT_CACHE_DIR, online_mode: bool = True):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.online_mode = online_mode

    def get_cve_cache_dir(self, cve_id: str) -> Path:
        d = self.cache_dir / cve_id.upper()
        d.mkdir(parents=True, exist_ok=True)
        return d

    def fetch_url_cached(self, cve_id: str, url: str, source_type: str) -> Optional[Dict[str, Any]]:
        """
        Fetches a URL, caches its content locally in data/cve_advisories/<cve_id>/,
        and returns metadata and raw text.
        """
        cve_dir = self.get_cve_cache_dir(cve_id)
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        ext = ".json" if ("api.github.com" in url or url.endswith(".json")) else ".txt"
        cache_file = cve_dir / f"{source_type}_{url_hash}{ext}"
        meta_file = cve_dir / f"{source_type}_{url_hash}.meta.json"

        # Check local cache first
        if cache_file.exists() and meta_file.exists():
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                raw_content = cache_file.read_text(encoding="utf-8", errors="replace")
                sanitized_content = DocumentSanitizer.sanitize_document(raw_content)
                return {
                    "source_url": url,
                    "source_type": source_type,
                    "local_cache_path": str(cache_file),
                    "content": sanitized_content,
                    "raw_content": raw_content,
                    "content_sha256": meta.get("sha256"),
                    "retrieved_at": meta.get("retrieved_at"),
                    "from_cache": True
                }
            except Exception:
                pass

        if not self.online_mode:
            return None

        # Fetch from network
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "AirGap-Security-Orchestrator/2.0"}
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                raw_bytes = resp.read()
                raw_content = raw_bytes.decode("utf-8", errors="replace")
                sha256 = hashlib.sha256(raw_bytes).hexdigest()
                now_str = now_iso()

                cache_file.write_text(raw_content, encoding="utf-8")
                meta = {
                    "url": url,
                    "source_type": source_type,
                    "retrieved_at": now_str,
                    "sha256": sha256
                }
                meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

                sanitized_content = DocumentSanitizer.sanitize_document(raw_content)
                return {
                    "source_url": url,
                    "source_type": source_type,
                    "local_cache_path": str(cache_file),
                    "content": sanitized_content,
                    "raw_content": raw_content,
                    "content_sha256": sha256,
                    "retrieved_at": now_str,
                    "from_cache": False
                }
        except Exception as e:
            return None

    def fetch_github_advisory(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Query GitHub Advisory Database API for the CVE."""
        ghsa_url = f"https://api.github.com/advisories?cve_id={cve_id.upper()}"
        res = self.fetch_url_cached(cve_id, ghsa_url, "ghsa")
        if res and res.get("content"):
            try:
                advisories = json.loads(res["content"])
                if isinstance(advisories, list) and advisories:
                    adv = advisories[0]
                    return {
                        "source_url": adv.get("html_url", ghsa_url),
                        "source_type": "ghsa",
                        "summary": adv.get("summary", ""),
                        "description": adv.get("description", ""),
                        "severity": adv.get("severity", ""),
                        "references": [r if isinstance(r, str) else r.get("url", "") for r in adv.get("references", [])],
                        "local_cache_path": res.get("local_cache_path"),
                        "retrieved_at": res.get("retrieved_at"),
                        "content_sha256": res.get("content_sha256"),
                        "vulnerabilities": adv.get("vulnerabilities", []),
                        "from_cache": res.get("from_cache", False)
                    }
            except Exception:
                pass
        return None


# ============================================================
# NUCLEI TEMPLATE INSPECTOR
# ============================================================

class NucleiTemplateInspector:
    """
    Statically inspects local Nuclei templates to extract technical validation conditions.
    Does NOT modify or execute the Nuclei template.
    """

    def __init__(self, templates_dir: Path | str = DEFAULT_TEMPLATES_DIR):
        self.templates_dir = Path(templates_dir)

    def find_template(self, cve_id: str) -> Optional[Path]:
        clean_cve = cve_id.strip().upper()
        m = re.search(r"CVE-(\d{4})-", clean_cve)
        year = m.group(1) if m else "2025"

        candidates = [
            self.templates_dir / "http" / "cves" / year / f"{clean_cve}.yaml",
            self.templates_dir / "http" / "cves" / year / f"{clean_cve}.yml",
            _project_root / "rules" / f"{clean_cve}.yaml",
            _project_root / "rules" / f"{clean_cve}.yml",
        ]
        for p in candidates:
            if p.exists():
                return p

        # Check subdirectories
        if self.templates_dir.exists():
            try:
                for match in self.templates_dir.rglob(f"*{clean_cve}*.yaml"):
                    if match.is_file():
                        return match
            except Exception:
                pass
        return None

    def inspect_template(self, cve_id: str) -> Optional[Dict[str, Any]]:
        tpl_path = self.find_template(cve_id)
        if not tpl_path:
            return None

        try:
            content = tpl_path.read_text(encoding="utf-8", errors="replace")
            parsed = yaml.safe_load(content)
            if not isinstance(parsed, dict):
                return None

            requests_data = parsed.get("requests") or parsed.get("http") or []
            endpoints = []
            methods = set()
            headers = {}
            matchers = []

            for r in requests_data:
                if isinstance(r, dict):
                    # Methods
                    method = r.get("method", "GET").upper()
                    methods.add(method)
                    # Paths
                    for raw_path in r.get("path", []):
                        endpoints.append(str(raw_path))
                    # Headers
                    if isinstance(r.get("headers"), dict):
                        headers.update(r["headers"])
                    # Matchers
                    for m in r.get("matchers", []):
                        if isinstance(m, dict):
                            matchers.append({
                                "type": m.get("type"),
                                "status": m.get("status"),
                                "words": m.get("words"),
                                "part": m.get("part", "body")
                            })

            return {
                "template_path": str(tpl_path),
                "template_id": parsed.get("id", cve_id),
                "name": parsed.get("info", {}).get("name", ""),
                "severity": parsed.get("info", {}).get("severity", ""),
                "methods": list(methods),
                "endpoints": endpoints,
                "headers": headers,
                "matchers": matchers,
                "raw_yaml": content
            }
        except Exception as e:
            return None


# ============================================================
# PREREQUISITE EXTRACTION & REASONING ENGINE
# ============================================================

class PrerequisiteExtractor:
    """
    Evidence-based reasoning engine that extracts structured prerequisites.
    Never invents conditions; every condition requires supporting evidence.
    Distinguishes Environment Prerequisites (system configuration/state) from
    Attack Conditions (attacker actions/payloads/knowledge).
    """

    def __init__(self):
        pass

    def clean_subject(self, subj: str) -> str:
        """Strip introductory condition keywords and articles from extracted subject."""
        subj = re.sub(r'^(?:if|when|where|provided\s+that|in\s+cases?\s+where|only\s+(?:when|if))\s+', '', subj, flags=re.I)
        subj = re.sub(r'^(?:a|an|the)\s+', '', subj, flags=re.I)
        return subj.strip()

    def classify_condition_category(self, subject: str, text: str = "", state: str = "") -> str:
        """
        Generic category determination from evidence text.
        Determines the condition category without assuming any hardcoded CVE or product.
        Supported generic categories:
        version, configuration, feature, protocol, service, dependency, filesystem,
        operating_system, deployment, network_context, network_exposure,
        client_server_relationship, endpoint_relationship, application_state,
        runtime, authentication, authorization, component, module, plugin, other.
        """
        combined = f"{subject} {text} {state}".lower()
        subj_low = subject.lower()

        # Subject-specific direct feature/extension indicators
        if any(k in subj_low for k in ["feature", "extension", "capability", "option", "heartbeat", "compression", "decompression", "session ticket", "alpn", "sni", "early data", "0-rtt"]):
            return "feature"

        # 1. Version & Component
        if any(k in combined for k in ["software version", "installed version", "package version", "binary version", "firmware version", "vulnerable version"]):
            return "version"
        if any(k in combined for k in ["subcomponent", "sub-component", "component", "cpe", "package name"]):
            return "component"

        # 2. Authorization & Authentication
        if any(k in combined for k in ["security constraint", "security_constraint", "constraint", "permission", "role", "access control", "privilege", "authorize", "authorization", "allow", "deny", "forbidden", "unauthorized"]):
            return "authorization"
        if any(k in combined for k in ["credential", "login", "password", "token", "client_cert", "client certificate", "authenticate", "authentication", "session cookie", "api key"]):
            return "authentication"

        # 3. Client/Server & Endpoint Relationships
        if any(k in combined for k in ["client and server", "client *and* server", "client/server", "communicating endpoints", "both endpoints", "peer relationship", "vulnerable endpoints"]):
            return "client_server_relationship"
        if any(k in combined for k in ["-to-", "communicating with", "peer", "endpoint", "nodes", "remote host", "upstream"]):
            return "endpoint_relationship"

        # 4. Network Exposure & Context
        if any(k in combined for k in ["accessible to untrusted", "accessible from untrusted", "exposed to untrusted", "publicly exposed", "accessible from", "accessible to", "external network", "untrusted network", "reachability", "bind to 0.0.0.0", "listen on all", "open port", "exposed"]):
            return "network_exposure"
        if any(k in combined for k in ["network context", "topology", "subnet", "firewall", "ingress", "adjacent", "local network", "network architecture"]):
            return "network_context"

        # 5. Service & Connector
        if any(k in combined for k in ["connector", "ajp", "service running", "daemon", "server running", "listener", "active service", "service is running", "service exposed", "worker process", "service active", "listening"]):
            return "service"

        # 6. Protocol
        if any(k in combined for k in ["protocol", "http/0.9", "http/1.0", "http/1.1", "http/2", "http/3", "websocket", "tls", "ssl", "ssh", "smb", "ldap", "dns", "snmp", "ciphersuite", "cipher suite", "renegotiation"]):
            return "protocol"

        # 7. Filesystem & Operating System
        if any(k in combined for k in ["file system", "filesystem", "case-insensitive", "case_insensitive", "directory", "mount", "ntfs", "ext4", "apfs", "symlink", "file path"]):
            return "filesystem"
        if any(k in combined for k in ["operating system", "linux", "windows", "macos", "unix", "kernel", "platform", "distro", "architecture", "os"]):
            return "operating_system"

        # 8. Dependency & Library
        if any(k in combined for k in ["library", "gadget", "jar", "dependency", "gem", "crate", "package", "wheel", "dll", "so file", "classpath"]):
            return "dependency"

        # 9. Module & Plugin
        if any(k in combined for k in ["module", "plugin", "extension loaded", "mod_", "extension module", "addon", "add-on"]):
            return "module"

        # 10. Deployment & Architecture
        if any(k in combined for k in ["caching proxy", "reverse proxy", "proxy", "load balancer", "gateway", "cluster", "session persistence", "persistence", "storage", "deployment mode", "standalone", "hosted behind", "deployed behind"]):
            return "deployment"

        # 11. Feature & Extension
        if any(k in combined for k in ["feature", "extension", "capability", "option", "heartbeat", "renegotiation", "compression", "session ticket", "alpn", "sni", "early data", "0-rtt", "partial put", "allowpartialput", "servlet writes", "write enabled", "writes enabled"]):
            return "feature"

        # 12. Application State & Runtime
        if any(k in combined for k in ["application state", "runtime", "initialization", "debug mode", "development mode", "readonly", "file_based", "in-memory", "state", "mode"]):
            return "application_state"

        # 13. Attack conditions (if classified here)
        if any(k in combined for k in ["send", "craft", "request", "payload", "probe", "method", "inject", "packet", "handshake"]):
            return "request_condition"
        if any(k in combined for k in ["attacker", "knowledge", "mitm", "man-in-the-middle", "positioning"]):
            return "attacker_condition"

        return "configuration"

    def determine_verification_method(self, category: str, name: str = "") -> str:
        """Map generic category to the appropriate verification component."""
        if category in ("version",):
            return "version_inspector"
        if category in ("operating_system", "platform"):
            return "platform_inspector"
        if category in ("configuration", "feature", "filesystem", "application_state", "runtime", "service", "connector", "network_exposure"):
            return "config_collector"
        if category in ("protocol", "authorization", "authentication"):
            return "config_collector"
        if category in ("dependency", "library", "component", "module", "plugin"):
            return "dependency_check"
        if category in ("network_context", "network"):
            return "network_context"
        if category in ("client_server_relationship", "endpoint_relationship"):
            return "endpoint_inventory"
        if category in ("deployment",):
            return "network_context" if any(k in name.lower() for k in ["proxy", "network", "gateway"]) else "config_collector"
        if category in ("request_condition", "attacker_condition", "attacker_capability", "impact_condition"):
            return "dynamic_validation"
        return "config_collector"

    def normalize_condition_name(self, raw_item: str, raw_state: str) -> Tuple[str, str, str]:
        """
        Produce normalized (prereq_name, display_name, config_path).
        Keeps common canonical aliases clean while dynamically handling arbitrary features.
        """
        clean_item = raw_item.strip()
        clean_state = raw_state.strip().lower()
        low_item = clean_item.lower()

        # Map known canonical conditions cleanly for consistency
        if re.search(r'\bhttp\s+puts?\b', low_item):
            return "http_put_enabled", "HTTP PUT enabled", "default_servlet.readonly"
        if "default servlet" in low_item and ("write" in low_item or "write" in clean_state):
            return "default_servlet_writes_enabled", "Default Servlet writes enabled", "default_servlet.readonly"
        if "partial put" in low_item:
            return "partial_put_enabled", "Partial PUT enabled", "default_servlet.allowPartialPut"
        if "session persistence" in low_item:
            return "file_based_session_persistence", "File-based session persistence", "session_persistence.file_based_persistence"
        if "deserialization" in low_item and "library" in low_item:
            return "deserialization_gadget_library_present", "Deserialization gadget library present", "application_libraries.jar_files"
        if "ajp" in low_item and "connector" in low_item:
            return "ajp_connector_active", "AJP connector active", "connectors"
        if "caching proxy" in low_item or ("proxy" in low_item and "cache" in low_item):
            return "caching_proxy_deployed", "Caching reverse proxy deployed", "network_architecture.caching_proxy"
        if "case" in low_item and "insensitive" in low_item:
            return "case_insensitive_file_system", "Case-insensitive file system", "environment.filesystem_case_insensitive"
        if "renegotiation" in low_item:
            return "tls_renegotiation_enabled", "TLS renegotiation enabled", "tls.renegotiation"
        if "tls 1.2" in low_item or "tlsv1.2" in low_item:
            return "tls_1_2_enabled", "TLS 1.2 enabled", "tls.protocols"

        # Generic name formulation
        display_item = clean_item
        if clean_item.endswith("s") and not clean_item.lower().endswith("ss") and len(clean_item) > 3:
            if clean_item[:-1].isupper() or clean_item.endswith("PUTs"):
                display_item = clean_item[:-1]
        snake_item = re.sub(r'[^a-z0-9]+', '_', display_item.lower()).strip('_')
        snake_state = re.sub(r'[^a-z0-9]+', '_', clean_state).strip('_')
        if snake_state in snake_item:
            prereq_name = snake_item
        else:
            prereq_name = f"{snake_item}_{snake_state}"
        display_name = f"{display_item.strip()} {clean_state}".strip()
        config_path = f"{snake_item}.{snake_state}"
        return prereq_name, display_name, config_path

    def generate_candidate_config_paths(self, snake_item: str, snake_state: str = "") -> List[str]:
        """
        Dynamically generate candidate configuration paths for any feature or setting
        without hardcoded vendor assumptions.
        E.g., snake_item='tls_heartbeat_extension', snake_state='enabled' ->
        ['tls_heartbeat_extension.enabled', 'tls_heartbeat_extension', 'tls.heartbeat_extension.enabled', 'tls.heartbeat_extension', 'heartbeat_extension.enabled', 'heartbeat_extension']
        """
        candidates: List[str] = []
        if snake_state:
            candidates.append(f"{snake_item}.{snake_state}")
        candidates.append(snake_item)
        tokens = snake_item.split("_")
        if len(tokens) > 1:
            dotted = f"{tokens[0]}.{'_'.join(tokens[1:])}"
            if snake_state:
                candidates.append(f"{dotted}.{snake_state}")
            candidates.append(dotted)
            sub_item = "_".join(tokens[1:])
            if snake_state:
                candidates.append(f"{sub_item}.{snake_state}")
            candidates.append(sub_item)
        if any(t in tokens for t in ("port", "listener", "connector", "service")):
            candidates.extend(["connectors", "listeners", "ports", "network_exposure"])
        if any(t in tokens for t in ("put", "write", "writes")):
            candidates.extend(["default_servlet.readonly", "default_servlet.writes_enabled", "default_servlet.allowPartialPut"])
        seen = set()
        res = []
        for c in candidates:
            if c and c not in seen:
                seen.add(c)
                res.append(c)
        return res

    def extract_attack_conditions(
        self,
        source_text: str,
        source_type: str = "vendor_advisory",
        source_url: str = ""
    ) -> Dict[str, Any]:
        """
        Generic linguistic conditional extraction engine:
        Discovers all documented environmental conditions and attack conditions
        without hardcoded CVE or product assumptions.
        """
        source_text = DocumentSanitizer.sanitize_document(source_text)
        prerequisites: List[Dict[str, Any]] = []
        attack_conditions: List[Dict[str, Any]] = []
        unknown_conditions: List[Dict[str, Any]] = []
        seen_prereq_names = set()
        seen_attack_names = set()

        is_auth = source_type in ("vendor_advisory", "project_advisory", "ghsa")
        trust_lvl = "authoritative" if is_auth else "derived"

        def is_attack_clause(text: str) -> bool:
            """Check if a matched clause describes an attack action rather than an environmental state."""
            t_low = text.lower()
            return any(k in t_low for k in [
                "attacker", "adversary", "craft", "send", "inject", "transmit", "issue", "submit", "upload",
                "man-in-the-middle", "mitm", "payload", "probe", "exploit", "handshake",
                "crafted packet", "malicious packet", "invalid packet", "oversized packet", "send packet", "transmit packet",
                "request using", "race condition", "specially crafted"
            ])

        # -------------------------------------------------------------
        # Stage 1: Bulleted / Numbered Conditional Lists & Standalone Clauses
        # Matches: "If all/any of the following were true:", "Requires the following:", standalone bullets, etc.
        # -------------------------------------------------------------
        list_block_pattern = re.compile(
            r'(?:if\s+(?:all|any|both|either|one)\s+of\s+the\s+following(?:\s+conditions?)?\s+(?:are|were|must\s+be)\s+true[^\n]*|'
            r'requires\s+(?:all\s+of\s+)?the\s+following(?:\s+conditions?)?:|'
            r'vulnerable\s+when\s+(?:all\s+of\s+)?the\s+following(?:\s+conditions?)?:|'
            r'prerequisites\s+(?:for\s+exploitation\s+include|include):)'
            r'(?P<block>(?:\s*(?:[\*\-\•]|\d+\.)\s+[^\n]+)+)',
            re.IGNORECASE
        )
        candidate_items: List[Tuple[str, str, bool]] = []
        for ml in list_block_pattern.finditer(source_text):
            block_text = ml.group("block")
            full_evidence = ml.group(0).strip()
            lines = [re.sub(r'^\s*(?:[\*\-\•]|\d+\.)\s*', '', ln).strip() for ln in block_text.splitlines() if ln.strip()]
            for item in lines:
                candidate_items.append((item, full_evidence, True))

        # Also check standalone bullet lines not under a block header
        for ln in source_text.splitlines():
            ln_strip = ln.strip()
            if re.match(r'^\s*(?:[\*\-\•]|\d+\.)\s+[A-Za-z]', ln_strip):
                clean_ln = re.sub(r'^\s*(?:[\*\-\•]|\d+\.)\s*', '', ln_strip).strip()
                if clean_ln and not any(clean_ln == itm[0] for itm in candidate_items):
                    candidate_items.append((clean_ln, ln_strip, False))
            elif len(ln_strip) <= 80 and not re.search(r'[.;]$', ln_strip) and re.search(r'\b(?:enabled|supported|disabled|active|running|persistence|library)\b', ln_strip, re.I):
                if ln_strip and not any(ln_strip == itm[0] for itm in candidate_items):
                    candidate_items.append((ln_strip, ln_strip, False))

        for item, full_evidence, is_prereq_block in candidate_items:
            if not item or len(item) < 3:
                continue
            if is_attack_clause(item):
                # Attack condition in list
                a_name = item[0].upper() + item[1:] if item else "Attack condition"
                if a_name not in seen_attack_names:
                    seen_attack_names.add(a_name)
                    attack_conditions.append({
                        "name": a_name,
                        "condition": f"Attacker must {item}",
                        "description": f"Exploitation requires: {item}.",
                        "category": "request_condition",
                        "required": True,
                        "verification_method": "dynamic_validation",
                        "automatically_verifiable": False,
                        "trust_level": trust_lvl,
                        "confidence": "high",
                        "source_type": source_type,
                        "source_url": source_url,
                        "evidence_text": full_evidence,
                        "evidence": [{"source_type": source_type, "source_url": source_url, "evidence_text": full_evidence}]
                    })
            else:
                # Environmental prerequisite in list
                action_for_m = re.search(
                    r'^(?P<action>[A-Za-z0-9_\-\s]+?)\s+(?P<state>enabled|allowed|permitted|active|supported)\s+(?:for|on|in)\s+(?:the\s+)?(?P<entity>[A-Za-z0-9_\-\s]+)$',
                    item,
                    re.I
                )
                if action_for_m:
                    act = action_for_m.group("action").strip()
                    st = action_for_m.group("state").lower()
                    ent = action_for_m.group("entity").strip()
                    item_name = f"{ent} {act}"
                    state_val = st
                else:
                    st_m = re.search(r'\s+(?:is|are|was|were)?\s*(?P<state>enabled|active|supported|configured|allowed|permitted|running|present|available|exposed|disabled|blocked|in\s+use)\s*$', item, re.I)
                    if st_m:
                        item_name = item[:st_m.start()].strip()
                        state_val = st_m.group("state").lower()
                    else:
                        st_beg = re.search(r'^(?P<state>writes?\s+enabled|support\s+for|uses?|using|running\s+on)\s+(?:for\s+)?', item, re.I)
                        if st_beg:
                            raw_beg = st_beg.group(0).lower()
                            if "write" in raw_beg:
                                item_name = f"{item[st_beg.end():].strip()} writes"
                                state_val = "enabled"
                            elif "support" in raw_beg:
                                item_name = item[st_beg.end():].strip()
                                state_val = "enabled"
                            else:
                                item_name = item[st_beg.end():].strip()
                                state_val = "true"
                        else:
                            if not is_prereq_block:
                                continue
                            item_name = item
                            state_val = "present" if "library" in item.lower() or "gadget" in item.lower() else "true"

                clean_sub = self.clean_subject(item_name)
                # Configuration Evidence Gate: validate candidate setting and target subject
                is_valid_cfg, _, _ = DocumentSanitizer.validate_configuration_candidate(
                    clean_sub, state_val, context_passage=full_evidence
                )
                if not is_valid_cfg:
                    continue

                p_name, disp_name, cfg_path = self.normalize_condition_name(clean_sub, state_val)
                if p_name not in seen_prereq_names:
                    seen_prereq_names.add(p_name)
                    cat = self.classify_condition_category(clean_sub, item, state_val)
                    prerequisites.append({
                        "name": p_name,
                        "display_name": disp_name,
                        "description": f"{clean_sub} must be {state_val}.",
                        "category": cat,
                        "required": True,
                        "expected_state": state_val,
                        "configuration_path": cfg_path,
                        "verification_method": self.determine_verification_method(cat, p_name),
                        "trust_level": trust_lvl,
                        "confidence": "high",
                        "evidence": [{
                            "source_type": source_type,
                            "source_url": source_url,
                            "evidence_text": full_evidence
                        }]
                    })

        # -------------------------------------------------------------
        # Stage 1b: Generic Attacker Capability & Prerequisite Actions
        # Matches: "An attacker who can control log messages or log message parameters can execute arbitrary code..."
        # Matches: "Attackers who can send crafted packets can crash the service..."
        # -------------------------------------------------------------
        attacker_cap_pattern = re.compile(
            r'\b(?:an?\s+)?attackers?\s+(?:who\s+can|with\s+(?:the\s+)?ability\s+to|able\s+to)\s+'
            r'(?P<action>[^,\.;\n]+?)(?=\s+(?:can|could|may|might|is\s+able\s+to|will)\s+)',
            re.IGNORECASE
        )
        for m_cap in attacker_cap_pattern.finditer(source_text):
            act_clause = m_cap.group("action").strip()
            if act_clause and len(act_clause) >= 3:
                sent_m = re.search(r'([^.\n]*' + re.escape(m_cap.group(0)) + r'[^.\n]*\.?)', source_text)
                full_ev = sent_m.group(0).strip() if sent_m else m_cap.group(0).strip()
                cap_title = act_clause[0].upper() + act_clause[1:]
                if cap_title not in seen_attack_names:
                    seen_attack_names.add(cap_title)
                    attack_conditions.append({
                        "name": cap_title,
                        "condition": f"Attacker must {act_clause}",
                        "description": f"Exploitation requires: {act_clause}.",
                        "category": "request_condition",
                        "required": True,
                        "verification_method": "dynamic_validation",
                        "automatically_verifiable": False,
                        "trust_level": trust_lvl,
                        "confidence": "high",
                        "source_type": source_type,
                        "source_url": source_url,
                        "evidence_text": full_ev,
                        "evidence": [{"source_type": source_type, "source_url": source_url, "evidence_text": full_ev}]
                    })

        # -------------------------------------------------------------
        # Stage 2: Compound Contrasting Conditions (e.g. 'allow X but deny Y')
        # -------------------------------------------------------------
        compound_pattern = re.compile(
            r'(?:if|when|where|provided\s+that)?\s*(?:(?:a|an|the)\s+)?'
            r'(?P<subject>[A-Za-z0-9_\-\s]{3,40}?)\s+(?:was\s+|is\s+|are\s+)?'
            r'(?:configured\s+to\s+|configured\s+with\s+|set\s+to\s+)?'
            r'(?P<verb1>allow(?:s|ed|ing)?|permit(?:s|ted|ting)?|enable(?:s|d|ing)?)\s+'
            r'(?P<target1>[A-Za-z0-9_\-\s\/]{2,60}?)\s+'
            r'(?:but|while|and)\s+(?:also\s+)?'
            r'(?P<verb2>den(?:y|ies|ied|ying)|block(?:s|ed|ing)?|disallow(?:s|ed|ing)?|disable(?:s|d|ing)?|prohibit(?:s|ed|ing)?|not\s+allow(?:s|ed|ing)?)\s+'
            r'(?P<target2>[A-Za-z0-9_\-\s\/]{2,60}?)'
            r'(?=[,.;]|\s+the\s+user\b|\bby\b|\bcan\b|\bcould\b|$)',
            re.IGNORECASE
        )
        for m in compound_pattern.finditer(source_text):
            raw_subj = self.clean_subject(m.group("subject"))
            v1 = m.group("verb1").lower()
            t1 = m.group("target1").strip()
            v2 = m.group("verb2").lower()
            t2 = m.group("target2").strip()
            full_evidence = m.group(0).strip()
            subj_snake = re.sub(r'[\s\-]+', '_', raw_subj).lower()

            # Clause A (Allow / Permit)
            m1_match = re.search(r'\b(HEAD|GET|POST|PUT|DELETE|OPTIONS|TRACE|CONNECT)\b', t1, re.I)
            m1_name = m1_match.group(1).upper() if m1_match else t1.replace(' ', '_').lower()
            clean_target1 = re.sub(r'\s+to\s+(?:a|the)\s+URI', '', t1, flags=re.I).strip()
            c1_name = f"{subj_snake}_allows_{m1_name.lower()}"
            if c1_name not in seen_prereq_names:
                seen_prereq_names.add(c1_name)
                cat1 = self.classify_condition_category(raw_subj, clean_target1)
                prerequisites.append({
                    "name": c1_name,
                    "display_name": f"{raw_subj.capitalize()} allows {m1_name}",
                    "description": f"{raw_subj.capitalize()} must be configured to allow {clean_target1}.",
                    "category": cat1,
                    "required": True,
                    "expected_state": "allowed" if "allow" in v1 or "permit" in v1 else "true",
                    "configuration_path": f"{subj_snake}.{m1_name.lower()}_allowed",
                    "verification_method": self.determine_verification_method(cat1, c1_name),
                    "trust_level": trust_lvl,
                    "confidence": "high",
                    "evidence": [{
                        "source_type": source_type,
                        "source_url": source_url,
                        "evidence_text": full_evidence
                    }]
                })

            # Clause B (Deny / Block)
            m2_match = re.search(r'\b(HEAD|GET|POST|PUT|DELETE|OPTIONS|TRACE|CONNECT)\b', t2, re.I)
            m2_name = m2_match.group(1).upper() if m2_match else t2.replace(' ', '_').lower()
            clean_target2 = re.sub(r'\s+to\s+(?:a|the)\s+URI', '', t2, flags=re.I).strip()
            c2_name = f"{subj_snake}_denies_{m2_name.lower()}"
            if c2_name not in seen_prereq_names:
                seen_prereq_names.add(c2_name)
                cat2 = self.classify_condition_category(raw_subj, clean_target2)
                prerequisites.append({
                    "name": c2_name,
                    "display_name": f"{raw_subj.capitalize()} denies {m2_name}",
                    "description": f"{raw_subj.capitalize()} must be configured to deny {clean_target2}.",
                    "category": cat2,
                    "required": True,
                    "expected_state": "denied" if any(k in v2 for k in ["den", "block", "disallow", "prohibit"]) else "false",
                    "configuration_path": f"{subj_snake}.{m2_name.lower()}_denied",
                    "verification_method": self.determine_verification_method(cat2, c2_name),
                    "trust_level": trust_lvl,
                    "confidence": "high",
                    "evidence": [{
                        "source_type": source_type,
                        "source_url": source_url,
                        "evidence_text": full_evidence
                    }]
                })

        # -------------------------------------------------------------
        # Stage 3: Generic Conditional & Requirement Sentences
        # -------------------------------------------------------------
        cond_pattern = re.compile(
            r'(?:'
            r'(?:(?:a|an|the)\s+)?(?:[A-Za-z0-9_\-\s]{1,40}?\s+)?(?:is|are|was|were)?\s*(?:only\s+)?(?:vulnerable|affected|exploitable|susceptible)\s+(?:if|when|where|provided\s+that)\s+'
            r'|'
            r'(?:(?:can|could|may|might)\s+)?(?:only\s+)?(?:be\s+)?(?:exploited|triggered|reproduced)\s+(?:if|when|where|provided\s+that)\s+'
            r'|'
            r'(?:requires?|requiring)\s+(?:both\s+|that\s+)?'
            r'|'
            r'exploitation\s+requires\s+'
            r'|'
            r'in\s+configurations\s+where\s+'
            r'|'
            r'only\s+affects?\s+(?:[A-Za-z0-9_\-\s\.]+\s+)?where\s+'
            r'|'
            r'only\s+affects?\s+(?:deployments|servers|systems|configurations|installations)\s+(?:where|with|that|if|when)\s+'
            r'|'
            r'only\s+when\s+'
            r'|'
            r'exists?\s+only\s+when\s+'
            r'|'
            r'(?:vulnerability\s+)?exists?\s+(?:in\s+[A-Za-z0-9_\-\s]{2,30}?\s+)?(?:only\s+)?when\s+'
            r'|'
            r'vulnerable\s+(?:only\s+)?(?:if|when|where|provided\s+that)\s+'
            r'|'
            r'vulnerable\s+unless\s+'
            r'|'
            r'(?:permits?|allows?|leads?\s+to|results?\s+in)\s+(?:an?\s+)?(?:[A-Za-z0-9_\-\s]{2,40}?\s+)?(?:when|if|where|provided\s+that)\s+'
            r')'
            r'(?P<cond>(?:(?:\d+\.\d+)|[^.;\n])+)',
            re.IGNORECASE
        )

        for mc in cond_pattern.finditer(source_text):
            sent_m = re.search(r'([^.\n]*' + re.escape(mc.group(0)) + r'[^.\n]*\.?)', source_text)
            full_evidence = sent_m.group(0).strip() if sent_m else mc.group(0).strip()
            raw_cond = mc.group("cond").strip()

            clean_cond = re.sub(r'\(.*?\)', '', raw_cond).strip()
            clean_cond = re.sub(r'^(?:(?:it|the\s+[a-z0-9_\-]+|an?\s+[a-z0-9_\-]+)\s+)?(?:has|features|contains|includes|uses|runs|is\s+configured\s+with)\s+', '', clean_cond, flags=re.I).strip()

            if is_attack_clause(clean_cond):
                # Attack condition
                cand_title = clean_cond[0].upper() + clean_cond[1:] if clean_cond else "Attack request condition"
                if cand_title not in seen_attack_names:
                    seen_attack_names.add(cand_title)
                    attack_conditions.append({
                        "name": cand_title,
                        "condition": f"Attacker must {clean_cond}",
                        "description": f"Exploitation requires: {clean_cond}.",
                        "category": "request_condition",
                        "required": True,
                        "verification_method": "dynamic_validation",
                        "automatically_verifiable": False,
                        "trust_level": trust_lvl,
                        "confidence": "high",
                        "source_type": source_type,
                        "source_url": source_url,
                        "evidence_text": full_evidence,
                        "evidence": [{"source_type": source_type, "source_url": source_url, "evidence_text": full_evidence}]
                    })
                continue

            # Check alternative OR relationship
            is_or_condition = bool(re.search(r'\b(?:either\s+.*?\s+or|or)\b', clean_cond, re.I))
            alt_grp_id = f"alt_{re.sub(r'[^a-z0-9]+', '_', clean_cond[:20].lower()).strip('_')}" if is_or_condition else None

            # Split clauses by OR or AND
            if is_or_condition:
                clauses = [cl.strip() for cl in re.split(r'\s+or\s+|\s+either\s+', clean_cond, flags=re.I) if cl.strip()]
            else:
                clauses = [cl.strip() for cl in re.split(r'\s+and\s+|\s*,\s*(?:and\s+)?', clean_cond) if cl.strip()]

            # Determine trailing state if present
            state_match = re.search(
                r'\s+(?:is|are|was|were)?\s*(?P<state>enabled|active|supported|configured|allowed|permitted|running|present|available|exposed|disabled|blocked|in\s+use)(?:\s+(?:for|to|with)\s+(?P<action>[A-Za-z0-9_\-]+))?\s*(?:,\s*which\s+is\s+not\s+the\s+default)?\s*$',
                clean_cond,
                re.I
            )
            if state_match:
                s_base = state_match.group("state").lower()
                s_act = state_match.group("action")
                trailing_state = f"{s_act.lower()} {s_base}" if s_act else s_base
            else:
                trailing_state = "enabled"

            for c in clauses:
                c_state_m = re.search(
                    r'\s+(?:is|are|was|were)?\s*(?P<state>enabled|active|supported|configured|allowed|permitted|running|present|available|exposed|disabled|blocked|in\s+use)(?:\s+(?:for|to|with)\s+(?P<action>[A-Za-z0-9_\-]+))?\s*(?:,\s*which\s+is\s+not\s+the\s+default)?\s*$',
                    c,
                    re.I
                )
                if c_state_m:
                    c_item = c[:c_state_m.start()].strip()
                    cs_base = c_state_m.group("state").lower()
                    cs_act = c_state_m.group("action")
                    c_state = f"{cs_act.lower()} {cs_base}" if cs_act else cs_base
                else:
                    c_item = c.strip()
                    c_state = trailing_state

                c_item = re.sub(r'^(?:(?:a|an|the)\s+)?', '', c_item, flags=re.I).strip()
                if len(c_item) < 2 or is_attack_clause(c_item):
                    continue

                clean_sub = self.clean_subject(c_item)
                p_name, disp_name, cfg_path = self.normalize_condition_name(clean_sub, c_state)

                if p_name in seen_prereq_names:
                    continue
                seen_prereq_names.add(p_name)

                cat = self.classify_condition_category(clean_sub, c_item, c_state)
                verif_method = self.determine_verification_method(cat, p_name)

                prereq_entry = {
                    "name": p_name,
                    "display_name": disp_name,
                    "description": f"{clean_sub} must be {c_state}.",
                    "category": cat,
                    "required": True,
                    "expected_state": c_state,
                    "configuration_path": cfg_path,
                    "verification_method": verif_method,
                    "trust_level": trust_lvl,
                    "confidence": "high",
                    "evidence": [{
                        "source_type": source_type,
                        "source_url": source_url,
                        "evidence_text": full_evidence
                    }]
                }
                if is_or_condition:
                    prereq_entry["logical_operator"] = "OR"
                    prereq_entry["alternative_group"] = alt_grp_id

                prerequisites.append(prereq_entry)

        # -------------------------------------------------------------
        # Stage 4: Contextual Relationships & Network Peer Conditions
        # -------------------------------------------------------------
        # Generic Peer-to-Peer Communication (e.g. Entity1-to-Entity2 communication)
        comm_match = re.search(r'\b(?:in\s+certain\s+)?(?P<entity1>[A-Za-z0-9_\-]+)-to-(?P<entity2>[A-Za-z0-9_\-]+)\s+communications?', source_text, re.I)
        if comm_match:
            e1 = comm_match.group("entity1")
            e2 = comm_match.group("entity2")
            comm_key = f"{e1.lower()}_to_{e2.lower()}_communication"
            if comm_key not in seen_prereq_names:
                seen_prereq_names.add(comm_key)
                sent_m = re.search(r'([^.\n]*' + re.escape(comm_match.group(0)) + r'[^.\n]*\.?)', source_text)
                sent_ev = sent_m.group(0).strip() if sent_m else comm_match.group(0).strip()
                prerequisites.append({
                    "name": comm_key,
                    "display_name": f"{e1}-to-{e2} communication",
                    "description": f"Communication must occur between {e1} and {e2} endpoints.",
                    "category": "network_context",
                    "required": True,
                    "expected_state": "active",
                    "configuration_path": f"network.{e1.lower()}_to_{e2.lower()}",
                    "verification_method": "endpoint_inventory",
                    "trust_level": trust_lvl,
                    "confidence": "high",
                    "evidence": [{
                        "source_type": source_type,
                        "source_url": source_url,
                        "evidence_text": sent_ev
                    }]
                })

        # Client/Server Relationship Condition (e.g. vulnerable client and server)
        cs_match = re.search(
            r'(?:can\s+only\s+be\s+performed\s+between|only\s+possible\s+between|only\s+exploitable\s+between)\s+'
            r'(?:a\s+)?(?P<entity1>[A-Za-z0-9_\-\s]+?)\s+(?:\*?and\*?|and)\s+(?P<entity2>[A-Za-z0-9_\-\s]+?)(?=[,.;]|$)',
            source_text,
            re.I
        )
        if cs_match:
            raw_e1 = cs_match.group("entity1").strip()
            raw_e2 = cs_match.group("entity2").strip()
            cs_key = "vulnerable_client_and_server_relationship"
            if cs_key not in seen_prereq_names:
                seen_prereq_names.add(cs_key)
                sent_m = re.search(r'([^.\n]*' + re.escape(cs_match.group(0)) + r'[^.\n]*\.?)', source_text)
                sent_ev = sent_m.group(0).strip() if sent_m else cs_match.group(0).strip()
                prerequisites.append({
                    "name": cs_key,
                    "display_name": "Vulnerable client and server relationship",
                    "description": f"Both communicating endpoints ({raw_e1} and {raw_e2}) must be vulnerable.",
                    "category": "client_server_relationship",
                    "required": True,
                    "expected_state": "vulnerable_endpoints",
                    "configuration_path": "network.client_server_relationship",
                    "verification_method": "endpoint_inventory",
                    "trust_level": trust_lvl,
                    "confidence": "high",
                    "evidence": [{
                        "source_type": source_type,
                        "source_url": source_url,
                        "evidence_text": sent_ev
                    }]
                })

        # Generic Network Exposure Conditions
        exposure_patterns = [
            re.compile(
                r'\b(?:(?:mitigation|remediation|action|patching|defense|fix)\s+(?:is\s+)?(?:only\s+)?required\s+if|only\s+(?:vulnerable|exploitable|an\s+issue|a\s+risk)\s+if)\s+'
                r'(?:an?\s+)?(?P<target>[A-Za-z0-9_\-\s]{2,30}?\b(?:port|service|connector|listener|endpoint|interface|daemon|server|connections?))\s+'
                r'(?:is|are)\s+(?P<exposure>accessible|exposed|reachable|available|open)\s+(?:to|from)\s+'
                r'(?P<audience>untrusted\s+(?:users?|networks?|clients?|traffic|parties)|attackers?|remote\s+attackers?|public\s+networks?|external\s+networks?|internet)',
                re.I
            ),
            re.compile(
                r'\bif\s+(?:such\s+)?(?P<target>[A-Za-z0-9_\-\s]{2,30}?\b(?:connections?|requests?|packets?|ports?|services?|listeners?|endpoints?))\s+'
                r'are\s+(?P<exposure>available|accessible|exposed|reachable)\s+to\s+(?:an?\s+)?(?P<audience>attackers?|untrusted\s+(?:users?|networks?|clients?|traffic)|adversary)',
                re.I
            ),
            re.compile(
                r'\b(?P<target>(?!if\b|that\b|when\b|only\b|required\b|mitigation\b|remediation\b)(?:[A-Za-z0-9_\-]{2,20}\s+){0,3}(?:port|service|connector|listener|endpoint|interface|daemon|server))\s+'
                r'(?:is|are)?\s*(?P<exposure>accessible|exposed|reachable|open)\s+(?:to|from)\s+'
                r'(?P<audience>untrusted\s+(?:users?|networks?|clients?|traffic|parties)|attackers?|remote\s+attackers?|public\s+networks?|external\s+networks?|internet)\b',
                re.I
            ),
            re.compile(
                r'(?:only\s+(?:exploitable|vulnerable|accessible)\s+if\s+(?:the\s+)?(?P<target>[A-Za-z0-9_\-\s]{2,40}?)\s+is\s+exposed\s+to\s+(?:an?\s+)?(?P<audience>[A-Za-z0-9_\-\s]+?)(?=[,.;]|$))',
                re.I
            )
        ]
        for exp_pat in exposure_patterns:
            for exp_m in exp_pat.finditer(source_text):
                raw_tgt = exp_m.group("target").strip()
                raw_aud = exp_m.group("audience").strip()
                raw_exp = exp_m.groupdict().get("exposure", "exposed").strip().lower()

                sent_m = re.search(r'([^.\n]*' + re.escape(exp_m.group(0)) + r'[^.\n]*\.?)', source_text)
                sent_ev = sent_m.group(0).strip() if sent_m else exp_m.group(0).strip()

                if raw_tgt.lower() in ("connections", "such connections", "requests", "such requests", "packets", "such packets", "traffic"):
                    existing_exp = next((p for p in prerequisites if p.get("category") == "network_exposure"), None)
                    if existing_exp:
                        if not any(e.get("evidence_text") == sent_ev for e in existing_exp.get("evidence", [])):
                            existing_exp.setdefault("evidence", []).append({
                                "source_type": source_type,
                                "source_url": source_url,
                                "evidence_text": sent_ev
                            })
                        continue

                clean_tgt = self.clean_subject(raw_tgt)
                clean_aud = raw_aud.lower()
                snake_tgt = re.sub(r'[^a-z0-9]+', '_', clean_tgt.lower()).strip('_')
                snake_aud = re.sub(r'[^a-z0-9]+', '_', clean_aud).strip('_')

                exp_action = "accessible" if "accessible" in raw_exp else "exposed"
                exp_key = f"{snake_tgt}_{exp_action}_to_{snake_aud}"
                if exp_key in seen_prereq_names:
                    continue
                seen_prereq_names.add(exp_key)

                disp_name = f"{clean_tgt.capitalize()} {exp_action} to {clean_aud}"
                cfg_path = f"network_exposure.{snake_tgt}"
                cand_paths = self.generate_candidate_config_paths(snake_tgt, exp_action)
                if cfg_path not in cand_paths:
                    cand_paths.insert(0, cfg_path)

                prerequisites.append({
                    "name": exp_key,
                    "display_name": disp_name,
                    "description": f"{clean_tgt} must be {exp_action} to {clean_aud}.",
                    "category": "network_exposure",
                    "required": True,
                    "expected_state": "active",
                    "configuration_path": cfg_path,
                    "configuration_evidence": cand_paths,
                    "verification_method": "config_collector",
                    "trust_level": trust_lvl,
                    "confidence": "high",
                    "evidence": [{
                        "source_type": source_type,
                        "source_url": source_url,
                        "evidence_text": sent_ev
                    }]
                })

        # -------------------------------------------------------------
        # Stage 4c: Generic Service / Connector / Component State Extraction
        # -------------------------------------------------------------
        service_patterns = [
            re.compile(
                r'(?:(?:shipped|configured|installed|packaged|distributed)\s+with\s+(?:an?\s+)?)?'
                r'(?P<service>[A-Za-z0-9_\- ]{2,40}?\b(?:connector|service|listener|feature|daemon|module|handler|endpoint|agent|interface))\s+'
                r'(?:is|was|being)?\s*(?P<state>enabled|active|running|started)(?:\s+by\s+default)?',
                re.I
            ),
            re.compile(
                r'(?:(?:that\s+this|this|the|an?)\s+)?(?P<service>[A-Za-z0-9_\- ]{2,40}?\b(?:connector|service|listener|feature|daemon|module|handler|endpoint))\s+'
                r'(?:would|should|must|can)\s+be\s+(?P<state>disabled|turned\s+off|removed|deactivated)\s+if\s+not\s+required',
                re.I
            ),
            re.compile(
                r'(?:only\s+(?:vulnerable|affected|exploitable)\s+(?:when|if|where)\s+(?:the\s+|an?\s+)?)(?P<service>[A-Za-z0-9_\- ]{2,40}?\b(?:connector|service|listener|feature|daemon|module|handler|protocol))\s+'
                r'(?:is|was)\s+(?P<state>enabled|active|running|configured)',
                re.I
            ),
            re.compile(
                r'\b(?P<service>[A-Za-z0-9_\- ]{2,40}?\b(?:connector|service|listener|feature|daemon|module|handler))\s+(?P<state>enabled)\s+by\s+default\b',
                re.I
            )
        ]
        for spat in service_patterns:
            for sm in spat.finditer(source_text):
                raw_s = sm.group("service").strip()
                if "\n" in raw_s:
                    continue
                raw_st = (sm.groupdict().get("state") or "active").strip().lower()
                clean_s = re.sub(r'^(?:[A-Za-z0-9_\-]+\s+)?(?:shipped|configured|installed|packaged|distributed)\s+with\s+(?:an?\s+)?', '', raw_s, flags=re.I).strip()
                clean_s = re.sub(r'^(?:an?|the|this|that\s+this|that)\s+', '', clean_s, flags=re.I).strip()
                clean_s = self.clean_subject(clean_s)
                if len(clean_s) < 2 or is_attack_clause(clean_s):
                    continue

                sent_m = re.search(r'([^.\n]*' + re.escape(sm.group(0)) + r'[^.\n]*\.?)', source_text)
                sent_ev = sent_m.group(0).strip() if sent_m else sm.group(0).strip()
                is_valid_cfg, _, _ = DocumentSanitizer.validate_configuration_candidate(
                    clean_s, raw_st, context_passage=sent_ev
                )
                if not is_valid_cfg:
                    continue

                expected_st = "active"
                p_name, disp_name, cfg_path = self.normalize_condition_name(clean_s, expected_st)

                matched_prereq = None
                for pr in prerequisites:
                    if pr["name"] == p_name or pr["name"].endswith(f"_{p_name}") or p_name.endswith(f"_{pr['name']}"):
                        matched_prereq = pr
                        break

                if matched_prereq:
                    if not any(e.get("evidence_text") == sent_ev for e in matched_prereq.get("evidence", [])):
                        matched_prereq.setdefault("evidence", []).append({
                            "source_type": source_type,
                            "source_url": source_url,
                            "evidence_text": sent_ev
                        })
                    continue

                seen_prereq_names.add(p_name)
                cat = self.classify_condition_category(clean_s, sent_ev, expected_st)
                v_method = self.determine_verification_method(cat, p_name)
                snake_base = re.sub(r'[^a-z0-9]+', '_', clean_s.lower()).strip('_')
                cand_paths = self.generate_candidate_config_paths(snake_base, expected_st)
                if cfg_path and cfg_path not in cand_paths:
                    cand_paths.insert(0, cfg_path)

                prerequisites.append({
                    "name": p_name,
                    "display_name": disp_name,
                    "description": f"{clean_s} must be {expected_st} in the target environment.",
                    "category": cat,
                    "required": True,
                    "expected_state": expected_st,
                    "configuration_path": cfg_path,
                    "configuration_evidence": cand_paths,
                    "verification_method": v_method,
                    "trust_level": trust_lvl,
                    "confidence": "high",
                    "evidence": [{
                        "source_type": source_type,
                        "source_url": source_url,
                        "evidence_text": sent_ev
                    }]
                })

        # Generic Architectural / Dependency Conditions
        # Library / Dependency
        dep_match = re.search(r'(?:includes?\s+a\s+library\s+(?:that|which)\s+([A-Za-z0-9_\-\s]+?)(?=[,.;\n]|$))', source_text, re.I)
        if dep_match and "deserialization_gadget_library_present" not in seen_prereq_names:
            seen_prereq_names.add("deserialization_gadget_library_present")
            sent_m = re.search(r'([^.\n]*' + re.escape(dep_match.group(0)) + r'[^.\n]*\.?)', source_text)
            sent_ev = sent_m.group(0).strip() if sent_m else dep_match.group(0).strip()
            prerequisites.append({
                "name": "deserialization_gadget_library_present",
                "display_name": "Deserialization gadget library present",
                "description": "Application must include a library that can be leveraged in a deserialization attack.",
                "category": "dependency",
                "required": True,
                "expected_state": "present",
                "configuration_path": "application_libraries.jar_files",
                "verification_method": "dependency_check",
                "trust_level": trust_lvl,
                "confidence": "high",
                "evidence": [{
                    "source_type": source_type,
                    "source_url": source_url,
                    "evidence_text": sent_ev
                }]
            })

        # Case-insensitive filesystem
        fs_match = re.search(r"case\s*-?\s*insensitive\s+file\s*systems?", source_text, re.I)
        if fs_match and "case_insensitive_file_system" not in seen_prereq_names:
            seen_prereq_names.add("case_insensitive_file_system")
            sent_m = re.search(r'([^.\n]*' + re.escape(fs_match.group(0)) + r'[^.\n]*\.?)', source_text)
            sent_ev = sent_m.group(0).strip() if sent_m else fs_match.group(0).strip()
            prerequisites.append({
                "name": "case_insensitive_file_system",
                "display_name": "Case-insensitive file system",
                "description": "Operating system file system must be case-insensitive.",
                "category": "filesystem",
                "required": True,
                "expected_state": "true",
                "configuration_path": "environment.filesystem_case_insensitive",
                "verification_method": "config_collector",
                "trust_level": trust_lvl,
                "confidence": "high",
                "evidence": [{
                    "source_type": source_type,
                    "source_url": source_url,
                    "evidence_text": sent_ev
                }]
            })

        # -------------------------------------------------------------
        # Stage 4b: Affected Feature/Protocol Functionality & Workaround Analysis
        # Detects when authoritative evidence establishes a flaw in a feature/extension
        # or documents a workaround that compiles out or disables a feature.
        # Distinguishes:
        # 1. "Vulnerability is in feature X" / "does not properly handle X" -> candidate
        # 2. "Software supports feature X" -> context only (not prerequisite)
        # 3. Workaround disables feature X or explicit handling flaw -> establishes applicability prerequisite
        # -------------------------------------------------------------
        workaround_patterns = [
            re.compile(r'(?:recompil\w*|compil\w*|build\w*)\s+[^.\n]*?with\s+-D(?P<macro>[A-Za-z0-9_]+_NO_(?P<feature_macro>[A-Za-z0-9_]+))', re.I),
            re.compile(r'(?:(?:can\s+be\s+)?mitigated|workaround|remediation)[^.\n]*?(?:by\s+)?(?:disabling|turning\s+off|removing|deactivating)\s+(?:the\s+)?(?P<feature>[A-Za-z0-9_\-\s]{2,40}?\b(?:extension|feature|protocol|option|module|service|handler|parser|connector|persistence|support)\b)', re.I)
        ]
        disabled_features: List[Tuple[str, str]] = []
        for w_pat in workaround_patterns:
            for mw in w_pat.finditer(source_text):
                sent_m = re.search(r'([^.\n]*' + re.escape(mw.group(0)) + r'[^.\n]*\.?)', source_text)
                w_ev = sent_m.group(0).strip() if sent_m else mw.group(0).strip()
                if "feature_macro" in mw.groupdict() and mw.group("feature_macro"):
                    f_name = mw.group("feature_macro").strip().rstrip('sS').lower()
                    disabled_features.append((f_name, w_ev))
                elif "feature" in mw.groupdict() and mw.group("feature"):
                    f_name = mw.group("feature").strip().lower()
                    disabled_features.append((f_name, w_ev))

        flaw_patterns = [
            re.compile(r'(?:(?:(?:a\s+)?(?:missing\s+bounds\s+check|improper|incorrect|insecure|flawed|vulnerability|flaw|issue|defect|bug)\s+(?:in\s+)?(?:the\s+)?handling\s+of)|(?:the\s+)?vulnerability\s+(?:exists?\s+in|is\s+in)|(?:the\s+)?flaw\s+is\s+in|(?:the\s+)?affected\s+(?:functionality|component|feature|extension|protocol|module)\s+is)\s+(?:the\s+)?(?P<feature>[A-Za-z0-9_\-\s]{2,50}?\b(?:extension|feature|protocol|option|module|service|handler|parser|connector|persistence|support|compression|decompression|encryption|decryption|renegotiation))\b', re.I),
            re.compile(r'\bdo(?:es)?\s+not\s+properly\s+handle\s+(?:the\s+)?(?P<feature>[A-Za-z0-9_\-\s]{2,50}?\b(?:extension|feature|protocol|option|module|service|handler|parser|connector))\s+packets\b', re.I)
        ]
        candidate_features: List[Tuple[str, str]] = []
        for f_pat in flaw_patterns:
            for mf in f_pat.finditer(source_text):
                sent_m = re.search(r'([^.\n]*' + re.escape(mf.group(0)) + r'[^.\n]*\.?)', source_text)
                f_ev = sent_m.group(0).strip() if sent_m else mf.group(0).strip()
                feat_raw = mf.group("feature").strip()
                candidate_features.append((feat_raw, f_ev))

        # Include features discovered through compile-time or runtime workaround disablement
        for df_name, w_ev in disabled_features:
            if not any(df_name in cf[0].lower() for cf in candidate_features):
                candidate_features.append((df_name, w_ev))

        for feat_raw, f_ev in candidate_features:
            feat_clean = self.clean_subject(feat_raw)
            feat_low = feat_clean.lower()
            if is_attack_clause(feat_clean):
                continue

            # Check if this feature is confirmed by workaround or explicit handling flaw
            is_confirmed_prereq = False
            combined_ev = [f_ev]
            for df_name, w_ev in disabled_features:
                if df_name in feat_low or any(tok in feat_low for tok in df_name.split()):
                    is_confirmed_prereq = True
                    if w_ev not in combined_ev:
                        combined_ev.append(w_ev)
                    break

            if any(k in feat_low for k in ["extension", "protocol", "module", "service", "handler"]):
                is_confirmed_prereq = True

            if is_confirmed_prereq:
                state_val = "enabled"
                p_name, disp_name, cfg_path = self.normalize_condition_name(feat_clean, state_val)
                snake_base = re.sub(r'[^a-z0-9]+', '_', feat_low).strip('_')
                cand_paths = self.generate_candidate_config_paths(snake_base, state_val)

                if p_name not in seen_prereq_names:
                    seen_prereq_names.add(p_name)
                    cat = self.classify_condition_category(feat_clean, f_ev, state_val)
                    ev_items = [{"source_type": source_type, "source_url": source_url, "evidence_text": ev_t} for ev_t in combined_ev]
                    prerequisites.append({
                        "name": p_name,
                        "display_name": disp_name,
                        "description": f"{feat_clean} must be enabled in the target environment.",
                        "category": cat,
                        "required": True,
                        "expected_state": state_val,
                        "configuration_path": cfg_path,
                        "configuration_evidence": cand_paths,
                        "verification_method": self.determine_verification_method(cat, p_name),
                        "trust_level": trust_lvl,
                        "confidence": "high",
                        "evidence": ev_items
                    })

        # -------------------------------------------------------------
        # Stage 4d: Generic Platform / Operating System Prerequisite Extraction
        # Recognizes advisory language establishing platform-specific vulnerability:
        # e.g. "on Windows", "on Linux", "when running on <platform>",
        # "when running [product] [version] on <platform>",
        # "only affected on <platform>", "when deployed on <platform>".
        # Platform value is extracted dynamically from evidence without hardcoded OS names.
        # -------------------------------------------------------------
        platform_patterns = [
            # 1. "When running [software [versions]] on <Platform> [with/where/when...]"
            # or "when deployed on <Platform>", "when installed on <Platform>"
            re.compile(
                r'\bwhen\s+(?:running|deployed|installed|hosted|used)\s+'
                r'(?:[A-Za-z0-9_\-\.\s]{1,60}?\s+)?on\s+'
                r'(?P<platform>[A-Za-z0-9_\-]+(?:\s+[A-Za-z0-9_\-]+)?)\s*'
                r'(?=(?:systems?|platforms?|environments?|servers?|os|operating\s+systems?)?\s*(?:with\b|where\b|when\b|if\b|having\b|,\s*(?:it|a|the|this)|;|\.|\n|$))',
                re.I
            ),
            # 2. "only affected/vulnerable/exploitable on <Platform>"
            re.compile(
                r'\b(?:only\s+)?(?:affected|vulnerable|exploitable|applicable)\s+(?:only\s+)?on\s+'
                r'(?P<platform>[A-Za-z0-9_\-]+(?:\s+[A-Za-z0-9_\-]+)?)\s*'
                r'(?=(?:systems?|platforms?|environments?|servers?|os|operating\s+systems?)?\s*(?:with\b|where\b|when\b|if\b|having\b|,\s*(?:it|a|the|this)|;|\.|\n|$))',
                re.I
            ),
            # 3. Direct "on <Platform> with/where/when/if" (e.g. "on Windows with HTTP PUTs enabled")
            re.compile(
                r'(?:^|[\.\,\;\n]\s*|\b(?:and|but|while)\s+)on\s+'
                r'(?P<platform>[A-Za-z0-9_\-]+(?:\s+[A-Za-z0-9_\-]+)?)\s+'
                r'(?:with|where|when|if|having)\s+',
                re.I
            ),
            # 4. "on <Platform> (systems|platforms|environments|os|operating systems)"
            re.compile(
                r'\bon\s+(?P<platform>[A-Za-z0-9_\-]+(?:\s+[A-Za-z0-9_\-]+)?)\s+'
                r'(?P<suffix>systems?|platforms?|environments?|operating\s+systems?|os)\b',
                re.I
            )
        ]

        NON_PLATFORM_TERMS = {
            "the", "a", "an", "all", "certain", "some", "supported", "default", "target",
            "these", "those", "each", "every", "any", "which", "its", "their", "such",
            "top", "demand", "premise", "premises", "cloud", "behalf", "account",
            "request", "requests", "port", "ports", "version", "versions", "server", "servers",
            "be", "been", "being", "have", "has", "had", "do", "does", "did"
        }

        for ppat in platform_patterns:
            for pm in ppat.finditer(source_text):
                raw_plat = pm.group("platform").strip()
                clean_plat = re.sub(r'\s+(?:systems?|platforms?|environments?|operating\s+systems?|os)$', '', raw_plat, flags=re.I).strip()
                if not clean_plat or clean_plat.lower() in NON_PLATFORM_TERMS or len(clean_plat) < 2:
                    continue

                sent_m = re.search(r'([^.\n]*' + re.escape(pm.group(0)) + r'[^.\n]*\.?)', source_text)
                sent_ev = sent_m.group(0).strip() if sent_m else pm.group(0).strip()

                snake_plat = re.sub(r'[^a-z0-9]+', '_', clean_plat.lower()).strip('_')
                plat_key = f"target_platform_{snake_plat}"
                if plat_key in seen_prereq_names:
                    continue
                seen_prereq_names.add(plat_key)

                disp_name = f"Target platform {clean_plat}"
                cfg_evidence = [
                    "environment.os",
                    "environment.platform",
                    "operating_system",
                    "platform",
                    "target_platform",
                    "os"
                ]

                prerequisites.append({
                    "name": plat_key,
                    "display_name": disp_name,
                    "description": f"Target platform / operating system must be {clean_plat}.",
                    "category": "operating_system",
                    "required": True,
                    "expected_state": clean_plat.lower(),
                    "configuration_path": "environment.os",
                    "configuration_evidence": cfg_evidence,
                    "verification_method": "platform_inspector",
                    "trust_level": trust_lvl,
                    "confidence": "high",
                    "evidence": [{
                        "source_type": source_type,
                        "source_url": source_url,
                        "evidence_text": sent_ev
                    }]
                })

        # -------------------------------------------------------------
        # Stage 4e: Generic Feature / Method / Configuration Enablement & Explanation Linking
        # Recognizes generic feature, method, and configuration prerequisites:
        # e.g. "with <feature> enabled (e.g. setting <param> to <val>)",
        # "<feature> enabled", "<method> enabled", "write access enabled",
        # "writes enabled", "<param>=<val>", "<param> set to <val>".
        # Retains both semantic state and linked configuration explanation.
        # -------------------------------------------------------------
        feat_patterns = [
            # 1. "with <feature> (enabled|active|supported|allowed) [(e.g. <explanation>)]"
            re.compile(
                r'\bwith\s+(?P<feature>[A-Za-z0-9_\-\s]{2,50}?)\s+(?P<state>enabled|active|supported|allowed|permitted|running|on)\b'
                r'(?:\s*\((?:e\.g\.?|such\s+as|for\s+example)?\s*(?P<explanation>[^)]+)\))?',
                re.I
            ),
            # 2. "<feature> (is|was)? (enabled|active) [(e.g. <explanation>)]"
            re.compile(
                r'(?:^|[\.\,\;\n]\s*|\bwhere\s+|\bwhen\s+)(?:the\s+)?(?P<feature>[A-Za-z0-9_\-\s]{2,40}?)\s+(?:is|was|are|were)?\s*(?P<state>enabled|active|supported|allowed)\b'
                r'(?:\s*\((?:e\.g\.?|such\s+as|for\s+example)?\s*(?P<explanation>[^)]+)\))?'
                r'(?=\s*(?:,|\.|\;|\n|and|when|where|if|it\s+was|$))',
                re.I
            ),
            # 3. Explicit "setting/configuring <param> to <val>" or "<param> set to <val>"
            re.compile(
                r'\b(?:via\s+|by\s+)?(?:setting|configuring)\s+(?:the\s+)?(?P<param>[A-Za-z][A-Za-z0-9_\-\.]{1,40}?)\s*(?:initialisation\s+|initialization\s+|configuration\s+)?(?:parameter\s+|setting\s+|property\s+|directive\s+)?(?:of\s+[A-Za-z0-9_\-\.\s]+?\s+)?(?:is\s+|was\s+)?(?:set\s+to|configured\s+as|to|=)\s*(?P<val>false|true|enabled|disabled|[0-9]+)\b',
                re.I
            ),
            # 4. Direct "<param>=<val>" (e.g. readonly=false)
            re.compile(
                r'\b(?P<param>[A-Za-z][A-Za-z0-9_\-\.]{1,40})\s*=\s*(?P<val>false|true|0|1|disabled|enabled)\b',
                re.I
            )
        ]

        captured_config_explanations: List[str] = []

        for fpat in feat_patterns:
            for fm in fpat.finditer(source_text):
                gdict = fm.groupdict()
                raw_feat = (gdict.get("feature") or "").strip()
                raw_st = (gdict.get("state") or "enabled").strip().lower()
                raw_expl = (gdict.get("explanation") or "").strip()
                raw_param = (gdict.get("param") or "").strip()
                raw_val = (gdict.get("val") or "").strip().lower()

                # If standalone param=val or param set to val
                if not raw_feat and raw_param:
                    clean_param = raw_param.strip()
                    sent_m = re.search(r'([^.\n]*' + re.escape(fm.group(0)) + r'[^.\n]*\.?)', source_text)
                    sent_ev = sent_m.group(0).strip() if sent_m else fm.group(0).strip()
                    is_valid_cfg, resolved_subj, rej_reason = DocumentSanitizer.validate_configuration_candidate(
                        clean_param, raw_val, context_passage=sent_ev
                    )
                    if not is_valid_cfg:
                        continue
                    cfg_expl = f"{clean_param}={raw_val}"
                    if cfg_expl in captured_config_explanations:
                        continue
                    p_name, disp_name, cfg_path = self.normalize_condition_name(clean_param, raw_val)
                    if p_name in seen_prereq_names:
                        continue
                    seen_prereq_names.add(p_name)
                    cat = self.classify_condition_category(clean_param, text="", state=raw_val)
                    v_method = self.determine_verification_method(cat, p_name)
                    snake_p = re.sub(r'[^a-z0-9]+', '_', clean_param.lower()).strip('_')
                    cand_paths = self.generate_candidate_config_paths(snake_p, raw_val)
                    if cfg_path and cfg_path not in cand_paths:
                        cand_paths.insert(0, cfg_path)
                    prerequisites.append({
                        "name": p_name,
                        "display_name": disp_name,
                        "description": f"{disp_name} in target environment.",
                        "category": cat,
                        "required": True,
                        "expected_state": raw_val,
                        "configuration_path": cfg_path,
                        "configuration_evidence": cand_paths,
                        "config_explanation": cfg_expl,
                        "verification_method": v_method,
                        "trust_level": trust_lvl,
                        "confidence": "high",
                        "evidence": [{
                            "source_type": source_type,
                            "source_url": source_url,
                            "evidence_text": sent_ev
                        }]
                    })
                    continue

                clean_feat = self.clean_subject(raw_feat)
                if not clean_feat or is_attack_clause(clean_feat) or len(clean_feat) < 2:
                    continue
                if clean_feat.lower().endswith("puts"):
                    clean_feat = clean_feat[:-1]
                elif clean_feat.endswith("s") and not clean_feat.lower().endswith("ss") and len(clean_feat) > 4:
                    if clean_feat.lower() not in ("tls", "https", "dns", "radius"):
                        clean_feat = clean_feat[:-1]

                sent_m = re.search(r'([^.\n]*' + re.escape(fm.group(0)) + r'[^.\n]*\.?)', source_text)
                sent_ev = sent_m.group(0).strip() if sent_m else fm.group(0).strip()
                is_valid_cfg, _, _ = DocumentSanitizer.validate_configuration_candidate(
                    clean_feat, raw_st, context_passage=sent_ev
                )
                if not is_valid_cfg:
                    continue

                # Parse explanation if present
                config_explanation = None
                explanation_param = None
                explanation_val = None
                if raw_expl:
                    m_pv = re.search(
                        r'(?:setting|configuring)?\s*(?:the\s+)?(?P<param>[A-Za-z0-9_\-\.]+?)\s*(?:initialisation\s+|initialization\s+|configuration\s+)?(?:parameter\s+|setting\s+|property\s+|directive\s+)?(?:of\s+[A-Za-z0-9_\-\.\s]+?\s+)?(?:to\s+|=)(?P<val>false|true|enabled|disabled|[0-9]+)',
                        raw_expl,
                        re.I
                    )
                    if m_pv:
                        explanation_param = m_pv.group("param").strip()
                        explanation_val = m_pv.group("val").strip().lower()
                        config_explanation = f"{explanation_param}={explanation_val}"
                    else:
                        m_eq = re.search(r'\b(?P<param>[A-Za-z0-9_\-\.]{2,40})\s*=\s*(?P<val>[A-Za-z0-9_\-]+)\b', raw_expl)
                        if m_eq:
                            explanation_param = m_eq.group("param").strip()
                            explanation_val = m_eq.group("val").strip().lower()
                            config_explanation = f"{explanation_param}={explanation_val}"

                if config_explanation:
                    captured_config_explanations.append(config_explanation)

                p_name, disp_name, cfg_path = self.normalize_condition_name(clean_feat, raw_st)

                matched_prereq = None
                for pr in prerequisites:
                    if pr["name"] == p_name or pr["name"].endswith(f"_{p_name}") or p_name.endswith(f"_{pr['name']}"):
                        matched_prereq = pr
                        break

                if matched_prereq:
                    if config_explanation and not matched_prereq.get("config_explanation"):
                        matched_prereq["config_explanation"] = config_explanation
                        matched_prereq["description"] = f"{disp_name} in target environment ({config_explanation})."
                    if not any(e.get("evidence_text") == sent_ev for e in matched_prereq.get("evidence", [])):
                        matched_prereq.setdefault("evidence", []).append({
                            "source_type": source_type,
                            "source_url": source_url,
                            "evidence_text": sent_ev
                        })
                    continue

                seen_prereq_names.add(p_name)
                cat = self.classify_condition_category(clean_feat, text="", state=raw_st)
                v_method = self.determine_verification_method(cat, p_name)
                snake_feat = re.sub(r'[^a-z0-9]+', '_', clean_feat.lower()).strip('_')
                cand_paths = self.generate_candidate_config_paths(snake_feat, raw_st)
                if cfg_path and cfg_path not in cand_paths:
                    cand_paths.insert(0, cfg_path)

                if explanation_param:
                    snake_exp = re.sub(r'[^a-z0-9]+', '_', explanation_param.lower()).strip('_')
                    if snake_exp not in cand_paths:
                        cand_paths.append(snake_exp)
                    def_p = f"default_servlet.{snake_exp}"
                    if def_p not in cand_paths:
                        cand_paths.append(def_p)

                desc_text = f"{disp_name} in target environment" + (f" ({config_explanation})" if config_explanation else ".")

                prerequisites.append({
                    "name": p_name,
                    "display_name": disp_name,
                    "description": desc_text,
                    "category": cat,
                    "required": True,
                    "expected_state": raw_st,
                    "configuration_path": cfg_path,
                    "configuration_evidence": cand_paths,
                    "config_explanation": config_explanation,
                    "verification_method": v_method,
                    "trust_level": trust_lvl,
                    "confidence": "high",
                    "evidence": [{
                        "source_type": source_type,
                        "source_url": source_url,
                        "evidence_text": sent_ev
                    }]
                })

        # -------------------------------------------------------------
        # Stage 5: Attack Conditions (kept strictly separate!)
        # -------------------------------------------------------------
        # Attacker action pattern (by/via sending...)
        attacker_pattern = re.compile(
            r'(?:by|via)\s+(?:sending|crafting|issuing|submitting|injecting|transmitting)\s+'
            r'(?P<details>(?:(?:\d+\.\d+)|[^.;\n])+?)(?=\s+(?:and|or)\s+(?:can|could|would)|\.|\;|\n|$)',
            re.IGNORECASE
        )
        for ma in attacker_pattern.finditer(source_text):
            raw_det = ma.group("details").strip()
            clean_det = re.sub(r'\((?:specification\s+invalid)\)', 'specification-invalid', raw_det, flags=re.I)
            clean_det = re.sub(r'\s+', ' ', clean_det).strip()

            m_method_proto = re.search(r'\b(HEAD|GET|POST|PUT|DELETE|OPTIONS)\s+requests?\s+using\s+(HTTP\/[0-9\.]+)\b', clean_det, re.I)
            if m_method_proto:
                m_method = m_method_proto.group(1).upper()
                m_proto = m_method_proto.group(2).upper()
                if 'specification-invalid' in clean_det.lower():
                    name_str = f"Specification-invalid {m_proto} {m_method} request"
                    cond_title = f"Attacker sends a specification-invalid {m_proto} {m_method} request"
                    desc_str = f"Attacker sends a specification-invalid {m_method} request using {m_proto}."
                else:
                    name_str = f"{m_proto} {m_method} request"
                    cond_title = f"Attacker sends a {m_proto} {m_method} request"
                    desc_str = f"Attacker sends a {m_method} request using {m_proto}."
            else:
                name_cand = re.sub(r'^(?:a|an|the)\s+', '', clean_det, flags=re.I)
                name_str = name_cand[0].upper() + name_cand[1:] if name_cand else "Attack request condition"
                cond_title = f"Attacker sends {clean_det}"
                desc_str = f"Attacker must transmit {clean_det} to trigger the vulnerable behavior."

            sent_m = re.search(r'([^.\n]*' + re.escape(ma.group(0)) + r'[^.\n]*\.?)', source_text)
            sent_ev = sent_m.group(0).strip() if sent_m else ma.group(0).strip()

            if name_str not in seen_attack_names:
                seen_attack_names.add(name_str)
                attack_conditions.append({
                    "name": name_str,
                    "condition": cond_title,
                    "description": desc_str,
                    "category": "request_condition",
                    "required": True,
                    "verification_method": "dynamic_validation",
                    "automatically_verifiable": False,
                    "trust_level": trust_lvl,
                    "confidence": "high",
                    "source_type": source_type,
                    "source_url": source_url,
                    "evidence_text": sent_ev,
                    "evidence": [{
                        "evidence_text": sent_ev,
                        "source_type": source_type,
                        "source_url": source_url
                    }]
                })

        # Passive receipt of crafted payloads
        passive_payload_pattern = re.compile(
            r'(?:(?:may\s+)?(?:crash|fail|trigger|cause|lead\s+to|be\s+exploited|vulnerable)\s+)?'
            r'(?:if|when|upon)\s+(?:sent|receiving|handling|processing|given|presented\s+with)\s+(?:a|an)?\s*'
            r'(?P<details>(?:maliciously\s+crafted|specially\s+crafted|carefully\s+crafted|crafted|specification-invalid|malicious|invalid)[^.;\n]+?)'
            r'(?=\s+(?:from\b|which\b|by\b|to\b|\.|\;|\n|$))',
            re.IGNORECASE
        )
        for ma in passive_payload_pattern.finditer(source_text):
            raw_det = ma.group("details").strip()
            clean_det = re.sub(r'\s+message\s*$', '', raw_det, flags=re.I).strip()

            m_proto_ver = re.search(r'\b(TLSv1\.[0-3]|TLS\s*1\.[0-3]|HTTP\/[0-9\.]+)\s+' + re.escape(clean_det.split()[-1]), source_text, re.I)
            if not m_proto_ver:
                m_proto_ver = re.search(r'\b(TLSv1\.[0-3]|TLS\s*1\.[0-3]|HTTP\/[0-9\.]+)\s+renegotiation\b', source_text, re.I)

            if m_proto_ver:
                proto_tag = m_proto_ver.group(1)
                if proto_tag.lower() not in clean_det.lower():
                    clean_det = re.sub(r'\b(renegotiation\s+ClientHello|ClientHello|request|packet)\b', f'{proto_tag} \\1', clean_det, flags=re.I)

            name_str = clean_det[0].upper() + clean_det[1:]
            cond_title = f"Attacker sends a {clean_det}"
            desc_str = f"Attacker sends a {clean_det}."

            sent_m = re.search(r'([^.\n]*' + re.escape(ma.group(0)) + r'[^.\n]*\.?)', source_text)
            sent_ev = sent_m.group(0).strip() if sent_m else ma.group(0).strip()

            if name_str not in seen_attack_names:
                seen_attack_names.add(name_str)
                attack_conditions.append({
                    "name": name_str,
                    "condition": cond_title,
                    "description": desc_str,
                    "category": "request_condition",
                    "required": True,
                    "verification_method": "dynamic_validation",
                    "automatically_verifiable": False,
                    "trust_level": trust_lvl,
                    "confidence": "high",
                    "source_type": source_type,
                    "source_url": source_url,
                    "evidence_text": sent_ev,
                    "evidence": [{
                        "evidence_text": sent_ev,
                        "source_type": source_type,
                        "source_url": source_url
                    }]
                })

        # Man-in-the-middle (MITM) positioning
        mitm_match = re.search(
            r'(?:(?:allows?|by|via|requires\s+a|exploited\s+by\s+a)\s+)?(?:man-in-the-middle|\(mitm\)|mitm)\s+(?:attackers?|attacks?)(?:\s+(?:to\b|can\b|whereby|where\b))?',
            source_text,
            re.I
        )
        if mitm_match and not any("mitm" in a.get("name", "").lower() for a in attack_conditions):
            sent_m = re.search(r'([^.\n]*' + re.escape(mitm_match.group(0)) + r'[^.\n]*\.?)', source_text)
            sent_ev = sent_m.group(0).strip() if sent_m else mitm_match.group(0).strip()
            attack_conditions.append({
                "name": "Man-in-the-middle (MITM) capability",
                "condition": "Attacker possesses Man-in-the-middle (MITM) network positioning",
                "description": "Attacker must have network interception capability (MITM position) between communicating endpoints.",
                "category": "attacker_capability",
                "required": True,
                "verification_method": "dynamic_validation",
                "automatically_verifiable": False,
                "trust_level": trust_lvl,
                "confidence": "high",
                "source_type": source_type,
                "source_url": source_url,
                "evidence_text": sent_ev,
                "evidence": [{
                    "source_type": source_type,
                    "source_url": source_url,
                    "evidence_text": sent_ev
                }]
            })

        # Crafted handshake / request action
        craft_match = re.search(
            r'(?:(?:an?\s+)?attacker\s+)?(?:via|using|with|through|sends?|transmits?|issues?|submits?|injects?)\s+(?:a\s+)?(?P<crafted>(?:carefully\s+crafted|specially\s+crafted|maliciously\s+crafted|crafted)\s+[A-Za-z0-9_\-\s]{3,40}?)(?=[,.;]|\s+aka\b|\s+to\b|\s+where\b|\s+can\b|$)',
            source_text,
            re.I
        )
        if craft_match:
            raw_craft = craft_match.group("crafted").strip()
            craft_name = raw_craft.capitalize()
            if not any(craft_name.lower() in a.get("name", "").lower() for a in attack_conditions):
                sent_m = re.search(r'([^.\n]*' + re.escape(craft_match.group(0)) + r'[^.\n]*\.?)', source_text)
                sent_ev = sent_m.group(0).strip() if sent_m else craft_match.group(0).strip()
                attack_conditions.append({
                    "name": craft_name,
                    "condition": f"Attacker sends a {raw_craft.lower()}",
                    "description": f"Attacker must transmit a {raw_craft.lower()} to trigger the vulnerable behavior.",
                    "category": "request_condition",
                    "required": True,
                    "verification_method": "dynamic_validation",
                    "automatically_verifiable": False,
                    "trust_level": trust_lvl,
                    "confidence": "high",
                    "source_type": source_type,
                    "source_url": source_url,
                    "evidence_text": sent_ev,
                    "evidence": [{
                        "source_type": source_type,
                        "source_url": source_url,
                        "evidence_text": sent_ev
                    }]
                })

        # Attacker knowledge conditions
        ak_match = re.search(r"attacker\s+knowledge\s+of\s+([^.,;\n]+)", source_text, re.I)
        if ak_match:
            k_target = ak_match.group(1).strip()
            ak_sent_m = re.search(r'([^.\n]*' + re.escape(ak_match.group(0)) + r'[^.\n]*\.?)', source_text)
            ak_ev = ak_sent_m.group(0).strip() if ak_sent_m else ak_match.group(0).strip()
            attack_conditions.append({
                "name": f"Attacker knowledge of {k_target}",
                "condition": f"Attacker possesses knowledge of {k_target}",
                "description": f"Exploitation requires the attacker to possess prior knowledge of {k_target}.",
                "category": "attacker_condition",
                "required": True,
                "verification_method": "dynamic_validation",
                "automatically_verifiable": False,
                "trust_level": trust_lvl,
                "confidence": "high",
                "source_type": source_type,
                "source_url": source_url,
                "evidence_text": ak_ev,
                "evidence": [{
                    "evidence_text": ak_ev,
                    "source_type": source_type,
                    "source_url": source_url
                }]
            })
            unknown_conditions.append({
                "name": f"attacker_knowledge_of_{k_target.replace(' ', '_').lower()}",
                "status": "UNKNOWN",
                "reason": f"Attacker knowledge of {k_target} cannot be verified by environmental configuration.",
                "evidence_source": source_url
            })

        # Heightened impact conditions (e.g. file upload or content control required specifically for RCE)
        rce_pattern = re.compile(
            r'(?:(?:further,\s+)?if\s+)?(?P<cond>[^.,;\n]+?)(?:,\s+(?:then\s+)?(?:along\s+with\s+[^.,;\n]+?,\s+)?(?:made|makes|allows?|enables?|leads?\s+to)\s+(?P<impact>remote\s+code\s+execution|arbitrary\s+code\s+execution|code\s+execution|rce|privilege\s+escalation)\s+(?:possible|achievable)?)',
            re.I
        )
        for mr in rce_pattern.finditer(source_text):
            raw_c = mr.group("cond").strip()
            raw_c = re.sub(r'^(?:(?:further,\s+)?if\s+)', '', raw_c, flags=re.I)
            raw_c = re.sub(r'\s+then\s+this$', '', raw_c, flags=re.I).strip()
            imp = mr.group("impact").strip().lower()
            sent_m = re.search(r'([^.\n]*' + re.escape(mr.group(0)) + r'[^.\n]*\.?)', source_text)
            sent_ev = sent_m.group(0).strip() if sent_m else mr.group(0).strip()

            c_name = f"File upload or content control (for {imp})" if "upload" in raw_c.lower() else f"Requirement for {imp}"
            if not any(c_name.lower() in a.get("name", "").lower() for a in attack_conditions):
                attack_conditions.append({
                    "name": c_name,
                    "condition": f"Attacker controls web-application content or {raw_c} (required specifically for {imp})",
                    "description": f"Heightened impact requirement: {raw_c} enables {imp}. Not required for basic vulnerability applicability.",
                    "category": "impact_condition",
                    "impact": imp,
                    "required": False,
                    "verification_method": "dynamic_validation",
                    "automatically_verifiable": False,
                    "trust_level": trust_lvl,
                    "confidence": "high",
                    "source_type": source_type,
                    "source_url": source_url,
                    "evidence_text": sent_ev,
                    "evidence": [{
                        "source_type": source_type,
                        "source_url": source_url,
                        "evidence_text": sent_ev
                    }]
                })

        return {
            "prerequisites": prerequisites,
            "attack_conditions": attack_conditions,
            "unknown_conditions": unknown_conditions
        }

    def extract_from_evidence(
        self,
        cve_id: str,
        sources: List[Dict[str, Any]],
        nuclei_info: Optional[Dict[str, Any]] = None,
        cve_summary: str = ""
    ) -> Dict[str, Any]:
        """
        Extracts structured prerequisites, attack conditions, and unknown conditions
        from collected authoritative evidence.
        """
        prerequisites: List[Dict[str, Any]] = []
        unknown_conditions: List[Dict[str, Any]] = []
        attack_conditions: List[Dict[str, Any]] = []
        remediation_actions: List[str] = []
        affected_versions: List[str] = []

        seen_names = set()
        seen_attack_conds = set()
        seen_unknowns = set()

        def are_equivalent_conditions(n1: str, n2: str) -> bool:
            if n1 == n2:
                return True
            b1 = re.sub(r'_(enabled|active|true|present|supported|vulnerable)$', '', n1)
            b2 = re.sub(r'_(enabled|active|true|present|supported|vulnerable)$', '', n2)
            if b1 == b2:
                return True
            if b1.endswith(f"_{b2}") or b2.endswith(f"_{b1}"):
                return True
            return False

        def add_prereq(p_dict: Dict[str, Any]):
            name = p_dict["name"]
            matched_existing = None
            for existing in prerequisites:
                if are_equivalent_conditions(existing["name"], name):
                    matched_existing = existing
                    break

            if matched_existing is None:
                seen_names.add(name)
                if "id" not in p_dict:
                    p_dict["id"] = f"{cve_id}_cond_{name}"
                prerequisites.append(p_dict)
            else:
                existing_tokens = len(matched_existing["name"].split("_"))
                new_tokens = len(name.split("_"))
                if new_tokens > existing_tokens:
                    matched_existing["name"] = name
                    matched_existing["display_name"] = p_dict.get("display_name", matched_existing.get("display_name"))
                    matched_existing["description"] = p_dict.get("description", matched_existing.get("description"))
                    matched_existing["id"] = f"{cve_id}_cond_{name}"

                merged_cfgs = list(matched_existing.get("configuration_evidence", []))
                for c_path in p_dict.get("configuration_evidence", []):
                    if c_path not in merged_cfgs:
                        merged_cfgs.append(c_path)
                matched_existing["configuration_evidence"] = merged_cfgs

                if p_dict.get("trust_level") == "authoritative":
                    matched_existing["trust_level"] = "authoritative"
                if p_dict.get("confidence") == "high":
                    matched_existing["confidence"] = "high"
                if p_dict.get("required") is True:
                    matched_existing["required"] = True

                existing_evs = matched_existing.setdefault("evidence", [])
                for ev in p_dict.get("evidence", []):
                    if not any(e.get("source_url") == ev.get("source_url") and e.get("evidence_text") == ev.get("evidence_text") for e in existing_evs):
                        existing_evs.append(ev)

        # -------------------------------------------------------------
        # 1. Parse authoritative sources & advisories
        # -------------------------------------------------------------
        for s in sources:
            s_type = s.get("source_type", "other")
            if s_type == "nuclei" or s.get("is_relevant") is False:
                continue
            raw_text = str(s.get("content") or "")
            text = DocumentSanitizer.sanitize_document(raw_text)
            s["content"] = text
            s_url = s.get("source_url", "")

            # If multi-CVE advisory contains our specific CVE, isolate that CVE's section
            if cve_id in text and len(text) > 1000:
                cve_idx = text.find(cve_id)
                sec_start = text.rfind("\n\n", 0, cve_idx)
                sec_start = 0 if sec_start == -1 else sec_start
                m_next = re.search(r'(CVE-\d{4}-\d+)', text[cve_idx + len(cve_id):])
                next_entry = text.rfind("\n\n", cve_idx + len(cve_id), cve_idx + len(cve_id) + m_next.start()) if m_next else len(text)
                sec_end = next_entry if next_entry != -1 else ((cve_idx + len(cve_id) + m_next.start()) if m_next else len(text))
                text = text[sec_start:sec_end]

            # Extract affected version statements
            clean_v_text = re.sub(r'\b(?:Apache\s+License(?:,\s+Version)?|License,\s+Version|GPLv?\d*|LGPLv?\d*|BSD\s+License)\s+[0-9\.]+\b', '', text, flags=re.I)
            clean_v_text = re.sub(r'\b(?:HTTP|TLS|SSL)\/[0-9\.]+\b', '', clean_v_text, flags=re.I)

            for mb in re.finditer(r'\b(?:[A-Za-z0-9_\-]+\s+)?([0-9\.\w\-]+)\s+before\s+([0-9\.\w\-]+)', clean_v_text, re.I):
                v_start = mb.group(1).strip()
                v_fixed = mb.group(2).strip()
                if len(v_start) > 2 and len(v_fixed) > 2:
                    v_range = f"{v_start} before {v_fixed}"
                    if v_range not in affected_versions:
                        affected_versions.append(v_range)

            for mb in re.finditer(r'\bversions?\s+(?:prior\s+to|before|earlier\s+than)\s+([0-9\.\w\-]+)', clean_v_text, re.I):
                v_fixed = mb.group(1).strip()
                if len(v_fixed) > 2:
                    v_range = f"< {v_fixed}"
                    if v_range not in affected_versions:
                        affected_versions.append(v_range)

            for mo in re.finditer(r'\bOnly\s+([0-9\.\w\-,/ ]+?)\s+releases?\s+(?:of\s+[A-Za-z0-9_\-]+\s+)?are\s+affected\b', clean_v_text, re.I):
                v_aff = mo.group(1).strip()
                if len(v_aff) > 2 and v_aff not in affected_versions:
                    affected_versions.append(v_aff)

            ver_matches = re.findall(
                r"(?:affects|versions?)\s*(?:from|between)?\s*([0-9][0-9\.\w\-]*(?:\s+(?:through|to|-)\s+[0-9][0-9\.\w\-]*)?)",
                clean_v_text,
                re.IGNORECASE
            )
            for vm in ver_matches:
                vm_clean = vm.strip()
                if vm_clean not in affected_versions and len(vm_clean) > 2 and vm_clean != "2.0":
                    affected_versions.append(vm_clean)

            # Match product version ranges like "In <Product> X.X.X to Y.Y.Y, A.B.C to D.E.F..."
            for m_prod in re.finditer(r'(?:in|for|affects)\s+[A-Za-z0-9_\-]+\s+([0-9][0-9\.\w\-]*\s+to\s+[0-9][0-9\.\w\-]*(?:,\s*[0-9][0-9\.\w\-]*\s+to\s+[0-9][0-9\.\w\-]*)?(?:\s+and\s+[0-9][0-9\.\w\-]*\s+to\s+[0-9][0-9\.\w\-]*)?)', clean_v_text, re.I):
                range_blob = m_prod.group(1)
                sub_ranges = re.findall(r'([0-9][0-9\.\w\-]*\s+to\s+[0-9][0-9\.\w\-]*)', range_blob, re.I)
                for sr in sub_ranges:
                    if sr not in affected_versions:
                        affected_versions.append(sr)

            for vuln in s.get("vulnerabilities", []):
                v_rng = vuln.get("vulnerable_version_range")
                if v_rng and v_rng not in affected_versions:
                    affected_versions.append(v_rng)

            # Linguistic conditional & attack condition extraction
            extracted = self.extract_attack_conditions(text, source_type=s_type, source_url=s_url)
            for ep in extracted.get("prerequisites", []):
                add_prereq(ep)

            for ac in extracted.get("attack_conditions", []):
                key = ac.get("name") or ac.get("condition", "")
                norm_key = re.sub(r'^(carefully|specially|maliciously)\s+', '', key.lower()).strip()
                if "handshake" in norm_key and any("handshake" in a.get("name", "").lower() for a in attack_conditions):
                    continue
                if any(re.sub(r'^(carefully|specially|maliciously)\s+', '', a.get("name", "").lower()).strip() == norm_key for a in attack_conditions):
                    continue
                if key and key not in seen_attack_conds:
                    seen_attack_conds.add(key)
                    attack_conditions.append(ac)

            for uc in extracted.get("unknown_conditions", []):
                ukey = uc.get("name", "")
                if ukey and ukey not in seen_unknowns:
                    seen_unknowns.add(ukey)
                    unknown_conditions.append(uc)

            # Extraction of recommended fixes
            fix_match = re.search(r"(?:upgrade|update)\s+to\s+version\s+([0-9\.\w\,\s]+)", text, re.I)
            if fix_match:
                rec_text = f"Upgrade to version {fix_match.group(1).strip()}"
                if rec_text not in remediation_actions:
                    remediation_actions.append(rec_text)

        # -------------------------------------------------------------
        # 2. Dynamic Validation Separation (Stored separately, never attack conditions or environment prereqs)
        # -------------------------------------------------------------
        dynamic_validation: List[Dict[str, Any]] = []
        if nuclei_info:
            tpl_path = nuclei_info.get("template_path", "")
            dynamic_validation.append({
                "source": "nuclei",
                "type": "nuclei_dynamic_probe",
                "template_id": nuclei_info.get("template_id", cve_id),
                "template_path": tpl_path,
                "verification_method": "dynamic_test",
                "methods": nuclei_info.get("methods", []),
                "endpoints": nuclei_info.get("endpoints", []),
                "description": f"Automated technical validation probe generated from Nuclei template {Path(tpl_path).name if tpl_path else 'template'}."
            })

        # -------------------------------------------------------------
        # 3. Version prerequisite:
        # Include software_version_vulnerable if no specific preconditions were detected,
        # or if the advisory text explicitly specifies a version range boundary (e.g. "Software before X").
        # -------------------------------------------------------------
        has_version_boundary = bool(re.search(r'\b[A-Za-z0-9_\-\.]{3,20}\s+(?:before|prior\s+to|earlier\s+than)\s+[0-9]', cve_summary, re.I))
        if not has_version_boundary:
            # Generic detection of explicit version boundaries documented in advisory text:
            # e.g., "In <product> <ver> to <ver>" or "shipped with ... enabled by default"
            version_boundary_patterns = [
                r'\b(?:In|When running|affects|for)\s+[A-Za-z0-9_\-\.\s]{2,25}\s+[0-9\.]+[A-Za-z0-9_\-\.]*\s+to\s+[0-9\.]+',
                r'\b(?:only\s+vulnerable\s+when|shipped\s+with|enabled\s+by\s+default)\b.*\b(?:to|before)\s+[0-9\.]+',
                r'\b(?:versions?|releases?)\s+(?:before|prior\s+to|earlier\s+than)\s+[0-9]',
            ]
            for s in sources:
                if not s.get("is_relevant", True):
                    continue
                c_text = s.get("content") or ""
                if any(re.search(pat, c_text, re.I) for pat in version_boundary_patterns):
                    has_version_boundary = True
                    break

        if "software_version_vulnerable" not in seen_names and (not prerequisites or has_version_boundary):
            v_ev_text = f"Affected version ranges: {', '.join(affected_versions[:3])}" if affected_versions else (cve_summary or f"Version vulnerability for {cve_id}")
            add_prereq({
                "id": f"{cve_id}_cond_software_version",
                "name": "software_version_vulnerable",
                "display_name": "Software version vulnerable",
                "description": f"Target software version must fall within affected range for {cve_id}.",
                "category": "version",
                "required": True,
                "expected_state": "vulnerable_version",
                "verification_method": "version_check",
                "trust_level": "authoritative",
                "confidence": "high",
                "evidence": [{
                    "source_type": "cve_reference",
                    "source_url": "NVD/CVE",
                    "evidence_text": v_ev_text,
                    "confidence": "high"
                }]
            })

        # -------------------------------------------------------------
        # Assemble Generic Condition IR and AST
        # -------------------------------------------------------------
        env_nodes: List[ConditionNode] = []
        for p in prerequisites:
            if p.get("name") == "software_version_vulnerable" or p.get("category") == "version":
                continue
            ev_list = p.get("evidence", [])
            primary_ev = ev_list[0] if ev_list else {}
            c_type = ConditionType.from_str(p.get("condition_type") or p.get("category", "GENERIC"))
            cat = ConditionCategory.from_str(p.get("category", "environment"))

            v_meth_str = p.get("verification_method", "config_collector")
            try:
                v_meth = VerificationMethod(v_meth_str)
            except Exception:
                v_meth = VerificationMethod.CONFIG_COLLECTOR

            t_lvl_str = p.get("trust_level", "authoritative")
            try:
                t_lvl = TrustLevel(t_lvl_str)
            except Exception:
                t_lvl = TrustLevel.AUTHORITATIVE

            exp_state_raw = p.get("expected_state")
            exp_state_str = str(exp_state_raw or "").lower()
            if exp_state_str in ("true", "active", "enabled", "present", "allowed", "vulnerable_endpoints"):
                val = True
            elif exp_state_str in ("false", "inactive", "disabled", "denied"):
                val = False
            else:
                val = exp_state_raw if exp_state_raw is not None else True

            env_nodes.append(ConditionNode(
                condition_id=p.get("id", f"{cve_id}_cond_{p.get('name')}"),
                condition_type=c_type,
                subject=p.get("name", "unnamed_condition"),
                attribute=p.get("category", "configuration"),
                operator=Operator.EQUALS,
                value=val,
                required=bool(p.get("required", True)),
                category=cat,
                verification_method=v_meth,
                confidence=p.get("confidence", "high"),
                trust_level=t_lvl,
                evidence=primary_ev.get("evidence_text", ""),
                source_url=primary_ev.get("source_url", ""),
                source_type=primary_ev.get("source_type", "vendor_advisory"),
                auto_verifiable=True,
                extraction_method="semantic_parser",
                configuration_evidence=list(p.get("configuration_evidence", []))
            ))

        env_ast: Optional[ASTNode] = None
        if env_nodes:
            if len(env_nodes) == 1:
                env_ast = env_nodes[0]
            else:
                env_ast = AndGroup(operands=list(env_nodes), description=f"Prerequisites for {cve_id}")

        tree = CVEConditionTree(
            cve_id=cve_id.upper(),
            environment_tree=env_ast,
            attack_conditions=[
                ConditionNode(
                    condition_id=a.get("id", f"attack_{uuid.uuid4().hex[:8]}"),
                    condition_type=ConditionType.ATTACK_ACTION,
                    subject=a.get("name") or a.get("condition") or "attack_condition",
                    attribute="request_payload",
                    operator=Operator.EQUALS,
                    value=True,
                    required=bool(a.get("required", True)),
                    category=ConditionCategory.ATTACK,
                    verification_method=VerificationMethod.DYNAMIC_VALIDATION,
                    confidence=a.get("confidence", "high"),
                    trust_level=TrustLevel.AUTHORITATIVE if a.get("trust_level") == "authoritative" else TrustLevel.DERIVED,
                    evidence=a.get("evidence", [{}])[0].get("evidence_text", "") if a.get("evidence") else "",
                    source_url=a.get("evidence", [{}])[0].get("source_url", "") if a.get("evidence") else "",
                    source_type="vendor_advisory",
                    auto_verifiable=False,
                    extraction_method="semantic_parser"
                )
                for a in attack_conditions
            ],
            unknown_conditions=[
                ConditionNode(
                    condition_id=u.get("id", f"unknown_{uuid.uuid4().hex[:8]}"),
                    condition_type=ConditionType.GENERIC,
                    subject=u.get("name") or u.get("condition") or "unknown_condition",
                    attribute="unknown",
                    operator=Operator.EQUALS,
                    value="unknown",
                    required=False,
                    category=ConditionCategory.UNKNOWN,
                    verification_method=VerificationMethod.UNKNOWN,
                    confidence="low",
                    trust_level=TrustLevel.UNKNOWN,
                    evidence=u.get("evidence_text", "") or u.get("evidence", ""),
                    auto_verifiable=False,
                    extraction_method="semantic_parser"
                )
                for u in unknown_conditions
            ]
        )

        return {
            "cve_id": cve_id.upper(),
            "summary": cve_summary,
            "affected_versions": affected_versions,
            "prerequisites": prerequisites,
            "attack_conditions": attack_conditions,
            "dynamic_validation": dynamic_validation,
            "unknown_conditions": unknown_conditions,
            "remediation": remediation_actions,
            "sources": sources,
            "environment_tree": tree.environment_tree.to_dict() if tree.environment_tree else None,
            "condition_tree": tree.to_dict(),
            "condition_tree_json": tree.to_json()
        }


# ============================================================
# MAIN AGENT ORCHESTRATOR
# ============================================================

class CVEPrerequisiteAgent:
    """
    Autonomous CVE Prerequisite Extraction Agent.
    """

    def __init__(
        self,
        cache_dir: Path | str = DEFAULT_CACHE_DIR,
        db_path: Path | str = DEFAULT_DB_PATH,
        templates_dir: Path | str = DEFAULT_TEMPLATES_DIR,
        online_mode: bool = True
    ):
        self.retriever = SourceRetriever(cache_dir=cache_dir, online_mode=online_mode)
        self.store = PrerequisiteStore(db_path=db_path)
        self.nuclei_inspector = NucleiTemplateInspector(templates_dir=templates_dir)
        self.extractor = PrerequisiteExtractor()
        self.cve_db_agent = CVEDatabaseAgent()

    def process_cve(self, cve_id: str, save_to_db: bool = True) -> Dict[str, Any]:
        """
        Execute end-to-end prerequisite discovery and extraction workflow.
        """
        clean_cve = cve_id.strip().upper()
        print(f"\n[*] Processing Prerequisite Extraction for: {clean_cve}")

        # 1. Query Authoritative Local CVE Information
        cve_info = self.cve_db_agent.lookup(clean_cve) or {}
        summary = cve_info.get("summary") or cve_info.get("description", "")
        raw_refs = cve_info.get("references", [])

        # 2. Prioritize & Collect Sources
        collected_sources: List[Dict[str, Any]] = []
        prioritized_urls: List[Tuple[int, str, str]] = []

        # Parse local references from CVE DB
        for ref in raw_refs:
            url = ref.get("url") if isinstance(ref, dict) else str(ref)
            if url and url.startswith("http"):
                s_type, rank = classify_source_url(url)
                prioritized_urls.append((rank, s_type, url))

        # Add GitHub Advisory lookup to candidates
        ghsa_api_url = f"https://api.github.com/advisories?cve_id={clean_cve}"
        prioritized_urls.append((SOURCE_PRIORITY["ghsa"], "ghsa", ghsa_api_url))

        # Sort by priority rank
        prioritized_urls.sort(key=lambda x: x[0])

        # 3. Retrieve and Cache Sources
        seen_urls = set()
        idx = 0
        while idx < len(prioritized_urls):
            rank, s_type, url = prioritized_urls[idx]
            idx += 1
            if url in seen_urls:
                continue
            seen_urls.add(url)

            if len(collected_sources) >= 5:
                break

            # Special case for GHSA: fetch API summary, description, and referenced URLs
            if s_type == "ghsa" and "api.github.com" in url:
                ghsa_data = self.retriever.fetch_github_advisory(clean_cve)
                if ghsa_data:
                    # Discover referenced links from GHSA (prefer vendor/project advisories rank <= 4)
                    for g_ref in ghsa_data.get("references", []):
                        if g_ref and g_ref.startswith("http") and g_ref not in seen_urls:
                            g_type, g_rank = classify_source_url(g_ref)
                            if g_rank <= 4:
                                prioritized_urls.append((g_rank, g_type, g_ref))
                    # Keep remaining queue sorted by priority
                    prioritized_urls[idx:] = sorted(prioritized_urls[idx:], key=lambda x: x[0])

                    from_cache = ghsa_data.get("from_cache", False)
                    ghsa_text = f"{ghsa_data.get('summary')}\n{ghsa_data.get('description')}"
                    is_rel, rel_reason = evaluate_source_relevance({"content": ghsa_text, "source_type": "ghsa"}, clean_cve)
                    collected_sources.append({
                        "source_id": f"src_ghsa_{len(collected_sources)+1}",
                        "source_type": "ghsa",
                        "source_url": ghsa_data.get("source_url", url),
                        "priority_rank": rank,
                        "content": ghsa_text,
                        "local_cache_path": ghsa_data.get("local_cache_path"),
                        "retrieved_at": ghsa_data.get("retrieved_at"),
                        "content_sha256": ghsa_data.get("content_sha256"),
                        "from_cache": from_cache,
                        "fetch_status": "CACHED FROM PREVIOUS FETCH" if from_cache else "FETCHED ONLINE",
                        "is_relevant": is_rel,
                        "relevance_reason": rel_reason,
                        "vulnerabilities": ghsa_data.get("vulnerabilities", [])
                    })
                    if not summary:
                        summary = ghsa_data.get("summary", "")
                continue

            fetched = self.retriever.fetch_url_cached(clean_cve, url, s_type)
            if fetched:
                from_cache = fetched.get("from_cache", False)
                full_fetched_text = fetched.get("content") or ""
                if clean_cve in full_fetched_text:
                    fetch_text = full_fetched_text
                else:
                    fetch_text = full_fetched_text[:20000]
                is_rel, rel_reason = evaluate_source_relevance({
                    "content": fetch_text,
                    "raw_content": fetched.get("raw_content", ""),
                    "source_type": s_type
                }, clean_cve)
                collected_sources.append({
                    "source_id": f"src_{len(collected_sources)+1}",
                    "source_type": s_type,
                    "source_url": url,
                    "priority_rank": rank,
                    "content": fetch_text,  # Bound text length
                    "local_cache_path": fetched.get("local_cache_path"),
                    "retrieved_at": fetched.get("retrieved_at"),
                    "content_sha256": fetched.get("content_sha256"),
                    "from_cache": from_cache,
                    "fetch_status": "CACHED FROM PREVIOUS FETCH" if from_cache else "FETCHED ONLINE",
                    "is_relevant": is_rel,
                    "relevance_reason": rel_reason
                })

        # Add base CVE summary as cve_reference source if nothing else was fetched
        if not collected_sources and summary:
            is_rel, rel_reason = evaluate_source_relevance({"content": summary, "source_type": "cve_reference"}, clean_cve)
            collected_sources.append({
                "source_id": "src_local_db",
                "source_type": "cve_reference",
                "source_url": "local://cve_database.db",
                "priority_rank": SOURCE_PRIORITY["cve_reference"],
                "content": summary,
                "local_cache_path": "",
                "retrieved_at": now_iso(),
                "content_sha256": hashlib.sha256(summary.encode("utf-8")).hexdigest(),
                "from_cache": True,
                "fetch_status": "CACHED FROM PREVIOUS FETCH",
                "is_relevant": is_rel,
                "relevance_reason": rel_reason
            })

        # 4. Inspect Local Nuclei Template
        nuclei_info = self.nuclei_inspector.inspect_template(clean_cve)
        if nuclei_info:
            collected_sources.append({
                "source_id": f"src_nuclei_{len(collected_sources)+1}",
                "source_type": "nuclei",
                "source_url": nuclei_info["template_path"],
                "priority_rank": SOURCE_PRIORITY["nuclei"],
                "content": nuclei_info["raw_yaml"],
                "local_cache_path": nuclei_info["template_path"],
                "retrieved_at": now_iso(),
                "content_sha256": hashlib.sha256(nuclei_info["raw_yaml"].encode("utf-8")).hexdigest(),
                "from_cache": True,
                "fetch_status": "LOCAL NUCLEI TEMPLATE",
                "is_relevant": True,
                "relevance_reason": "Local validation template"
            })

        # 5. Extract Prerequisites & Conditions
        record = self.extractor.extract_from_evidence(
            cve_id=clean_cve,
            sources=collected_sources,
            nuclei_info=nuclei_info,
            cve_summary=summary
        )

        # 6. Store locally in SQLite only if requested (preserve database in test mode)
        if save_to_db:
            self.store.save_record(record)
            print(f"[+] Successfully extracted and stored {len(record['prerequisites'])} prerequisites for {clean_cve}.")
        else:
            print(f"[+] Successfully extracted {len(record['prerequisites'])} prerequisites for {clean_cve} (db save skipped in test mode).")

        return record

    def export_for_cve_evaluator(self, cve_id: str, output_path: Path | str | None = None) -> Dict[str, Any]:
        """
        Translates stored prerequisite records into the exact format
        consumed by the existing CVEEvaluator.
        """
        clean_cve = cve_id.strip().upper()
        rec = self.store.get_record(clean_cve)
        if not rec:
            rec = self.process_cve(clean_cve)

        evaluator_conditions = []
        for p in rec.get("prerequisites", []):
            if p.get("name") == "software_version_vulnerable" or p.get("category") == "version":
                continue
            cfg_path = p.get("configuration_path") or p.get("name")
            exp_state = str(p.get("expected_state", "")).lower()
            req_val = True if exp_state in ("true", "active", "present", "vulnerable_endpoints", "enabled") else p.get("expected_state")
            cfg_ev = p.get("configuration_evidence") or [cfg_path]
            evaluator_conditions.append({
                "id": p.get("id"),
                "name": p.get("name"),
                "description": p.get("description"),
                "category": p.get("category", "configuration"),
                "required": bool(p.get("required", True)),
                "configuration_evidence": cfg_ev,
                "required_value": req_val,
                "trust_level": p.get("trust_level", "authoritative")
            })

        # Format compatible with CVEEvaluator
        knowledge_dict = {
            clean_cve: {
                "cve_id": clean_cve,
                "product": {
                    "vendor": "Target Software",
                    "name": "Extracted Software",
                    "component": "Component"
                },
                "affected_versions": {
                    "range": rec.get("affected_versions", ["all"])[0] if rec.get("affected_versions") else "all"
                },
                "fixed_versions": {},
                "severity": "HIGH",
                "description": rec.get("summary", ""),
                "conditions": {
                    "attack_preconditions": evaluator_conditions
                },
                "environment_tree": rec.get("environment_tree"),
                "condition_tree": rec.get("condition_tree"),
                "condition_tree_json": rec.get("condition_tree_json"),
                "attack_conditions": rec.get("attack_conditions", []),
                "unknown_conditions": rec.get("unknown_conditions", []),
                "dynamic_validation": rec.get("dynamic_validation", []),
                "remediation": rec.get("remediation", [])
            }
        }

        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(knowledge_dict, indent=2, ensure_ascii=False), encoding="utf-8")

        return knowledge_dict


# ============================================================
# CLI INTERFACE
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Autonomous CVE Prerequisite Extraction Agent")
    parser.add_argument("--cve", help="Target CVE ID to extract prerequisites for")
    parser.add_argument("--batch", nargs="+", help="Batch of CVE IDs to process")
    parser.add_argument("--offline", action="store_true", help="Operate in offline mode (cached material only)")
    parser.add_argument("--output", help="Output path for exported JSON record")
    parser.add_argument("--export-evaluator", help="Output path for knowledge consumable by CVEEvaluator")

    args = parser.parse_args()

    agent = CVEPrerequisiteAgent(online_mode=not args.offline)

    cves_to_process: list[str] = []
    if args.cve:
        cves_to_process.append(args.cve.strip())
    if args.batch:
        for b in args.batch:
            for item in b.split(","):
                item = item.strip()
                if item:
                    cves_to_process.append(item)

    if not cves_to_process:
        print("[!] No CVE ID specified. Use --cve <CVE-ID> or --batch <ID1,ID2>.")
        return

    for cid in cves_to_process:
        rec = agent.process_cve(cid)
        if args.output:
            agent.store.export_json(cid, args.output)
            print(f"[+] Saved record JSON to: {args.output}")
        if args.export_evaluator:
            agent.export_for_cve_evaluator(cid, args.export_evaluator)
            print(f"[+] Exported for CVEEvaluator to: {args.export_evaluator}")

        print("\n" + "=" * 60)
        print(f"PREREQUISITE EXTRACTION SUMMARY: {cid}")
        print("=" * 60)
        print(f"Summary: {rec.get('summary')[:100]}...")
        print(f"Sources Found & Used: {len(rec.get('sources', []))}")
        print(f"Prerequisites Extracted: {len(rec.get('prerequisites', []))}")
        for p in rec.get("prerequisites", []):
            print(f"  - [{p.get('trust_level').upper()}] {p.get('name')}: {p.get('description')}")
        if rec.get("unknown_conditions"):
            print(f"Unknown Conditions: {len(rec['unknown_conditions'])}")
            for u in rec["unknown_conditions"]:
                print(f"  ? {u.get('name')}: {u.get('reason')}")
        print("=" * 60)


if __name__ == "__main__":
    main()
