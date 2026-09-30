"""PHASE B: Deterministic CVE Lookup and Version Evidence Bridge.

Provides a unified, deterministic bridge for Trivy and Nuclei scanner findings:
    Trivy/Nuclei finding
          ↓
    identifier normalization & classification
          ↓
    exact local SQLite CVE lookup (< 100 ms indexed query)
          ↓
    canonical CVE record
          ↓
    scanner package/version evidence preservation
          ↓
    ecosystem-appropriate version comparison
          ↓
    Phase B result (AFFECTED, NOT_AFFECTED, UNKNOWN, VERSION_EVIDENCE_CONFLICT)

STRICT BOUNDARIES:
- Does NOT perform Phase C environmental applicability or prerequisite checks.
- Does NOT use LLMs or external networks (100% offline).
- Preserves distinct NVD, CVE List V5, and Trivy/Nuclei source provenance.
- Detects genuine material version conflicts vs harmless range differences.
- Handles uncertain CPE-to-package mappings conservatively.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from packaging.version import InvalidVersion, Version
except ImportError:
    Version = None  # type: ignore

try:
    from orchestrator.cve_db import CVEDatabase
except ImportError:
    try:
        from cve_db import CVEDatabase
    except ImportError:
        CVEDatabase = None  # type: ignore

CVE_PATTERN = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)

NON_CVE_PATTERNS = {
    "GHSA": re.compile(r"^GHSA-[2-9a-cf-hj-mr-z]{4}-[2-9a-cf-hj-mr-z]{4}-[2-9a-cf-hj-mr-z]{4}$", re.I),
    "OSV": re.compile(r"^OSV-\d{4}-\d+$", re.I),
    "PYSEC": re.compile(r"^PYSEC-\d{4}-\d+$", re.I),
    "RHSA": re.compile(r"^RHSA-\d{4}:\d+$", re.I),
    "ALAS": re.compile(r"^ALAS\d*-\d{4}-\d+$", re.I),
}


# ======================================================================
# 1. Identifier Classification & Normalization
# ======================================================================

def classify_identifier(raw_id: str) -> Tuple[str, Optional[str]]:
    """
    Classify and normalize vulnerability identifier.

    Returns:
        (identifier_type, normalized_id_or_original)
        - If valid CVE: ("CVE", "CVE-YYYY-NNNN")
        - If non-CVE or invalid: ("UNSUPPORTED_IDENTIFIER_FORMAT", raw_id)
    """
    if not raw_id or not isinstance(raw_id, str):
        return "UNSUPPORTED_IDENTIFIER_FORMAT", str(raw_id or "")

    clean_id = raw_id.strip()
    cve_match = CVE_PATTERN.match(clean_id)
    if cve_match:
        year, num = cve_match.groups()
        return "CVE", f"CVE-{year}-{num}"

    for type_name, pattern in NON_CVE_PATTERNS.items():
        if pattern.match(clean_id):
            return "UNSUPPORTED_IDENTIFIER_FORMAT", clean_id

    return "UNSUPPORTED_IDENTIFIER_FORMAT", clean_id


def extract_cve_identifiers(raw_finding: Dict[str, Any]) -> List[str]:
    """
    Extract all candidate vulnerability identifiers from a Trivy or Nuclei finding.
    Supports single strings, lists, and multi-CVE delimited strings.
    """
    candidates = []

    # 1. Check primary ID fields
    for key in ("cve", "VulnerabilityID", "vulnerability_id", "id", "CVE"):
        val = raw_finding.get(key)
        if isinstance(val, list):
            candidates.extend(str(v).strip() for v in val if v)
        elif isinstance(val, str) and val.strip():
            candidates.append(val.strip())

    # 2. Check classification in Nuclei info
    info = raw_finding.get("info", {})
    if isinstance(info, dict):
        classification = info.get("classification", {})
        if isinstance(classification, dict):
            cve_val = classification.get("cve-id")
            if isinstance(cve_val, list):
                candidates.extend(str(v).strip() for v in cve_val if v)
            elif isinstance(cve_val, str) and cve_val.strip():
                candidates.append(cve_val.strip())

    # 3. Check tags for embedded CVE identifiers
    tags = raw_finding.get("tags") or (info.get("tags") if isinstance(info, dict) else None)
    if isinstance(tags, list):
        for tag in tags:
            m = CVE_PATTERN.search(str(tag))
            if m:
                candidates.append(m.group(0))

    # Split multi-CVE delimited strings (e.g. "CVE-2025-24813, CVE-2021-44228")
    expanded = []
    for cand in candidates:
        if "," in cand:
            parts = [p.strip() for p in cand.split(",") if p.strip()]
            expanded.extend(parts)
        elif ";" in cand:
            parts = [p.strip() for p in cand.split(";") if p.strip()]
            expanded.extend(parts)
        else:
            expanded.append(cand)

    # Deduplicate while preserving order
    seen = set()
    result = []
    for c in expanded:
        if c not in seen:
            seen.add(c)
            result.append(c)

    return result if result else [str(raw_finding.get("id") or "UNKNOWN")]


# ======================================================================
# 2. Ecosystem-Specific Version Semantics
# ======================================================================

class EcosystemVersionComparator:
    """
    Evaluates version relationships according to package-manager/ecosystem semantics.
    Strictly avoids generic lexicographic string comparison ('9.0.98' < '9.0.99').
    """

    SUPPORTED_ECOSYSTEMS = {
        "pypi": "python",
        "pip": "python",
        "python": "python",
        "npm": "semver",
        "node": "semver",
        "javascript": "semver",
        "semver": "semver",
        "cargo": "semver",
        "composer": "semver",
        "nuget": "semver",
        "maven": "maven",
        "java": "maven",
        "pom": "maven",
        "jar": "maven",
        "deb": "debian",
        "debian": "debian",
        "ubuntu": "debian",
        "rpm": "rpm",
        "redhat": "rpm",
        "centos": "rpm",
        "fedora": "rpm",
        "go": "golang",
        "gomod": "golang",
        "golang": "golang",
    }

    MAVEN_QUALIFIER_ORDER = {
        "alpha": -5, "a": -5,
        "beta": -4, "b": -4,
        "milestone": -3, "m": -3,
        "rc": -2, "cr": -2,
        "snapshot": -1,
        "": 0, "ga": 0, "final": 0, "release": 0,
        "sp": 1
    }

    @classmethod
    def normalize_ecosystem(cls, raw_ecosystem: Optional[str]) -> Optional[str]:
        if not raw_ecosystem:
            return None
        eco = str(raw_ecosystem).strip().lower()
        return cls.SUPPORTED_ECOSYSTEMS.get(eco)

    @classmethod
    def can_compare(cls, ecosystem: Optional[str], v1: str, v2: str) -> bool:
        eco_type = cls.normalize_ecosystem(ecosystem)
        if not eco_type:
            return False
        try:
            cls.compare(ecosystem, v1, v2)
            return True
        except Exception:
            return False

    @classmethod
    def compare(cls, ecosystem: Optional[str], v1: str, v2: str) -> int:
        """
        Compare two version strings according to ecosystem semantics.

        Returns:
            -1 if v1 < v2
             0 if v1 == v2
             1 if v1 > v2

        Raises:
            ValueError: If ecosystem is unsupported or version cannot be parsed.
        """
        eco_type = cls.normalize_ecosystem(ecosystem)
        if not eco_type:
            raise ValueError(f"Unsupported or uncertain version ecosystem: '{ecosystem}'")

        s1, s2 = str(v1).strip(), str(v2).strip()

        if eco_type == "python":
            return cls._compare_pep440(s1, s2)
        elif eco_type in ("semver", "golang"):
            return cls._compare_semver(s1, s2)
        elif eco_type == "maven":
            return cls._compare_maven(s1, s2)
        elif eco_type == "debian":
            return cls._compare_debian(s1, s2)
        elif eco_type == "rpm":
            return cls._compare_rpm(s1, s2)

        raise ValueError(f"No comparator implementation for ecosystem '{eco_type}'")

    @classmethod
    def _compare_pep440(cls, v1: str, v2: str) -> int:
        if Version is None:
            raise ValueError("packaging library not available for PEP 440 comparison")
        ver1 = Version(v1)
        ver2 = Version(v2)
        if ver1 < ver2:
            return -1
        elif ver1 > ver2:
            return 1
        return 0

    @classmethod
    def _compare_semver(cls, v1: str, v2: str) -> int:
        # Strip leading 'v' if present (e.g. Go modules: v1.2.3)
        v1_clean = v1.lstrip("vV")
        v2_clean = v2.lstrip("vV")

        def parse_semver(s: str):
            # Split build metadata (+)
            main_part = s.split("+")[0]
            # Split prerelease (-)
            if "-" in main_part:
                core, pre = main_part.split("-", 1)
                pre_parts = pre.split(".")
            else:
                core = main_part
                pre_parts = None

            core_digits = []
            for item in core.split("."):
                m = re.match(r"^(\d+)", item)
                if not m:
                    raise ValueError(f"Invalid semver segment: '{item}' in '{s}'")
                core_digits.append(int(m.group(1)))

            while len(core_digits) < 3:
                core_digits.append(0)

            return core_digits[:3], pre_parts

        digits1, pre1 = parse_semver(v1_clean)
        digits2, pre2 = parse_semver(v2_clean)

        if digits1 < digits2:
            return -1
        if digits1 > digits2:
            return 1

        # Prerelease precedence: version without prerelease > version with prerelease
        if pre1 is None and pre2 is None:
            return 0
        if pre1 is None and pre2 is not None:
            return 1
        if pre1 is not None and pre2 is None:
            return -1

        # Both have prereleases: compare each identifier
        for p1, p2 in zip(pre1, pre2):
            is_p1_num = p1.isdigit()
            is_p2_num = p2.isdigit()
            if is_p1_num and is_p2_num:
                i1, i2 = int(p1), int(p2)
                if i1 != i2:
                    return -1 if i1 < i2 else 1
            elif is_p1_num and not is_p2_num:
                return -1  # Numeric identifiers have lower precedence than non-numeric
            elif not is_p1_num and is_p2_num:
                return 1
            else:
                if p1 != p2:
                    return -1 if p1 < p2 else 1

        if len(pre1) != len(pre2):
            return -1 if len(pre1) < len(pre2) else 1

        return 0

    @classmethod
    def _compare_maven(cls, v1: str, v2: str) -> int:
        """
        Maven ComparableVersion ordering implementation.
        Handles qualifiers: alpha < beta < milestone/m < rc < snapshot < final/ga < sp.
        """
        def tokenize(s: str) -> List[Any]:
            # Replace transition boundaries: 9.0.0M1 -> 9.0.0.m1
            s_norm = re.sub(r"([0-9])([a-zA-Z])", r"\1.\2", s)
            s_norm = re.sub(r"([a-zA-Z])([0-9])", r"\1.\2", s_norm)
            parts = re.split(r"[.\-_]", s_norm.lower())
            tokens = []
            for p in parts:
                if not p:
                    continue
                if p.isdigit():
                    tokens.append(int(p))
                else:
                    tokens.append(p)
            return tokens

        t1 = tokenize(v1)
        t2 = tokenize(v2)

        max_len = max(len(t1), len(t2))
        for idx in range(max_len):
            tok1 = t1[idx] if idx < len(t1) else 0
            tok2 = t2[idx] if idx < len(t2) else 0

            # If both are numbers
            if isinstance(tok1, int) and isinstance(tok2, int):
                if tok1 != tok2:
                    return -1 if tok1 < tok2 else 1
            # If one is string and other is int
            elif isinstance(tok1, str) and isinstance(tok2, int):
                # String qualifiers like 'm1' or 'beta' compare before release integer 0
                q_val = cls.MAVEN_QUALIFIER_ORDER.get(tok1, -1)
                return -1 if q_val < 0 else 1
            elif isinstance(tok1, int) and isinstance(tok2, str):
                q_val = cls.MAVEN_QUALIFIER_ORDER.get(tok2, -1)
                return 1 if q_val < 0 else -1
            else:
                # Both are strings
                q1 = cls.MAVEN_QUALIFIER_ORDER.get(str(tok1), 0)
                q2 = cls.MAVEN_QUALIFIER_ORDER.get(str(tok2), 0)
                if q1 != q2:
                    return -1 if q1 < q2 else 1
                if tok1 != tok2:
                    return -1 if str(tok1) < str(tok2) else 1

        return 0

    @classmethod
    def _compare_debian(cls, v1: str, v2: str) -> int:
        def parse_deb(s: str):
            epoch = 0
            if ":" in s:
                ep_str, s = s.split(":", 1)
                epoch = int(ep_str) if ep_str.isdigit() else 0
            if "-" in s:
                upstream, revision = s.rsplit("-", 1)
            else:
                upstream, revision = s, "0"
            return epoch, upstream, revision

        def deb_order(c: str) -> int:
            if c == "~":
                return -1
            if c.isdigit():
                return 0
            if c.isalpha():
                return ord(c)
            return ord(c) + 256

        def compare_segment(s1: str, s2: str) -> int:
            i, j = 0, 0
            while i < len(s1) or j < len(s2):
                c1 = s1[i] if i < len(s1) else ""
                c2 = s2[j] if j < len(s2) else ""

                if c1 == "~" and c2 != "~":
                    return -1
                if c1 != "~" and c2 == "~":
                    return 1

                if c1.isdigit() and c2.isdigit():
                    num1_str = re.match(r"\d+", s1[i:]).group(0)
                    num2_str = re.match(r"\d+", s2[j:]).group(0)
                    n1, n2 = int(num1_str), int(num2_str)
                    if n1 != n2:
                        return -1 if n1 < n2 else 1
                    i += len(num1_str)
                    j += len(num2_str)
                    continue

                o1 = deb_order(c1) if c1 else 0
                o2 = deb_order(c2) if c2 else 0
                if o1 != o2:
                    return -1 if o1 < o2 else 1
                i += 1
                j += 1
            return 0

        e1, u1, r1 = parse_deb(v1)
        e2, u2, r2 = parse_deb(v2)

        if e1 != e2:
            return -1 if e1 < e2 else 1
        cmp_u = compare_segment(u1, u2)
        if cmp_u != 0:
            return cmp_u
        return compare_segment(r1, r2)

    @classmethod
    def _compare_rpm(cls, v1: str, v2: str) -> int:
        # Standard rpmvercmp logic
        def parse_rpm(s: str):
            epoch = 0
            if ":" in s:
                ep_str, s = s.split(":", 1)
                epoch = int(ep_str) if ep_str.isdigit() else 0
            if "-" in s:
                ver, rel = s.split("-", 1)
            else:
                ver, rel = s, ""
            return epoch, ver, rel

        def rpmvercmp(a: str, b: str) -> int:
            while a and b:
                # Handle ~ (tilde)
                if a[0] == "~" or b[0] == "~":
                    if a[0] != "~":
                        return 1
                    if b[0] != "~":
                        return -1
                    a = a[1:]
                    b = b[1:]
                    continue

                # Strip non-alphanumerics
                a = re.sub(r"^[^a-zA-Z0-9~^]+", "", a)
                b = re.sub(r"^[^a-zA-Z0-9~^]+", "", b)
                if not a or not b:
                    break

                if a[0].isdigit():
                    m_a = re.match(r"^\d+", a).group(0)
                    m_b = re.match(r"^\d+", b)
                    if not m_b:
                        return 1  # numbers are newer than letters
                    m_b = m_b.group(0)
                    # Strip leading zeros for numeric comparison
                    n_a = int(m_a)
                    n_b = int(m_b)
                    if n_a != n_b:
                        return -1 if n_a < n_b else 1
                    a = a[len(m_a):]
                    b = b[len(m_b):]
                else:
                    m_a = re.match(r"^[a-zA-Z]+", a).group(0)
                    m_b = re.match(r"^[a-zA-Z]+", b)
                    if not m_b:
                        return -1  # letters are older than numbers
                    m_b = m_b.group(0)
                    if m_a != m_b:
                        return -1 if m_a < m_b else 1
                    a = a[len(m_a):]
                    b = b[len(m_b):]

            if not a and not b:
                return 0
            return 1 if a else -1

        e1, v1_str, r1_str = parse_rpm(v1)
        e2, v2_str, r2_str = parse_rpm(v2)

        if e1 != e2:
            return -1 if e1 < e2 else 1
        res = rpmvercmp(v1_str, v2_str)
        if res != 0:
            return res
        return rpmvercmp(r1_str, r2_str)


# ======================================================================
# 3. CPE-to-Package Mapping
# ======================================================================

def verify_cpe_package_mapping(cpe_vendor: Optional[str], cpe_product: Optional[str], package_name: Optional[str]) -> Tuple[str, str]:
    """
    Evaluate whether a CPE product can be reliably mapped to a scanner package name.

    Returns:
        (mapping_status, reason)
        - "VERIFIED": Known reliable direct correspondence.
        - "UNCERTAIN": Cannot be reliably established.
    """
    if not package_name or not cpe_product:
        return "UNCERTAIN", "Missing package name or CPE product"

    pkg_clean = str(package_name).lower().strip()
    prod_clean = str(cpe_product).lower().strip()

    # Exact product name match
    if pkg_clean == prod_clean:
        return "VERIFIED", f"CPE product '{prod_clean}' matches package name '{pkg_clean}' exactly"

    # Normalized comparison (stripping hyphens and underscores)
    pkg_norm = pkg_clean.replace("-", "").replace("_", "")
    prod_norm = prod_clean.replace("-", "").replace("_", "")
    if pkg_norm == prod_norm:
        return "VERIFIED", f"CPE product '{cpe_product}' matches package name '{package_name}' after normalization"

    # Maven groupId:artifactId match (e.g. 'org.apache.tomcat:tomcat-catalina')
    if ":" in pkg_clean:
        _, artifact = pkg_clean.split(":", 1)
        artifact_norm = artifact.replace("-", "").replace("_", "")
        if prod_norm == artifact_norm or prod_norm in artifact_norm or artifact_norm in prod_norm:
            return "VERIFIED", f"CPE product '{cpe_product}' matches Maven artifact '{artifact}'"

    # Common prefix/suffix matching where product is directly embedded
    if prod_clean.startswith(pkg_clean) or pkg_clean.startswith(prod_clean):
        # Only accept if length is sufficiently specific
        if len(pkg_clean) >= 4 and len(prod_clean) >= 4:
            return "VERIFIED", f"CPE product '{cpe_product}' corresponds to package prefix/suffix in '{package_name}'"

    return "UNCERTAIN", f"Uncertain or unverified CPE product '{cpe_product}' mapping to package '{package_name}'"


# ======================================================================
# 4. Phase B Shared Evidence Service
# ======================================================================

class PhaseBEvidenceService:
    """
    Canonical deterministic CVE lookup and version evidence service.
    Serves both Trivy and Nuclei findings uniformly.
    """

    def __init__(self, db: Optional[Any] = None):
        if db is None:
            # Default to local production SQLite database
            db_candidate = Path(__file__).with_name("cve_database.db")
            if not db_candidate.exists():
                db_candidate = Path(__file__).parent.parent / "cve_database.db"
            self.db = CVEDatabase(db_candidate)
        elif isinstance(db, (str, Path)):
            self.db = CVEDatabase(str(db))
        else:
            self.db = db

    def lookup_cve_exact(self, normalized_cve_id: str) -> Tuple[Optional[Dict[str, Any]], float]:
        """
        Execute indexed exact CVE lookup against local SQLite database.
        Returns (record_dict, elapsed_milliseconds).
        """
        t0 = time.perf_counter()
        record = self.db.lookup_cve(normalized_cve_id, include_rejected=False)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return record, elapsed_ms

    def evaluate_finding(self, raw_finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate a single scanner finding (Trivy or Nuclei) through the canonical Phase B pipeline.
        Supports multi-CVE findings by returning a list of canonical results.
        """
        scanner_type = str(raw_finding.get("scanner") or "UNKNOWN").upper()
        candidate_ids = extract_cve_identifiers(raw_finding)

        results = []
        for cand_id in candidate_ids:
            res = self._process_single_identifier(cand_id, raw_finding, scanner_type)
            results.append(res)

        return results

    def _process_single_identifier(self, raw_id: str, raw_finding: Dict[str, Any], scanner_type: str) -> Dict[str, Any]:
        """Process a single identifier extracted from a finding."""
        id_type, normalized_id = classify_identifier(raw_id)

        # Extract normalized scanner evidence
        pkg_name = (
            raw_finding.get("package")
            or raw_finding.get("PkgName")
            or raw_finding.get("template_name")
            or raw_finding.get("title")
        )
        installed_version = (
            raw_finding.get("installed_version")
            or raw_finding.get("InstalledVersion")
        )
        # If Nuclei extracted results contain version
        if not installed_version and scanner_type == "NUCLEI":
            extracted = raw_finding.get("extracted_results") or raw_finding.get("extracted-results")
            if extracted and isinstance(extracted, list):
                # Search for version pattern in extracted results
                for ex in extracted:
                    m = re.search(r"(\d+(\.\d+)+[a-zA-Z0-9\.\-]*)", str(ex))
                    if m:
                        installed_version = m.group(1)
                        break

        fixed_version = raw_finding.get("fixed_version") or raw_finding.get("FixedVersion")
        ecosystem = (
            raw_finding.get("ecosystem")
            or raw_finding.get("Type")
            or raw_finding.get("Class")
            or ("maven" if "tomcat" in str(pkg_name or "").lower() else None)
        )

        scanner_evidence = {
            "scanner": scanner_type,
            "vulnerability_id": raw_id,
            "package_name": pkg_name,
            "pkg_id": raw_finding.get("PkgID"),
            "installed_version": installed_version,
            "fixed_version": fixed_version,
            "severity": raw_finding.get("severity") or raw_finding.get("Severity"),
            "vendor_severity": raw_finding.get("VendorSeverity"),
            "pkg_path": raw_finding.get("file") or raw_finding.get("PkgPath") or raw_finding.get("target"),
            "layer": raw_finding.get("Layer"),
            "ecosystem": ecosystem,
            "original_finding": raw_finding
        }

        # 1. Non-CVE Unsupported Format
        if id_type != "CVE":
            return {
                "identifier": raw_id,
                "identifier_type": "UNSUPPORTED_IDENTIFIER_FORMAT",
                "database_status": "UNSUPPORTED_IDENTIFIER_FORMAT",
                "canonical_cve": None,
                "version_evidence": "UNKNOWN",
                "version_evidence_reason": f"Identifier '{raw_id}' is not in standard CVE format",
                "scanner": scanner_type,
                "scanner_evidence": scanner_evidence,
                "source_evidence": {},
                "provenance": {},
                "mapping_status": "NOT_APPLICABLE",
                "mapping_reason": "Non-CVE identifier",
                "performance_metadata": {"lookup_duration_ms": 0.0}
            }

        # 2. Exact SQLite Lookup
        cve_record, elapsed_ms = self.lookup_cve_exact(normalized_id)

        if not cve_record:
            return {
                "identifier": raw_id,
                "identifier_type": "CVE",
                "database_status": "DATABASE_MISS",
                "canonical_cve": normalized_id,
                "version_evidence": "UNKNOWN",
                "version_evidence_reason": f"Valid CVE '{normalized_id}' not found in local database",
                "scanner": scanner_type,
                "scanner_evidence": scanner_evidence,
                "source_evidence": {},
                "provenance": {},
                "mapping_status": "NOT_APPLICABLE",
                "mapping_reason": "CVE absent from database",
                "performance_metadata": {"lookup_duration_ms": round(elapsed_ms, 3)}
            }

        # 3. Evaluate Version Evidence from each source separately
        source_evidence: Dict[str, Any] = {}
        provenance: Dict[str, Any] = {
            "database_sources": cve_record.get("sources", []),
            "field_provenance": cve_record.get("provenance", {})
        }

        # Source A: Trivy scanner determination (if Trivy)
        trivy_status = "UNKNOWN"
        trivy_reason = "No Trivy fixed version reported"
        if scanner_type == "TRIVY" and installed_version and fixed_version:
            if EcosystemVersionComparator.can_compare(ecosystem, installed_version, fixed_version):
                cmp_res = EcosystemVersionComparator.compare(ecosystem, installed_version, fixed_version)
                if cmp_res < 0:
                    trivy_status = "AFFECTED"
                    trivy_reason = f"Installed version {installed_version} < fixed version {fixed_version} ({ecosystem})"
                else:
                    trivy_status = "NOT_AFFECTED"
                    trivy_reason = f"Installed version {installed_version} >= fixed version {fixed_version} ({ecosystem})"
            else:
                trivy_status = "UNKNOWN"
                trivy_reason = f"Unsupported or uncertain version scheme for ecosystem '{ecosystem}'"

        if scanner_type == "TRIVY":
            source_evidence["trivy"] = {
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "version_status": trivy_status,
                "details": trivy_reason
            }

        # Source B: NVD CPE matches
        nvd_status = "UNKNOWN"
        nvd_reason = "No NVD CPE matches found"
        mapping_status = "NOT_APPLICABLE"
        mapping_reason = "No CPE matches to evaluate"

        cpe_matches = cve_record.get("cpe_matches", [])
        if cpe_matches:
            # Check CPE-to-package mapping (Requirement 11 & TEST U)
            first_cpe = cpe_matches[0]
            cpe_prod = first_cpe.get("product")
            cpe_vendor = first_cpe.get("vendor")

            mapping_status, mapping_reason = verify_cpe_package_mapping(cpe_vendor, cpe_prod, pkg_name)

            if mapping_status == "UNCERTAIN":
                nvd_status = "UNKNOWN"
                nvd_reason = f"Uncertain CPE product '{cpe_prod}' to package '{pkg_name}' mapping. NVD evidence held as UNKNOWN."
            elif not installed_version:
                nvd_status = "UNKNOWN"
                nvd_reason = "No installed version provided by scanner"
            elif not EcosystemVersionComparator.can_compare(ecosystem, installed_version, "0.0.1"):
                nvd_status = "UNKNOWN"
                nvd_reason = f"Unsupported ecosystem '{ecosystem}' for version comparison"
            else:
                # Evaluate NVD version ranges
                matched_affected = False
                matched_outside = False
                all_evaluable = True

                for m in cpe_matches:
                    if not m.get("vulnerable"):
                        continue
                    in_range, reason = self._check_range(
                        ecosystem,
                        installed_version,
                        start_inc=m.get("version_start_including"),
                        start_exc=m.get("version_start_excluding"),
                        end_inc=m.get("version_end_including"),
                        end_exc=m.get("version_end_excluding"),
                        exact_ver=m.get("version")
                    )
                    if in_range is True:
                        matched_affected = True
                        nvd_reason = f"Installed version {installed_version} matches NVD CPE range: {reason}"
                        break
                    elif in_range is False:
                        matched_outside = True
                    else:
                        all_evaluable = False

                if matched_affected:
                    nvd_status = "AFFECTED"
                elif matched_outside and all_evaluable:
                    nvd_status = "NOT_AFFECTED"
                    nvd_reason = f"Installed version {installed_version} is outside all NVD vulnerable ranges"
                else:
                    nvd_status = "UNKNOWN"
                    nvd_reason = "Installed version could not be conclusively evaluated against NVD CPE ranges"

            source_evidence["nvd"] = {
                "cpe_matches_count": len(cpe_matches),
                "mapping_status": mapping_status,
                "mapping_reason": mapping_reason,
                "version_status": nvd_status,
                "details": nvd_reason
            }

        # Source C: CVE List V5 (CNA statements)
        cve_list_status = "UNKNOWN"
        cve_list_reason = "No CVE List V5 affected version ranges found"
        aff_versions = cve_record.get("affected_versions", [])

        if aff_versions:
            if not installed_version:
                cve_list_status = "UNKNOWN"
                cve_list_reason = "No installed version provided by scanner"
            elif not EcosystemVersionComparator.can_compare(ecosystem, installed_version, "0.0.1"):
                cve_list_status = "UNKNOWN"
                cve_list_reason = f"Unsupported ecosystem '{ecosystem}' for version comparison"
            else:
                matched_affected = False
                matched_outside = False
                for aff in aff_versions:
                    st = aff.get("version_status", "affected")
                    v_val = aff.get("version_value")
                    lt = aff.get("less_than")
                    lte = aff.get("less_than_or_equal")

                    in_range, reason = self._check_range(
                        ecosystem,
                        installed_version,
                        start_inc=v_val,
                        end_inc=lte,
                        end_exc=lt
                    )
                    if in_range is True:
                        if st == "affected":
                            matched_affected = True
                            cve_list_reason = f"Installed version {installed_version} matches CVE List V5 affected range: {reason}"
                            break
                        elif st == "unaffected":
                            matched_outside = True
                            cve_list_reason = f"Installed version {installed_version} explicitly marked unaffected: {reason}"
                    elif in_range is False:
                        matched_outside = True

                if matched_affected:
                    cve_list_status = "AFFECTED"
                elif matched_outside:
                    cve_list_status = "NOT_AFFECTED"
                    cve_list_reason = cve_list_reason or f"Installed version {installed_version} outside CVE List V5 affected statements"
                else:
                    cve_list_status = "UNKNOWN"

            source_evidence["cve_list_v5"] = {
                "affected_ranges_count": len(aff_versions),
                "version_status": cve_list_status,
                "details": cve_list_reason
            }

        # 4. Synthesize final version evidence and detect material conflicts (Requirement 12)
        final_status, final_reason = self._synthesize_evidence(
            source_evidence,
            trivy_status,
            nvd_status,
            cve_list_status,
            scanner_type
        )

        return {
            "identifier": raw_id,
            "identifier_type": "CVE",
            "database_status": "FOUND",
            "canonical_cve": normalized_id,
            "version_evidence": final_status,
            "version_evidence_reason": final_reason,
            "scanner": scanner_type,
            "scanner_evidence": scanner_evidence,
            "source_evidence": source_evidence,
            "provenance": provenance,
            "mapping_status": mapping_status,
            "mapping_reason": mapping_reason,
            "performance_metadata": {
                "lookup_duration_ms": round(elapsed_ms, 3)
            }
        }

    def _check_range(
        self,
        ecosystem: Optional[str],
        installed: str,
        start_inc: Optional[str] = None,
        start_exc: Optional[str] = None,
        end_inc: Optional[str] = None,
        end_exc: Optional[str] = None,
        exact_ver: Optional[str] = None
    ) -> Tuple[Optional[bool], str]:
        """Check if an installed version falls within boundary constraints."""
        if exact_ver and exact_ver != "*":
            if EcosystemVersionComparator.can_compare(ecosystem, installed, exact_ver):
                eq = (EcosystemVersionComparator.compare(ecosystem, installed, exact_ver) == 0)
                return eq, f"exact match == {exact_ver}"

        # Evaluate lower bound
        if start_inc and start_inc != "*":
            if not EcosystemVersionComparator.can_compare(ecosystem, installed, start_inc):
                return None, f"Cannot compare with start_including: {start_inc}"
            if EcosystemVersionComparator.compare(ecosystem, installed, start_inc) < 0:
                return False, f"{installed} < start_including {start_inc}"

        if start_exc and start_exc != "*":
            if not EcosystemVersionComparator.can_compare(ecosystem, installed, start_exc):
                return None, f"Cannot compare with start_excluding: {start_exc}"
            if EcosystemVersionComparator.compare(ecosystem, installed, start_exc) <= 0:
                return False, f"{installed} <= start_excluding {start_exc}"

        # Evaluate upper bound
        if end_inc and end_inc != "*":
            if not EcosystemVersionComparator.can_compare(ecosystem, installed, end_inc):
                return None, f"Cannot compare with end_including: {end_inc}"
            if EcosystemVersionComparator.compare(ecosystem, installed, end_inc) > 0:
                return False, f"{installed} > end_including {end_inc}"

        if end_exc and end_exc != "*":
            if not EcosystemVersionComparator.can_compare(ecosystem, installed, end_exc):
                return None, f"Cannot compare with end_excluding: {end_exc}"
            if EcosystemVersionComparator.compare(ecosystem, installed, end_exc) >= 0:
                return False, f"{installed} >= end_excluding {end_exc}"

        range_desc = f"[{start_inc or '*'}:{end_inc or end_exc or '*'}]"
        return True, f"{installed} within range {range_desc}"

    def _synthesize_evidence(
        self,
        source_evidence: Dict[str, Any],
        trivy_status: str,
        nvd_status: str,
        cve_list_status: str,
        scanner_type: str
    ) -> Tuple[str, str]:
        """
        Synthesize final version evidence and enforce genuine material conflict detection.
        """
        # Collect distinct authoritative determinations
        authoritative = {}
        if scanner_type == "TRIVY" and trivy_status in ("AFFECTED", "NOT_AFFECTED"):
            authoritative["TRIVY"] = trivy_status
        if nvd_status in ("AFFECTED", "NOT_AFFECTED"):
            authoritative["NVD"] = nvd_status
        if cve_list_status in ("AFFECTED", "NOT_AFFECTED"):
            authoritative["CVE_LIST_V5"] = cve_list_status

        has_affected = any(st == "AFFECTED" for st in authoritative.values())
        has_not_affected = any(st == "NOT_AFFECTED" for st in authoritative.values())

        # Genuine material conflict: contradictory conclusions on the actual installed version
        if has_affected and has_not_affected:
            conflicting_sources = [f"{src}={st}" for src, st in authoritative.items()]
            return (
                "VERSION_EVIDENCE_CONFLICT",
                f"Material version evidence conflict between sources: {', '.join(conflicting_sources)}"
            )

        if has_affected:
            sources_affected = [src for src, st in authoritative.items() if st == "AFFECTED"]
            return "AFFECTED", f"Authoritative source(s) conclude installed version is affected: {', '.join(sources_affected)}"

        if has_not_affected:
            sources_not_affected = [src for src, st in authoritative.items() if st == "NOT_AFFECTED"]
            return "NOT_AFFECTED", f"Authoritative source(s) conclude installed version is not affected: {', '.join(sources_not_affected)}"

        # If Nuclei scanner had valid CVE but insufficient version
        if scanner_type == "NUCLEI":
            return "UNKNOWN", "Nuclei template match confirms CVE occurrence on live endpoint but provides insufficient version bounds"

        return "UNKNOWN", "Insufficient authoritative version evidence to establish deterministic status"

    # ==================================================================
    # 5. Performance Benchmark
    # ==================================================================

    def benchmark_exact_lookup(self, cve_id: str = "CVE-2025-24813", repetitions: int = 100) -> Dict[str, Any]:
        """
        Benchmark exact CVE lookup latency against local SQLite database.
        Strict performance target: < 100 ms per lookup.
        """
        counts = self.db.get_counts()
        total_records = counts["total_cves"]

        latencies_ms = []
        for _ in range(repetitions):
            t0 = time.perf_counter()
            rec = self.db.lookup_cve(cve_id, include_rejected=False)
            t_ms = (time.perf_counter() - t0) * 1000.0
            latencies_ms.append(t_ms)

        mean_latency = sum(latencies_ms) / len(latencies_ms)
        p95_latency = sorted(latencies_ms)[int(len(latencies_ms) * 0.95)]
        target_met = (p95_latency < 100.0)

        return {
            "database_record_count": total_records,
            "lookup_cve": cve_id,
            "repetitions": repetitions,
            "mean_latency_ms": round(mean_latency, 3),
            "p95_latency_ms": round(p95_latency, 3),
            "target_ms": 100.0,
            "target_met": target_met,
            "environment": os.name
        }
