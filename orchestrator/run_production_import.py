"""Production CVE Database Importer & Full-Scale Benchmark Runner.

Executes the Phase A Final production import from C:\\airgap-security\\cve_data_production
into orchestrator/cve_database_production.db.

Monitors:
- Cryptographic manifest verification
- Pre-import and post-import disk space
- Physical RAM (RSS) and Python heap
- Batch commits and checkpoint state
- Progress every 10,000 records
- Verification of CVE-2025-24813
- Full-scale exact lookup benchmark against the full production database
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

# Setup paths
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))
workspace_dir = current_dir.parent
if str(workspace_dir) not in sys.path:
    sys.path.insert(0, str(workspace_dir))

from cve_db import CVEDatabase
from cve_importer import CVEImporter


def main():
    print("=" * 70)
    print("AIRGAP SECURITY PLATFORM — PHASE A PRODUCTION DATABASE IMPORT")
    print("=" * 70)

    pkg_dir = Path("C:/airgap-security/cve_data_production")
    db_path = current_dir / "cve_database_production.db"

    if not pkg_dir.exists():
        print(f"[FATAL] Production acquisition directory not found: {pkg_dir}")
        sys.exit(1)

    print(f"Acquisition Package : {pkg_dir}")
    print(f"Target Database     : {db_path}")

    # Check disk space before import
    has_space, free_gb_before, total_gb = CVEImporter.check_disk_space(db_path, min_free_gb=5.0)
    print(f"Disk Space Before   : {free_gb_before:.2f} GB free of {total_gb:.2f} GB total")

    if not has_space:
        print(f"[FATAL] Insufficient disk space ({free_gb_before:.2f} GB < 5.0 GB minimum required).")
        sys.exit(1)

    # Initialize Importer
    importer = CVEImporter(db_path)

    # Verify Manifest
    print("\nVerifying manifest.json cryptographic integrity...")
    manifest_ok, manifest_msg = importer.verify_manifest(pkg_dir)
    print(manifest_msg)
    if not manifest_ok:
        print("[FATAL] Manifest verification failed. Halting build.")
        sys.exit(1)

    print("\nStarting production import (NVD Chunks + CVE List V5 Baseline ZIP)...")
    print("Batch size: 2000 | Progress reporting every 10,000 records\n")

    t_start = time.perf_counter()
    import_res = importer.import_package(
        pkg_dir,
        verify_hashes=False,  # Already verified above
        batch_size=2000,
        progress_interval=10000,
        resume=True
    )
    t_end = time.perf_counter()
    total_duration = t_end - t_start

    print("\n" + "=" * 70)
    print("PRODUCTION IMPORT COMPLETE")
    print("=" * 70)

    stats = import_res["stats"]
    db = importer.db
    counts = db.get_detailed_counts()

    print(f"Total Duration           : {stats.get('duration_formatted', f'{total_duration:.1f}s')} ({total_duration:.2f}s)")
    print(f"Peak RSS RAM             : {stats.get('peak_rss_mb', 0):.2f} MB")
    print(f"Peak Traced Heap         : {stats.get('peak_memory_mb', 0):.2f} MB")
    print(f"Final DB Size            : {stats.get('final_db_size_mb', 0):.2f} MB")
    print(f"Final WAL Size           : {stats.get('wal_size_mb', 0):.2f} MB")
    print(f"Disk Space After         : {stats.get('disk_space_after_gb', 0):.2f} GB free")

    print("\n[DATABASE RECORD COUNTS]")
    print(f"Total Canonical CVEs     : {counts['total_cves']:,}")
    print(f"Active CVEs              : {counts['active_cves']:,}")
    print(f"Rejected CVEs            : {counts['rejected_cves']:,}")
    print(f"NVD Source Records       : {counts['nvd_record_count']:,}")
    print(f"CVE List V5 Records      : {counts['cve_list_record_count']:,}")
    print(f"Multi-Source Linked CVEs : {counts['linked_cve_count']:,}")
    print(f"CVEs with CPE Data       : {counts['cves_with_cpe']:,}")
    print(f"CVEs Without CPE Data    : {counts['no_cpe_count']:,}")
    print(f"CVEs with Affected Vers  : {counts['cves_with_affected_versions']:,}")
    print(f"CVEs with CVSS Metrics   : {counts['cves_with_cvss']:,}")
    print(f"CVEs with CWEs           : {counts['cves_with_cwe']:,}")
    print(f"CVEs with References     : {counts['cves_with_references']:,}")

    # ------------------------------------------------------------------
    # Verify Regression CVE-2025-24813
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("REGRESSION VERIFICATION: CVE-2025-24813")
    print("=" * 70)

    reg_cve = db.lookup_cve("CVE-2025-24813")
    if not reg_cve:
        print("[FAIL] CVE-2025-24813 not found in production database!")
    else:
        print("[PASS] CVE-2025-24813 successfully retrieved via exact lookup.")
        print(f"  Summary               : {reg_cve.get('summary')}")
        print(f"  Primary Severity      : {reg_cve.get('primary_severity')} (Score: {reg_cve.get('primary_cvss_score')})")
        print(f"  Sources               : {reg_cve.get('sources')}")
        print(f"  CPE Matches Count     : {len(reg_cve.get('cpe_matches', []))}")
        print(f"  Affected Ranges Count : {len(reg_cve.get('affected_versions', []))}")
        print(f"  CVSS Metrics Count    : {len(reg_cve.get('cvss_metrics', []))}")
        print(f"  References Count      : {len(reg_cve.get('references', []))}")

    # ------------------------------------------------------------------
    # Full-Scale Exact Lookup Benchmark
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("FULL-SCALE PRODUCTION EXACT LOOKUP BENCHMARK")
    print("=" * 70)

    import statistics
    repetitions = 100
    latencies_ms = []

    # Warmup
    for _ in range(5):
        db.lookup_cve("CVE-2025-24813")

    for _ in range(repetitions):
        t0 = time.perf_counter()
        db.lookup_cve("CVE-2025-24813")
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)

    mean_ms = statistics.mean(latencies_ms)
    median_ms = statistics.median(latencies_ms)
    sorted_lats = sorted(latencies_ms)
    p95_index = int(0.95 * len(sorted_lats))
    p95_ms = sorted_lats[p95_index]
    target_met = mean_ms < 100.0

    print(f"Representative CVE       : CVE-2025-24813")
    print(f"Benchmark Repetitions    : {repetitions}")
    print(f"Mean Latency             : {mean_ms:.3f} ms")
    print(f"Median Latency           : {median_ms:.3f} ms")
    print(f"P95 Latency              : {p95_ms:.3f} ms")
    print(f"Performance Target       : < 100 ms")
    print(f"Target Met (< 100 ms)    : {'YES (PASS)' if target_met else 'NO (FAIL)'}")

    # Save complete structured results
    out_results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "acquisition_package": str(pkg_dir),
        "target_database": str(db_path),
        "manifest_verified": manifest_ok,
        "disk_space_before_gb": free_gb_before,
        "disk_space_after_gb": stats.get("disk_space_after_gb"),
        "final_db_size_mb": stats.get("final_db_size_mb"),
        "final_wal_size_mb": stats.get("wal_size_mb"),
        "peak_rss_mb": stats.get("peak_rss_mb"),
        "peak_heap_mb": stats.get("peak_memory_mb"),
        "total_duration_seconds": total_duration,
        "total_duration_formatted": stats.get("duration_formatted"),
        "counts": counts,
        "cve_2025_24813_verified": reg_cve is not None,
        "benchmark": {
            "cve": "CVE-2025-24813",
            "repetitions": repetitions,
            "mean_ms": round(mean_ms, 3),
            "median_ms": round(median_ms, 3),
            "p95_ms": round(p95_ms, 3),
            "target_ms": 100.0,
            "target_met": target_met
        }
    }

    results_path = current_dir / "production_import_results.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(out_results, f, indent=2)
    print(f"\nStructured results saved to: {results_path}")


if __name__ == "__main__":
    main()
