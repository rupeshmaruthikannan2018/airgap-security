"""
Secure Archive Extractor for AirGap Security Platform.

Provides hardened ZIP validation and extraction protecting against:
- Zip Slip / path traversal attacks (relative paths escaping root, '..')
- Absolute path archive entries (/etc/passwd, C:\\Windows)
- Zip bombs / explosive compression ratios
- Excessive archive sizes, individual file sizes, or file counts
- Deeply nested recursive archives (configurable max recursion depth)
- Malformed or corrupt ZIP archives
- Dangerous symbolic links pointing outside workspace

Design Invariants:
- Never executes extracted files.
- Never imports extracted code into scanner processes.
- Never overwrites files outside destination.
- Preserves relative file paths inside target.
- Produces structured extraction metadata including rejected entries.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any, Dict, List, Optional, Set, Tuple
import zipfile


class ArchiveSecurityError(Exception):
    """Raised when an archive violates security constraints or limits."""
    pass


class ArchiveLimits:
    """Configurable security constraints for archive extraction."""
    def __init__(
        self,
        max_archive_size: int = 200 * 1024 * 1024,      # 200 MB
        max_extracted_size: int = 500 * 1024 * 1024,    # 500 MB
        max_files: int = 10000,                         # 10,000 files
        max_file_size: int = 100 * 1024 * 1024,         # 100 MB per file
        max_nested_archive_depth: int = 2,              # Max recursion depth
        max_compression_ratio: float = 100.0,           # Zip bomb threshold
        min_bytes_for_ratio_check: int = 100 * 1024     # 100 KB min to check ratio
    ):
        self.max_archive_size = max_archive_size
        self.max_extracted_size = max_extracted_size
        self.max_files = max_files
        self.max_file_size = max_file_size
        self.max_nested_archive_depth = max_nested_archive_depth
        self.max_compression_ratio = max_compression_ratio
        self.min_bytes_for_ratio_check = min_bytes_for_ratio_check

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_archive_size": self.max_archive_size,
            "max_extracted_size": self.max_extracted_size,
            "max_files": self.max_files,
            "max_file_size": self.max_file_size,
            "max_nested_archive_depth": self.max_nested_archive_depth,
            "max_compression_ratio": self.max_compression_ratio,
        }


class ExtractionResult:
    """Summary of archive extraction operation."""
    def __init__(self, destination: Path):
        self.destination = destination
        self.extracted_files: List[str] = []
        self.rejected_entries: List[Dict[str, str]] = []
        self.warnings: List[str] = []
        self.total_extracted_bytes: int = 0
        self.file_count: int = 0
        self.archive_sha256: str = ""
        self.archive_size: int = 0
        self.nested_archives_extracted: int = 0

    @property
    def total_extracted_files(self) -> int:
        return len(self.extracted_files)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "destination": str(self.destination),
            "total_extracted_files": len(self.extracted_files),
            "total_extracted_bytes": self.total_extracted_bytes,
            "archive_sha256": self.archive_sha256,
            "archive_size": self.archive_size,
            "rejected_entries_count": len(self.rejected_entries),
            "rejected_entries": self.rejected_entries,
            "warnings_count": len(self.warnings),
            "warnings": self.warnings,
            "nested_archives_extracted": self.nested_archives_extracted,
        }


class SecureArchiveExtractor:
    """
    Dedicated secure archive extractor for the AirGap Security platform.
    """

    def __init__(self, limits: Optional[ArchiveLimits] = None):
        self.limits = limits or ArchiveLimits()

    @staticmethod
    def compute_sha256(file_path: Path) -> str:
        """Calculate SHA256 digest of a file safely in chunks."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def validate_and_extract(
        self,
        archive_path: Path | str,
        destination: Path | str,
        current_depth: int = 0,
        result: Optional[ExtractionResult] = None
    ) -> ExtractionResult:
        """
        Validates archive constraints and safely extracts contents into destination.
        """
        archive_path = Path(archive_path).resolve()
        destination = Path(destination).resolve()

        if result is None:
            result = ExtractionResult(destination)
            result.archive_size = archive_path.stat().st_size if archive_path.exists() else 0
            if archive_path.exists():
                result.archive_sha256 = self.compute_sha256(archive_path)

        # 1. Basic existence and archive size checks
        if not archive_path.exists() or not archive_path.is_file():
            raise ArchiveSecurityError(f"Archive file not found: {archive_path}")

        archive_size = archive_path.stat().st_size
        if archive_size == 0:
            raise ArchiveSecurityError("Archive file is empty (0 bytes).")

        if archive_size > self.limits.max_archive_size:
            raise ArchiveSecurityError(
                f"Archive size ({archive_size} bytes) exceeds configured maximum "
                f"of {self.limits.max_archive_size} bytes."
            )

        # 2. Check valid zip structure
        if not zipfile.is_zipfile(archive_path):
            raise ArchiveSecurityError(f"File is not a valid ZIP archive: {archive_path.name}")

        try:
            zf = zipfile.ZipFile(archive_path, "r")
        except Exception as e:
            raise ArchiveSecurityError(f"Malformed or corrupt ZIP archive: {e}") from e

        with zf:
            infolist = zf.infolist()

            # Pre-flight inspection across all entries
            if len(infolist) == 0:
                raise ArchiveSecurityError("ZIP archive contains zero entries.")

            projected_files = result.file_count + len([i for i in infolist if not i.is_dir()])
            if projected_files > self.limits.max_files:
                raise ArchiveSecurityError(
                    f"Archive entry count exceeds configured limit of {self.limits.max_files} files."
                )

            nested_archives: List[Tuple[Path, str]] = []
            destination.mkdir(parents=True, exist_ok=True)

            for info in infolist:
                raw_filename = info.filename

                # A. Check for path traversal / Zip Slip
                is_safe, reason = self._is_safe_path(raw_filename, destination)
                if not is_safe:
                    result.rejected_entries.append({
                        "entry": raw_filename,
                        "reason": f"Path traversal / unsafe path: {reason}"
                    })
                    continue

                target_path = (destination / raw_filename).resolve()

                # B. Check for single file size limits
                if info.file_size > self.limits.max_file_size:
                    result.rejected_entries.append({
                        "entry": raw_filename,
                        "reason": f"File size ({info.file_size} B) exceeds maximum ({self.limits.max_file_size} B)"
                    })
                    continue

                # C. Check compression ratio (Zip Bomb detection)
                if info.file_size >= self.limits.min_bytes_for_ratio_check and info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > self.limits.max_compression_ratio:
                        result.rejected_entries.append({
                            "entry": raw_filename,
                            "reason": f"Suspicious compression ratio ({ratio:.1f}:1 > {self.limits.max_compression_ratio}:1)"
                        })
                        continue

                # D. Check cumulative extracted size
                if result.total_extracted_bytes + info.file_size > self.limits.max_extracted_size:
                    raise ArchiveSecurityError(
                        f"Cumulative extracted size exceeds configured limit of {self.limits.max_extracted_size} bytes."
                    )

                # E. Handle directories
                if info.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue

                # F. Handle Symlinks safely
                # In ZIP archives, symlinks store target path in file content
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    symlink_target = zf.read(info).decode("utf-8", errors="replace").strip()
                    # Check whether symlink escapes destination
                    resolved_link = (target_path.parent / symlink_target).resolve()
                    try:
                        if not resolved_link.is_relative_to(destination):
                            result.rejected_entries.append({
                                "entry": raw_filename,
                                "reason": f"Symlink targets outside extraction directory: '{symlink_target}'"
                            })
                            continue
                    except AttributeError:
                        # Fallback for older python or Windows path quirks
                        if not str(resolved_link).startswith(str(destination)):
                            result.rejected_entries.append({
                                "entry": raw_filename,
                                "reason": f"Symlink targets outside extraction directory: '{symlink_target}'"
                            })
                            continue

                    # For security and portable air-gapped consistency, we do not create live symlinks
                    # that could point to arbitrary OS paths; we store symlink reference safely
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    target_path.write_text(f"[SYMLINK -> {symlink_target}]", encoding="utf-8")
                    result.extracted_files.append(str(target_path.relative_to(destination)))
                    result.warnings.append(f"Sanitized symbolic link '{raw_filename}' targeting '{symlink_target}'")
                    continue

                # G. Extract regular file safely in bounded chunks
                target_path.parent.mkdir(parents=True, exist_ok=True)
                written_bytes = 0

                with zf.open(info, "r") as source, open(target_path, "wb") as target_file:
                    while chunk := source.read(65536):
                        written_bytes += len(chunk)
                        result.total_extracted_bytes += len(chunk)
                        if written_bytes > self.limits.max_file_size:
                            target_file.close()
                            if target_path.exists():
                                target_path.unlink()
                            raise ArchiveSecurityError(
                                f"Extracted file '{raw_filename}' exceeded maximum size during stream decompression."
                            )
                        if result.total_extracted_bytes > self.limits.max_extracted_size:
                            target_file.close()
                            if target_path.exists():
                                target_path.unlink()
                            raise ArchiveSecurityError(
                                f"Cumulative extracted size exceeded limit ({self.limits.max_extracted_size} B) during decompression."
                            )
                        target_file.write(chunk)

                result.file_count += 1
                result.extracted_files.append(str(target_path.relative_to(destination)))

                # Check if this is a nested zip file
                if target_path.suffix.lower() == ".zip":
                    nested_archives.append((target_path, raw_filename))

        # Handle nested archives up to configured depth limit
        for nested_path, entry_name in nested_archives:
            if current_depth < self.limits.max_nested_archive_depth:
                nested_dest = nested_path.parent / f"{nested_path.stem}_nested"
                try:
                    self.validate_and_extract(
                        nested_path,
                        nested_dest,
                        current_depth=current_depth + 1,
                        result=result
                    )
                    result.nested_archives_extracted += 1
                except Exception as err:
                    result.warnings.append(
                        f"Could not extract nested archive '{entry_name}' at depth {current_depth+1}: {err}"
                    )
            else:
                result.warnings.append(
                    f"Skipped nested archive '{entry_name}': recursion depth limit ({self.limits.max_nested_archive_depth}) reached."
                )

        return result

    @staticmethod
    def _is_safe_path(entry_path: str, destination: Path) -> Tuple[bool, Optional[str]]:
        """
        Validates that entry_path does not attempt path traversal or absolute escape.
        """
        clean_path = entry_path.strip()

        # Reject absolute paths (POSIX and Windows)
        if clean_path.startswith("/") or clean_path.startswith("\\"):
            return False, "Absolute path not permitted"
        if len(clean_path) >= 2 and clean_path[1] == ":":
            return False, "Drive letter absolute path not permitted"

        # Check for traversal components in path segments
        pure_posix = PurePosixPath(clean_path)
        parts = pure_posix.parts
        if ".." in parts:
            return False, "Relative parent '..' segment detected in path"

        # Resolve destination path check
        dest_resolved = destination.resolve()
        target_resolved = (dest_resolved / clean_path).resolve()

        try:
            if not target_resolved.is_relative_to(dest_resolved):
                return False, "Resolved path escapes extraction directory"
        except AttributeError:
            # Fallback for Python < 3.9
            if not str(target_resolved).startswith(str(dest_resolved)):
                return False, "Resolved path escapes extraction directory"

        return True, None
