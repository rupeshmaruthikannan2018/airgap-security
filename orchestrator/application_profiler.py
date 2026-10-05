"""
Application Profiler for AirGap Security Platform.

Inspects an extracted project tree and produces rich, structured metadata
for automated scanner selection, including:
- Programming languages
- Frameworks (Flask, Django, Spring, Tomcat, Express, FastAPI, etc.)
- Dependency manifests and lockfiles
- Infrastructure-as-code files (Docker, Kubernetes, Terraform, Helm, etc.)
- Web application determination (true/false/unknown)
- Detected executables and binaries
- Configuration files and candidate secret files
- Test suites vs documentation-only archives
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class ApplicationProfiler:
    """
    Generic application inspection engine.
    Does NOT hardcode any CVE or product specific rules.
    """

    LANGUAGE_EXTENSIONS = {
        "python": {".py", ".pyw"},
        "java": {".java"},
        "javascript": {".js", ".jsx", ".mjs", ".cjs"},
        "typescript": {".ts", ".tsx"},
        "go": {".go"},
        "rust": {".rs"},
        "php": {".php", ".phtml"},
        "ruby": {".rb"},
        "c": {".c", ".h"},
        "cpp": {".cpp", ".cc", ".cxx", ".hpp", ".hh"},
        "csharp": {".cs"},
    }

    MANIFEST_FILENAMES = {
        "requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg",
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
        "go.mod", "go.sum",
        "Cargo.toml", "Cargo.lock",
        "Gemfile", "Gemfile.lock",
        "composer.json", "composer.lock"
    }

    BINARY_EXTENSIONS = {
        ".jar", ".war", ".ear", ".class", ".pyc", ".pyo",
        ".dll", ".exe", ".so", ".dylib", ".bin", ".dat", ".o", ".a"
    }

    EXECUTABLE_EXTENSIONS = {
        ".exe", ".bat", ".cmd", ".sh", ".bash", ".ps1", ".vbs"
    }

    SECRET_PATTERNS = [
        re.compile(r'^\.env(\.[a-z0-9_\-]+)?$', re.I),
        re.compile(r'^id_rsa(\.pub)?$', re.I),
        re.compile(r'^id_ed25519(\.pub)?$', re.I),
        re.compile(r'^credentials\.json$', re.I),
        re.compile(r'.*\.(pem|key|pkcs12|pfx|p12|jks|kdb)$', re.I),
        re.compile(r'.*secret.*\.(yaml|yml|json|txt|env)$', re.I)
    ]

    CONFIG_FILENAMES = {
        "server.xml", "web.xml", "context.xml", "nginx.conf", "httpd.conf",
        "application.properties", "application.yml", "application.yaml",
        "settings.py", "config.json", "config.yaml", "config.yml",
        ".env", "docker-compose.yml", "docker-compose.yaml"
    }

    DOC_EXTENSIONS = {
        ".md", ".markdown", ".txt", ".rst", ".pdf", ".docx", ".doc",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".license", ".changelog"
    }

    @staticmethod
    def determine_application_root(target_dir: Path) -> Path:
        """
        Determines the actual project root directory inside an extracted archive tree.
        Handles GitHub-style wrapper directories (e.g. repo-master/, repo-main/)
        or nested application trees based on manifest and source file evidence.
        """
        target_dir = Path(target_dir).resolve()
        if not target_dir.exists() or not target_dir.is_dir():
            return target_dir

        manifest_names = {
            "package.json", "requirements.txt", "pyproject.toml", "pom.xml",
            "build.gradle", "go.mod", "cargo.toml", "gemfile", "composer.json",
            "dockerfile", "docker-compose.yml", "docker-compose.yaml", "server.xml"
        }

        # Check if target_dir itself contains manifest files
        try:
            root_entries = list(target_dir.iterdir())
        except OSError:
            return target_dir

        root_files = [f for f in root_entries if f.is_file() and not f.name.startswith(".")]
        root_file_names = {f.name.lower() for f in root_files}

        if root_file_names & manifest_names:
            return target_dir

        # Check non-hidden, non-system subdirectories
        subdirs = [
            d for d in root_entries
            if d.is_dir() and not d.name.startswith(".") and d.name != "__MACOSX"
        ]

        # Case 1: Exactly one top-level directory (standard GitHub release/archive wrapper)
        if len(subdirs) == 1:
            candidate = subdirs[0]
            # Recursively check if candidate itself has a single wrapper or is the root
            return ApplicationProfiler.determine_application_root(candidate)

        # Case 2: If root has no manifests, check if exactly one subdirectory has manifests
        subdirs_with_manifests = []
        for d in subdirs:
            try:
                d_files = {f.name.lower() for f in d.iterdir() if f.is_file()}
                if d_files & manifest_names:
                    subdirs_with_manifests.append(d)
            except OSError:
                continue

        if len(subdirs_with_manifests) == 1:
            return subdirs_with_manifests[0]

        return target_dir

    def __init__(self, target_dir: Path | str):
        self.root = Path(target_dir).resolve()
        self.app_root = self.determine_application_root(self.root)

    def profile(self) -> Dict[str, Any]:
        """
        Inspects the directory tree and builds the structured profile.
        """
        scan_target = self.app_root if self.app_root.exists() else self.root
        if not scan_target.exists():
            return {
                "application": self.root.name,
                "path": str(self.root),
                "application_root": str(scan_target),
                "error": "Directory does not exist",
                "languages": [],
                "frameworks": [],
                "dependency_manifests": [],
                "infrastructure": [],
                "web_application": "unknown",
                "executables": [],
                "binary_files": [],
                "config_files": [],
                "secret_candidate_files": [],
                "test_files": [],
                "documentation_only": False,
                "total_files": 0,
                "files": []
            }

        all_files: List[Path] = []
        try:
            for p in scan_target.rglob("*"):
                if p.is_file():
                    all_files.append(p)
        except OSError:
            pass

        relative_files = [str(f.relative_to(scan_target)).replace("\\", "/") for f in all_files]

        detected_languages: Set[str] = set()
        detected_manifests: Set[str] = set()
        detected_infra: Set[str] = set()
        detected_frameworks: Set[str] = set()
        detected_executables: List[str] = []
        detected_binaries: List[str] = []
        detected_configs: List[str] = []
        detected_secrets: List[str] = []
        detected_tests: List[str] = []

        has_code_or_manifest = False

        for f_path in all_files:
            rel = str(f_path.relative_to(scan_target)).replace("\\", "/")
            name = f_path.name
            low_name = name.lower()
            suffix = f_path.suffix.lower()

            # 1. Dependency Manifests
            if low_name in self.MANIFEST_FILENAMES or name in self.MANIFEST_FILENAMES:
                detected_manifests.add(name)
                has_code_or_manifest = True
                if "requirements" in low_name or "pyproject" in low_name or "pipfile" in low_name or low_name.startswith("setup."):
                    detected_languages.add("python")
                elif "package" in low_name or "yarn" in low_name or "pnpm" in low_name:
                    detected_languages.add("javascript")
                elif "pom.xml" in low_name or "gradle" in low_name:
                    detected_languages.add("java")
                elif "go.mod" in low_name or "go.sum" in low_name:
                    detected_languages.add("go")
                elif "cargo" in low_name:
                    detected_languages.add("rust")
                elif "gemfile" in low_name:
                    detected_languages.add("ruby")
                elif "composer" in low_name:
                    detected_languages.add("php")

            # 2. Languages by extension
            for lang, exts in self.LANGUAGE_EXTENSIONS.items():
                if suffix in exts:
                    detected_languages.add(lang)
                    has_code_or_manifest = True

            # 3. Binaries & Executables
            if suffix in self.BINARY_EXTENSIONS:
                detected_binaries.append(rel)
                has_code_or_manifest = True
            if suffix in self.EXECUTABLE_EXTENSIONS:
                detected_executables.append(rel)

            # 4. Config files
            if low_name in self.CONFIG_FILENAMES or suffix in {".conf", ".properties", ".ini"}:
                detected_configs.append(rel)

            # 5. Secret candidate files
            if any(pat.match(name) for pat in self.SECRET_PATTERNS):
                detected_secrets.append(rel)

            # 6. Test files
            if (
                low_name.startswith("test_") or low_name.endswith("_test.py") or
                low_name.endswith("_test.go") or "test" in low_name.split(".")[0].lower() or
                "/test/" in f"/{rel.lower()}" or "/tests/" in f"/{rel.lower()}" or
                suffix in {".spec.js", ".test.js", ".spec.ts", ".test.ts"}
            ):
                detected_tests.append(rel)

            # 7. Infrastructure Detection
            if low_name == "dockerfile" or low_name.startswith("dockerfile."):
                detected_infra.add("Dockerfile")
                has_code_or_manifest = True
            elif "docker-compose" in low_name:
                detected_infra.add("docker-compose")
                has_code_or_manifest = True
            elif suffix in {".tf", ".tfvars"}:
                detected_infra.add("Terraform")
                has_code_or_manifest = True
            elif low_name == "chart.yaml" or low_name == "values.yaml":
                detected_infra.add("Helm")
                has_code_or_manifest = True
            elif low_name in {"playbook.yml", "playbook.yaml"} or "/roles/" in f"/{rel}":
                detected_infra.add("Ansible")
                has_code_or_manifest = True
            elif suffix in {".yaml", ".yml"}:
                # Check for Kubernetes YAML or CloudFormation
                if self._check_file_snippet(f_path, r'kind:\s*(Deployment|Service|Pod|ConfigMap|Ingress|StatefulSet|DaemonSet)'):
                    detected_infra.add("Kubernetes YAML")
                    has_code_or_manifest = True
                elif self._check_file_snippet(f_path, r'AWS::CloudFormation'):
                    detected_infra.add("CloudFormation")
                    has_code_or_manifest = True

        # Framework detection by inspecting manifests and code imports
        detected_frameworks = self._detect_frameworks(all_files, detected_languages, detected_manifests)

        # Web application determination
        is_web = False
        web_frameworks = {
            "Flask", "Django", "FastAPI", "Express", "Spring", "Tomcat",
            "Next.js", "Rails", "Gin", "Laravel", "ASP.NET", "Koa"
        }
        if detected_frameworks & web_frameworks:
            is_web = True
        elif any(f.endswith(("server.xml", "web.xml", "nginx.conf", "httpd.conf")) for f in relative_files):
            is_web = True
        elif any("router" in f.lower() or "controller" in f.lower() or "servlet" in f.lower() for f in relative_files):
            is_web = True

        # Documentation-only check
        doc_only = False
        if not has_code_or_manifest and not detected_languages and not detected_manifests and not detected_infra:
            if all_files:
                doc_only = all(f.suffix.lower() in self.DOC_EXTENSIONS or f.name.lower() in {"readme", "license", "authors", "notice"} for f in all_files)
            else:
                doc_only = False

        # Maintain manifest list backward compatibility (adding string names)
        manifest_names = sorted(list(detected_manifests))
        if "Dockerfile" in detected_infra and "Dockerfile" not in manifest_names:
            manifest_names.append("Dockerfile")

        # Determine human-friendly application name
        app_name = self.app_root.name
        for f in all_files:
            if f.name.lower() == "package.json":
                try:
                    import json
                    pkg_data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
                    if pkg_data.get("name") and isinstance(pkg_data["name"], str):
                        app_name = pkg_data["name"]
                        break
                except Exception:
                    pass

        return {
            "application": app_name,
            "path": str(self.root),
            "application_root": str(self.app_root),
            "languages": sorted(list(detected_languages)),
            "frameworks": sorted(list(detected_frameworks)),
            "dependency_manifests": sorted(list(detected_manifests)),
            "manifests": manifest_names,  # backward compatibility with profiler.py
            "infrastructure": sorted(list(detected_infra)),
            "web_application": is_web,
            "executables": detected_executables[:100],
            "binary_files": detected_binaries[:100],
            "config_files": detected_configs[:100],
            "secret_candidate_files": detected_secrets[:100],
            "test_files": detected_tests[:100],
            "documentation_only": doc_only,
            "total_files": len(all_files),
            "files": relative_files
        }

    def _detect_frameworks(
        self,
        files: List[Path],
        languages: Set[str],
        manifests: Set[str]
    ) -> Set[str]:
        """Scans manifest files and representative code files for framework markers."""
        frameworks: Set[str] = set()

        # Check Python frameworks
        if "python" in languages:
            req_files = [f for f in files if f.name.lower() in {"requirements.txt", "pyproject.toml"}]
            req_text = ""
            for rf in req_files:
                try:
                    req_text += "\n" + rf.read_text(encoding="utf-8", errors="replace").lower()
                except Exception:
                    pass

            if "flask" in req_text:
                frameworks.add("Flask")
            if "django" in req_text:
                frameworks.add("Django")
            if "fastapi" in req_text:
                frameworks.add("FastAPI")
            if "tornado" in req_text:
                frameworks.add("Tornado")

            if not frameworks:
                for f in files[:30]:
                    if f.suffix == ".py":
                        try:
                            content = f.read_text(encoding="utf-8", errors="replace")[:2000]
                            if re.search(r'\bfrom\s+flask\s+import|\bimport\s+flask\b', content):
                                frameworks.add("Flask")
                            if re.search(r'\bfrom\s+django\s+import|\bimport\s+django\b', content):
                                frameworks.add("Django")
                            if re.search(r'\bfrom\s+fastapi\s+import|\bimport\s+fastapi\b', content):
                                frameworks.add("FastAPI")
                        except Exception:
                            pass

        # Check JS/TS frameworks
        if "javascript" in languages or "typescript" in languages:
            pkg_files = [f for f in files if f.name.lower() == "package.json"]
            pkg_text = ""
            for pf in pkg_files:
                try:
                    pkg_text += "\n" + pf.read_text(encoding="utf-8", errors="replace").lower()
                except Exception:
                    pass

            if '"express"' in pkg_text or 'express' in pkg_text:
                frameworks.add("Express")
            if '"next"' in pkg_text or 'next' in pkg_text:
                frameworks.add("Next.js")
            if '"react"' in pkg_text or 'react' in pkg_text:
                frameworks.add("React")
            if '"vue"' in pkg_text or 'vue' in pkg_text:
                frameworks.add("Vue")
            if '"@angular/' in pkg_text or 'angular' in pkg_text:
                frameworks.add("Angular")
            if '"koa"' in pkg_text:
                frameworks.add("Koa")
            if '"fastify"' in pkg_text:
                frameworks.add("Fastify")
            if '"@nestjs/' in pkg_text:
                frameworks.add("NestJS")

        # Check Java frameworks
        if "java" in languages:
            java_build_files = [f for f in files if f.name.lower() in {"pom.xml", "build.gradle", "build.gradle.kts"}]
            java_build_text = ""
            for jf in java_build_files:
                try:
                    java_build_text += "\n" + jf.read_text(encoding="utf-8", errors="replace").lower()
                except Exception:
                    pass

            if "spring-boot" in java_build_text:
                frameworks.add("Spring Boot")
                frameworks.add("Spring")
            elif "springframework" in java_build_text:
                frameworks.add("Spring")
            if "quarkus" in java_build_text:
                frameworks.add("Quarkus")
            if "micronaut" in java_build_text:
                frameworks.add("Micronaut")

            for f in files[:40]:
                if f.name in {"server.xml", "web.xml"}:
                    frameworks.add("Tomcat")
                elif f.suffix == ".java":
                    try:
                        content = f.read_text(encoding="utf-8", errors="replace")[:2000]
                        if "@SpringBootApplication" in content or "org.springframework" in content:
                            frameworks.add("Spring")
                    except Exception:
                        pass

        # Check Go frameworks
        if "go" in languages:
            go_mod_files = [f for f in files if f.name.lower() == "go.mod"]
            mod_text = ""
            for gf in go_mod_files:
                try:
                    mod_text += "\n" + gf.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass

            if "github.com/gin-gonic/gin" in mod_text:
                frameworks.add("Gin")
            if "github.com/labstack/echo" in mod_text:
                frameworks.add("Echo")
            if "github.com/gofiber/fiber" in mod_text:
                frameworks.add("Fiber")

        return frameworks

    @staticmethod
    def _check_file_snippet(file_path: Path, pattern: str) -> bool:
        """Reads initial part of file and tests regex pattern safely."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                header = f.read(4096)
                return bool(re.search(pattern, header, re.I))
        except Exception:
            return False


def profile_application(app_path: Path | str) -> Dict[str, Any]:
    """
    Drop-in replacement for the original profile_application function
    enriched with full multi-language, manifest, framework, and infrastructure detection.
    """
    profiler = ApplicationProfiler(app_path)
    return profiler.profile()
