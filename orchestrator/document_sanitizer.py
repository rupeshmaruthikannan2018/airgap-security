"""
Generic Source Content Sanitization and Relevance Pipeline.

Provides structural document normalization, main security content extraction,
code-block context discrimination, passage relevance scoring, and the
configuration evidence gate before semantic condition extraction.

Architecture:
  URL -> Document Retrieval -> Document Type Detection -> Document Normalization
  -> Main Content Extraction -> Security Evidence Selection -> Semantic Extractor (Condition IR)
"""

from __future__ import annotations

import enum
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from bs4 import BeautifulSoup, Comment, NavigableString, Tag


class DocumentType(enum.Enum):
    HTML = "HTML"
    JSON = "JSON"
    MARKDOWN = "MARKDOWN"
    PLAIN_TEXT = "PLAIN_TEXT"


class PassageRelevance(enum.Enum):
    # Security-relevant categories
    SECURITY_ADVISORY_CONTENT = "SECURITY_ADVISORY_CONTENT"
    SECURITY_CONFIGURATION = "SECURITY_CONFIGURATION"
    SECURITY_VERSION = "SECURITY_VERSION"
    SECURITY_IMPACT = "SECURITY_IMPACT"
    SECURITY_ATTACK_CONDITION = "SECURITY_ATTACK_CONDITION"
    SECURITY_MITIGATION = "SECURITY_MITIGATION"
    SECURITY_REFERENCE = "SECURITY_REFERENCE"

    # Non-security webpage implementation / noise categories
    WEBPAGE_BOILERPLATE = "WEBPAGE_BOILERPLATE"
    JAVASCRIPT = "JAVASCRIPT"
    CSS = "CSS"
    ANALYTICS = "ANALYTICS"
    NAVIGATION = "NAVIGATION"
    UNRELATED_CONTENT = "UNRELATED_CONTENT"


class DocumentSanitizer:
    """
    Generic DOM and text normalizer that purges webpage implementation artifacts,
    retains legitimate security advisory prose and configuration examples, and gates
    configuration evidence to ensure target software context.
    """

    # HTML tags that are structural layout, scripting, metadata, or presentation noise
    NON_CONTENT_TAGS = {
        "script", "style", "noscript", "iframe", "object", "embed", "applet",
        "svg", "canvas", "audio", "video", "source", "track",
        "nav", "menu", "header", "footer", "aside",
        "form", "input", "button", "select", "textarea", "keygen",
        "dialog", "template", "portal", "link", "meta"
    }

    # ARIA roles that indicate non-advisory page UI
    DISCARD_ROLES = {
        "navigation", "banner", "contentinfo", "complementary", "search",
        "dialog", "alertdialog", "toolbar", "menubar", "menuitem"
    }

    # Generic CSS class / ID tokens indicating page boilerplate, cookies, ads, or tracking
    BOILERPLATE_ATTR_TOKENS = (
        "cookie", "consent", "privacy", "banner", "tracking", "analytics",
        "advert", "social", "share", "nav-", "navbar", "menu", "header",
        "footer", "sidebar", "breadcrumb", "pagination", "search-bar", "disclaimer"
    )

    # Main content container class / ID hints for security advisories
    CONTENT_HINT_TOKENS = (
        "advisory", "vulnerability", "cve", "bulletin", "security",
        "article", "content", "main", "document", "entry", "post", "body"
    )

    # Keywords establishing security/system configuration context for code blocks
    SECURITY_CONFIG_KEYWORDS = (
        "config", "setting", "parameter", "property", "directive",
        "option", "workaround", "mitigation", "remediation", "system property",
        "jvm", "flag", "-d", "attribute", "variable", "syntax", "example",
        "enabled", "allowed", "active", "running", "supported", "disabled",
        "feature", "service", "connector", "protocol", "method", "listener", "extension",
        "server.xml", "web.xml", "properties", "conf", "yaml", "yml", "json", "ini"
    )

    # Common DOM / JavaScript programming identifiers that must never be treated as target software settings
    DOM_AND_JS_ATTRIBUTES = {
        "async", "defer", "src", "href", "width", "height", "border",
        "style", "display", "color", "background", "margin", "padding",
        "title", "alt", "rel", "type", "id", "class", "content", "charset",
        "target", "action", "method", "value", "name", "viewport", "scale",
        "user-scalable", "text", "siteid", "countryid",
        "updateddate", "robots", "onload", "onerror", "onclick"
    }

    # -------------------------------------------------------------
    # 1. Document Type Detection
    # -------------------------------------------------------------
    @classmethod
    def detect_document_type(cls, content: str) -> DocumentType:
        """
        Determines the structural format of the retrieved document.
        """
        if not content:
            return DocumentType.PLAIN_TEXT

        stripped = content.strip()
        # JSON detection
        if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
            try:
                import json
                json.loads(stripped)
                return DocumentType.JSON
            except Exception:
                pass

        # HTML detection: doctype, html tag, or high density of tags
        if re.search(r'<!DOCTYPE\s+html', stripped, re.IGNORECASE) or re.search(r'<html[\s>]', stripped, re.IGNORECASE):
            return DocumentType.HTML
        if re.search(r'<(?:body|head|div|p|script|table)[\s>]', stripped, re.IGNORECASE) and "<" in stripped and ">" in stripped:
            return DocumentType.HTML

        # Markdown detection
        md_heading_count = len(re.findall(r'^#{1,6}\s+\S+', stripped, re.MULTILINE))
        md_link_count = len(re.findall(r'\[[^\]]+\]\([^\)]+\)', stripped))
        if md_heading_count >= 2 or md_link_count >= 3:
            return DocumentType.MARKDOWN

        return DocumentType.PLAIN_TEXT

    # -------------------------------------------------------------
    # 2. HTML Document Normalization & Sanitization
    # -------------------------------------------------------------
    @classmethod
    def sanitize_html(cls, html_content: str, preserve_code_blocks: bool = True) -> str:
        """
        Parses DOM structurally, decomposes non-content elements, strips UI/tracking,
        and extracts normalized text suitable for security advisory analysis.
        """
        if not html_content:
            return ""

        # Pre-repair unclosed script/style tags if followed by block-level elements
        repaired_html = re.sub(
            r'(<(?:script|style)\b[^>]*>[\s\S]*?)(?=<(?:p|div|section|article|h[1-6]|main|body|table|ul|ol)\b)',
            r'\1</script>',
            html_content,
            flags=re.I
        )
        soup = BeautifulSoup(repaired_html, "html.parser")

        # 1. Remove comments
        for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
            comment.extract()

        # 2. Remove standard non-content tags
        for tag_name in cls.NON_CONTENT_TAGS:
            for el in soup.find_all(tag_name):
                el.decompose()

        # 3. Remove elements matching non-content ARIA roles
        for el in soup.find_all(attrs={"role": True}):
            role_val = str(el.get("role", "")).lower()
            if any(r in role_val for r in cls.DISCARD_ROLES):
                el.decompose()

        # 4. Remove elements matching boilerplate class or ID tokens
        for el in soup.find_all(True):
            if not el or not el.parent:
                continue
            id_val = str(el.get("id", "")).lower()
            class_val = " ".join(el.get("class", [])) if isinstance(el.get("class"), list) else str(el.get("class", "")).lower()
            combined_attr = f"{id_val} {class_val}"
            if any(token in combined_attr for token in cls.BOILERPLATE_ATTR_TOKENS):
                # Ensure we don't accidentally delete the main article/body if it has a class like 'content'
                is_content_holder = any(h in combined_attr for h in ("advisory", "vulnerability", "article-body", "main-content"))
                if not is_content_holder:
                    el.decompose()

        # 5. Extract main content container if present
        main_root = cls._find_main_content_container(soup)

        # 6. Extract formatted text preserving structural hierarchy
        return cls._render_dom_to_text(main_root, preserve_code_blocks=preserve_code_blocks)

    @classmethod
    def _find_main_content_container(cls, soup: BeautifulSoup) -> Tag:
        """
        Identifies the primary content-bearing container (article, main, advisory div),
        falling back to body or root.
        """
        # Prioritize <article>
        article = soup.find("article")
        if article and len(article.get_text(strip=True)) > 100:
            return article

        # Prioritize <main> or <div role="main">
        main_el = soup.find("main") or soup.find(attrs={"role": "main"})
        if main_el and len(main_el.get_text(strip=True)) > 100:
            return main_el

        # Look for containers with advisory/content hints in class or id
        best_candidate = None
        best_score = 0
        for container in soup.find_all(["div", "section"]):
            c_id = str(container.get("id", "")).lower()
            c_class = " ".join(container.get("class", [])) if isinstance(container.get("class"), list) else str(container.get("class", "")).lower()
            comb = f"{c_id} {c_class}"
            if any(hint in comb for hint in cls.CONTENT_HINT_TOKENS):
                text_len = len(container.get_text(strip=True))
                if text_len > best_score:
                    best_score = text_len
                    best_candidate = container

        if best_candidate and best_score > 150:
            return best_candidate

        # Fallback to <body> or entire soup
        return soup.body if soup.body else soup

    @classmethod
    def _render_dom_to_text(cls, root: Tag, preserve_code_blocks: bool = True) -> str:
        """
        Converts sanitized DOM subtree into clean lines, preserving paragraph spacing,
        headings, bullet lists, tables, and valid configuration code blocks.
        """
        lines: List[str] = []

        def recurse(node: Any, surrounding_context: str = ""):
            if isinstance(node, NavigableString):
                val = str(node).strip()
                if val:
                    lines.append(val)
                return

            if not isinstance(node, Tag):
                return

            tag_name = node.name.lower()

            # Handle code blocks
            if tag_name in ("pre", "code"):
                code_text = node.get_text().strip()
                if code_text:
                    if cls.is_security_relevant_code_block(code_text, surrounding_context):
                        lines.append(code_text)
                return

            # Handle headings
            if re.match(r'^h[1-6]$', tag_name):
                h_text = node.get_text(separator=" ", strip=True)
                if h_text:
                    lines.append("")
                    lines.append(h_text)
                    lines.append("")
                return

            # Handle list items
            if tag_name == "li":
                item_text = node.get_text(separator=" ", strip=True)
                if item_text:
                    lines.append(f"* {item_text}")
                return

            # Handle paragraphs and table rows
            if tag_name in ("p", "tr"):
                p_text = node.get_text(separator=" ", strip=True)
                if p_text:
                    lines.append(p_text)
                    lines.append("")
                return

            # Handle block containers
            node_context = node.get_text(separator=" ", strip=True)[:200]
            for child in node.children:
                recurse(child, surrounding_context=node_context)

        recurse(root)

        # Normalize multiple blank lines into standard markdown paragraph breaks
        cleaned_text = "\n".join(lines)
        cleaned_text = re.sub(r'\n{3,}', '\n\n', cleaned_text)
        return cleaned_text.strip()

    # -------------------------------------------------------------
    # 3. Code-Block Context Discrimination
    # -------------------------------------------------------------
    @classmethod
    def is_security_relevant_code_block(cls, code_text: str, surrounding_context: str = "") -> bool:
        """
        Distinguishes security-relevant configuration examples from webpage JavaScript/HTML.
        """
        clean_code = code_text.strip()
        code_low = clean_code.lower()
        context_low = surrounding_context.lower()

        # Reject obvious embedded client-side script code
        js_patterns = [
            r'\bfunction\s*\(', r'\bvar\s+[a-zA-Z0-9_$]+\s*=', r'\blet\s+[a-zA-Z0-9_$]+\s*=',
            r'\bconst\s+[a-zA-Z0-9_$]+\s*=', r'\bwindow\.', r'\bdocument\.', r'\$\([\'\"]',
            r'\baddEventListener\b', r'\bconsole\.log\b', r'\breturn\s+(?:false|true);',
            r'<\s*script\b', r'<\s*\/\s*script\b'
        ]
        if any(re.search(pat, clean_code) for pat in js_patterns):
            return False

        # If it looks like a system property or CLI parameter: e.g. -Dproperty=value or property=value
        if re.search(r'^-D[A-Za-z0-9_\-\.]+\s*=', clean_code) or re.search(r'^[A-Za-z0-9_\-\.]+\s*=\s*[^\s]+$', clean_code):
            # Check context or property structure
            if any(k in context_low for k in cls.SECURITY_CONFIG_KEYWORDS) or "." in clean_code or len(clean_code) > 10:
                return True

        # If surrounding context explicitly discusses configuration or remediation
        if any(k in context_low for k in cls.SECURITY_CONFIG_KEYWORDS):
            return True

        # By default, standalone code fragments without context are not treated as authoritative configuration
        return False

    # -------------------------------------------------------------
    # 4. Passage Relevance Scoring
    # -------------------------------------------------------------
    @classmethod
    def score_passage_relevance(cls, passage: str) -> PassageRelevance:
        """
        Classifies a candidate passage into security-relevant categories or noise categories.
        """
        p_clean = passage.strip()
        if not p_clean or len(p_clean) < 3:
            return PassageRelevance.UNRELATED_CONTENT

        p_low = p_clean.lower()

        # 1. Detect Webpage JavaScript / Scripting
        if any(tok in p_low for tok in ["var d=", "function(", "window.", "document.", "typeof ", "=>", "=== ", ";a.src=", "location.href"]):
            return PassageRelevance.JAVASCRIPT

        # 2. Detect CSS
        if any(tok in p_low for tok in ["display:none", "font-family:", "margin:", "padding:", "@media", "border:0"]):
            return PassageRelevance.CSS

        # 3. Detect Analytics / Tracking
        if any(tok in p_low for tok in ["consent", "tracking", "telemetry", "tealium", "truste", "doubleclick"]):
            return PassageRelevance.ANALYTICS

        # 4. Detect Webpage Navigation & Boilerplate
        if any(p_low.startswith(prefix) for prefix in ["home >", "copyright ©", "all rights reserved", "terms of use", "privacy policy"]):
            return PassageRelevance.WEBPAGE_BOILERPLATE
        if p_low in ("navigation", "menu", "footer", "skip to content", "search"):
            return PassageRelevance.NAVIGATION

        # 5. Security Versions
        if re.search(r'\b(?:versions?|releases?)\s*(?:before|prior\s+to|earlier\s+than|through|to|from|\d+\.\d+)\b', p_low):
            return PassageRelevance.SECURITY_VERSION

        # 6. Security Mitigation & Workarounds
        if any(k in p_low for k in ["mitigat", "workaround", "upgrade to", "update to", "patch", "remediation", "disable the", "disabling"]):
            return PassageRelevance.SECURITY_MITIGATION

        # 7. Security Attack Conditions
        if any(k in p_low for k in ["attacker", "adversary", "craft", "send packet", "payload", "untrusted input", "exploit", "handshake"]):
            return PassageRelevance.SECURITY_ATTACK_CONDITION

        # 8. Security Impact
        if any(k in p_low for k in ["remote code execution", "rce", "denial of service", "privilege escalation", "arbitrary code"]):
            return PassageRelevance.SECURITY_IMPACT

        # 9. Security Configuration
        if any(k in p_low for k in ["configured", "configuration", "setting", "parameter", "system property", "directive", "enabled", "disabled", "allowlinking", "readonly", "read-only"]):
            return PassageRelevance.SECURITY_CONFIGURATION

        # 10. Security References
        if re.search(r'\b(?:cve-\d{4}-\d+|ghsa-[a-z0-9\-]+)\b', p_low):
            return PassageRelevance.SECURITY_REFERENCE

        # 11. General Security Advisory Prose
        if any(k in p_low for k in ["vulnerability", "vulnerable", "flaw", "issue", "advisory", "exposed", "affected", "security alert"]):
            return PassageRelevance.SECURITY_ADVISORY_CONTENT

        return PassageRelevance.UNRELATED_CONTENT

    @classmethod
    def is_security_relevant(cls, passage: str) -> bool:
        """Returns True if the passage belongs to a security-relevant category."""
        rel = cls.score_passage_relevance(passage)
        return rel in {
            PassageRelevance.SECURITY_ADVISORY_CONTENT,
            PassageRelevance.SECURITY_CONFIGURATION,
            PassageRelevance.SECURITY_VERSION,
            PassageRelevance.SECURITY_IMPACT,
            PassageRelevance.SECURITY_ATTACK_CONDITION,
            PassageRelevance.SECURITY_MITIGATION,
            PassageRelevance.SECURITY_REFERENCE
        }

    # -------------------------------------------------------------
    # 5. Configuration Evidence Gate & Subject Requirement
    # -------------------------------------------------------------
    @classmethod
    def validate_configuration_candidate(
        cls,
        candidate_name: str,
        candidate_val: Any,
        context_passage: str = "",
        document_subjects: Optional[Set[str]] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Enforces the Configuration Evidence Gate and Subject Requirement.
        A candidate setting X=Y is only admitted as an environmental configuration condition if:
        1. It represents a state/setting of a TARGET SYSTEM/SOFTWARE (not a webpage/DOM property).
        2. It has an identifiable target subject (not a single-letter variable or DOM property).
        3. The surrounding context is security-relevant.

        Returns: (is_valid, resolved_subject, rejection_reason)
        """
        raw_name = candidate_name.strip()
        low_name = raw_name.lower()
        val_str = str(candidate_val).strip().lower()

        # Reject single-character or trivial programming variables (e.g. 'a', 'd', 'r', 'i', 'x')
        if len(raw_name) <= 1 or re.match(r'^[a-zA-Z]$', raw_name):
            return False, None, "Single-character variable cannot be an authoritative target system configuration"

        # Reject compound variables starting with single-letter prefixes (e.g. single-letter script references)
        if re.match(r'^[a-zA-Z]\.[a-zA-Z]', raw_name):
            return False, None, "Prefixed script variable identifier without target system qualification"

        # Reject common DOM / HTML / Webpage styling and metadata attributes
        if low_name in cls.DOM_AND_JS_ATTRIBUTES or any(low_name.endswith(f".{attr}") for attr in cls.DOM_AND_JS_ATTRIBUTES) or "scale" in low_name:
            return False, None, f"'{raw_name}' is a webpage DOM/metadata attribute, not a software configuration"

        # Reject assignments from passages classified as script, CSS, analytics, or navigation noise
        if context_passage:
            rel = cls.score_passage_relevance(context_passage)
            if rel in (PassageRelevance.JAVASCRIPT, PassageRelevance.CSS, PassageRelevance.ANALYTICS, PassageRelevance.NAVIGATION, PassageRelevance.WEBPAGE_BOILERPLATE):
                return False, None, f"Context passage is classified as non-security noise: {rel.value}"

        # Resolve subject:
        # If dotted (e.g. 'subsystem.setting_name'), the prefix is the subject
        if "." in raw_name:
            subject_prefix = raw_name.split(".")[0].strip()
            if len(subject_prefix) > 1 and subject_prefix.lower() not in ("a", "b", "c", "d", "r", "e", "f", "window", "document"):
                return True, subject_prefix, None

        # If subject is established via surrounding context:
        # e.g., context discusses target software, daemon, server, or component
        if context_passage:
            subj_match = re.search(r'\b([A-Za-z0-9_\-]{3,30}?)\s+(?:configuration|server|service|daemon|handler|servlet|property|component)\b', context_passage, re.I)
            if subj_match:
                return True, subj_match.group(1).strip(), None

        # Check known document subjects
        if document_subjects:
            for ds in document_subjects:
                if len(ds) >= 3:
                    return True, ds, None

        # Check if candidate name itself references a known system protocol/method/service/feature
        if any(term in low_name for term in ["http", "tls", "ssl", "tcp", "udp", "put", "get", "post", "delete", "head", "service", "connector", "protocol", "feature", "extension", "listener", "daemon", "server", "filesystem", "system", "platform", "memory", "auth", "permission", "constraint", "lookup", "filter", "servlet", "component", "session", "persistence"]):
            return True, raw_name, None

        # If candidate name itself has substantive semantic length and context is security relevant
        if len(raw_name) >= 4 and not re.match(r'^[0-9]', raw_name):
            if context_passage and any(k in context_passage.lower() for k in cls.SECURITY_CONFIG_KEYWORDS):
                return True, raw_name, None

        return False, None, f"Missing semantic target software subject for setting '{raw_name}'"

    # -------------------------------------------------------------
    # 6. Top-Level Normalization Pipeline
    # -------------------------------------------------------------
    @classmethod
    def sanitize_document(cls, raw_content: str, doc_type: Optional[DocumentType] = None) -> str:
        """
        Primary entry point: normalizes raw retrieved content according to document type.
        """
        if not raw_content:
            return ""

        effective_type = doc_type or cls.detect_document_type(raw_content)

        if effective_type == DocumentType.HTML:
            return cls.sanitize_html(raw_content)
        elif effective_type == DocumentType.JSON:
            return raw_content
        elif effective_type == DocumentType.MARKDOWN:
            return raw_content.strip()
        else:
            return raw_content.strip()
