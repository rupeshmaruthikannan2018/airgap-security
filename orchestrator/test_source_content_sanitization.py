"""
Regression Test Suite for Source Content Sanitization & Relevance Pipeline.

Tests:
A. HTML JavaScript is removed
B. CSS is removed
C. Analytics content is removed
D. Navigation is removed
E. Webpage metadata is removed
F. Legitimate advisory prose remains
G. Legitimate configuration code remains
H. JavaScript assignments are not configurations
I. HTML attributes are not configurations
J. Exact evidence spans survive normalization
K. Configuration requires target/software context
L. Security-relevant code examples survive
M. Malformed HTML does not break extraction
N. Plain-text advisories continue working
O. Markdown advisories continue working
"""

import unittest
from orchestrator.document_sanitizer import (
    DocumentSanitizer,
    DocumentType,
    PassageRelevance
)
from orchestrator.cve_prerequisite_agent import PrerequisiteExtractor


class TestSourceContentSanitization(unittest.TestCase):

    def setUp(self):
        self.sanitizer = DocumentSanitizer()
        self.extractor = PrerequisiteExtractor()

    # -------------------------------------------------------------
    # Test A: HTML JavaScript is removed
    # -------------------------------------------------------------
    def test_a_html_javascript_is_removed(self):
        raw_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <script type="text/javascript">
                var d = document.documentElement;
                d.className = 'js';
                function loadTracking() { var a = document.createElement('script'); a.src = '/lib.js'; }
            </script>
        </head>
        <body>
            <script>console.log("running inline script");</script>
            <article>
                <h1>Security Advisory</h1>
                <p>A critical buffer overflow exists in the network handler daemon.</p>
            </article>
        </body>
        </html>
        """
        sanitized = self.sanitizer.sanitize_html(raw_html)
        self.assertNotIn("var d =", sanitized)
        self.assertNotIn("loadTracking", sanitized)
        self.assertNotIn("console.log", sanitized)
        self.assertIn("A critical buffer overflow exists in the network handler daemon.", sanitized)

    # -------------------------------------------------------------
    # Test B: CSS is removed
    # -------------------------------------------------------------
    def test_b_css_is_removed(self):
        raw_html = """
        <html>
        <head>
            <style>
                body { font-family: sans-serif; margin: 0; }
                #chat-widget { display: none; visibility: hidden; }
                @media (max-width: 600px) { .sidebar { display: none; } }
            </style>
        </head>
        <body>
            <main>
                <p>The authentication service fails to validate user tokens.</p>
            </main>
        </body>
        </html>
        """
        sanitized = self.sanitizer.sanitize_html(raw_html)
        self.assertNotIn("font-family", sanitized)
        self.assertNotIn("display: none", sanitized)
        self.assertNotIn("@media", sanitized)
        self.assertIn("The authentication service fails to validate user tokens.", sanitized)

    # -------------------------------------------------------------
    # Test C: Analytics content is removed
    # -------------------------------------------------------------
    def test_c_analytics_content_is_removed(self):
        raw_html = """
        <html>
        <body>
            <div id="cookie-consent-banner" class="cookie-banner tracking-consent">
                <p>We use cookies to improve your experience. Click accept to continue.</p>
            </div>
            <div class="analytics-tracker" data-tracking-id="UA-99999-1">
                <span>Analytics widget</span>
            </div>
            <article>
                <p>Vulnerability allows remote attackers to trigger denial of service.</p>
            </article>
        </body>
        </html>
        """
        sanitized = self.sanitizer.sanitize_html(raw_html)
        self.assertNotIn("We use cookies", sanitized)
        self.assertNotIn("Analytics widget", sanitized)
        self.assertIn("Vulnerability allows remote attackers to trigger denial of service.", sanitized)

    # -------------------------------------------------------------
    # Test D: Navigation is removed
    # -------------------------------------------------------------
    def test_d_navigation_is_removed(self):
        raw_html = """
        <html>
        <body>
            <nav class="site-nav">
                <ul>
                    <li><a href="/">Home</a></li>
                    <li><a href="/products">Products</a></li>
                    <li><a href="/support">Support</a></li>
                </ul>
            </nav>
            <div role="navigation" class="breadcrumbs">
                Home > Support > Security Alerts
            </div>
            <main>
                <h1>Security Bulletin</h1>
                <p>Improper input validation in web connector causes command injection.</p>
            </main>
            <footer class="site-footer">
                <p>Copyright 2026 Corporation. All rights reserved.</p>
            </footer>
        </body>
        </html>
        """
        sanitized = self.sanitizer.sanitize_html(raw_html)
        self.assertNotIn("Products", sanitized)
        self.assertNotIn("Support > Security Alerts", sanitized)
        self.assertIn("Improper input validation in web connector causes command injection.", sanitized)

    # -------------------------------------------------------------
    # Test E: Webpage metadata is removed
    # -------------------------------------------------------------
    def test_e_webpage_metadata_is_removed(self):
        raw_html = """
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <meta name="robots" content="index, follow">
            <meta name="theme-color" content="#ffffff">
            <link rel="icon" href="/favicon.ico">
        </head>
        <body>
            <p>Target service must have SSLv3 protocol enabled.</p>
        </body>
        </html>
        """
        sanitized = self.sanitizer.sanitize_html(raw_html)
        self.assertNotIn("width=device-width", sanitized)
        self.assertNotIn("initial-scale", sanitized)
        self.assertNotIn("robots", sanitized)
        self.assertIn("Target service must have SSLv3 protocol enabled.", sanitized)

    # -------------------------------------------------------------
    # Test F: Legitimate advisory prose remains
    # -------------------------------------------------------------
    def test_f_legitimate_advisory_prose_remains(self):
        raw_html = """
        <html>
        <body>
            <div class="advisory-container">
                <h1>Security Bulletin 2026-01</h1>
                <p>A flaw was discovered in the message processing framework.</p>
                <p>When running on Windows with file upload enabled, unauthenticated users can write arbitrary files.</p>
                <h3>Affected Versions</h3>
                <p>Versions 1.0.0 through 1.4.2 are affected.</p>
            </div>
        </body>
        </html>
        """
        sanitized = self.sanitizer.sanitize_html(raw_html)
        self.assertIn("A flaw was discovered in the message processing framework.", sanitized)
        self.assertIn("When running on Windows with file upload enabled", sanitized)
        self.assertIn("Versions 1.0.0 through 1.4.2 are affected.", sanitized)

    # -------------------------------------------------------------
    # Test G: Legitimate configuration code remains
    # -------------------------------------------------------------
    def test_g_legitimate_configuration_code_remains(self):
        raw_html = """
        <html>
        <body>
            <article>
                <p>To mitigate the vulnerability, configure the following system property:</p>
                <pre>messaging.systemLookupDisabled=true</pre>
                <p>Alternatively, set the parameter in your application configuration:</p>
                <code>allowUntrustedLookups=false</code>
            </article>
        </body>
        </html>
        """
        sanitized = self.sanitizer.sanitize_html(raw_html)
        self.assertIn("messaging.systemLookupDisabled=true", sanitized)
        self.assertIn("allowUntrustedLookups=false", sanitized)

    # -------------------------------------------------------------
    # Test H: JavaScript assignments are not configurations
    # -------------------------------------------------------------
    def test_h_javascript_assignments_are_not_configurations(self):
        # Single-letter variable and script properties
        is_valid_1, _, reason_1 = self.sanitizer.validate_configuration_candidate(
            "a.async", False, context_passage="a.async=false; a.src=url;"
        )
        self.assertFalse(is_valid_1)
        self.assertIsNotNone(reason_1)

        is_valid_2, _, reason_2 = self.sanitizer.validate_configuration_candidate(
            "d.async", True, context_passage="d.async=true;"
        )
        self.assertFalse(is_valid_2)

        is_valid_3, _, reason_3 = self.sanitizer.validate_configuration_candidate(
            "a", "false", context_passage="var a = false;"
        )
        self.assertFalse(is_valid_3)

    # -------------------------------------------------------------
    # Test I: HTML attributes are not configurations
    # -------------------------------------------------------------
    def test_i_html_attributes_are_not_configurations(self):
        test_cases = [
            ("initial-scale", "1", "meta name=viewport content=initial-scale=1"),
            ("r.width", "0", "img tracker width=0 height=0 border=0"),
            ("r.height", "0", "img tracker width=0 height=0 border=0"),
            ("r.border", "0", "border=0"),
            ("width", "100", "table width=100"),
            ("text", "true", "consent.truste.com/notice?text=true"),
        ]
        for name, val, ctx in test_cases:
            is_valid, _, rej = self.sanitizer.validate_configuration_candidate(name, val, context_passage=ctx)
            self.assertFalse(is_valid, f"Expected {name} to be rejected as a configuration, but it was accepted")

    # -------------------------------------------------------------
    # Test J: Exact evidence spans survive normalization
    # -------------------------------------------------------------
    def test_j_exact_evidence_spans_survive_normalization(self):
        raw_html = """
        <html>
        <head><script>var useless = 1;</script></head>
        <body>
            <article>
                <p>The service is only vulnerable when the AJP connector is active.</p>
            </article>
        </body>
        </html>
        """
        normalized = self.sanitizer.sanitize_html(raw_html)
        target_sentence = "The service is only vulnerable when the AJP connector is active."
        self.assertIn(target_sentence, normalized)

        # Run extraction on normalized text
        res = self.extractor.extract_attack_conditions(normalized)
        prereqs = res.get("prerequisites", [])
        self.assertTrue(len(prereqs) >= 1)
        # Check that evidence_text is verbatim substring of normalized text
        for p in prereqs:
            for ev in p.get("evidence", []):
                self.assertIn(ev["evidence_text"], normalized)

    # -------------------------------------------------------------
    # Test K: Configuration requires target/software context
    # -------------------------------------------------------------
    def test_k_configuration_requires_target_software_context(self):
        # Without target software context: generic single word assignment
        is_valid_no_context, _, _ = self.sanitizer.validate_configuration_candidate(
            "debug", "true", context_passage="debug=true"
        )
        self.assertFalse(is_valid_no_context)

        # With target software context: dotted property prefix
        is_valid_dotted, subj_dotted, _ = self.sanitizer.validate_configuration_candidate(
            "engine_core.messageLookupEnabled", "true", context_passage="Set engine_core.messageLookupEnabled=true in config"
        )
        self.assertTrue(is_valid_dotted)
        self.assertEqual(subj_dotted, "engine_core")

        # With target software context in surrounding passage
        is_valid_context, subj_context, _ = self.sanitizer.validate_configuration_candidate(
            "readonly", "false", context_passage="When the Tomcat servlet configuration sets readonly=false"
        )
        self.assertTrue(is_valid_context)
        self.assertIsNotNone(subj_context)

    # -------------------------------------------------------------
    # Test L: Security-relevant code examples survive
    # -------------------------------------------------------------
    def test_l_security_relevant_code_examples_survive(self):
        raw_html = """
        <html>
        <body>
            <section class="workaround">
                <h2>Remediation</h2>
                <p>Pass the following JVM flag on startup:</p>
                <pre>-Dtarget.formatMsgNoLookups=true</pre>
            </section>
        </body>
        </html>
        """
        sanitized = self.sanitizer.sanitize_html(raw_html)
        self.assertIn("-Dtarget.formatMsgNoLookups=true", sanitized)

    # -------------------------------------------------------------
    # Test M: Malformed HTML does not break extraction
    # -------------------------------------------------------------
    def test_m_malformed_html_does_not_break_extraction(self):
        malformed = """
        <div>
        <p>Vulnerability exists in <b>daemon listener
        <script>function broken( { <style>#none
        <p>When running on Linux with remote debugging enabled, attackers can execute code.
        """
        sanitized = self.sanitizer.sanitize_html(malformed)
        self.assertIsInstance(sanitized, str)
        self.assertIn("When running on Linux with remote debugging enabled", sanitized)
        # Verify extractor still processes sanitized text
        res = self.extractor.extract_attack_conditions(sanitized)
        prereq_names = [p["name"] for p in res.get("prerequisites", [])]
        self.assertIn("target_platform_linux", prereq_names)

    # -------------------------------------------------------------
    # Test N: Plain-text advisories continue working
    # -------------------------------------------------------------
    def test_n_plain_text_advisories_continue_working(self):
        plain_advisory = (
            "Apache Tomcat 9.0.0.M1 to 9.0.0.M21 on Windows.\n"
            "When running on Windows with HTTP PUT enabled, an attacker can upload files."
        )
        doc_type = self.sanitizer.detect_document_type(plain_advisory)
        self.assertEqual(doc_type, DocumentType.PLAIN_TEXT)
        sanitized = self.sanitizer.sanitize_document(plain_advisory)
        self.assertEqual(sanitized, plain_advisory)

        res = self.extractor.extract_attack_conditions(sanitized)
        prereq_names = [p["name"] for p in res.get("prerequisites", [])]
        self.assertIn("target_platform_windows", prereq_names)
        self.assertIn("http_put_enabled", prereq_names)

    # -------------------------------------------------------------
    # Test O: Markdown advisories continue working
    # -------------------------------------------------------------
    def test_o_markdown_advisories_continue_working(self):
        markdown_advisory = (
            "# Vulnerability Advisory\n\n"
            "## Description\n"
            "An attacker who can send crafted packets can trigger a denial of service.\n\n"
            "## Requirements\n"
            "Vulnerable when the telemetry service is enabled.\n\n"
            "[Vendor Reference](https://example.com/advisory-1)"
        )
        doc_type = self.sanitizer.detect_document_type(markdown_advisory)
        self.assertEqual(doc_type, DocumentType.MARKDOWN)
        sanitized = self.sanitizer.sanitize_document(markdown_advisory)
        self.assertEqual(sanitized, markdown_advisory.strip())

        res = self.extractor.extract_attack_conditions(sanitized)
        prereq_names = [p["name"] for p in res.get("prerequisites", [])]
        self.assertIn("telemetry_service_enabled", prereq_names)


if __name__ == "__main__":
    unittest.main()
