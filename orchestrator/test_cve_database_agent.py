import unittest
from pathlib import Path

from cve_database_agent import CVEDatabaseAgent


class CVEDatabaseAgentTests(unittest.TestCase):
    def test_lookup_and_search_project_knowledge(self):
        agent = CVEDatabaseAgent(Path(__file__).with_name("cve_knowledge.json"))
        self.assertEqual(agent.lookup("cve-2025-24813")["product"], "Tomcat")
        self.assertEqual(agent.search("apache tomcat")[0]["cve_id"], "CVE-2025-24813")

    def test_reads_nvd_export(self):
        raw = {"id": "CVE-2026-12345", "descriptions": [{"value": "Example issue"}],
               "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]}}
        record = CVEDatabaseAgent._normalize_record(raw, Path("nvd.json"))
        self.assertEqual(record["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
