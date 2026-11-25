"""Automated verification tests for Project 07: Phishing Triage (Phases 1-4)."""
import os
import tempfile
import unittest
from pathlib import Path

from triage.pipeline import PhishingTriagePipeline
from triage.report_generator import generate_pdf_report_bytes, render_html_report
from triage.threat_intel import ThreatIntelClient

os.environ["TRIAGE_DNS"] = "0"  # tests must not depend on the network
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


class TestPhishingTriagePipeline(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test_triage.db"
        self.pipeline = PhishingTriagePipeline(
            db_path=self.db_path,
            intel_client=ThreatIntelClient(vt_api_key="", abuseipdb_api_key=""),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_phishing_credential_harvest_scores_critical(self) -> None:
        res = self.pipeline.analyze_file(SAMPLES_DIR / "phishing_credential_harvest.eml")
        self.assertGreaterEqual(res["risk"]["score"], 75)
        self.assertIn("Suspected", res["risk"]["verdict"])
        self.assertNotIn("Confirmed", res["risk"]["verdict"])
        self.assertIn("corroborates", res["risk"]["recommended_action"])
        self.assertEqual(res["forensics"]["authentication"]["spf"], "fail")
        self.assertEqual(res["forensics"]["authentication"]["dkim"], "fail")
        self.assertEqual(res["forensics"]["authentication"]["dmarc"], "fail")
        self.assertEqual(res["forensics"]["routing"]["hop_count"], 2)
        self.assertEqual(res["forensics"]["routing"]["origin_ip"], "185.220.101.19")
        self.assertGreaterEqual(len(res["urls"]), 1)
        self.assertEqual(res["urls"][0]["heuristic_risk"], "high")
        self.assertEqual(res["attachments"][0]["heuristic_rating"], "high")
        self.assertEqual(len(res["attachments"][0]["sha256"]), 64)

    def test_suspicious_invoice_scores_high_or_medium(self) -> None:
        res = self.pipeline.analyze_file(SAMPLES_DIR / "suspicious_invoice_macro.eml")
        self.assertGreaterEqual(res["risk"]["score"], 45)
        self.assertEqual(res["forensics"]["authentication"]["spf"], "softfail")
        self.assertEqual(res["attachments"][0]["heuristic_rating"], "medium")

    def test_benign_newsletter_scores_low(self) -> None:
        res = self.pipeline.analyze_file(SAMPLES_DIR / "benign_newsletter.eml")
        self.assertLess(res["risk"]["score"], 25)
        self.assertEqual(res["forensics"]["authentication"]["spf"], "pass")
        self.assertEqual(res["forensics"]["authentication"]["dkim"], "pass")
        self.assertEqual(res["forensics"]["authentication"]["dmarc"], "pass")

    def test_sqlite_persistence_and_report_exports(self) -> None:
        res = self.pipeline.analyze_file(SAMPLES_DIR / "phishing_credential_harvest.eml")
        fetched = self.pipeline.get_analysis(res["id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["id"], res["id"])

        html = render_html_report(fetched, TEMPLATES_DIR)
        self.assertIn("SOC Phishing Triage Report", html)
        self.assertIn(res["id"], html)

        pdf_bytes = generate_pdf_report_bytes(fetched)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertGreater(len(pdf_bytes), 1000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
