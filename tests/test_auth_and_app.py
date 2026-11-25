"""Tests for SPF/DKIM/DMARC re-validation, upload handling and output escaping.
No network access is needed: DNS answers are injected."""
import base64
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ["TRIAGE_DNS"] = "0"
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import dkim  # noqa: E402

from triage import auth_revalidate as av  # noqa: E402
from triage.pipeline import PhishingTriagePipeline  # noqa: E402
from triage.threat_intel import ThreatIntelClient  # noqa: E402

SAMPLES = ROOT / "samples"


def _make_key():
    d = tempfile.mkdtemp()
    subprocess.run(["openssl", "genrsa", "-out", f"{d}/k.pem", "2048"], capture_output=True, check=True)
    pub = subprocess.run(["openssl", "rsa", "-in", f"{d}/k.pem", "-pubout", "-outform", "DER"],
                         capture_output=True, check=True).stdout
    with open(f"{d}/k.pem", "rb") as fh:
        return fh.read(), pub


class TestRevalidation(unittest.TestCase):
    def test_dkim_pass_then_tamper_fails(self):
        key, pub = _make_key()
        raw = b"From: a@example.org\r\nTo: b@example.com\r\nSubject: hi\r\nDate: Wed, 25 Nov 2026 09:00:00 +0000\r\n\r\nhello\r\n"
        signed = dkim.sign(raw, b"sel", b"example.org", key) + raw
        dns = lambda name, timeout=5: b"v=DKIM1; k=rsa; p=" + base64.b64encode(pub)
        res, doms = av.dkim_validate(signed, dnsfunc=dns)
        self.assertEqual(res["result"], "pass")
        self.assertEqual(doms, ["example.org"])
        self.assertEqual(av.dkim_validate(signed.replace(b"hello", b"HELLO"), dnsfunc=dns)[0]["result"], "fail")
        self.assertEqual(av.dkim_validate(raw, dnsfunc=dns)[0]["result"], "none")

    def test_spf_and_dmarc_logic(self):
        ok = lambda **k: ("pass", 250, "ok")
        self.assertEqual(av.spf_validate("203.0.113.5", "a@example.org", "h", check=ok)["result"], "pass")
        self.assertEqual(av.spf_validate(None, "a@example.org", "h", check=ok)["result"], "unavailable")
        lk = lambda n: ["v=DMARC1; p=reject"] if n == "_dmarc.example.org" else []
        self.assertEqual(av.dmarc_validate("example.org", "pass", "evil.test", [], lookup=lk)["result"], "fail")
        self.assertEqual(av.dmarc_validate("example.org", "fail", "example.org", ["example.org"], lookup=lk)["result"], "pass")
        self.assertEqual(av.dmarc_validate("nodmarc.test", "pass", "nodmarc.test", [], lookup=lk)["result"], "none")

    def test_offline_mode_never_reports_pass(self):
        pipe = PhishingTriagePipeline(db_path=Path(tempfile.mkdtemp()) / "t.db",
                                      intel_client=ThreatIntelClient(vt_api_key="", abuseipdb_api_key=""))
        res = pipe.analyze_file(SAMPLES / "benign_newsletter.eml")
        for k in ("spf", "dkim", "dmarc"):
            self.assertNotEqual(res["forensics"]["revalidation"][k]["result"], "pass")


class TestWebApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as app_module
        cls.m = app_module
        app_module.app.config["TESTING"] = True
        cls.c = app_module.app.test_client()

    def _post(self, name, data):
        return self.c.post("/analyze", data={"email_file": (io.BytesIO(data), name)},
                           content_type="multipart/form-data")

    def test_rejects_bad_extension(self):
        r = self._post("evil.exe", b"MZ")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.headers["Location"], "/")

    def test_upload_is_deleted_and_name_kept(self):
        before = set(self.m.UPLOAD_DIR.iterdir())
        r = self._post("my sample.eml", (SAMPLES / "phishing_credential_harvest.eml").read_bytes())
        self.assertIn("/analysis/TRIAGE-", r.headers["Location"])
        self.assertEqual(set(self.m.UPLOAD_DIR.iterdir()), before)
        page = self.c.get(r.headers["Location"]).get_data(as_text=True)
        self.assertIn("my_sample.eml", page)
        self.assertIn("claimed", page)
        self.assertIn("not a confirmed verdict", page)

    def test_hostile_email_is_escaped_and_exports_work(self):
        raw = (b"From: Evil <a@evil.test>\r\nTo: b@example.com\r\n"
               b"Subject: <script>alert(1)</script> <b>x\r\n\r\n"
               b"<img src=x onerror=alert(2)> http://evil.test/login\r\n")
        r = self._post("hostile.eml", raw)
        loc = r.headers["Location"]
        page = self.c.get(loc).get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn("<img src=x onerror", page)
        case = loc.rsplit("/", 1)[1]
        self.assertTrue(self.c.get(f"/analysis/{case}/export/html").get_data().startswith(b"<"))
        self.assertTrue(self.c.get(f"/analysis/{case}/export/pdf").get_data().startswith(b"%PDF"))

    def test_size_limit(self):
        old = self.m.app.config["MAX_CONTENT_LENGTH"]
        self.m.app.config["MAX_CONTENT_LENGTH"] = 200
        try:
            r = self._post("big.eml", b"x" * 5000)
            self.assertEqual(r.status_code, 302)
        finally:
            self.m.app.config["MAX_CONTENT_LENGTH"] = old


if __name__ == "__main__":
    unittest.main(verbosity=2)
