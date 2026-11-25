"""Unified 4-Phase Phishing Triage Pipeline with SQLite Case Storage."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing, contextmanager
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .auth_revalidate import revalidate
from .email_parser import parse_email_file, parse_eml_bytes
from .header_forensics import analyze_headers
from .risk_scorer import compute_risk_score
from .threat_intel import ThreatIntelClient
from .url_attachment_analyzer import analyze_attachments, extract_urls


def _safe_revalidate(raw: bytes, forensics: Dict[str, Any], from_addr: str, env: Dict[str, Any]) -> Dict[str, Any]:
    import email
    from email import policy

    msg = email.message_from_bytes(raw, policy=policy.default)
    hops = forensics["routing"]["hops"]
    try:
        return revalidate(raw, msg, hops, from_addr)
    except Exception as exc:  # never let a DNS or parsing problem break the whole analysis
        u = {"result": "unavailable", "source": "error", "note": f"Re-validation failed: {type(exc).__name__}"}
        return {"spf": u, "dkim": u, "dmarc": u}


@contextmanager
def _db(path):
    """sqlite3's own context manager commits but does not close; close explicitly (no ResourceWarning)."""
    with closing(sqlite3.connect(path)) as conn:
        with conn:
            yield conn


class PhishingTriagePipeline:
    """Executes Phases 1-4 end-to-end and persists results in SQLite."""

    def __init__(
        self,
        db_path: str | Path = "phishing_triage.db",
        intel_client: Optional[ThreatIntelClient] = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.intel = intel_client or ThreatIntelClient()
        self._init_db()

    def _init_db(self) -> None:
        with _db(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    id TEXT PRIMARY KEY,
                    analyzed_at TEXT NOT NULL,
                    source_filename TEXT NOT NULL,
                    sender TEXT,
                    subject TEXT,
                    risk_score INTEGER NOT NULL,
                    verdict TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )
                """
            )

    def _run_on_parsed(self, parsed: Dict[str, Any], raw_bytes: Optional[bytes] = None) -> Dict[str, Any]:
        forensics = analyze_headers(parsed)
        # Header verdicts are claims written by a mail server and can be forged (RFC 8601 s7.1).
        # For .eml files, re-check them ourselves. .msg files do not keep the original bytes.
        if raw_bytes is not None:
            env = parsed["envelope"]
            from_addr = (env.get("from_addresses") or [""])[0]
            forensics["revalidation"] = _safe_revalidate(raw_bytes, forensics, from_addr, env)
        else:
            u = {"result": "unavailable", "source": "n/a", "note": ".msg files do not keep the original bytes"}
            forensics["revalidation"] = {"spf": u, "dkim": u, "dmarc": u}
        urls = extract_urls(parsed["body"]["text"], parsed["body"]["html"])
        attachments = analyze_attachments(parsed["attachments"])

        for u in urls:
            u["threat_intel"] = self.intel.check_url_virustotal(u["url"])
        for att in attachments:
            att["threat_intel"] = self.intel.check_hash_virustotal(att["sha256"])

        ip_intel = self.intel.check_ip_abuseipdb(forensics["routing"].get("origin_ip"))
        risk = compute_risk_score(
            parsed["envelope"],
            parsed["body"],
            forensics,
            urls,
            attachments,
            ip_intel,
        )

        case_id = f"TRIAGE-{uuid.uuid4().hex[:8].upper()}"
        analyzed_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        result: Dict[str, Any] = {
            "id": case_id,
            "analyzed_at": analyzed_at,
            "source_filename": parsed["source_filename"],
            "format": parsed["format"],
            "intel_mode": self.intel.mode,
            "envelope": parsed["envelope"],
            "body_preview": (parsed["body"]["text"] or parsed["body"]["html"])[:1200],
            "forensics": forensics,
            "ip_intel": ip_intel,
            "urls": urls,
            "attachments": attachments,
            "risk": risk,
        }
        self._save_result(result)
        return result

    def analyze_file(self, file_path: str | Path) -> Dict[str, Any]:
        path = Path(file_path)
        parsed = parse_email_file(path)
        raw = path.read_bytes() if path.suffix.lower() == ".eml" else None
        return self._run_on_parsed(parsed, raw)

    def analyze_eml_bytes(self, raw_bytes: bytes, filename: str = "uploaded.eml") -> Dict[str, Any]:
        parsed = parse_eml_bytes(raw_bytes, filename=filename)
        return self._run_on_parsed(parsed, raw_bytes)

    def _save_result(self, result: Dict[str, Any]) -> None:
        with _db(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO analyses (id, analyzed_at, source_filename, sender, subject, risk_score, verdict, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result["id"],
                    result["analyzed_at"],
                    result["source_filename"],
                    result["envelope"].get("from_raw", ""),
                    result["envelope"].get("subject", ""),
                    result["risk"]["score"],
                    result["risk"]["verdict"],
                    json.dumps(result),
                ),
            )

    def rename_source(self, case_id: str, filename: str) -> None:
        """Record the analyst's original filename (the stored copy has a random name)."""
        with _db(self.db_path) as conn:
            row = conn.execute("SELECT result_json FROM analyses WHERE id = ?", (case_id,)).fetchone()
            if not row:
                return
            data = json.loads(row[0])
            data["source_filename"] = filename
            conn.execute(
                "UPDATE analyses SET source_filename = ?, result_json = ? WHERE id = ?",
                (filename, json.dumps(data), case_id),
            )

    def list_analyses(self, limit: int = 50) -> List[Dict[str, Any]]:
        with _db(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, analyzed_at, source_filename, sender, subject, risk_score, verdict "
                "FROM analyses ORDER BY rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_analysis(self, case_id: str) -> Optional[Dict[str, Any]]:
        with _db(self.db_path) as conn:
            row = conn.execute("SELECT result_json FROM analyses WHERE id = ?", (case_id,)).fetchone()
        return json.loads(row[0]) if row else None
