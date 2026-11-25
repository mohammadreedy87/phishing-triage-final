# Project 07: Automated Phishing Triage & Email Forensics Platform

A lightweight SOC Phishing Triage platform built for the **DEPI (Digital Egypt Pioneers Initiative)** SOC Track. It automates `.eml` and `.msg` ingestion, SMTP header forensics (SPF, DKIM, DMARC, routing hops), embedded URL and attachment analysis, Threat Intelligence enrichment ([VirusTotal API v3](https://docs.virustotal.com/reference/overview) and [AbuseIPDB API v2](https://docs.abuseipdb.com/)), weighted phishing risk scoring, and HTML/PDF triage report generation.

## Team Roles (Update with Member Names Before GitHub Submission)

| Role | Assigned Team Member | Primary Ownership |
| :--- | :--- | :--- |
| Team Lead & System Architect | `[Team Member 1]` | Repository structure, pipeline orchestration, SQLite schema, documentation |
| Email Ingestion & Header Forensics Engineer | `[Team Member 2]` | Phase 1 (`email_parser.py`) & Phase 2 (`header_forensics.py`) |
| Threat Intel & Artifact Triage Engineer | `[Team Member 3]` | Phase 3 (`url_attachment_analyzer.py`, `threat_intel.py`) |
| Web Dashboard, Reporting & QA Engineer | `[Team Member 4]` | Phase 4 (`app.py`, `risk_scorer.py`, `report_generator.py`, `tests/`) |

## Quick Start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate | Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # optional: API keys, secret key
python app.py
```

Open `http://127.0.0.1:5000` in your browser and upload any sample from `samples/`.

> **Offline Demo Mode:** If `VIRUSTOTAL_API_KEY` or `ABUSEIPDB_API_KEY` are left blank in `.env`, the platform automatically falls back to deterministic local heuristic analysis so live classroom demos never fail due to missing keys or rate limits.

## Project Structure

```
app.py                    Flask analyst portal (upload, dashboard, report export)
triage/email_parser.py    Phase 1: .eml / .msg ingestion
triage/header_forensics.py  Phase 2: Received hops, claimed SPF/DKIM/DMARC, spoofing indicators
triage/auth_revalidate.py Phase 2: independent SPF/DKIM/DMARC re-check of the exported file
triage/url_attachment_analyzer.py  Phase 3: URLs, attachment hashes, heuristics
triage/threat_intel.py    Phase 3: VirusTotal v3 and AbuseIPDB v2 (offline fallback)
triage/risk_scorer.py     Phase 4: explainable 0-100 risk score
triage/report_generator.py  Phase 4: HTML and PDF export
triage/pipeline.py        Orchestration and SQLite case storage
tests/                    Unit and web tests (no network needed)
samples/                  Three sample .eml files (phishing, suspicious invoice, benign)
```

## Authentication: claimed vs re-validated

SPF, DKIM and DMARC results written in `Authentication-Results` headers are claims by whichever server added them and can be forged ([RFC 8601 section 7.1](https://www.rfc-editor.org/info/rfc8601)). The report therefore shows the claim and a re-check side by side. For `.eml` files the tool verifies the DKIM signature against the public key in DNS, evaluates SPF for the IP of the newest public hop in the `Received` chain, and checks DMARC alignment. Limits:

- DKIM is only valid if the exported file is byte-identical to what was received, and a rotated or removed key gives "fail" for an old genuine mail.
- SPF uses an IP inferred from headers an attacker can influence, and today's SPF record, so SPF and DMARC are marked conditional.
- `.msg` files do not keep the original bytes, so re-validation is "unavailable".
- "unavailable" and "inconclusive" never count as pass. A claim/re-check mismatch is not proof of forgery.
- Set `TRIAGE_DNS=0` to disable DNS lookups.

## Security notes

Emails are treated as data: attachments are hashed in memory, uploads are saved under a random name and deleted after analysis, links are never fetched, and all output is HTML-escaped. Upload limit is 25 MB and only `.eml` / `.msg` are accepted. Not included: login, CSRF protection and rate limiting, so run it on localhost only. Use a VM or container for real malware samples.

## Running Automated Tests

```bash
python -m unittest discover -s tests -v
```

Live VirusTotal and AbuseIPDB calls are not covered by the tests (they need API keys).

## Standards & References

- [RFC 7208 — Sender Policy Framework (SPF)](https://www.rfc-editor.org/info/rfc7208/)
- [RFC 6376 — DomainKeys Identified Mail (DKIM)](https://www.rfc-editor.org/info/rfc6376/)
- [RFC 7489 — DMARC](https://www.rfc-editor.org/info/rfc7489/)
- [NIST SP 800-177 Rev. 1 — Trustworthy Email](https://csrc.nist.gov/pubs/sp/800/177/r1/final)
- [NIST SP 800-61 Rev. 3 — Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [MITRE ATT&CK T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
