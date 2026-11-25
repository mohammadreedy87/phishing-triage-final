# Project 07: Phishing Triage - Documentation

## 1. Project Planning & Management
**Goal:** a Flask platform that analyzes reported suspicious emails (.eml/.msg), extracts routing headers, checks SPF/DKIM/DMARC, finds malicious attachments and URLs, and shows a risk score to SOC analysts.

| Phase | Work | Output | PDF deadline (DEPI) |
|---|---|---|---|
| Planning | Scope, tasks, risks | This document | 16 Oct 2026 |
| Literature review | Phishing techniques, existing tools | Section 2 | 16 Oct 2026 |
| Requirements | Functional and non-functional | Section 3 | 16 Oct 2026 |
| Analysis & design | Architecture, data, scoring | Section 4 | 6 Nov 2026 |
| Implementation | Code + tests | `triage/` package, `app.py`, `tests/` | 30 Nov 2026 |
| Final presentation, testing, reports | Test report, demo | Sections 5-6 | 4 Dec 2026 |

**Risks:** false positives from heuristics (tune weights); untrusted input (see section 5); API rate limits (APIs optional, local heuristics always run).

## 2. Literature Review
**Phishing as a problem.** Khonji, Iraqi and Jones [1] survey phishing detection and split defenses into email-level detection (content and header features, classifiers), URL and website analysis, and user education, noting that no single method catches everything. Industry reporting shows the problem continues: the APWG Q2 2026 trends report, as summarized by Fortra [7], found wire-transfer business email compromise attacks up 88% over the previous quarter, with the average requested transfer up 45% to $61,732, and describes attackers using spoofed reply chains and fake invoices. These are the techniques this tool looks for: sender spoofing, lookalike links and dangerous attachments.

**Email format and routing.** An email is a set of header fields plus a body defined by RFC 5322 [2]. Servers add `Received` fields as the message travels, so the chain shows the path. Only fields added by servers you trust can be believed, because a sender can add fake lower hops.

**Email authentication.** SPF [3] lets a domain list which IPs may send for it, checked against the SMTP connecting IP and the envelope sender. DKIM [4] adds a cryptographic signature over selected headers and the body, verified with a public key published in DNS. DMARC [5] ties them to the visible From domain through identifier alignment and publishes a policy (none, quarantine, reject). The receiving server records its verdicts in an `Authentication-Results` header [6].

**Why header verdicts are not proof.** RFC 8601 section 7.1 [6] covers forged header fields: a malicious sender can write a fake Authentication-Results field, and a mail client could trust it. The protection is that the receiving border server removes or ignores such fields claiming its own identity. A tool that reads an exported email cannot know whether that happened, so this project treats the header as a claim and re-validates where it can (section 4).

**Reputation services.** VirusTotal's v3 API exposes URL and file objects with analysis stats of how many engines flag them [8]. AbuseIPDB's API v2 exposes a check endpoint returning an abuse confidence score for an IP [9]. This project reads these when API keys are set.

**Gap.** The surveyed work is mostly about classifiers or large platforms. This project is a small, self-hostable analyst tool that shows each check, what evidence it rests on, and what it could not verify.

**References** (all opened and confirmed to exist on 25 Nov 2026)

1. M. Khonji, Y. Iraqi, A. Jones, "Phishing Detection: A Literature Survey," IEEE Communications Surveys & Tutorials 15(4), 2013. https://doi.org/10.1109/surv.2013.032213.00009
2. P. Resnick (ed.), RFC 5322, Internet Message Format, 2008. https://www.rfc-editor.org/info/rfc5322
3. S. Kitterman, RFC 7208, Sender Policy Framework (SPF), 2014. https://www.rfc-editor.org/info/rfc7208
4. D. Crocker, T. Hansen, M. Kucherawy (eds.), RFC 6376, DomainKeys Identified Mail (DKIM) Signatures, 2011. https://www.rfc-editor.org/info/rfc6376
5. M. Kucherawy, E. Zwicky (eds.), RFC 7489, DMARC, 2015. https://www.rfc-editor.org/info/rfc7489
6. M. Kucherawy, RFC 8601, Message Header Field for Indicating Message Authentication Status, 2019, section 7.1. https://www.rfc-editor.org/info/rfc8601
7. Fortra, "APWG: Phishing Activity Trends Report, 2nd Quarter 2026," 14 Sep 2026. https://www.fortra.com/resources/articles/apwg-phishing-activity-trends-report-2nd-quarter-2026 (report itself: https://docs.apwg.org/reports/apwg_trends_report_q2_2026.pdf, not read in full)
8. VirusTotal API v3 documentation, URL object. https://docs.virustotal.com/reference/url-object
9. AbuseIPDB APIv2 documentation. https://docs.abuseipdb.com/

## 3. Requirements
**Functional**

1. FR1 Upload and parse .eml and .msg files (`triage/email_parser.py`).
2. FR2 Extract sender, recipients, subject, date, Message-ID, Reply-To, Return-Path.
3. FR3 Parse the Received chain, list hops and origin IPs (`header_forensics.py`).
4. FR4 Read SPF/DKIM/DMARC verdicts from headers; re-check them independently for .eml files (`auth_revalidate.py`); detect From / Return-Path / Reply-To mismatch and display-name impersonation.
5. FR5 Extract URLs from text and HTML with regex and BeautifulSoup; flag IP hosts, shorteners, risky TLDs, punycode, lure keywords and link-text mismatch (`url_attachment_analyzer.py`).
6. FR6 Extract attachments, compute MD5 and SHA-256, flag dangerous extensions, double extensions and macro-capable Office files.
7. FR7 Query VirusTotal v3 (URLs, file hashes) and AbuseIPDB v2 (origin IP) when API keys are set; fall back to local heuristics otherwise (`threat_intel.py`).
8. FR8 Dashboard with counts, case history, per-email report, risk score 0-100 and export to HTML and PDF (`app.py`, `risk_scorer.py`, `report_generator.py`).

**Non-functional:** explainable score (every point has a reason), works offline without API keys, no execution or fetching of email content, escaped output, 25 MB upload cap.

## 4. System Analysis & Design
**Components:** `triage/` package (parsing, forensics, re-validation, URL and attachment analysis, threat intelligence, scoring, reports, pipeline), `app.py` (Flask routes), `templates/` and `static/` (Bootstrap UI), `samples/` (three test emails).

**Flow:** upload -> `email_parser` -> `header_forensics` (+ `auth_revalidate` for .eml) -> URL and attachment analysis -> threat-intel lookups -> `risk_scorer` -> result stored as JSON in SQLite -> dashboard, report, HTML/PDF export.

**Data:** table `analyses(id, analyzed_at, source_filename, sender, subject, risk_score, verdict, result_json)`.

**Scoring:** additive, capped at 100, with a reason recorded for each addition. SPF fail 15 (softfail 8), DKIM fail 12 (6), DMARC fail 15 (8); header mismatch or impersonation 15 (high) or 10; URL flagged by VirusTotal 30, URL with two or more heuristic flags 18, one flag 8; attachment flagged by VirusTotal 35, dangerous extension 28, macro-capable Office file 12; AbuseIPDB confidence >= 50 gives 20 (>= 20 gives 10); urgency wording 5 or 10; headers claim DKIM pass but re-check fails 5 (inconclusive). Priority levels: Low < 25, Medium 25-49, High 50-74, Critical >= 75. These are review priorities for an analyst (for example "Critical Priority (Suspected Phishing)"), not a confirmed verdict. The report lists a suggested next step (for example quarantine or blocking), worded as a recommendation to consider only after an analyst corroborates the indicators.

## 5. Testing, Security and Limitations
**Tests run (11, all pass, no network needed):**

- `test_triage_pipeline.py`: the credential-harvest sample scores Critical priority (>= 75, labelled "Suspected", never "Confirmed") with SPF, DKIM and DMARC fail, 2 hops, origin IP 185.220.101.19, a high-risk URL and a high-rated attachment with a 64-character SHA-256; the invoice sample scores High or Medium; the benign newsletter scores Low; SQLite storage, HTML export and PDF export work.
- `test_auth_and_app.py`: real DKIM signing and verification with a generated key and injected DNS (pass, then tamper gives fail, no signature gives none); SPF and DMARC alignment cases with injected checks; offline mode never reports a pass; a bad extension is rejected; the uploaded copy is deleted and the original filename is kept; a hostile email with script and onerror payloads is rendered escaped and exports to HTML and PDF; the size limit redirects with an error.

**Handling untrusted uploads:** emails are parsed as data only, never executed; attachments are hashed in memory and not saved; the app never fetches URLs found in emails (it only asks VirusTotal about a URL when a key is set); uploads are stored under a random name and deleted after analysis; output is HTML-escaped by Jinja; `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` are sent; 25 MB limit; only .eml and .msg accepted. `.msg` parsing uses the third-party `extract_msg` library, so run the app in a container or VM for real malware samples. Not addressed: login, CSRF protection, rate limiting, a Content-Security-Policy and a per-file parsing timeout, so keep it on localhost. The page loads Bootstrap from a CDN.

**Authentication: what is checked and what is not.** The report shows two lines. "Claimed in headers" is the text of the Authentication-Results and Received-SPF headers, written by whichever server added them, and can be forged [6]. "Re-validated by this tool" is what the app can recompute from an exported .eml plus live DNS:

- DKIM: real cryptographic verification against the public key in DNS today. It works only if the exported file is byte-identical to what was received. A rotated or deleted key, or a mail client that rewrote the file, gives "fail" even for a genuine old email.
- SPF: evaluated for the IP of the newest public hop in the Received chain (an assumption: only the receiving server knows the real connecting IP) against today's SPF record. The IP comes from headers an attacker can influence, so SPF is CONDITIONAL, not authoritative, and can differ from the verdict at delivery time.
- DMARC: current DMARC record plus alignment of the results above, also CONDITIONAL because it depends on SPF. Organizational domains use the Public Suffix List (publicsuffix2 package, bundled list dated 2019); if it is missing, relaxed alignment is reported as "inconclusive".
- .msg files do not keep the original bytes, so re-validation is "unavailable". "unavailable" (offline mode TRIAGE_DNS=0, DNS failure, missing data) never counts as pass. A mismatch between a claimed DKIM pass and a failed re-check adds only a small marked penalty (5): a forged header, rotated key or altered export can all cause it, so it is not proof of forgery.
- Not verifiable from a file at all: the receiving server's own verdict at delivery time, whether it stripped forged headers, and the true SMTP envelope.

A "pass" does not mean safe: attackers send from compromised or newly registered domains with valid SPF and DKIM.

**Scoring limits:** weights are hand-chosen, not trained or calibrated on real data; several indicators saturate at 100; keyword matching is English only and can flag legitimate invoices and password resets; no content analysis of attachments beyond name, extension and hash; no sandboxing, so a new malware file unknown to VirusTotal scores only by extension; link checks are string-based with no redirect following or domain age. Without API keys, URL and file reputation are not checked at all. Treat the score as a triage aid for analysts, not a verdict: no automatic blocking or deletion is performed, and any response action needs analyst corroboration.

## 6. Demo / Presentation outline

1. Problem and SOC context
2. Architecture (four phases)
3. Live demo: upload `samples/phishing_credential_harvest.eml`, show the report
4. Authentication: claimed vs re-validated
5. Scoring explanation
6. Security and limitations
7. Future work: sandbox, ML scoring, login and multi-user, live threat-intel tests

## 7. Status against the PDF
Implemented and tested: the four phases of Project 07 (PDF page 8). Verified without API keys: parsing, header forensics, DKIM cryptography, SPF/DMARC logic (with injected DNS), URL and attachment checks, scoring, escaping, HTML/PDF export, upload handling. Not verified live: the real VirusTotal and AbuseIPDB calls (they need API keys), re-validation against real mail from a real mailbox, `.msg` parsing with a real Outlook file, and any real malware sample. The corrected code and these documents are delivered as files; they have not been uploaded to GitHub.
