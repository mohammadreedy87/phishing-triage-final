"""Phase 3: Embedded URL Extraction, Attachment Hashing & Heuristic Triage."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from bs4 import BeautifulSoup

URL_REGEX = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".js", ".jse", ".bat", ".cmd", ".ps1",
    ".hta", ".msi", ".dll", ".com", ".pif", ".jar", ".iso", ".lnk",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".doc", ".xls"}
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".zip", ".mov", ".ru", ".cn"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "rb.gy"}
PHISHING_KEYWORDS = {
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "password", "confirm", "suspend", "unlock", "invoice", "wire", "credential",
}


def _inspect_url_heuristics(url: str, anchor_text: str = "") -> Dict[str, Any]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    flags: List[str] = []

    is_ip_host = False
    if host:
        try:
            ipaddress.ip_address(host)
            is_ip_host = True
            flags.append("Direct IP address used instead of domain name")
        except ValueError:
            pass

    if parsed.scheme == "http":
        flags.append("Unencrypted HTTP link")
    if "@" in url:
        flags.append("Contains '@' credential/obfuscation symbol")
    if host in URL_SHORTENERS:
        flags.append("URL shortener hides final destination")
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        flags.append("High-risk or frequently abused TLD")
    if host.startswith("xn--") or ".xn--" in host:
        flags.append("Punycode/IDN domain (possible homograph attack)")
    if host.count(".") >= 3 and not is_ip_host:
        flags.append("Excessive subdomain depth")

    lower_url = url.lower()
    matched_kw = [kw for kw in PHISHING_KEYWORDS if kw in lower_url]
    if matched_kw:
        flags.append(f"Credential/lure keywords in URL: {', '.join(sorted(matched_kw)[:4])}")

    # Mismatched visible anchor URL vs actual href target
    if anchor_text:
        anchor_urls = URL_REGEX.findall(anchor_text)
        if anchor_urls:
            anchor_host = (urlparse(anchor_urls[0]).hostname or "").lower()
            if anchor_host and host and anchor_host != host:
                flags.append(f"Anchor text displays '{anchor_host}' but links to '{host}'")

    return {
        "url": url,
        "domain": host,
        "scheme": parsed.scheme,
        "anchor_text": anchor_text.strip()[:120],
        "heuristic_flags": flags,
        "heuristic_risk": "high" if len(flags) >= 2 else ("medium" if len(flags) == 1 else "low"),
    }


def extract_urls(body_text: str, body_html: str) -> List[Dict[str, Any]]:
    """Extract and deduplicate hyperlinks from both HTML and plain-text email bodies."""
    seen: Dict[str, Dict[str, Any]] = {}

    if body_html:
        soup = BeautifulSoup(body_html, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = str(tag["href"]).strip()
            if href.lower().startswith(("http://", "https://")):
                anchor = tag.get_text(" ", strip=True)
                if href not in seen:
                    seen[href] = _inspect_url_heuristics(href, anchor)

    for text_source in (body_text, body_html):
        if not text_source:
            continue
        for match in URL_REGEX.findall(text_source):
            cleaned = match.rstrip(".,;:!?)\"'")
            if cleaned not in seen:
                seen[cleaned] = _inspect_url_heuristics(cleaned)

    return list(seen.values())


def analyze_attachments(attachments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Compute MD5/SHA-256 hashes and flag dangerous or double-extension attachments."""
    results: List[Dict[str, Any]] = []
    for att in attachments:
        filename = str(att.get("filename", "unnamed_attachment"))
        payload = att.get("payload", b"") or b""
        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="replace")

        md5_hash = hashlib.md5(payload).hexdigest()
        sha256_hash = hashlib.sha256(payload).hexdigest()

        suffixes = [s.lower() for s in Path(filename).suffixes]
        ext = suffixes[-1] if suffixes else ""
        flags: List[str] = []

        if ext in DANGEROUS_EXTENSIONS:
            flags.append(f"Dangerous executable/script extension ({ext})")
        elif ext in MACRO_EXTENSIONS:
            flags.append(f"Macro-capable Office document ({ext})")

        if len(suffixes) >= 2 and ext in DANGEROUS_EXTENSIONS:
            flags.append(f"Double-extension masquerading detected ({''.join(suffixes[-2:])})")

        if not flags:
            rating = "low"
        elif ext in DANGEROUS_EXTENSIONS:
            rating = "high"
        else:
            rating = "medium"

        results.append({
            "filename": filename,
            "extension": ext or "(none)",
            "content_type": att.get("content_type", "application/octet-stream"),
            "size_bytes": len(payload),
            "md5": md5_hash,
            "sha256": sha256_hash,
            "flags": flags,
            "heuristic_rating": rating,
        })
    return results
