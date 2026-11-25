"""Phase 2: Header Forensics, Routing Hop Tracing & SPF/DKIM/DMARC Verification."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FROM_BY_PATTERN = re.compile(
    r"from\s+(?P<from_host>[^\s;()]+).*?by\s+(?P<by_host>[^\s;()]+)",
    re.IGNORECASE | re.DOTALL,
)
AUTH_TOKEN_PATTERN = {
    "spf": re.compile(r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE),
    "dkim": re.compile(r"\bdkim=(pass|fail|neutral|none|temperror|permerror)\b", re.IGNORECASE),
    "dmarc": re.compile(r"\bdmarc=(pass|fail|bestguesspass|none|temperror|permerror)\b", re.IGNORECASE),
}


def _extract_domain(addr: str) -> str:
    if "@" not in addr:
        return ""
    return addr.split("@", 1)[1].strip().lower().rstrip(">")


def _is_public_ipv4(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_link_local
        )
    except ValueError:
        return False


def parse_received_hops(received_headers: List[str]) -> Dict[str, Any]:
    """Parse Received headers in chronological order (origin -> destination)."""
    hops: List[Dict[str, Any]] = []
    public_ips: List[str] = []

    # Received headers are prepended by each MTA; reversing gives chronological path.
    for idx, raw in enumerate(reversed(received_headers), start=1):
        compact = " ".join(raw.split())
        match = FROM_BY_PATTERN.search(compact)
        from_host = match.group("from_host") if match else "unknown"
        by_host = match.group("by_host") if match else "unknown"

        ips_found: List[str] = []
        for candidate in IPV4_PATTERN.findall(compact):
            try:
                ipaddress.ip_address(candidate)
                if candidate not in ips_found:
                    ips_found.append(candidate)
                if _is_public_ipv4(candidate) and candidate not in public_ips:
                    public_ips.append(candidate)
            except ValueError:
                continue

        timestamp = compact.rsplit(";", 1)[1].strip() if ";" in compact else ""
        hops.append({
            "hop": idx,
            "from_host": from_host,
            "by_host": by_host,
            "ips": ips_found,
            "timestamp": timestamp,
            "raw": compact,
        })

    origin_ip = public_ips[0] if public_ips else (hops[0]["ips"][0] if hops and hops[0]["ips"] else None)
    return {
        "hop_count": len(hops),
        "origin_ip": origin_ip,
        "public_ips": public_ips,
        "hops": hops,
    }


def analyze_headers(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze routing headers, SPF/DKIM/DMARC statuses, and spoofing anomalies."""
    headers = parsed_email.get("headers", {})
    envelope = parsed_email.get("envelope", {})

    routing = parse_received_hops(headers.get("received", []))

    auth_blob = " ; ".join(
        headers.get("authentication_results", []) + headers.get("received_spf", [])
    )
    auth_status: Dict[str, str] = {}
    for mech, pattern in AUTH_TOKEN_PATTERN.items():
        match = pattern.search(auth_blob)
        if match:
            auth_status[mech] = match.group(1).lower()
        else:
            auth_status[mech] = "missing"

    # Also check Received-SPF standalone status word at beginning if needed
    if auth_status["spf"] == "missing" and headers.get("received_spf"):
        first_word = headers["received_spf"][0].strip().split(" ", 1)[0].lower()
        if first_word in {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}:
            auth_status["spf"] = first_word

    has_dkim_signature = bool(headers.get("dkim_signature"))

    from_addrs = envelope.get("from_addresses", [])
    reply_to_addrs = envelope.get("reply_to_addresses", [])
    return_path_addrs = envelope.get("return_path_addresses", [])

    from_domain = _extract_domain(from_addrs[0]) if from_addrs else ""
    reply_to_domain = _extract_domain(reply_to_addrs[0]) if reply_to_addrs else ""
    return_path_domain = _extract_domain(return_path_addrs[0]) if return_path_addrs else ""

    spoofing_indicators: List[Dict[str, str]] = []
    if from_domain and return_path_domain and from_domain != return_path_domain:
        spoofing_indicators.append({
            "indicator": "From / Return-Path Domain Mismatch",
            "severity": "high",
            "detail": f"Visible From domain '{from_domain}' differs from envelope Return-Path '{return_path_domain}'.",
        })
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        spoofing_indicators.append({
            "indicator": "From / Reply-To Domain Mismatch",
            "severity": "medium",
            "detail": f"Visible From domain '{from_domain}' redirects replies to '{reply_to_domain}'.",
        })

    # Display-name spoofing check: display name embeds a different email/domain
    from_raw = envelope.get("from_raw", "")
    embedded_emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", from_raw)
    if len(embedded_emails) >= 2 and _extract_domain(embedded_emails[0]) != _extract_domain(embedded_emails[-1]):
        spoofing_indicators.append({
            "indicator": "Display-Name Email Impersonation",
            "severity": "high",
            "detail": f"Display name references '{embedded_emails[0]}' while actual sender is '{embedded_emails[-1]}'.",
        })

    for mech in ("spf", "dkim", "dmarc"):
        val = auth_status[mech]
        if val in {"fail", "softfail", "permerror"}:
            spoofing_indicators.append({
                "indicator": f"{mech.upper()} Verification Failed ({val})",
                "severity": "high" if val == "fail" else "medium",
                "detail": f"Header authentication reported {mech}={val}.",
            })
        elif val == "missing":
            spoofing_indicators.append({
                "indicator": f"{mech.upper()} Result Missing",
                "severity": "low",
                "detail": f"No {mech.upper()} result was recorded in Authentication-Results headers.",
            })

    return {
        "routing": routing,
        "authentication": {
            "spf": auth_status["spf"],
            "dkim": auth_status["dkim"],
            "dmarc": auth_status["dmarc"],
            "has_dkim_signature": has_dkim_signature,
        },
        "domains": {
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
        },
        "spoofing_indicators": spoofing_indicators,
    }
