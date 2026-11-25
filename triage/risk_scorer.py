"""Phase 4: Weighted Phishing Risk Scoring Engine (0-100)."""
from __future__ import annotations

from typing import Any, Dict, List

URGENCY_TERMS = {
    "urgent", "immediately", "suspended", "verify your account", "action required",
    "within 24 hours", "unauthorized", "wire transfer", "overdue invoice", "password expires",
}


def compute_risk_score(
    envelope: Dict[str, Any],
    body: Dict[str, Any],
    forensics: Dict[str, Any],
    urls: List[Dict[str, Any]],
    attachments: List[Dict[str, Any]],
    ip_intel: Dict[str, Any],
) -> Dict[str, Any]:
    """Calculate an explainable 0-100 Phishing Risk Score and verdict tier."""
    score = 0
    breakdown: List[Dict[str, Any]] = []

    def add_points(points: int, category: str, reason: str) -> None:
        nonlocal score
        score += points
        breakdown.append({"category": category, "points": points, "reason": reason})

    # 1. Authentication & Spoofing (max ~45 pts)
    auth = forensics.get("authentication", {})
    for mech, fail_pts, soft_pts in (("spf", 15, 8), ("dkim", 12, 6), ("dmarc", 15, 8)):
        status = auth.get(mech, "missing")
        if status == "fail":
            add_points(fail_pts, "Authentication", f"{mech.upper()} failed")
        elif status in {"softfail", "permerror"}:
            add_points(soft_pts, "Authentication", f"{mech.upper()} returned {status}")

    reval = forensics.get("revalidation", {})
    if auth.get("dkim") == "pass" and reval.get("dkim", {}).get("result") == "fail":
        add_points(5, "Authentication (inconclusive)",
                   "Headers claim DKIM pass but the signature did not verify here "
                   "(could be a forged header, rotated key, or an altered export)")

    for ind in forensics.get("spoofing_indicators", []):
        if "Mismatch" in ind["indicator"] or "Impersonation" in ind["indicator"]:
            pts = 15 if ind["severity"] == "high" else 10
            add_points(pts, "Header Spoofing", ind["indicator"])

    # 2. URL & Domain Analysis
    for u in urls:
        vt = u.get("threat_intel", {})
        if vt.get("malicious", 0) > 0:
            add_points(30, "Threat Intel (URL)", f"VirusTotal flagged {u['domain']} ({vt['malicious']} detections)")
        elif u.get("heuristic_risk") == "high":
            add_points(18, "URL Heuristics", f"Multiple phishing flags on {u['domain'] or u['url'][:40]}")
        elif u.get("heuristic_risk") == "medium":
            add_points(8, "URL Heuristics", f"Suspicious URL attribute on {u['domain'] or u['url'][:40]}")

    # 3. Attachment Analysis
    for att in attachments:
        vt = att.get("threat_intel", {})
        if vt.get("malicious", 0) > 0:
            add_points(35, "Threat Intel (Attachment)", f"VirusTotal flagged '{att['filename']}' ({vt['malicious']} detections)")
        elif att.get("heuristic_rating") == "high":
            add_points(28, "Attachment Risk", f"Dangerous executable/script attachment: {att['filename']}")
        elif att.get("heuristic_rating") == "medium":
            add_points(12, "Attachment Risk", f"Macro-capable Office attachment: {att['filename']}")

    # 4. Origin IP Reputation
    abuse_score = int(ip_intel.get("abuse_confidence_score", 0))
    if abuse_score >= 50:
        add_points(20, "IP Reputation", f"AbuseIPDB confidence {abuse_score}% for {ip_intel.get('ip')}")
    elif abuse_score >= 20:
        add_points(10, "IP Reputation", f"AbuseIPDB confidence {abuse_score}% for {ip_intel.get('ip')}")

    # 5. Social Engineering / Urgency Language
    combined_text = f"{envelope.get('subject', '')} {body.get('text', '')}".lower()
    matched_urgency = [t for t in URGENCY_TERMS if t in combined_text]
    if len(matched_urgency) >= 2:
        add_points(10, "Content Heuristics", f"Urgency/pressure phrases detected: {', '.join(sorted(matched_urgency)[:3])}")
    elif len(matched_urgency) == 1:
        add_points(5, "Content Heuristics", f"Urgency phrase detected: {matched_urgency[0]}")

    final_score = min(score, 100)
    if final_score >= 75:
        verdict, badge = "Critical Priority (Suspected Phishing)", "danger"
        action = "Review now. If an analyst corroborates the indicators, consider quarantining the email, blocking the sender or origin IP, and warning affected recipients."
    elif final_score >= 50:
        verdict, badge = "High Priority (Suspected Phishing)", "danger"
        action = "Escalate to a Tier-2 analyst for review. If corroborated, consider blocking the embedded domains and removing the email from mailboxes."
    elif final_score >= 25:
        verdict, badge = "Medium Priority (Suspicious)", "warning"
        action = "Hold for manual analyst review and verify the sender through another channel."
    else:
        verdict, badge = "Low Priority (No strong indicators)", "success"
        action = "No strong indicators found by these checks. This does not prove the email is safe; close or monitor at analyst discretion."

    return {
        "score": final_score,
        "verdict": verdict,
        "badge_class": badge,
        "recommended_action": action,
        "breakdown": breakdown,
    }
