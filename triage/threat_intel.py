"""Phase 3: Threat Intelligence API Integrations (VirusTotal v3 & AbuseIPDB v2) + Offline Fallback."""
from __future__ import annotations

import base64
import os
from typing import Any, Dict, Optional

import requests


class ThreatIntelClient:
    """Queries VirusTotal v3 (URLs & SHA-256 hashes) and AbuseIPDB v2 (IPs) with graceful offline fallback."""

    VT_BASE = "https://www.virustotal.com/api/v3"
    ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self,
        vt_api_key: Optional[str] = None,
        abuseipdb_api_key: Optional[str] = None,
        timeout: int = 8,
    ) -> None:
        self.vt_api_key = (vt_api_key if vt_api_key is not None else os.getenv("VIRUSTOTAL_API_KEY", "")).strip()
        self.abuseipdb_api_key = (
            abuseipdb_api_key if abuseipdb_api_key is not None else os.getenv("ABUSEIPDB_API_KEY", "")
        ).strip()
        self.timeout = timeout

    @property
    def mode(self) -> str:
        if self.vt_api_key or self.abuseipdb_api_key:
            return "live_api"
        return "offline_heuristic"

    def check_url_virustotal(self, url: str) -> Dict[str, Any]:
        if not self.vt_api_key:
            return {
                "provider": "VirusTotal v3",
                "mode": "offline_fallback",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "status": "API key not configured — heuristic scoring applied",
            }
        try:
            url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")
            resp = requests.get(
                f"{self.VT_BASE}/urls/{url_id}",
                headers={"x-apikey": self.vt_api_key, "accept": "application/json"},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "provider": "VirusTotal v3",
                    "mode": "live_api",
                    "malicious": int(stats.get("malicious", 0)),
                    "suspicious": int(stats.get("suspicious", 0)),
                    "harmless": int(stats.get("harmless", 0)),
                    "status": "ok",
                }
            return {
                "provider": "VirusTotal v3",
                "mode": "live_api",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "status": f"HTTP {resp.status_code}",
            }
        except requests.RequestException as exc:
            return {
                "provider": "VirusTotal v3",
                "mode": "error_fallback",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "status": f"Lookup unavailable: {exc.__class__.__name__}",
            }

    def check_hash_virustotal(self, sha256_hash: str) -> Dict[str, Any]:
        if not self.vt_api_key:
            return {
                "provider": "VirusTotal v3",
                "mode": "offline_fallback",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "status": "API key not configured — heuristic scoring applied",
            }
        try:
            resp = requests.get(
                f"{self.VT_BASE}/files/{sha256_hash}",
                headers={"x-apikey": self.vt_api_key, "accept": "application/json"},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "provider": "VirusTotal v3",
                    "mode": "live_api",
                    "malicious": int(stats.get("malicious", 0)),
                    "suspicious": int(stats.get("suspicious", 0)),
                    "harmless": int(stats.get("harmless", 0)),
                    "status": "ok",
                }
            return {
                "provider": "VirusTotal v3",
                "mode": "live_api",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "status": f"HTTP {resp.status_code}",
            }
        except requests.RequestException as exc:
            return {
                "provider": "VirusTotal v3",
                "mode": "error_fallback",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "status": f"Lookup unavailable: {exc.__class__.__name__}",
            }

    def check_ip_abuseipdb(self, ip_address: Optional[str]) -> Dict[str, Any]:
        if not ip_address:
            return {
                "provider": "AbuseIPDB v2",
                "mode": "skipped",
                "ip": None,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "status": "No public origin IP extracted",
            }
        if not self.abuseipdb_api_key:
            return {
                "provider": "AbuseIPDB v2",
                "mode": "offline_fallback",
                "ip": ip_address,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "status": "API key not configured — heuristic scoring applied",
            }
        try:
            resp = requests.get(
                self.ABUSEIPDB_CHECK,
                headers={"Key": self.abuseipdb_api_key, "Accept": "application/json"},
                params={"ipAddress": ip_address, "maxAgeInDays": "90"},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "provider": "AbuseIPDB v2",
                    "mode": "live_api",
                    "ip": ip_address,
                    "abuse_confidence_score": int(data.get("abuseConfidenceScore", 0)),
                    "total_reports": int(data.get("totalReports", 0)),
                    "country_code": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "status": "ok",
                }
            return {
                "provider": "AbuseIPDB v2",
                "mode": "live_api",
                "ip": ip_address,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "status": f"HTTP {resp.status_code}",
            }
        except requests.RequestException as exc:
            return {
                "provider": "AbuseIPDB v2",
                "mode": "error_fallback",
                "ip": ip_address,
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "status": f"Lookup unavailable: {exc.__class__.__name__}",
            }
