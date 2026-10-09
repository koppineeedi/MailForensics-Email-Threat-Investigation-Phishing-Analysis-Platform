import httpx
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import logging
from app.config import settings

logger = logging.getLogger(__name__)

class ThreatIntelService:
    def __init__(self):
        # Support both naming conventions
        self.vt_key = os.getenv("VT_API_KEY") or settings.VIRUSTOTAL_API_KEY
        self.otx_key = os.getenv("OTX_API_KEY") or settings.ALIENVAULT_OTX_API_KEY
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY") or settings.ABUSEIPDB_API_KEY

    def get_provider_status(self) -> Dict[str, str]:
        """Return the configuration status of each external threat intelligence provider."""
        return {
            "VirusTotal": "CONFIGURED" if bool(self.vt_key) else "NOT_CONFIGURED",
            "AlienVault_OTX": "CONFIGURED" if bool(self.otx_key) else "NOT_CONFIGURED",
            "AbuseIPDB": "CONFIGURED" if bool(self.abuse_key) else "NOT_CONFIGURED"
        }

    async def lookup_hash(self, sha256: str) -> Dict[str, Any]:
        """
        Perform file hash lookup across configured providers.
        Guaranteed: Never fabricates data or converts errors into fake 'clean' results.
        """
        now_utc = datetime.now(timezone.utc).isoformat()
        results = {}

        # 1. VirusTotal
        if not self.vt_key:
            results["VirusTotal"] = {
                "provider": "VirusTotal",
                "indicator": sha256,
                "indicator_type": "FILE_HASH_SHA256",
                "lookup_time": now_utc,
                "status": "NOT_CONFIGURED",
                "source": "NOT_CONFIGURED",
                "evidence": None,
                "error": "VirusTotal API key is not configured in environment settings."
            }
        else:
            try:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.get(
                        f"https://www.virustotal.com/api/v3/files/{sha256}",
                        headers={"x-apikey": self.vt_key}
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        results["VirusTotal"] = {
                            "provider": "VirusTotal",
                            "indicator": sha256,
                            "indicator_type": "FILE_HASH_SHA256",
                            "lookup_time": now_utc,
                            "status": "LIVE_PROVIDER_VERIFIED",
                            "source": "LIVE_EXTERNAL_PROVIDER",
                            "malicious_count": stats.get("malicious", 0),
                            "suspicious_count": stats.get("suspicious", 0),
                            "harmless_count": stats.get("harmless", 0),
                            "undetected_count": stats.get("undetected", 0),
                            "evidence": stats,
                            "error": None
                        }
                    elif resp.status_code in (401, 403):
                        results["VirusTotal"] = {
                            "provider": "VirusTotal",
                            "indicator": sha256,
                            "indicator_type": "FILE_HASH_SHA256",
                            "lookup_time": now_utc,
                            "status": "INVALID_CREDENTIALS",
                            "source": "LIVE_EXTERNAL_PROVIDER",
                            "evidence": None,
                            "error": f"Authentication rejected by VirusTotal (HTTP {resp.status_code})"
                        }
                    elif resp.status_code == 404:
                        results["VirusTotal"] = {
                            "provider": "VirusTotal",
                            "indicator": sha256,
                            "indicator_type": "FILE_HASH_SHA256",
                            "lookup_time": now_utc,
                            "status": "LIVE_PROVIDER_VERIFIED",
                            "source": "LIVE_EXTERNAL_PROVIDER",
                            "evidence": {"message": "Hash not found in VirusTotal dataset"},
                            "error": None
                        }
                    elif resp.status_code == 429:
                        results["VirusTotal"] = {
                            "provider": "VirusTotal",
                            "indicator": sha256,
                            "indicator_type": "FILE_HASH_SHA256",
                            "lookup_time": now_utc,
                            "status": "RATE_LIMITED",
                            "source": "LIVE_EXTERNAL_PROVIDER",
                            "evidence": None,
                            "error": "VirusTotal API rate limit reached"
                        }
                    else:
                        results["VirusTotal"] = {
                            "provider": "VirusTotal",
                            "indicator": sha256,
                            "indicator_type": "FILE_HASH_SHA256",
                            "lookup_time": now_utc,
                            "status": "PROVIDER_ERROR",
                            "source": "LIVE_EXTERNAL_PROVIDER",
                            "evidence": None,
                            "error": f"Provider returned HTTP {resp.status_code}"
                        }
            except httpx.TimeoutException:
                results["VirusTotal"] = {
                    "provider": "VirusTotal",
                    "indicator": sha256,
                    "indicator_type": "FILE_HASH_SHA256",
                    "lookup_time": now_utc,
                    "status": "TIMEOUT",
                    "source": "LIVE_EXTERNAL_PROVIDER",
                    "evidence": None,
                    "error": "Request to VirusTotal timed out after 8.0s"
                }
            except Exception as e:
                results["VirusTotal"] = {
                    "provider": "VirusTotal",
                    "indicator": sha256,
                    "indicator_type": "FILE_HASH_SHA256",
                    "lookup_time": now_utc,
                    "status": "PROVIDER_ERROR",
                    "source": "LIVE_EXTERNAL_PROVIDER",
                    "evidence": None,
                    "error": str(e)
                }

        # 2. AlienVault OTX
        if not self.otx_key:
            results["AlienVault_OTX"] = {
                "provider": "AlienVault_OTX",
                "indicator": sha256,
                "indicator_type": "FILE_HASH_SHA256",
                "lookup_time": now_utc,
                "status": "NOT_CONFIGURED",
                "source": "NOT_CONFIGURED",
                "evidence": None,
                "error": "AlienVault OTX API key is not configured in environment settings."
            }
        else:
            try:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.get(
                        f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general",
                        headers={"X-OTX-API-KEY": self.otx_key}
                    )
                    if resp.status_code == 200:
                        otx_data = resp.json()
                        pulse_count = otx_data.get("pulse_info", {}).get("count", 0)
                        results["AlienVault_OTX"] = {
                            "provider": "AlienVault_OTX",
                            "indicator": sha256,
                            "indicator_type": "FILE_HASH_SHA256",
                            "lookup_time": now_utc,
                            "status": "LIVE_PROVIDER_VERIFIED",
                            "source": "LIVE_EXTERNAL_PROVIDER",
                            "pulse_count": pulse_count,
                            "evidence": {"pulse_count": pulse_count},
                            "error": None
                        }
                    elif resp.status_code in (401, 403):
                        results["AlienVault_OTX"] = {
                            "provider": "AlienVault_OTX",
                            "indicator": sha256,
                            "indicator_type": "FILE_HASH_SHA256",
                            "lookup_time": now_utc,
                            "status": "INVALID_CREDENTIALS",
                            "source": "LIVE_EXTERNAL_PROVIDER",
                            "evidence": None,
                            "error": f"Authentication rejected by AlienVault OTX (HTTP {resp.status_code})"
                        }
                    else:
                        results["AlienVault_OTX"] = {
                            "provider": "AlienVault_OTX",
                            "indicator": sha256,
                            "indicator_type": "FILE_HASH_SHA256",
                            "lookup_time": now_utc,
                            "status": "PROVIDER_ERROR",
                            "source": "LIVE_EXTERNAL_PROVIDER",
                            "evidence": None,
                            "error": f"OTX returned HTTP {resp.status_code}"
                        }
            except Exception as e:
                results["AlienVault_OTX"] = {
                    "provider": "AlienVault_OTX",
                    "indicator": sha256,
                    "indicator_type": "FILE_HASH_SHA256",
                    "lookup_time": now_utc,
                    "status": "PROVIDER_ERROR",
                    "source": "LIVE_EXTERNAL_PROVIDER",
                    "evidence": None,
                    "error": str(e)
                }

        return results

    async def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """Perform IP reputation lookup via AbuseIPDB."""
        now_utc = datetime.now(timezone.utc).isoformat()
        results = {}

        if not self.abuse_key:
            results["AbuseIPDB"] = {
                "provider": "AbuseIPDB",
                "indicator": ip_address,
                "indicator_type": "IPV4_ADDRESS",
                "lookup_time": now_utc,
                "status": "NOT_CONFIGURED",
                "source": "NOT_CONFIGURED",
                "evidence": None,
                "error": "AbuseIPDB API key is not configured in environment settings."
            }
        else:
            try:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": self.abuse_key, "Accept": "application/json"},
                        params={"ipAddress": ip_address, "maxAgeInDays": 90}
                    )
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        results["AbuseIPDB"] = {
                            "provider": "AbuseIPDB",
                            "indicator": ip_address,
                            "indicator_type": "IPV4_ADDRESS",
                            "lookup_time": now_utc,
                            "status": "LIVE_PROVIDER_VERIFIED",
                            "source": "LIVE_EXTERNAL_PROVIDER",
                            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                            "total_reports": data.get("totalReports", 0),
                            "country_code": data.get("countryCode"),
                            "isp": data.get("isp"),
                            "evidence": data,
                            "error": None
                        }
                    elif resp.status_code in (401, 403):
                        results["AbuseIPDB"] = {
                            "provider": "AbuseIPDB",
                            "indicator": ip_address,
                            "indicator_type": "IPV4_ADDRESS",
                            "lookup_time": now_utc,
                            "status": "INVALID_CREDENTIALS",
                            "source": "LIVE_EXTERNAL_PROVIDER",
                            "evidence": None,
                            "error": "Invalid AbuseIPDB API key"
                        }
                    elif resp.status_code == 429:
                        results["AbuseIPDB"] = {
                            "provider": "AbuseIPDB",
                            "indicator": ip_address,
                            "indicator_type": "IPV4_ADDRESS",
                            "lookup_time": now_utc,
                            "status": "RATE_LIMITED",
                            "source": "LIVE_EXTERNAL_PROVIDER",
                            "evidence": None,
                            "error": "AbuseIPDB rate limit reached"
                        }
                    else:
                        results["AbuseIPDB"] = {
                            "provider": "AbuseIPDB",
                            "indicator": ip_address,
                            "indicator_type": "IPV4_ADDRESS",
                            "lookup_time": now_utc,
                            "status": "PROVIDER_ERROR",
                            "source": "LIVE_EXTERNAL_PROVIDER",
                            "evidence": None,
                            "error": f"AbuseIPDB returned HTTP {resp.status_code}"
                        }
            except httpx.TimeoutException:
                results["AbuseIPDB"] = {
                    "provider": "AbuseIPDB",
                    "indicator": ip_address,
                    "indicator_type": "IPV4_ADDRESS",
                    "lookup_time": now_utc,
                    "status": "TIMEOUT",
                    "source": "LIVE_EXTERNAL_PROVIDER",
                    "evidence": None,
                    "error": "AbuseIPDB request timed out"
                }
            except Exception as e:
                results["AbuseIPDB"] = {
                    "provider": "AbuseIPDB",
                    "indicator": ip_address,
                    "indicator_type": "IPV4_ADDRESS",
                    "lookup_time": now_utc,
                    "status": "PROVIDER_ERROR",
                    "source": "LIVE_EXTERNAL_PROVIDER",
                    "evidence": None,
                    "error": str(e)
                }

        return results

threat_intel_service = ThreatIntelService()
