import dns.resolver
from typing import Dict, Any, Optional, List
import logging
from app.config import settings

logger = logging.getLogger(__name__)

class DNSVerifier:
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.enabled = settings.ENABLE_LIVE_DNS_LOOKUPS

    def _get_resolver(self) -> dns.resolver.Resolver:
        res = dns.resolver.Resolver()
        res.timeout = self.timeout
        res.lifetime = self.timeout
        return res

    def lookup_spf(self, domain: Optional[str]) -> Dict[str, Any]:
        """
        Query DNS TXT records for domain and extract SPF policy.
        Distinguishes DNS_VERIFIED, DNS_LOOKUP_FAILED, DNS_NOT_PERFORMED.
        """
        if not domain or not self.enabled:
            return {
                "status": "DNS_NOT_PERFORMED",
                "source": "NOT_CONFIGURED" if not self.enabled else "REAL_EMAIL_ARTIFACT",
                "record": None,
                "mechanisms": [],
                "error": "Live DNS lookups disabled by policy (ENABLE_LIVE_DNS_LOOKUPS=False)" if not self.enabled else "No domain provided"
            }

        try:
            resolver = self._get_resolver()
            answers = resolver.resolve(domain, "TXT")
            spf_records = []
            for rdata in answers:
                txt_str = "".join([s.decode('utf-8', errors='replace') if isinstance(s, bytes) else str(s) for s in rdata.strings])
                if txt_str.startswith("v=spf1"):
                    spf_records.append(txt_str)

            if spf_records:
                chosen = spf_records[0]
                mechanisms = chosen.split()[1:]
                return {
                    "status": "DNS_VERIFIED",
                    "source": "LOCAL_DNS_LOOKUP",
                    "record": chosen,
                    "mechanisms": mechanisms,
                    "error": None
                }
            else:
                return {
                    "status": "DNS_LOOKUP_FAILED",
                    "source": "LOCAL_DNS_LOOKUP",
                    "record": None,
                    "mechanisms": [],
                    "error": "No SPF TXT record found on domain"
                }
        except dns.resolver.NXDOMAIN:
            return {
                "status": "DNS_LOOKUP_FAILED",
                "source": "LOCAL_DNS_LOOKUP",
                "record": None,
                "mechanisms": [],
                "error": f"NXDOMAIN: Domain '{domain}' does not exist in public DNS"
            }
        except dns.resolver.NoAnswer:
            return {
                "status": "DNS_LOOKUP_FAILED",
                "source": "LOCAL_DNS_LOOKUP",
                "record": None,
                "mechanisms": [],
                "error": "No TXT answer returned by DNS nameserver"
            }
        except Exception as e:
            return {
                "status": "DNS_LOOKUP_FAILED",
                "source": "LOCAL_DNS_LOOKUP",
                "record": None,
                "mechanisms": [],
                "error": f"DNS error: {str(e)}"
            }

    def lookup_dmarc(self, domain: Optional[str]) -> Dict[str, Any]:
        """
        Query DNS TXT records for _dmarc.<domain> and extract DMARC policy tags.
        """
        if not domain or not self.enabled:
            return {
                "status": "DNS_NOT_PERFORMED",
                "source": "NOT_CONFIGURED" if not self.enabled else "REAL_EMAIL_ARTIFACT",
                "record": None,
                "policy": None,
                "tags": {},
                "error": "Live DNS lookups disabled by policy (ENABLE_LIVE_DNS_LOOKUPS=False)" if not self.enabled else "No domain provided"
            }

        dmarc_host = f"_dmarc.{domain}"
        try:
            resolver = self._get_resolver()
            answers = resolver.resolve(dmarc_host, "TXT")
            for rdata in answers:
                txt_str = "".join([s.decode('utf-8', errors='replace') if isinstance(s, bytes) else str(s) for s in rdata.strings])
                if txt_str.startswith("v=DMARC1"):
                    # Parse tags (p=, sp=, pct=, rua=, ruf=)
                    tags = {}
                    parts = txt_str.split(";")
                    for p in parts:
                        p_strip = p.strip()
                        if "=" in p_strip:
                            k, v = p_strip.split("=", 1)
                            tags[k.strip().lower()] = v.strip()

                    return {
                        "status": "DNS_VERIFIED",
                        "source": "LOCAL_DNS_LOOKUP",
                        "record": txt_str,
                        "policy": tags.get("p", "none"),
                        "tags": tags,
                        "error": None
                    }

            return {
                "status": "DNS_LOOKUP_FAILED",
                "source": "LOCAL_DNS_LOOKUP",
                "record": None,
                "policy": None,
                "tags": {},
                "error": "No v=DMARC1 record found at host"
            }
        except dns.resolver.NXDOMAIN:
            return {
                "status": "DNS_LOOKUP_FAILED",
                "source": "LOCAL_DNS_LOOKUP",
                "record": None,
                "policy": None,
                "tags": {},
                "error": f"NXDOMAIN: '{dmarc_host}' does not exist"
            }
        except Exception as e:
            return {
                "status": "DNS_LOOKUP_FAILED",
                "source": "LOCAL_DNS_LOOKUP",
                "record": None,
                "policy": None,
                "tags": {},
                "error": str(e)
            }

    def lookup_dkim_key(self, domain: Optional[str], selector: Optional[str]) -> Dict[str, Any]:
        """
        Query DNS TXT records for <selector>._domainkey.<domain> to fetch DKIM public key.
        """
        if not domain or not selector or not self.enabled:
            return {
                "status": "DNS_NOT_PERFORMED",
                "source": "NOT_CONFIGURED" if not self.enabled else "REAL_EMAIL_ARTIFACT",
                "record": None,
                "public_key": None,
                "error": "Live DNS lookups disabled or selector/domain missing"
            }

        dkim_host = f"{selector}._domainkey.{domain}"
        try:
            resolver = self._get_resolver()
            answers = resolver.resolve(dkim_host, "TXT")
            for rdata in answers:
                txt_str = "".join([s.decode('utf-8', errors='replace') if isinstance(s, bytes) else str(s) for s in rdata.strings])
                if "p=" in txt_str:
                    return {
                        "status": "DNS_VERIFIED",
                        "source": "LOCAL_DNS_LOOKUP",
                        "record": txt_str,
                        "error": None
                    }
            return {
                "status": "DNS_LOOKUP_FAILED",
                "source": "LOCAL_DNS_LOOKUP",
                "record": None,
                "error": "DKIM record found but missing public key parameter (p=)"
            }
        except Exception as e:
            return {
                "status": "DNS_LOOKUP_FAILED",
                "source": "LOCAL_DNS_LOOKUP",
                "record": None,
                "error": str(e)
            }

dns_verifier = DNSVerifier()
