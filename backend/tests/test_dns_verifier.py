import pytest
from unittest.mock import MagicMock, patch
from app.services.dns_verifier import dns_verifier, DNSVerifier

def test_dns_verifier_null_inputs():
    res_spf = dns_verifier.lookup_spf(None)
    assert res_spf["status"] == "DNS_NOT_PERFORMED"

    res_dmarc = dns_verifier.lookup_dmarc(None)
    assert res_dmarc["status"] == "DNS_NOT_PERFORMED"

    res_dkim = dns_verifier.lookup_dkim_key(None, None)
    assert res_dkim["status"] == "DNS_NOT_PERFORMED"

def test_dns_verifier_mocked_spf():
    verifier = DNSVerifier()
    verifier.enabled = True

    mock_rdata = MagicMock()
    mock_rdata.strings = [b"v=spf1 include:_spf.google.com ~all"]

    with patch("dns.resolver.Resolver.resolve", return_value=[mock_rdata]):
        res = verifier.lookup_spf("example.com")
        assert res["status"] == "DNS_VERIFIED"
        assert res["source"] == "LOCAL_DNS_LOOKUP"
        assert res["record"] == "v=spf1 include:_spf.google.com ~all"
        assert "include:_spf.google.com" in res["mechanisms"]

def test_dns_verifier_mocked_dmarc():
    verifier = DNSVerifier()
    verifier.enabled = True

    mock_rdata = MagicMock()
    mock_rdata.strings = [b"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]

    with patch("dns.resolver.Resolver.resolve", return_value=[mock_rdata]):
        res = verifier.lookup_dmarc("example.com")
        assert res["status"] == "DNS_VERIFIED"
        assert res["source"] == "LOCAL_DNS_LOOKUP"
        assert res["policy"] == "reject"
        assert res["tags"]["rua"] == "mailto:dmarc@example.com"

def test_dns_verifier_nxdomain():
    import dns.resolver
    verifier = DNSVerifier()
    verifier.enabled = True

    with patch("dns.resolver.Resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
        res = verifier.lookup_spf("domain-does-not-exist.test")
        assert res["status"] == "DNS_LOOKUP_FAILED"
        assert "NXDOMAIN" in res["error"]
