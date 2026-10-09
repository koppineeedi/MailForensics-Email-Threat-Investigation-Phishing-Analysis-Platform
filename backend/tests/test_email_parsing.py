from app.services.email_parser import parse_raw_email, parse_address
from app.services.demo_data_service import BENIGN_EMAIL

def test_parse_address_utility():
    parsed = parse_address("Security Team <security@acme.lab>")
    assert len(parsed) == 1
    assert parsed[0]["normalized_address"] == "security@acme.lab"
    assert parsed[0]["display_name"] == "Security Team"
    assert parsed[0]["domain"] == "acme.lab"

def test_parse_raw_email():
    res = parse_raw_email(BENIGN_EMAIL)
    assert res["subject"] == "CONTROLLED LAB DEMO: Quarterly Defensive Security Update"
    assert res["sender"] == "security@acme-corp-defensive.lab"
    assert len(res["headers"]) > 0
    assert "Defensive Security Team" in res["body_plain"]
