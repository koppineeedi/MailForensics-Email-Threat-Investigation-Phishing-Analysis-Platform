from app.services.received_chain import parse_received_headers

def test_received_chain_parsing():
    # In raw email headers, top header is final hop, bottom header is original sender hop.
    headers = [
        {"header_name": "Received", "header_value": "from relay.mx.lab (relay.mx.lab [192.168.1.20]) by mailbox.dest.lab (Postfix) with ESMTPS id 67890; Mon, 28 Sep 2026 10:00:05 +0000"},
        {"header_name": "Received", "header_value": "from mail.sender.lab (mail.sender.lab [192.168.1.10]) by relay.mx.lab (Postfix) with ESMTPS id 12345; Mon, 28 Sep 2026 10:00:00 +0000"}
    ]

    hops, anomalies = parse_received_headers(headers)
    assert len(hops) == 2
    assert hops[0]["hop_order"] == 1
    assert hops[0]["from_host"] == "mail.sender.lab"
    assert hops[1]["hop_order"] == 2
    assert hops[1]["from_host"] == "relay.mx.lab"
    assert hops[1]["delay_seconds"] == 5.0
