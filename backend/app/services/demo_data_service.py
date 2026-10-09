"""
Controlled Lab Demo Emails Generator for MailForensics.
All demo samples are harmless, simulated RFC822 messages for testing and presentation.
"""

BENIGN_EMAIL = b"""From: Security Team <security@acme-corp-defensive.lab>
To: Analyst <analyst@acme-corp-defensive.lab>
Subject: CONTROLLED LAB DEMO: Quarterly Defensive Security Update
Date: Mon, 28 Sep 2026 10:00:00 +0000
Message-ID: <lab-msg-001@acme-corp-defensive.lab>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Received-SPF: pass (domain of acme-corp-defensive.lab designates 192.168.1.10 as permitted sender)
Authentication-Results: acme-corp-defensive.lab; spf=pass smtp.mailfrom=acme-corp-defensive.lab; dkim=pass header.i=@acme-corp-defensive.lab; dmarc=pass action=none header.from=acme-corp-defensive.lab
DKIM-Signature: v=1; a=rsa-sha256; d=acme-corp-defensive.lab; s=s1; h=from:to:subject:date:message-id; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=demo-signature-bytes
Received: from mail.acme-corp-defensive.lab (mail.acme-corp-defensive.lab [192.168.1.10]) by mx.acme-corp-defensive.lab (Postfix) with ESMTP id 4X9Y1Z; Mon, 28 Sep 2026 10:00:00 +0000

Hello Analyst,

This is a harmless, controlled lab demo email representing legitimate internal corporate communications.

Regards,
Defensive Security Team
"""

SUSPICIOUS_REPLY_TO = b"""From: HR Portal <hr@acme-corp-defensive.lab>
Reply-To: External Collector <collector@external-phish-test.lab>
To: Employee <user@acme-corp-defensive.lab>
Subject: CONTROLLED LAB DEMO: Urgent HR Survey Update
Date: Mon, 28 Sep 2026 10:15:00 +0000
Message-ID: <lab-msg-002@acme-corp-defensive.lab>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Received-SPF: neutral
Authentication-Results: acme-corp-defensive.lab; spf=neutral; dkim=none; dmarc=none

Please complete your annual employee survey by replying directly to this email.

This is a controlled lab demo email testing Reply-To domain mismatch rules.
"""

SPF_FAILURE_EMAIL = b"""From: Finance Department <billing@acme-corp-defensive.lab>
To: Accounts Payable <ap@acme-corp-defensive.lab>
Subject: CONTROLLED LAB DEMO: Invoice Payment Confirmation
Date: Mon, 28 Sep 2026 10:30:00 +0000
Message-ID: <lab-msg-003@unauthorized-relay.lab>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Received-SPF: fail (domain of acme-corp-defensive.lab does not designate 198.51.100.42 as permitted sender)
Authentication-Results: acme-corp-defensive.lab; spf=fail smtp.mailfrom=acme-corp-defensive.lab; dkim=none; dmarc=fail

Please review attached invoice statement.

This is a controlled lab demo email testing SPF failure authentication detection.
"""

DMARC_FAILURE_EMAIL = b"""From: Executive Office <ceo@acme-corp-defensive.lab>
To: Finance Director <finance@acme-corp-defensive.lab>
Subject: CONTROLLED LAB DEMO: Urgent Wire Request
Date: Mon, 28 Sep 2026 11:00:00 +0000
Message-ID: <lab-msg-004@spoofed-host.lab>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Received-SPF: fail
Authentication-Results: acme-corp-defensive.lab; spf=fail; dkim=fail; dmarc=fail action=quarantine header.from=acme-corp-defensive.lab

I am in a meeting. Please process an urgent wire transfer immediately.

This is a controlled lab demo email testing DMARC policy failure detection.
"""

LOOKALIKE_DOMAIN_EMAIL = b"""From: Microsoft Support <support@micros0ft-login-verify.lab>
To: Victim Analyst <analyst@acme-corp-defensive.lab>
Subject: CONTROLLED LAB DEMO: Password Expiration Notice
Date: Mon, 28 Sep 2026 11:30:00 +0000
Message-ID: <lab-msg-005@micros0ft-login-verify.lab>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Received-SPF: neutral
Authentication-Results: acme-corp-defensive.lab; spf=neutral; dkim=none; dmarc=none

Your Microsoft 365 password will expire today. Verify your password to maintain access.

This is a controlled lab demo email testing lookalike domain detection.
"""

SUSPICIOUS_URL_EMAIL = b"""From: IT Service Desk <helpdesk@acme-corp-defensive.lab>
To: Analyst <analyst@acme-corp-defensive.lab>
Subject: CONTROLLED LAB DEMO: System Re-authentication Required
Date: Mon, 28 Sep 2026 12:00:00 +0000
Message-ID: <lab-msg-006@acme-corp-defensive.lab>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Received-SPF: pass
Authentication-Results: acme-corp-defensive.lab; spf=pass

<html>
<body>
<p>Please click here to verify your account login credentials:</p>
<p><a href="http://192.168.1.100/login/verify.php?user=analyst">http://login.acme-corp-defensive.lab/verify</a></p>
<p>Controlled lab demo email testing IP-based URL & unencrypted HTTP detection.</p>
</body>
</html>
"""

SUSPICIOUS_ATTACHMENT_EMAIL = b"""From: Legal Notice <legal@external-partner.lab>
To: Corporate Legal <legal@acme-corp-defensive.lab>
Subject: CONTROLLED LAB DEMO: Legal Summons Document
Date: Mon, 28 Sep 2026 12:30:00 +0000
Message-ID: <lab-msg-007@external-partner.lab>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY_DEMO_007"

--BOUNDARY_DEMO_007
Content-Type: text/plain; charset=utf-8

Please find attached court summons document.

Controlled lab demo email testing attachment extension detection.

--BOUNDARY_DEMO_007
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="Summons_Notice.pdf.exe"

MZ_SIMULATED_SAFE_HARMLERSS_DEMO_PAYLOAD_BYTES
--BOUNDARY_DEMO_007--
"""

MULTI_INDICATOR_PHISHING_EMAIL = b"""From: PayPal Security <security-update@paypa1-verify-account.lab>
Reply-To: Collector <harvest@attacker-domain-test.lab>
Return-Path: <bounce@unauthorized-mailer.lab>
To: Victim Analyst <analyst@acme-corp-defensive.lab>
Subject: CONTROLLED LAB DEMO: URGENT: Account Suspended - Action Required
Date: Mon, 28 Sep 2026 13:00:00 +0000
Message-ID: <lab-msg-008@paypa1-verify-account.lab>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY_DEMO_008"
Received-SPF: fail
Authentication-Results: acme-corp-defensive.lab; spf=fail; dkim=fail; dmarc=fail

--BOUNDARY_DEMO_008
Content-Type: text/html; charset=utf-8

<html>
<body>
<h2>URGENT: Unauthorized Login Attempt Detected</h2>
<p>Your PayPal account has been suspended due to suspicious activity within 24 hours.</p>
<p>Please enter your credentials immediately to confirm your account and restore access:</p>
<p><a href="http://203.0.113.50/paypal/login.html?session=12345">Click here to re-authenticate account</a></p>
<p>Attached is your security violation report.</p>
<p><i>CONTROLLED LAB DEMO: Multi-indicator phishing test case.</i></p>
</body>
</html>

--BOUNDARY_DEMO_008
Content-Type: application/vnd.ms-excel.macroEnabled.12
Content-Disposition: attachment; filename="Account_Verification_Form.xlsm"

MZ_SIMULATED_MACRO_PAYLOAD_BYTES_AutoOpen_WScript.Shell
--BOUNDARY_DEMO_008--
"""

DEMO_SAMPLES = {
    "BENIGN_EMAIL": BENIGN_EMAIL,
    "SUSPICIOUS_REPLY_TO": SUSPICIOUS_REPLY_TO,
    "SPF_FAILURE_EMAIL": SPF_FAILURE_EMAIL,
    "DMARC_FAILURE_EMAIL": DMARC_FAILURE_EMAIL,
    "LOOKALIKE_DOMAIN_EMAIL": LOOKALIKE_DOMAIN_EMAIL,
    "SUSPICIOUS_URL_EMAIL": SUSPICIOUS_URL_EMAIL,
    "SUSPICIOUS_ATTACHMENT_EMAIL": SUSPICIOUS_ATTACHMENT_EMAIL,
    "MULTI_INDICATOR_PHISHING_EMAIL": MULTI_INDICATOR_PHISHING_EMAIL
}
