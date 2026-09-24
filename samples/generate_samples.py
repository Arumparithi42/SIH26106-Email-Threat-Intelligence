"""Generate the synthetic demo .eml files in this folder.

ALL CONTENT IS SYNTHETIC. Organisations ("National Trust Bank", "Corp") are fictional
and use the reserved .example TLD. No real people, mailboxes or credentials.
Relay IPs are real public IPs of shared infrastructure (Amazon SES, Microsoft 365,
Tor exit relays) so that live providers return real, not invented, intelligence.

Run from the repository root with the backend venv active:
    python samples/generate_samples.py
The legitimate sample is DKIM-signed with a throwaway key generated here; the
private key is deleted afterwards and only the public key is printed (it is NOT
published in DNS, so live DKIM verification reports "key not found").
"""
from __future__ import annotations

import base64
import subprocess
import tempfile
from pathlib import Path

import dkim

OUT = Path(__file__).parent
CRLF = "\r\n"


def write(name: str, text: str) -> bytes:
    data = text.strip("\n").replace("\r\n", "\n").replace("\n", CRLF).encode() + CRLF.encode()
    (OUT / name).write_bytes(data)
    return data


def b64(data: bytes) -> str:
    s = base64.b64encode(data).decode()
    return "\n".join(s[i:i + 76] for i in range(0, len(s), 76))


# ------------------------------------------------------------------ 1 legitimate
legit_body = """\
Content-Type: multipart/alternative; boundary="b1"
MIME-Version: 1.0

--b1
Content-Type: text/plain; charset="utf-8"

Dear customer,

Your account statement for September 2026 is now available in NetBanking.
You can view it at https://portal.ntbank.example/statements after logging in as usual.
No action is required. We will never ask for your password or OTP by email.

Regards,
National Trust Bank - Customer Communications
--b1
Content-Type: text/html; charset="utf-8"

<html><body><p>Dear customer,</p>
<p>Your account statement for September 2026 is now available in NetBanking.
You can view it at <a href="https://portal.ntbank.example/statements">portal.ntbank.example/statements</a> after logging in as usual.</p>
<p>No action is required. We will never ask for your password or OTP by email.</p>
<p>Regards,<br>National Trust Bank - Customer Communications</p></body></html>
--b1--
"""
legit_headers = """\
From: "National Trust Bank" <alerts@ntbank.example>
To: analyst@corp.example
Subject: Your September account statement is ready
Date: Tue, 22 Sep 2026 09:15:02 +0530
Message-ID: <20260922034502.4471@mail.ntbank.example>
X-Mailer: NTB Notification Service 3.2
"""
with tempfile.TemporaryDirectory() as tmp:
    key = Path(tmp) / "demo.key"
    subprocess.run(["openssl", "genrsa", "-out", str(key), "2048"], check=True, capture_output=True)
    pub = subprocess.run(["openssl", "rsa", "-in", str(key), "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
    unsigned = (legit_headers + legit_body).replace("\n", CRLF).encode()
    sig = dkim.sign(unsigned, b"demo2026", b"ntbank.example", key.read_bytes(),
                    include_headers=[b"from", b"to", b"subject", b"date", b"message-id"])
    signature_header = sig.decode().replace("\r\n", "\n").strip("\n")
public_txt = "v=DKIM1; k=rsa; p=" + base64.b64encode(pub).decode()
(OUT / "demo_dkim_public_key.txt").write_text(
    "# Throwaway DEMO key - not a secret, not published in DNS.\n"
    "# DNS name it would live at: demo2026._domainkey.ntbank.example\n" + public_txt + "\n")

write("legitimate.eml", f"""\
Return-Path: <bounce@ntbank.example>
Received: from mx1.corp.example (mx1.corp.example [10.20.0.5])
	by mbox.corp.example (Postfix) with ESMTP id 4Q7kZt1xYz
	for <analyst@corp.example>; Tue, 22 Sep 2026 03:45:09 +0000 (UTC)
Authentication-Results: mx1.corp.example;
	spf=pass smtp.mailfrom=bounce@ntbank.example;
	dkim=pass header.d=ntbank.example header.s=demo2026;
	dmarc=pass (p=reject) header.from=ntbank.example
Received: from a8-10.smtp-out.amazonses.com (a8-10.smtp-out.amazonses.com [54.240.8.10])
	by mx1.corp.example (Postfix) with ESMTPS id 7B2C1400A1
	for <analyst@corp.example>; Tue, 22 Sep 2026 03:45:05 +0000 (UTC)
Received: from app01.ntbank.example (app01.ntbank.example [10.1.2.3])
	by email-smtp.ntbank.example with ESMTP id 0100abcd;
	Tue, 22 Sep 2026 03:45:03 +0000
{signature_header}
{legit_headers}{legit_body}""")

# ------------------------------------------------------------------ 2 phishing
write("phishing.eml", """\
Return-Path: <bounce@mailer-ntbamk.example>
Received: from mx1.corp.example (mx1.corp.example [10.20.0.5])
	by mbox.corp.example (Postfix) with ESMTP id 5A1B2C3D4E
	for <analyst@corp.example>; Tue, 22 Sep 2026 11:02:41 +0000 (UTC)
Authentication-Results: mx1.corp.example;
	spf=fail (sender IP is 185.220.101.47) smtp.mailfrom=mailer-ntbamk.example;
	dkim=none (message not signed);
	dmarc=fail (p=none) header.from=ntbamk.example
Received: from ntbamk.example (unknown [185.220.101.47])
	by mx1.corp.example (Postfix) with ESMTP id 9F8E7D6C5B
	for <analyst@corp.example>; Tue, 22 Sep 2026 11:02:39 +0000 (UTC)
From: "NTBank Security Team" <security@ntbamk.example>
Reply-To: <verify-desk@ntbank-support.example>
To: analyst@corp.example
Subject: URGENT: Your NTBank account has been suspended
Date: Tue, 22 Sep 2026 11:15:00 +0000
Message-ID: <a81c9f00e1@localhost.localdomain>
X-Mailer: PHPMailer 6.0.3 (https://github.com/PHPMailer/PHPMailer)
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="p1"

--p1
Content-Type: text/plain; charset="utf-8"

Dear Customer,

We detected unusual sign-in activity and your NetBanking account has been suspended.
To restore access you must verify your identity within 24 hours, otherwise the account
will be permanently closed.

Click here to verify your account: http://ntbank-secure-verify.example/login/verify.php?id=88341

You will be asked to confirm your customer ID, password and the OTP sent to your phone.

NTBank Security Team
--p1
Content-Type: text/html; charset="utf-8"

<html><body>
<p>Dear Customer,</p>
<p>We detected <b>unusual sign-in activity</b> and your NetBanking account has been <b>suspended</b>.</p>
<p>To restore access you must verify your identity <b>within 24 hours</b>, otherwise the account will be permanently closed.</p>
<p><a href="http://ntbank-secure-verify.example/login/verify.php?id=88341">https://www.ntbank.example/secure/verify</a></p>
<p>You will be asked to confirm your customer ID, password and the OTP sent to your phone.</p>
<p>NTBank Security Team</p>
</body></html>
--p1--
""")

# ------------------------------------------------------------------ 3 spoofing
write("spoofing.eml", """\
Return-Path: <root@vps-4471.hosting.example>
Received: from mx1.corp.example (mx1.corp.example [10.20.0.5])
	by mbox.corp.example (Postfix) with ESMTP id 1C2D3E4F5A
	for <analyst@corp.example>; Wed, 23 Sep 2026 06:40:12 +0000 (UTC)
Authentication-Results: mx1.corp.example;
	spf=fail smtp.mailfrom=vps-4471.hosting.example;
	dkim=fail (signature verification failed) header.d=ntbank.example;
	dmarc=fail (p=reject) header.from=ntbank.example
Received: from vps-4471.hosting.example (unknown [185.220.101.33])
	by mx1.corp.example (Postfix) with ESMTP id 6B7C8D9E0F
	for <analyst@corp.example>; Wed, 23 Sep 2026 06:40:09 +0000 (UTC)
Received: from mail.ntbank.example (mail.ntbank.example [54.240.8.10])
	by relay.ntbank.example with ESMTPS id 00ff00ff;
	Wed, 23 Sep 2026 07:55:00 +0000
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=ntbank.example; s=demo2026;
	h=from:to:subject:date:message-id; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
	b=Zm9yZ2VkLXNpZ25hdHVyZS1mb3ItZGVtby1vbmx5LW5vdC1hLXJlYWwtc2lnbmF0dXJl
From: "National Trust Bank" <alerts@ntbank.example>
To: analyst@corp.example
Subject: Official notice: update to your account terms
Date: Wed, 23 Sep 2026 06:39:58 +0000
Message-ID: <1695451198.4471@vps-4471.hosting.example>
X-Mailer: PHPMailer 5.2.9
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Dear valued customer,

This is an official communication from the compliance department of National Trust Bank,
issued on behalf of the head office.

Our account terms have been updated. For any questions, simply reply to this email and
our customer care team will assist you.

National Trust Bank
""")

# ------------------------------------------------------------------ 4 BEC
write("bec.eml", """\
Return-Path: <sih-demo-ceo-office@outlook.com>
Received: from mx1.corp.example (mx1.corp.example [10.20.0.5])
	by mbox.corp.example (Postfix) with ESMTP id 2D3E4F5A6B
	for <finance@corp.example>; Thu, 24 Sep 2026 04:31:40 +0000 (UTC)
Authentication-Results: mx1.corp.example;
	spf=pass smtp.mailfrom=outlook.com;
	dkim=none;
	dmarc=pass header.from=outlook.com
Received: from EUR05-AM6-obe.outbound.protection.outlook.com (mail-am6eur05olkn2021.outbound.protection.outlook.com [40.92.58.21])
	by mx1.corp.example (Postfix) with ESMTPS id 3E4F5A6B7C
	for <finance@corp.example>; Thu, 24 Sep 2026 04:31:38 +0000 (UTC)
From: "Rajesh Menon, CEO" <sih-demo-ceo-office@outlook.com>
Reply-To: <sih-demo-ceo-private@gmail.com>
To: finance@corp.example
Subject: Urgent and confidential - vendor payment today
Date: Thu, 24 Sep 2026 10:01:30 +0530
Message-ID: <PAXP193MB1234.sihdemo@PAXP193MB1234.EURP193.PROD.OUTLOOK.COM>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi,

I am in a board meeting and cannot take calls. We are closing an acquisition and I need you
to process an urgent wire transfer of Rs 18,40,000 to our new vendor today.

Please use the updated bank account details below (the vendor changed banks last week):
Beneficiary: Northstar Advisory Services
Account number: 000000000000 (demo)
IFSC: DEMO0000000

Keep this strictly confidential until the deal is announced and do not discuss it with anyone.
Reply to me once the transfer is done.

Rajesh
Sent from my phone
""")

# ------------------------------------------------------------------ 5 suspicious URLs + attachments
fake_js = b"// SIH26106 DEMO PLACEHOLDER - inert text, not functional code.\n"
fake_docm = b"PK\x03\x04" + b"SIH26106 demo placeholder bytes - not a real document" + b"\x00" * 16
write("suspicious_url.eml", f"""\
Return-Path: <no-reply@share-docs.example>
Received: from mx1.corp.example (mx1.corp.example [10.20.0.5])
	by mbox.corp.example (Postfix) with ESMTP id 4F5A6B7C8D
	for <analyst@corp.example>; Thu, 24 Sep 2026 09:48:02 +0000 (UTC)
Authentication-Results: mx1.corp.example;
	spf=softfail smtp.mailfrom=share-docs.example;
	dkim=none;
	dmarc=none header.from=share-docs.example
Received: from relay7.share-docs.example (relay7.share-docs.example [185.220.101.47])
	by mx1.corp.example (Postfix) with ESMTP id 5A6B7C8D9E
	for <analyst@corp.example>; Thu, 24 Sep 2026 09:48:00 +0000 (UTC)
Received: from localhost (localhost [127.0.0.1])
	by relay7.share-docs.example with SMTP id x1;
	Thu, 24 Sep 2026 07:21:44 +0000
From: "Cloud Drive" <no-reply@share-docs.example>
To: analyst@corp.example
Subject: A document has been shared with you
Date: Thu, 24 Sep 2026 07:21:40 +0000
Message-ID: <share.7788@share-docs.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="s1"

--s1
Content-Type: text/html; charset="utf-8"

<html><body>
<p>A colleague shared "Salary_Revision_2026.pdf" with you.</p>
<p><a href="http://185.220.101.47:8080/drive/view.php?doc=salary">Open document</a></p>
<p>Mirror: <a href="http://xn--ntbnk-sqa.example/login">http://ntbank.example/login</a></p>
<p>Backup link: http://ntbank.example@203.0.113.9/secure/signin</p>
<p>Portal: https://ntbank.example.docs-share-login.example/account/verify</p>
</body></html>
--s1
Content-Type: application/pdf; name="Shared_Document.pdf.js"
Content-Disposition: attachment; filename="Shared_Document.pdf.js"
Content-Transfer-Encoding: base64

{b64(fake_js)}
--s1
Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="Q3_report.docm"
Content-Disposition: attachment; filename="Q3_report.docm"
Content-Transfer-Encoding: base64

{b64(fake_docm)}
--s1--
""")

print("Wrote samples to", OUT)
print("Demo DKIM public key (NOT in DNS):", public_txt[:60] + "...")
