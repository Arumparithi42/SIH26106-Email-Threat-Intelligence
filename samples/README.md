# Synthetic demo emails

**Everything here is synthetic demonstration data.**

- Organisations are fictional ("National Trust Bank" `ntbank.example`, recipient "Corp" `corp.example`) and use the reserved
  `.example` TLD (RFC 2606), so they can never belong to anyone.
- Mailbox names on real free-mail domains (`sih-demo-…@outlook.com`, `…@gmail.com`) are deliberately artificial placeholders.
- Relay IPs are public IPs of **shared** infrastructure (Amazon SES `54.240.8.10`, Microsoft consumer mail `40.92.58.21`,
  Tor exit relays `185.220.101.x`), so live providers return real, not invented, intelligence. Their use here does not
  accuse the operators of anything.
- Attachments are inert placeholder bytes, not code or documents.
- `Authentication-Results` headers represent what a receiving server would have recorded.
- These files are **not** part of the ML training dataset.

| File | Scenario |
| --- | --- |
| `legitimate.eml` | Bank statement notification: aligned SPF/DKIM/DMARC, DKIM-signed with a throwaway demo key |
| `phishing.eml` | Look-alike sender domain, Reply-To to another domain, SPF/DMARC fail, credential lure, link text ≠ link target |
| `spoofing.eml` | Exact bank domain spoofed from a VPS; forged DKIM signature; forged upstream Received hop |
| `bec.eml` | CEO impersonation from free webmail; SPF/DMARC **pass**; urgent confidential payment to "new bank details" |
| `suspicious_url.eml` | IP-based URL, punycode, `@` trick, brand-in-subdomain, `.pdf.js` + `.docm` attachments |

Regenerate with `python samples/generate_samples.py` (backend venv active). The legitimate sample is re-signed with a new
throwaway key each time; its public key is written to `demo_dkim_public_key.txt` and is **not** published in DNS, so the
live DKIM check reports "key not found" and the dashboard falls back to the receiver-recorded result.
