# MailForensics — Email Authentication & DNS Verification Architecture

## 1. Authentication Triad & Dual-Phase Methodology

MailForensics strictly distinguishes between:
1. **Header-Reported Results (`HEADER_RESULT`):** Authentication headers (`Authentication-Results`, `Received-SPF`) inserted by intermediate or receiving MTAs.
2. **Independent DNS Verification (`DNS_RESULT`):** Direct queries to public DNS records for SPF policies, DMARC policies, and DKIM public keys.
3. **Cryptographic Verification (`CRYPTOGRAPHIC_RESULT`):** Direct mathematical verification of digital signatures (`DKIM-Signature`) over the raw email byte payload using `dkimpy`.

---

## 2. Status Taxonomies

To prevent analyst confusion and honey-trap beaconing, every authentication component classifies its evidence:

| Status Code | Meaning |
| :--- | :--- |
| `HEADER_REPORTED` | Result extracted directly from RFC headers recorded by receiving MTAs. |
| `DNS_VERIFIED` | Active DNS query succeeded and validated policy/key existence. |
| `DNS_LOOKUP_FAILED` | DNS query failed (e.g. `NXDOMAIN`, `NoAnswer`, or timeout). |
| `DNS_NOT_PERFORMED` | Live DNS lookups were deliberately disabled for operational security (`ENABLE_LIVE_DNS_LOOKUPS=False`). |

---

## 3. SPF Analysis (RFC 7208)

1. **Header Phase:** Evaluates `Received-SPF` header and `Authentication-Results: spf=...` tags.
2. **DNS Phase:** Queries TXT records on the `smtp.mailfrom` domain to extract `v=spf1 ...` mechanisms (e.g., `ip4`, `include`, `redirect`, `all`).
3. **Alignment:** Compares sending MTA IP against authorized IP blocks.

---

## 4. DKIM Verification (RFC 6376)

1. **Header Parsing:** Parses `DKIM-Signature` headers to identify signing domain (`d=`), selector (`s=`), canonicalization algorithm (`c=`), and signature algorithms (`a=rsa-sha256` or `a=ed25519-sha256`).
2. **DNS Public Key Retrieval:** Resolves `<selector>._domainkey.<domain>` to fetch public key bytes (`p=...`).
3. **Cryptographic Validation:** Executes `dkim.verify(raw_email_bytes)`.
   - Returns `PASS` only if the cryptographic hash matches and signature is verified.
   - If headers or body were altered in transit, verification returns `FAIL`.

---

## 5. DMARC Evaluation (RFC 7489)

1. **DNS Policy Retrieval:** Resolves `_dmarc.<from_domain>` to extract `v=DMARC1; p=...; rua=...`.
2. **Alignment Evaluation:**
   - **SPF Alignment:** Requires RFC 5322 `From` domain to match the SPF evaluated domain (strict or relaxed).
   - **DKIM Alignment:** Requires RFC 5322 `From` domain to match the `d=` signing domain.
3. **DMARC Result:**
   - `PASS`: If at least one mechanism (SPF or DKIM) passes AND is aligned.
   - `FAIL`: If neither mechanism passes with domain alignment.
