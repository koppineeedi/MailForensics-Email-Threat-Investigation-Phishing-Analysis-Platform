# MailForensics — Platform Limitations & Boundary Declarations

## Objective Technical Limitations

1. **Static Analysis Scope**: MailForensics performs defensive static analysis. It does NOT sandbox or execute attachments in dynamic Windows/Linux virtual machines.
2. **DNS Verification Scope**: SPF, DKIM, and DMARC verification are evaluated primarily against preserved `Authentication-Results` and `Received-SPF` headers. Live DNS queries require explicit configuration.
3. **Threat Intelligence Dependencies**: External reputation lookups require valid, rate-permitted API keys. In the absence of API keys, providers safely return `NOT_CONFIGURED`.
4. **Heuristic Confidence**: Textual urgency and credential request rules are heuristic indicators and do not constitute absolute proof of intent.
