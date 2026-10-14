# Security Policy

Bicameral is a permission layer for LLM agent orchestration; its own attack
surface is the two HTTP planes it exposes.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

Open a private security advisory via GitHub ("Security" → "Report a
vulnerability") instead of a public issue. Please include the reason code
chain (D1–D16) and the audit evidence for the bypass. Fixes land as patch
releases with a red-team retest under `docs/redteam/`.

## Known boundaries (not vulnerabilities, by design)

See README §6 and `docs/architecture.md` §7: unauthenticated control plane
(deploy on a trusted segment / add mTLS for production), in-memory budget and
nonce ledgers, no throughput hardening.
