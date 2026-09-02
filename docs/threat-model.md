# Threat model

## Protected assets

- Human authorization intent and consent evidence
- Agent and workload identities
- AOAT, WIT, and WPT credentials
- Resource operations and parameters
- Authorization policies and decision records
- Signing and verification keys

## Trust boundaries

- The LLM and generated tool arguments are untrusted.
- The calling agent may be compromised.
- Network traffic may be observed, delayed, replayed, or modified.
- Resource servers trust only configured issuers and trust domains.
- Trace viewers are less trusted than the enforcement path and never receive raw tokens.

## Initial attack categories

| Threat | Required defense |
|---|---|
| Token tampering | Signature, issuer, audience, expiry, and algorithm validation |
| Workload/user confusion | Cryptographic AOAT/WIT identity binding |
| Replay | Request digest, token ID/nonce cache, and bounded validity |
| Scope escalation | Operation-to-policy match and monotonic delegation checks |
| Delegation forgery | Per-record AS signature and chain-link verification |
| Context leakage | Redaction, explicit trace schema, and data minimization |
| Protocol confusion | Transport-specific canonicalization and expected token types |
| Fail-open error handling | Deny on verifier timeout, exception, or indeterminate state |

## Explicit non-goals for the first milestone

- Claiming production readiness of the upstream beta protocol
- Protecting a compromised Authorization Server signing key
- Inferring safe authorization policies from arbitrary natural language
- Persisting raw prompts or credentials in the trace store

