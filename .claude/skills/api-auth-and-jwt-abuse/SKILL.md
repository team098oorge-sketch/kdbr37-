---
name: api-auth-and-jwt-abuse
description: >-
  API authentication and JWT abuse playbook. Use when testing bearer tokens, API keys, claim trust, header spoofing, rate limits, and API auth boundary weaknesses.
---

# SKILL: API Auth and JWT Abuse

## 1. TOKEN TRIAGE

Inspect: `alg`, `kid`, `jku`, `x5u`, role/org/tenant/scope claims, issuer and audience mismatches.

## 2. QUICK ATTACK PICKS

| Pattern | First Test |
|---|---|
| `alg:none` acceptance | unsigned token with trailing dot |
| RS256 confusion | switch to HS256 using public key as secret |
| `kid` lookup trust | path traversal or injection in `kid` |
| remote key fetch trust | attacker-controlled `jku` or `x5u` |
| weak secret | offline crack with targeted wordlists |

## 3. RATE LIMIT BYPASS

```text
X-Forwarded-For
X-Real-IP
Forwarded
User-Agent rotation
Path case / slash variants
```
