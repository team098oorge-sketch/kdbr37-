---
name: subdomain-takeover
description: >-
  Subdomain takeover detection and exploitation playbook. Use when targets have
  dangling CNAME/NS/MX records pointing to deprovisioned cloud resources, expired
  third-party services, or unclaimed SaaS tenants.
---

# SKILL: Subdomain Takeover — Detection & Exploitation Playbook

> **AI LOAD INSTRUCTION**: Covers CNAME/NS/MX takeover, per-provider fingerprint matching, claim procedures, and defensive monitoring. Key: a CNAME to S3 that returns 403 (bucket exists, private) is NOT vulnerable. Only `NoSuchBucket` (404) is.

## 0. RELATED ROUTING

- [ssrf](../ssrf-server-side-request-forgery/SKILL.md) when takeover bypasses SSRF allowlists trusting `*.target.com`
- [cors](../cors-cross-origin-misconfiguration/SKILL.md) when CORS trusts `*.target.com` — takeover = full cross-origin read
- [xss](../xss-cross-site-scripting/SKILL.md) takeover gives script execution under target origin
- [http-host-header-attacks](../http-host-header-attacks/SKILL.md) for Host routing / subdomain-scoped cache

---

## 1. CORE CONCEPT

1. `sub.target.com` has DNS (CNAME/NS/A) pointing to external service
2. External resource is **no longer provisioned**
3. Attacker can **register/claim** that resource name on the provider
4. Attacker controls content served under `sub.target.com`

**Impact**: cookie theft, OAuth token interception, phishing, CORS bypass, CSP bypass.

---

## 2. DETECTION METHODOLOGY

```
1. Collect subdomains (amass, subfinder, assetfinder, crt.sh)
2. Resolve DNS: dig CNAME sub.target.com +short
3. For each CNAME → check if target returns NXDOMAIN or provider error
4. Match response against fingerprint table (Section 3)
```

| Signal | Meaning |
|---|---|
| CNAME → `xxx.s3.amazonaws.com` + HTTP 404 "NoSuchBucket" | S3 bucket deleted, claimable |
| CNAME → `xxx.herokuapp.com` + "No such app" | Heroku app deleted |
| CNAME → `xxx.github.io` + 404 GitHub Pages message | GitHub Pages unclaimed |
| NXDOMAIN on CNAME target domain | Domain expired or never existed |

### Tools

| Tool | Purpose |
|---|---|
| `subjack` | Automated CNAME takeover checking |
| `nuclei -t takeovers/` | Nuclei takeover templates |
| `can-i-take-over-xyz` (GitHub) | Reference for vulnerable services |
| `dnsreaper` | Multi-provider scanner |
| `subzy` | Fast verification |

---

## 3. SERVICE PROVIDER FINGERPRINT TABLE

| Provider | CNAME Pattern | Fingerprint | Claimable? |
|---|---|---|---|
| **AWS S3** | `*.s3.amazonaws.com` | `NoSuchBucket` (404) | Yes — create bucket |
| **GitHub Pages** | `*.github.io` | `There isn't a GitHub Pages site here` | Yes — create repo + enable Pages |
| **Heroku** | `*.herokuapp.com` | `No such app` | Yes — create app |
| **Azure** | `*.azurewebsites.net` / `*.cloudapp.azure.com` | Various defaults, NXDOMAIN | Yes |
| **Shopify** | `*.myshopify.com` | `Sorry, this shop is currently unavailable` | Yes |
| **Fastly** | Fastly edge CNAME | `Fastly error: unknown domain` | Yes |
| **Zendesk** | `*.zendesk.com` | `Help Center Closed` | Yes |
| **Ghost** | `*.ghost.io` | 404 Ghost error | Yes |
| **Surge.sh** | `*.surge.sh` | `project not found` | Yes |
| **Fly.io** | `*.fly.dev` | Fly.io default 404 | Yes |

---

## 4. TAKEOVER PROCEDURES

### AWS S3
```
1. Confirm: curl -s http://sub.target.com → "NoSuchBucket"
2. aws s3 mb s3://sub.target.com --region <region>
3. Upload index.html + enable static website hosting
```

### GitHub Pages
```
1. Create GitHub repo, add CNAME file containing "sub.target.com"
2. Enable GitHub Pages in repo settings
```

### Heroku
```
1. heroku create <app-name-from-cname>
2. heroku domains:add sub.target.com
```

---

## 5. NS TAKEOVER — HIGH SEVERITY

```
target.com NS → ns1.expireddomain.com
                 ↓
attacker registers expireddomain.com
                 ↓
attacker controls ALL DNS for target.com
```

Detection: `dig NS target.com +short` → check each NS domain via whois for expiry.

Impact: full domain control, issue TLS certs via DNS-01, modify SPF/DKIM/DMARC.

---

## 6. MX TAKEOVER

MX → deprovisioned mail service → attacker claims tenant → receives password resets.

Common: expired Google Workspace/Microsoft 365 tenant with MX still pointing there.

---

## 7. WILDCARD DNS RISKS

`*.target.com CNAME → claimable service` — every undefined subdomain is vulnerable.

Detection: `dig A random1234567.target.com` — if resolves, wildcard exists.

---

## 8. DECISION TREE

```
sub.target.com discovered?
├── Has CNAME → external service?
│   ├── HTTP fingerprint matches table? → attempt claim → TAKEOVER
│   └── CNAME target NXDOMAIN? → register domain → full control
├── Has NS → external nameserver?
│   └── NS domain expired/available? → register → FULL ZONE TAKEOVER
├── Has MX → external mail service?
│   └── Deprovisioned/claimable? → claim tenant → EMAIL INTERCEPTION
└── Post-takeover impact:
    ├── Shared cookies with parent? → session hijacking
    ├── CORS trusts *.target.com? → cross-origin data theft
    ├── CSP whitelists *.target.com? → XSS
    └── OAuth redirect_uri allows sub? → token theft
```

---

## 9. WHAT AI MODELS MISS

1. **CNAME ≠ takeover**: S3 returning 403 (private bucket) is NOT vulnerable — only 404 NoSuchBucket is.
2. **Region matters for S3**: Bucket names are global but website endpoints are regional.
3. **GitHub Pages verification**: Org-verified domains cannot be claimed by others.
4. **Second-order takeover**: `sub.target.com → other.target.com → dead-service.com` — follow the full chain.
5. **SPF subdomain takeover**: If SPF includes `include:sub.target.com` and you take it over, you can modify SPF to authorize your mail server.
