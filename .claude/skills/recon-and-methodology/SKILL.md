---
name: recon-and-methodology
description: >-
  Reconnaissance and methodology playbook. Use when mapping assets, discovering endpoints, fingerprinting technology, and building a structured testing plan for a new target.
---

# SKILL: Recon and Methodology — Expert Bug Bounty Playbook

> **AI LOAD INSTRUCTION**: Systematic recon and bug-finding methodology. Covers subdomain enumeration, endpoint discovery, tech fingerprinting, and the hunter's mental model. Key insight: most high-severity bugs are found through systematic coverage, not just clever payloads.

---

## 1. RECON HIERARCHY

```
Target Selection
└── Scope Definition
    └── Asset Discovery (subdomains, IPs, domains)
        └── Tech Fingerprinting
            └── Endpoint Discovery
                └── Vulnerability Testing
```

---

## 2. SUBDOMAIN ENUMERATION

### Passive
```bash
subfinder -d target.com -o subdomains.txt
amass enum -passive -d target.com
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

### Active
```bash
massdns -r /path/to/resolvers.txt -t A -o S -w output.txt \
  <(cat wordlist.txt | sed 's/$/.target.com/')
ffuf -w subdomains-wordlist.txt -u https://FUZZ.target.com \
  -mc 200,301,302,403 -H "Host: FUZZ.target.com"
cat subdomains.txt | dnsx -a -resp -o resolved.txt
```

### Virtual Host Discovery
```bash
ffuf -w wordlist.txt -u https://target.com \
  -H "Host: FUZZ.target.com" -mc 200,301,403
gobuster vhost -u https://target.com -w wordlist.txt
```

---

## 3. SERVICE AND PORT DISCOVERY

```bash
nmap -T4 -F target.com -oN ports.txt
cat subdomains.txt | httpx -title -tech-detect -status-code -o live_hosts.txt
masscan -p 80,443,8080,8443 10.0.0.0/8 --rate=1000
```

---

## 4. WEB TECHNOLOGY FINGERPRINTING

```bash
whatweb https://target.com
httpx -u https://target.com -tech-detect
curl -sI https://target.com | grep -i "server\|x-powered-by\|x-generator\|cf-ray"
```

Fingerprint from: Server header, X-Powered-By, Cookies (PHPSESSID/JSESSIONID/_rails_session), HTML comments, meta generator, JS framework files.

---

## 5. ENDPOINT DISCOVERY

### Directory Brute Force
```bash
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -mc 200,301,302,403 -t 50
gobuster dir -u https://target.com -w wordlist.txt -x php,html,js,json
feroxbuster -u https://target.com -w wordlist.txt -x php,html,txt -r
```

### Parameter Discovery
```bash
arjun -u https://target.com/api/endpoint
x8 -u https://target.com/api/endpoint -w params-wordlist.txt
```

### JavaScript Source Mining
```bash
gau target.com | grep '\.js$' | httpx -mc 200 | xargs -I{} curl -s {} | \
  grep -oE '"/[a-zA-Z0-9/_-]+"' | sort -u
python3 linkfinder.py -i https://target.com -d -o output.html
waybackurls target.com | sort -u > wayback_urls.txt
```

### API Endpoint Discovery
```bash
ffuf -u https://target.com/FUZZ -w /SecLists/Discovery/Web-Content/api/api-endpoints.txt
# Test: /swagger.json /api-docs /openapi.json /v2/api-docs /.well-known/ /docs/
# GraphQL: /graphql /gql /v1/graphql /api/graphql
```

---

## 6. SOURCE CODE RECON

```bash
trufflehog git https://github.com/target-org/target-repo
gitleaks detect --source /path/to/cloned/repo
# GitHub dorks: site:github.com "target.com" "api_key" OR "secret"
# org:target-org secret OR password OR apikey
```

Exposed paths to check: `/.env`, `/.git/config`, `/config.json`, `/wp-config.php`, `/backup.sql`

---

## 7. ZSEANO'S TESTING METHODOLOGY

### Core Philosophy
1. Go deep on one program — learn the application thoroughly
2. Build a profile of the company — tech stack, developers, processes
3. Look where others don't — error pages, admin paths, old versions, mobile API
4. Follow the filter — if input is filtered somewhere, that functionality exists and may be bypassed

### Testing Sequence (One Page / Feature)
```
For each input point:
1. Non-malicious HTML tags (<h2>, <img>) → are they reflected?
2. Incomplete tags → what happens? (<iframe src=//evil.com )
3. Encoding tests → %0d, %0a, %09, <%00
4. Observe OUTPUT too — where does your input appear?
5. Test same input in ALL similarly-structured pages
6. Check mobile/API endpoint (less protected)
```

### Parameter → Vulnerability Mapping
```
Filename        → Path Traversal / CMDi
URL/location    → SSRF
Template/HTML   → SSTI
XML field       → XXE
SQL filter      → SQLi
User-content    → Stored XSS
```

---

## 8. BUG BOUNTY PROGRAM TRIAGE

### High-Value Target Selection
```
✓ Programs with large scope (*.target.com)
✓ Programs that pay for P2/P3
✓ Programs with recent tech changes (migrations = new bugs)
× Avoid: frozen/old codebases with well-known CVEs
× Avoid: strict programs with narrow scope
```

### High-Value Feature Focus
```
Priority 1: Authentication, password reset, 2FA → account takeover
Priority 2: File upload, profile edit, API endpoints → stored XSS, IDOR
Priority 3: Admin panels, user management → BFLA, privilege escalation
Priority 4: Payment flows, subscription → business logic
Priority 5: Import/export, template rendering → XXE, SSTI
```

---

## 9. NUCLEI TEMPLATES

```bash
nuclei -u https://target.com -t /nuclei-templates/ -o nuclei-results.txt
nuclei -u https://target.com -t cves/ -severity critical,high
nuclei -u https://target.com -t exposures/
cat subdomains.txt | nuclei -t exposures/ -t misconfiguration/ -o exposed.txt
```

---

## 10. COMMON MISCONFIGURATIONS (QUICK WINS)

```
□ CORS: Access-Control-Allow-Origin: * with credentials
□ S3 bucket public: curl https://target.s3.amazonaws.com/
□ Directory listing: response contains "Index of /"
□ .git exposed: curl https://target.com/.git/config
□ .env exposed: curl https://target.com/.env
□ Debug mode / stack traces in production
□ Default credentials: admin:admin on admin panels
□ phpinfo.php accessible
□ GraphQL introspection: POST /graphql {"query":"{__schema{types{name}}}"}
□ Admin panels: /admin /manager /console /phpmyadmin /wp-admin
```

---

## 11. QUICK REFERENCE TOOLS

| Category | Tool |
|---|---|
| Subdomain enum | subfinder, amass, massdns |
| Port scan | nmap, masscan |
| HTTP probe | httpx |
| Dir brute | ffuf, feroxbuster, gobuster |
| JS mining | LinkFinder, gau, waybackurls |
| Secret scan | trufflehog, gitleaks |
| Parameter fuzz | arjun, x8 |
| Vuln scan | nuclei |
| Proxy/intercept | Burp Suite Pro |
| SQLi | sqlmap |
| XSS | dalfox, XSStrike |
| SSRF | SSRFmap, Gopherus |

---

## 12. JAVA MIDDLEWARE FINGERPRINT MATRIX

| Middleware | Detection Path | Key Indicators |
|---|---|---|
| Apache Tomcat | `/manager/html`, `/manager/status` | Default creds: `tomcat:tomcat` |
| JBoss / WildFly | `/jmx-console/`, `/web-console/` | JMX MBean access, WAR deployment |
| WebLogic | `/console/`, `/wls-wsat/` | T3 protocol on 7001/7002 |
| Spring Boot Actuator | `/actuator/`, `/actuator/env` | JSON endpoint listing |
| Jenkins | `/script`, `/manage` | Groovy console |
| GlassFish | `/common/`, `/theme/` | Admin on 4848 |
| Jetty | `/jolokia/` | JMX access |
| Resin | `/resin-admin/` | Admin panel |

### Spring Boot Actuator Exploitation Priority

```
/actuator/env          → Leak environment variables (DB creds, API keys)
/actuator/heapdump     → Download JVM heap → search for passwords in memory
/actuator/jolokia      → JMX → possible RCE via MBean manipulation
/actuator/gateway/routes → Spring Cloud Gateway → SpEL injection (CVE-2022-22947)
/actuator/configprops  → All configuration properties
/actuator/mappings     → All URL mappings (hidden endpoints)
/actuator/beans        → All Spring beans
/actuator/threaddump   → Thread dump (may leak session tokens in stack frames)
```

---

## 13. INFORMATION LEAK DETECTION CHECKLIST

### Version Control
```
/.git/HEAD    /.svn/entries    /.hg/requires    /.DS_Store
```

### Backup Files
```
/backup.zip  /backup.tar.gz  /backup.sql
/config.php.bak  /config.php~  /.env.bak  /.env.production
```

### API Documentation & Debug
```
/swagger-ui.html  /api-docs  /graphql  /graphiql
/phpinfo.php  /server-status  /nginx_status
```

### Cloud & Infrastructure
```
/.aws/credentials  /.docker/config.json
/robots.txt  /sitemap.xml  /.well-known/
```
