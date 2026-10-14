---
name: api-authorization-and-bola
description: >-
  API authorization and BOLA testing playbook. Use when APIs expose object identifiers, nested resources, hidden writable fields, or weak function-level authorization.
---

# SKILL: API Authorization and BOLA

## 1. CORE TEST LOOP

1. Create Account A and Account B.
2. As Account A, capture create, read, update, and delete flows.
3. Replay with Account B's token.
4. Test sibling endpoints, nested endpoints, and alternate HTTP verbs.

## 2. QUICK PAYLOADS

```json
{"role":"admin"}
{"isAdmin":true}
{"org":"target-company"}
{"verified":true}
```
