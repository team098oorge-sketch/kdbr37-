# Test Matrix and Effort

Use with `SKILL.md` §3. What to hit first, what "tested" means per class, and when you must not stop. Probe recipes live in deep topic skills.

## 1. Effort order

1. Unauthenticated access to another user, tenant, or subject
2. Auth takeover: issue session, reset, rebind, swap ticket
3. Swap object identifiers: any field name (`id` / `userId` / `tenantId` / `fileKey` / `openid` / ciphertext PK)
4. Authenticated writes and business logic: add role, change amount or state, skip approval, coupon/inventory concurrency
5. Injection, SSRF, XSS, command or template execution on surfaces that show a **diff**
6. Salts, hardcoded keys, demo accounts in scripts and pages

## 2. Type matrix

| Class | Done means |
|---|---|
| Unauthenticated | Critical read/write with credentials stripped. On success, swap identifiers |
| IDOR | No account: after unauthenticated success, swap. With account: record same-subject baseline, then neighbor account |
| Injection | Only endpoints where count, content, or a fetched URL can change. Baseline → probe → diff |
| SSRF | Every URL / callback / webhook / file / fetch / import / preview / proxy parameter |
| Command or template exec | Command, expression, template, deserialization, dangerous upload followed to execution or falsified |
| Credentials | Pass the liveness gate: production accepts real value (rejects a fake) and one read-only call returns identity or a list |
| Default creds | Middleware/component naked defaults that actually issue a session |
| Sensitive paths | Swagger / Actuator / debug / heapdump / env; secrets found here get mined |
| XSS | Reflected on reflection points; stored on write-then-read-back |
| Upload | Type, path, executable or SSRF or business IDOR. Do not stop at store+download |
| Path traversal | `file` / `path` / `filename` / `key` |
| CSRF | Write succeeds with missing or bad token; self-only CSRF is not a primary result |
| Logic and privilege | Write endpoints that add role/amount/state; multi-step skip; concurrency |
| Auth takeover | Inventory has issue-session, reset, rebind, ticket-swap, or step-up → tick |

## 3. Do not stop on a half-chain

| You saw | You must continue to |
|---|---|
| File channel open | Business API, executable, path, or SSRF chain |
| OTP or slider passed | Does the code return in-band, bind an account, reset swap the user |
| Config has host but no creds | Keep looking for the full credential |
| Copied a secret | Fake-vs-real + identity or list, read-only |
| List or detail passed | Same object’s attachment, export, preview, approval |
| Medium already confirmed | Follow the same object to write, cross-user, takeover, or execution |

## 4. Parameters, diffs, and response classes

| Response looks like | It is | Do |
|---|---|---|
| One sentence "please log in", no list/total | Login gate | N/A the injection class |
| Has list / total / business fields, even `total=0` | Differential surface | Swap params, swap identifiers, inject per stack |
| Error, timeout, or length/timing clearly off baseline | Differential surface | Compare; stop if the diff is unstable |
| Missing a parameter dumps a roster or detail | Unauthenticated exception | Treat as unauthenticated + identifier swap |

## 5. Pre-conclusion self-check

- [ ] On differential surfaces, each filter param got an injection or IDOR diff
- [ ] Unauthenticated tested with credentials stripped
- [ ] Cross-user / cross-tenant tested
- [ ] With a session: object graph, identifier swap, extra fields, step skip
- [ ] Upload followed to executable, SSRF, or business IDOR
- [ ] Auth chain followed past OTP / slider
- [ ] After a block, location or encoding changed; injection probes matched the stack
- [ ] Confirmed medium on an object was chained up
- [ ] Copied credentials passed the liveness gate
- [ ] Session findings were not written as anonymous unauthorized
- [ ] Empty list / error was not treated as "please log in"
