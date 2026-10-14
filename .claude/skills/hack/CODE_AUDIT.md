# Code Audit

Use with `SKILL.md` §3 R6. The core is taint paths and missing controls, not a report of dangerous function names.

## Phases

0. **Map**: language, framework, build, module boundaries, real entry points, where authn/authz actually land.
1. **Mental model**: trust boundaries, data-to-storage paths, permission checkpoints, developer security assumptions.
2. **Historical variants**: read fix commits of similar CVEs, extract the pattern, search the repo.
3. **Sink reverse**: list dangerous operations, walk parameters upward, mark filters, evaluate bypass.
4. **Framework specialty**: audit framework features this repo actually uses (mass assignment, expressions, annotation authz, ORM dynamic concat, template engines).
5. **Deep**: unlocked read-check-write, payment and state machines, hardcoded keys, dependency defects, reverted security fixes.
6. **Verify**: every finding must answer: is input controllable, can the filter be bypassed, preconditions, impact, can it be proven non-destructively.

## Dual track plus missing controls

### A. Sink → Source

1. List sinks by class
2. See whether parameters are concatenated, deserialized, or built into command/path/URL/template
3. Walk callers upward until an entry or an uncontrollable constant
4. On a sanitizer: prove it works for *this* payload class, or keep walking
5. No controllable source → drop the item

### B. Source → Sink

1. Take user-controllable fields from the entry
2. Follow assignment, wrapping, serialization, cross-service calls
3. See which sink it lands in

### C. Missing controls

- Horizontal/vertical IDOR
- Unauthenticated admin / debug / internal endpoints exposed
- Batch endpoints that validate only the first ID
- Hidden in the UI, unchecked on the server
- Workflow state client-controlled

Build an object × action matrix (read, change, delete, approve, export). For each cell, does the server enforce "current subject + object ownership"?

## Sink index

| Class | Look for |
|---|---|
| Command exec | User-controllable args, whether a shell is involved |
| SQL / query concat | Real parameterization; ORM dynamic concat, sort field, table name |
| Deserialization | Type allow-list, source, filter bypass |
| File I/O | Root constraint, symlinks, archive paths |
| SSRF | Protocol, redirects, intranet, cloud metadata |
| Template render | User content entering the engine |
| Path / expression injection | SpEL, OGNL, EL, JSTL |
| Authz decision points | Which role/tenant a negative condition missed |
| Crypto and keys | Key source, hardcoded, home-rolled crypto |

## When a sanitizer counts

- It sits on every Source→Sink path; no bypass
- Semantics match this bug class (HTML escape does not save SQL)
- Not undone by double-decode, split-and-rejoin, or encoding tricks
- Failure is deny, not "best-effort clean and continue"

## Anti-hallucination

Every file path, symbol, and line number in the report must have been read.

Forbidden:

- Inventing a "theoretically reachable" call chain
- Treating a dangerous function in a dependency as called by the product
- Filing test code, dead code, or intranet-only CLI as externally hittable
- Critical RCE with no reproduction path

## Deliverable

Each code finding at minimum:

- Source location
- Sink location
- Propagation summary (file / function / key variables)
- Sanitizer present or not, and why it fails
- How an external request hits this path
- Impact
- Fix
