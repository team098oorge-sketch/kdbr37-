# Evidence and Report Standard

Shared by red and blue. Read this before writing a conclusion.

## Minimum evidence block

Any "confirmed" vulnerability, intrusion, or risk must be reproducible by someone who was not in the room.

```
Title
Location (URL / host / repo path / rule name / event ID)
Time (with timezone)
Preconditions
Step-by-step repro or step-by-step query
Observed result (redacted response, command output, or raw event)
Impact (what control was obtained / what harm was done)
Non-destructive proof (what was done, what was not)
Residual risk
Fix or detection recommendation
Evidence attachment names
```

Missing repro or query → "hypothesis" or "insufficient evidence" only.

## Severity (impact first)

- Critical: production high privilege or bulk sensitive data already held or immediately reachable
- High: auth bypass, object-level IDOR to core data, live cloud key, stable path to a host
- Medium: extra conditions needed but the path is real
- Low: isolated config issue
- Info: a clue that helps later testing; not harm by itself

## Two write-to-disk gates

### Session-attribution gate

- Session present → IDOR or auth issue: "used the current session to reach someone else’s object"
- Still works with credentials stripped → then write unauthenticated
- Tested with a session, then stripped the cookie in the report to label anonymous = forbidden

### Secret liveness gate

1. Fake rejected, real accepted by production
2. One non-impacting read-only call returns identity or an object list

Fail the gate → clue only.

## Do not file as results

A half-chain; weak password that never issued a session; connection string with host and no creds; secret that failed the liveness gate; self-only CSRF; missing security headers; expired cert with no exploit path.

## Finding template

```md
## [ID] Title (impact in one sentence)

- Severity: critical / high / medium / low / info
- Status: confirmed / hypothesis / insufficient evidence
- Asset:
- Found at (timezone):
- Did the break carry a session: yes / no

### Problem
(Three to six sentences. What the attacker can do now, whom it harms.)

### Location
- URL / host / resource ID:
- Code: `path:line` symbol

### Preconditions
- Account required:
- Role:

### Repro or query
1.
2.
3.

### Observation
(redacted response, command output, or raw event)

### Impact
- Control proven:
- Data or systems involved:

### Remediation
1. Immediate:
2. Root:
3. How to verify the fix:
```

## Detection-rule template

```md
## Rule name

- Status: draft / test / prod / retired
- Owner:
- ATT&CK: Txxxx
- Severity: by business impact

### Hypothesis
If the attacker does ________, we should see ________ in ________.

### Data source
- Product and index:
- Key fields:

### Logic
(Pseudocode or Sigma-style.)

### Known TP fixture
- How to fire:

### FP profile
- Expected benign fires:
- Suppression:

### Retirement
- When to merge, shrink, or take offline:
```
