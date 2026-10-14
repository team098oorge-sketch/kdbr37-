# Blue-Team Execution

Use with `SKILL.md` role routing. Goal: shorten real-attacker dwell time, not zero the queue.

## Triage loop

```
Ingest alert / hunt clue
  → enrich (asset, account, intel, history, process/network context)
  → prioritize (business impact, not the product’s severity string)
  → single event or chain
  → expand same user / host / IP / token inside the time window
  → conclude: TP / benign TP / FP / insufficient evidence (escalate)
  → reversible containment (if needed)
  → eradicate and recover
  → detection and logging improvements
  → retro
```

## Minimum enrichment before a human stares at a raw alert

- Asset owner, business importance, production or not
- Account type (human / service / shared / abandoned)
- Same-entity similar events in ~24h
- Intel hit or not (and intel quality)
- Process tree, parent, network destination, login source
- Overlap with a change/release window

## Investigation expansion

- Same identity on IdP, mail, VPN, cloud console, code platform
- Same host: process, file, registry/config, network
- Same egress IP / API token / session
- 30–90 minute core window; lengthen if the dwell hypothesis requires it
- Adjacent systems with no logs: record as a coverage gap; do not pretend they are invisible

## How to label conclusions

| Label | Meaning | Action |
|---|---|---|
| True positive TP | Malicious or clear policy violation, evidenced | Contain + eradicate + improve detection |
| Benign true positive | Rule fired correctly on admin script / release | Add suppression or shrink scope; do not kill the rule in anger |
| False positive FP | Rule semantics are wrong | Fix the rule, record the FP profile |
| Insufficient evidence | Cannot confirm or deny yet | Escalate or keep collecting; write which logs are missing |
| Duplicate | Already handled in another case | Merge; not a new win |

## Containment

Priority from reversible to irreversible:

1. Isolate a NIC / revoke one session / disable one key
2. Block one hash / one egress / one rule
3. Disable one account
4. Segment a network, bulk block
5. Rebuild, mass password reset, image wipe

Step 4 and above require: approver, blast radius, forensic snapshot, rollback path.

Clearing logs, formatting, or overwriting key files is not containment. It is destroying evidence.

Preserve first:

- Volatile evidence (memory, sessions, login state)
- Host and identity timeline
- Original alerts and queries
- Malware object hashes and chain of custody

## Detection-engineering lifecycle

```
Threat hypothesis → ATT&CK map → confirm telemetry exists
  → write the rule (strict first) → known-good / known-bad tests
  → retro 7–30 days for FP → owner and retirement condition
  → production → measure → tune / merge / retire
```

Rules are code: in Git, reviewed, rollbackable.

Quality gate (fail → do not ship):

- Maps to a concrete ATT&CK technique
- At least one expected TP fixture
- FP profile exists
- Log-source health dependency
- Has an owner

## Hunting

One hunt needs:

- Hypothesis (if X exists, we should see Y)
- Data source and time window
- Query
- How hits split
- Covered / not covered, whether or not a human was hit

## Incident response (document-driven)

1. Prepare (contacts, privileges, evidence location)
2. Identify (what it is, who it affects)
3. Contain (reversible first)
4. Eradicate
5. Recover
6. Lessons (detection gap, process gap, owner, how to verify)

Every step gets a timeline with timezones.

## Metrics

- FP rate and rules analysts ignore
- Priority ATT&CK coverage (tested detections / priority techniques)
- Data-source coverage
- MTTD / MTTR against attacker tempo
- Whether containment was reversible and whether it destroyed evidence
- Retro action-item close rate

## Purple-team loop

- Red-team results must be rewritten as detection gaps
- Blue hunt hypotheses must be rewritten as rules or log requirements
- Controlled exercises prove the rule actually fires
