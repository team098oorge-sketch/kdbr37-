# Source and Secret Leak Handling

Use with `SKILL.md` §3 R5. Red team: mine the clue to the end. Blue team: treat it as an incident, not a low-severity info-leak ticket.

How to detect and dump exposed VCS / backups: [insecure-source-code-management](../insecure-source-code-management/SKILL.md). This file is what to do after the leak is in hand.

## Common shapes

- `/.git`, `.svn`, backup tarballs, source packs, wrong object-storage ACL
- Public or semi-public org repos, employee personal repos, Gists, mirrors
- `.env`, sample configs, sourcemaps, CI artifacts, container image layers
- Secrets in docs, tickets, screenshots, demo videos
- "Already deleted" but still in git history or a fork

## Pipeline

```
Snapshot preservation
  → full acquire (current tree + history + dangling objects)
  → secret scan (verified first)
  → reconstruct structure (routes, config, env, CI, deps)
  → clues onto the map (intranet URLs, hidden APIs, old vulns, account model)
  → in-scope minimal read-only verification
  → impact and blast radius
  → report / incident escalate
  → owner decides rotation and invalidation
```

Red default: preserve and report; do not rotate production secrets on your own.
Blue default: treat as already compromised; push the owner to rotate.

## What must be mined

1. Secrets and identity: cloud keys, repo tokens, CI secrets, DB passwords, private keys, webhooks, third-party APIs
2. History: deleted commits, renamed files, forks from before a force-push
3. Attack surface: internal URLs, admin, debug routes, unpublished APIs
4. Engineering: CI workflows, self-hosted runners, dependency sources, package names
5. People and org: mail, employee repos, test accounts

## Verification discipline

- Fake-vs-real on production, plus one read-only call that returns identity or an object list
- One failed verification does not become a destructive retry
- Full secrets do not go in report body, ticket plaintext, or chat
- Third-party secrets out of scope: record and tell the authorizing party

## Common failures

- Only report "`.git` is reachable"
- Only look at HEAD, not history
- File every scanner-hit fake secret as Critical
- Use a leaked secret to delete, create, or encrypt as "proof"
- Let the customer "delete it from git" count as the fix
- Paste a full AWS key into a PDF
