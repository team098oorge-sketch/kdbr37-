---
name: api-sec
description: >-
  Entry P1 category router for API security. Use when choosing between API
  recon, authorization, token abuse, and hidden-parameter workflows before any
  deeper API topic skill.
---

# API Security Router

This is the routing entry point for API security testing.

## Skill Map

- [API Recon and Docs](../api-recon-and-docs/SKILL.md)
- [API Authorization and BOLA](../api-authorization-and-bola/SKILL.md)
- [API Auth and JWT Abuse](../api-auth-and-jwt-abuse/SKILL.md)
- [GraphQL and Hidden Parameters](../graphql-and-hidden-parameters/SKILL.md)

## Quick Triage

| Observation | Route |
|---|---|
| Swagger or OpenAPI is present | api-recon-and-docs |
| IDs appear in URL, JSON, headers, or GraphQL args | api-authorization-and-bola |
| JWT token visible in traffic | api-auth-and-jwt-abuse |
| `/graphql` or batched JSON arrays are present | graphql-and-hidden-parameters |

## Related Categories

- [auth-sec](../auth-sec/SKILL.md)
- [business-logic-vuln](../business-logic-vuln/SKILL.md)
- [recon-for-sec](../recon-for-sec/SKILL.md)
