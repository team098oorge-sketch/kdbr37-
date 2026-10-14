---
name: api-recon-and-docs
description: >-
  API reconnaissance and documentation review playbook. Use when discovering endpoints, schemas, versions, OpenAPI specs, hidden docs, and surface area for API testing.
---

# SKILL: API Recon and Docs

## 1. RECON CHECKLIST

```bash
curl https://target/app.js | grep -oE '(/api|/rest|/graphql)[^"'\'' ]+' | sort -u
```

### Common paths

```text
/swagger.json
/openapi.json
/api-docs
/docs
/.well-known/
/graphql
/api/v1/
/api/v2/
/api/mobile/v1/
```
