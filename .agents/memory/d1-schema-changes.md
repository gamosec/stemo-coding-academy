---
name: D1 schema changes
description: Rules for avoiding request amplification and unsafe Cloudflare D1 schema rollout.
---

Do not run table creation, column alteration, data backfills, or index creation in
global request middleware.

**Why:** request-time schema setup multiplied ordinary page and API traffic into
several D1 operations per request. It also hid whether production had received the
intended schema.

**How to apply:** inspect the live D1 schema read-only before removing legacy
runtime setup. For new schema work, use a one-time migration tested against both
fresh and legacy database shapes, and verify it before deploying dependent code.