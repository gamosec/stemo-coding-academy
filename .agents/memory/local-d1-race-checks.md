---
name: Local D1 race checks
description: Reliable way to exercise Cloudflare D1 compare-and-swap SQL when the local Worker runner cannot start.
---

Use Wrangler's `d1 execute --local` mode with a newly created temporary persistence directory for local D1 race verification. Do not rely on a direct Miniflare instance or the Pages runner in this environment.

**Why:** the local Worker runtime can hang before it becomes ready here, while Wrangler's local D1 command successfully runs the same D1 SQL engine without a remote preview or Cloudflare account access.

**How to apply:** test each ordered race using the production compare-and-swap statement, query `changes()` immediately after each update, and remove the temporary state directory in a `finally` block.