---
name: GitHub–Cloudflare synchronization
description: Defines the release source of truth and verification needed after direct Cloudflare deployments.
---

GitHub `main` is the release source of truth. A release is complete only when the
local branch matches GitHub and the active Cloudflare Pages deployment names that
same GitHub source commit.

**Why:** direct Wrangler deployments updated production without updating GitHub,
leaving older repository code able to overwrite production on the next automatic
build. In this environment, connected GitHub OAuth may work through the API while
the existing HTTPS git credential remains invalid.

**How to apply:** prefer pushing verified commits to GitHub and let the configured
Cloudflare integration deploy them. If an emergency direct deployment is used,
sync GitHub before finishing and verify the newest active Pages deployment source.