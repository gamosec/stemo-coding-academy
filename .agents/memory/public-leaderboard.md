---
name: Public leaderboard privacy
description: Privacy boundary for ranking data shown on the unauthenticated landing page
---
The public landing-page leaderboard must show only approved students and only a limited display name (first name plus last initial), XP, and level. Do not expose usernames, class names, school names, or full names through the public endpoint.

**Why:** the leaderboard is intentionally public for social proof, but student identity and school affiliation should remain protected.

**How to apply:** keep the public ranking endpoint separate from the authenticated full leaderboard APIs, and preserve the limited response shape when adding public landing-page features.