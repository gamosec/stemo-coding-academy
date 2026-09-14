---
name: Student startup hydration
description: Keeps authenticated academy data surfaces independent and prevents silent empty states.
---

Authenticated startup must initialize progress, curriculum, badges, and profile as
independent responsibilities.

**Why:** curriculum loading was coupled to a redundant progress refresh. Removing
that refresh left the Curriculum Path completely empty for authenticated students.
Also, authoritative state may already equal local storage while the DOM still has
zero placeholders, so rendering cannot be conditional on state values changing.

**How to apply:** invoke each required loader explicitly after authentication.
Every loader must validate response status and shape and render a visible retry
state rather than silently leaving an empty container. After accepting an
authoritative progress snapshot, always render every progress summary surface
from the same in-memory state.