---
name: Curriculum sections must stay in sync with server-side progress validation
description: Adding a new curriculum section requires updating the allLessons whitelist in the progress-save routes, or completions get silently stripped.
---

When a new curriculum section is added to the `curriculum` object in `src/index.tsx`
(e.g. `creative`), the client can complete those lessons and `/api/lesson/:id` can
serve them, but progress will be SILENTLY LOST on save unless the new section is also
spread into the `allLessons` whitelist used by the server-side sanitization routes
(`POST /api/progress` and `POST /api/admin/sanitize-progress/:studentId`).

**Why:** Those routes filter `completed_lessons` against valid lesson IDs and recompute
XP/level. Any lesson ID not in `allLessons` is dropped, so XP/level/completions for the
new section vanish after refresh or device change — even though the in-session UI looked
correct.

**How to apply:** Every `curriculum.<section>` must appear in BOTH the lesson-lookup
spread AND every `allLessons` array in the progress-validation routes. Grep for
`as any[]` / `allLessons` after adding a section and confirm the new section is included.
