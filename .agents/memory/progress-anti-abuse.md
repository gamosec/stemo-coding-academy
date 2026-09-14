---
name: Server-authoritative progress saving
description: How POST /api/progress protects XP, lessons, streak, and badges from forged/abusive client requests
---

The progress-save route trusts NOTHING from the client except which lesson IDs it claims; everything else is recomputed server-side.

**Rules enforced:**
- XP/level: fully recomputed from the de-duplicated set of whitelisted completed lesson IDs (re-running a lesson adds nothing; client XP ignored).
- Completed lessons: merge-only (never shrink); NEW IDs must be unlocked — predecessor in the ordered main path complete, creative (art) lessons always unlocked, teacher-assigned lessons (assigned_lessons × class_students) unlocked, `-challenge` IDs require the base lesson in the set (base sorted before challenge so same-save pairs work). Max 3 new per save; only 1 if the last save was < 20s ago (cooldown vs scripted rapid-fire).
- Streak: derived purely from stored `updated_at` UTC date — same day keeps, yesterday +1, gap resets to 1, first save = 1. Client value ignored.
- Badges: recomputed server-side from xp/level/lesson-count/streak (mirrors client isBadgeEarned incl. challenge IDs counting toward "lessons" type); stored badges kept; client claims ignored.
- Save response returns authoritative xp/level/streak/earned_badges; client saveProgress syncs stemo state + localStorage from it and refreshes UI on any change.

**Why:** students could previously forge requests to inflate XP, jump streaks, or claim badges.

**Accepted limit:** a determined attacker scripting sequential in-order requests (with the cooldown) can still progress without executing lessons — full prevention would need server-verified completion events. Deemed out of threat model for a kids' academy.

**How to apply:** any new lesson section or badge type must be reflected in the unlock logic and isBadgeEarnedServer, or legit completions/badges get silently stripped.

Teacher/admin resets and student saves must compare the revision loaded by the
client with the current durable revision and update it using compare-and-swap.
Never clear a shared "reset acknowledged" marker when one tab reloads.

**Why:** a student can have multiple academy tabs open, and a save started before
a reset must not be able to restore removed completions after the reset wins.

**How to apply:** every progress GET returns the current revision, every student
save sends it, and both saves and resets only update the row when that revision
still matches. A stale save receives and applies the current server state.

Cross-device hydration must also be server-authoritative and revision-aware.
Authenticated academy HTML, progress responses, and authenticated leaderboard
responses must not be cached; an older or revisionless refresh must never replace
a newer hydrated snapshot.

**Why:** browser-local XP can briefly render correctly and then be overwritten by
an older zero response, creating disagreement between the header and leaderboard.

**How to apply:** hydrate authenticated pages from D1, include the durable progress
revision in every authenticated progress view, and apply only the newest revision.
