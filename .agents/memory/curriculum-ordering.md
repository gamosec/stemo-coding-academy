---
name: Curriculum lesson ordering & the three places that must stay in sync
description: How lesson display/unlock order is determined in src/index.tsx, why lesson IDs are immutable, and the three structures to mirror when reordering.
---

Lesson display order AND unlock order follow the **array order** of each
`curriculum.<section>` in `src/index.tsx` (loadLessons walks the array). The
`nextLesson` field is the "Next Lesson" button target only — it does NOT control
display/unlock order. To reorder lessons you must physically move the lesson object
within the array; editing `nextLesson` alone is not enough.

**Lesson IDs are immutable.** D1 `student_progress` is keyed by lesson ID
(`completed_lessons` / `-challenge` IDs). Never rename an ID to reorder — move the block
and keep the ID.

**Three structures must stay consistent when you reorder or add lessons:**
1. `curriculum.<section>` (server source of truth) — array order + `nextLesson` chain.
2. `CHALLENGE_LESSON_META` — lookup map used to restore saved challenge files; mirror the
   `nextLesson` chain and add an entry per new lesson.
3. Teacher-dashboard `CURRICULUM` list (separate `<script>`) — used for lesson assignment;
   mirror order/grouping and add entries, or teachers can't assign the lesson.

**Why:** these three lists are independent; a finale or new section that looks right in
the student view can still be missing/mis-ordered in the teacher assignment UI or break
the post-challenge "next" button.

**How to apply:** after reordering, confirm the array order, the `nextLesson` chain, and
both the META map and teacher `CURRICULUM` all agree, then `npm run build`.
