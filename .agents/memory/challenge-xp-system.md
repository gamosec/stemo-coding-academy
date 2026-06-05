---
name: Challenge XP system & the two server-side whitelists
description: How free-build vs challenge XP works in src/index.tsx, and the TWO separate server whitelists a challenge-capable lesson must appear in.
---

Free build awards a lesson's base XP as soon as the robot moves/draws. Challenge mode
awards a 2× bonus tracked as a separate completion ID `lesson-X-challenge` pushed into
`completed_lessons`. A lesson is challenge-capable if it has an entry in the client
`LESSON_CHALLENGES` object (setup + objectives) and is listed in `MISSION_LESSON_IDS`.

**The trap — there are TWO independent server-side whitelists, not one:**
1. `allLessons` (spread of every `curriculum.<section>`) — validates plain lesson IDs in
   the progress-save / sanitize routes. Miss it → the whole lesson completion is stripped.
2. The server `curriculum.challenges` array — an explicit `{ id:'lesson-X-challenge',
   xpReward:N }` table. This is what authorizes the 2× bonus IDs. **A `-challenge` ID not
   present here is silently dropped on save, so the bonus XP vanishes after refresh** even
   though the in-session UI showed it awarded.

**Why:** progress-save recomputes XP from `completed_lessons` filtered against these
whitelists. The two lists are maintained separately and it is easy to add challenge
definitions on the client while forgetting the server `challenges` entry (this exact bug
left lessons 15–19 without persisted bonus XP until their entries were added).

**How to apply:** When you make ANY lesson challenge-capable (numbered or creative/art),
add its `lesson-X-challenge` entry to the server `challenges` array AND ensure its section
is in `allLessons`. The set of `LESSON_CHALLENGES` keys should be a 1:1 match with the
`-challenge` IDs in the server `challenges` array — diff them after editing.
