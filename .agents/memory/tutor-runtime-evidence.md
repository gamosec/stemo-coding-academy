---
name: Tutor runtime evidence
description: Authority and lifecycle rules for STEMO feedback about world actions and accomplishments.
---

Tutor facts about collection, spraying, extinguishing, condition outcomes, avoidance, and target reach must come from run-scoped execution events and be frozen when the run ends.

**Why:** Final board state can erase real accomplishments: dropping a collected object resets its picked-up flag, moving away hides an earlier target reach, and refilling water hides prior consumption. Recomputing later can also attribute board edits to an old run. The user confirmed this event-based accounting works correctly in Magnet Magic Challenge Mode with three collected objects and none remaining.

**How to apply:** Increment evidence in every manual and automated execution path, share counters through nested commands, and freeze a sanitized snapshot before feedback. “Remaining metal” means never collected in that run, so a collected-then-dropped object is not counted again. Never use tutor evidence to award XP or declare challenge completion.

Metal sensing conditions and magnet pickup must use the same strict range.

**Why:** A sensor that reports nearby metal outside the magnet’s actual reach would make `If Metal Nearby → Magnet ON` appear broken to children.

**How to apply:** Keep both checks aligned so metal one coding step away is detected and collected immediately, while metal outside pickup range takes the else branch.