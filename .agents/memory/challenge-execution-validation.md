---
name: Challenge execution validation
description: Rules for keeping challenge-world execution checks aligned with lesson objectives.
---

Representative challenge programs should run through a deterministic headless state model and assert every objective declared by each challenge world. The model should track transient progress (such as reaching a target before returning home), not only final robot state.

**Why:** Static curriculum checks cannot catch runtime capability regressions, and some objectives are intentionally completed at an intermediate point in a program.

**How to apply:** Keep one fixture per challenge world, discover objective IDs from the source without evaluating it, and run the execution check as part of the curriculum validation/build gate.