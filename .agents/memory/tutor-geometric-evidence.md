---
name: Tutor geometric evidence
description: Invariants for preserving complex drawing structure in STEMO tutor requests.
---

The browser and server must use the same bounded trail-history limit when preparing deterministic drawing evidence.

**Why:** Large nested-loop drawings can exceed a smaller client cap. Truncating the beginning removes repeated returns to the shared center, so a valid mandala is reduced to a generic collection of line sections while simple shapes still appear correct.

**How to apply:** When changing drawing limits or adding complex-pattern recognition, verify a representative drawing near the cap through the complete browser-to-server path, not only by unit-testing the recognizer with a full synthetic trail array.