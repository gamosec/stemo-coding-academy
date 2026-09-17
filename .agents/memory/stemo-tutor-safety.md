---
name: STEMO tutor safety boundary
description: Durable authority and safety rules for AI-generated student coaching.
---

STEMO must use deterministic program and trail analysis as the source of truth. The language model may phrase coaching, but it must never determine or announce XP, lesson completion, challenge success, rewards, or access.

**Why:** Student session context is client-reported, prompt instructions can be bypassed, and general content-safety classifiers do not understand application-specific progress authority.

**How to apply:** Keep history and session context inside an explicitly untrusted data envelope, discard client completion flags, serialize replies, moderate generated text fail-closed, and separately reject progress/reward authority claims before showing AI text to a child.