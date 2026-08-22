---
name: Curriculum capability validation
description: Safety and coverage rules for the curriculum build gate.
---

Curriculum validation must statically trace every taught control from its Blockly definition and student palette entry through its `parseBlocks` branch and a matching command execution handler. It must never execute or dynamically evaluate source code while reading curriculum data.

**Why:** A visible block can be silently ignored when its parser or execution path changes. Evaluating extracted source during a build can also turn curriculum edits into a CI secret-exposure path.

**How to apply:** When adding or renaming a taught control, update the capability contract and keep negative fixtures for missing definition, palette, parser, and handler coverage. Use data-only parsing for all source-derived validation inputs.