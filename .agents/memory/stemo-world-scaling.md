---
name: STEMO world scaling
description: Safe rules for resizing the simulator without breaking coordinates or layered views
---
Keep the STEMO simulation in its established logical coordinate system. Resize and fit it through a display-only transform with matching inverse pointer mapping, rather than changing movement, challenge, or saved-position coordinates.

**Why:** changing logical dimensions would ripple through lessons and challenges. Independent sizing also caused the 2D canvas, 3D view, and mission overlay to drift out of alignment at responsive breakpoints.

**How to apply:** use one square stage as the sizing authority for every world layer, synchronize WebGL sizing when that stage changes, and reject pointer clicks that land in display-only fit margins.