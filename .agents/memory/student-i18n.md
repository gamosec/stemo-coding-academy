---
name: Student academy Arabic i18n
description: How en/ar translation works in the student academy client code
---
- Static UI: I18N dict + data-i18n attrs, applied by applyLanguage (also sets dir=rtl for ar).
- Palette: PALETTE_AR keyed by English text; original stored in data-en attr for reversible switching.
- Blockly: BLOCK_AR + wrapper in initBlockly monkey-patches each block's init (guarded by def.__i18n) to translate labels/dropdowns when currentLang==='ar'; language switch reloads workspace XML.
- Dynamic content: AR_L/AR_CH/AR_BADGES dicts + helpers trL/trTask/trDiff/trBadge/trChTitle/trChDesc/trObj — every render site (including project-restore and assigned-lesson banner paths) must use these, not raw English fields.
**Why:** review found English leaked via secondary render paths (file restore, badges empty state, mission counter, assigned lesson banner).
**How to apply:** any new student-facing string or render site must go through I18N or a tr* helper; verify by grepping for raw .title/.description/.label writes.
