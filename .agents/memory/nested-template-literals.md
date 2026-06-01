---
name: Nested template literals in src/index.tsx
description: All pages are server-rendered HTML template strings in TypeScript. Client-side JS embedded in those strings must use escaped backticks.
---

# Nested Template Literals in src/index.tsx

All HTML pages are returned as TypeScript template literals (backtick strings). Any client-side JavaScript inside those pages that itself uses template literals must escape its backticks as `\`` — otherwise TypeScript/esbuild sees unmatched backtick pairs and throws `Expected ";" but found "class"` (or similar parse errors).

**Why:** The entire HTML page is one big TS template literal. An unescaped `` ` `` inside it terminates the outer string and starts a new one, breaking the TypeScript AST.

**How to apply:** Whenever writing or editing client-side JS inside an HTML page handler in `src/index.tsx`, replace all `` ` `` with `` \` `` and all `${` with `\${`. This includes nested template literals (map callbacks returning HTML rows, innerHTML assignments, etc.).
