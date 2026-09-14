import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

const source = await readFile(new URL('../src/index.tsx', import.meta.url), 'utf8')

const loadBadgesMatch = source.match(
  /function loadBadges\(\) \{([\s\S]*?)\n        \}\n\n        function renderProfileBadges/,
)
assert.ok(loadBadgesMatch, 'loadBadges function must remain discoverable')
assert.doesNotMatch(
  loadBadgesMatch[1],
  /saveProgress\s*\(/,
  'rendering badges must never save or rewrite student progress',
)

assert.match(
  source,
  /media-src 'self' data: https:\/\/static\.blockly\.com;/,
  'CSP must permit Blockly audio media',
)
assert.match(
  source,
  /connect-src 'self' https:\/\/static\.blockly\.com;/,
  'CSP must permit Blockly audio requests',
)

console.log('Client progress invariants passed: badge loading is read-only and Blockly audio is allowed.')