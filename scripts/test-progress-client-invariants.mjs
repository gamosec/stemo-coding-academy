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

const loadLeaderboardMatch = source.match(
  /async function loadLeaderboard\(\) \{([\s\S]*?)\n        function setPlacementMode/,
)
assert.ok(loadLeaderboardMatch, 'loadLeaderboard function must remain discoverable')
assert.doesNotMatch(
  loadLeaderboardMatch[1],
  /applyAuthoritativeProgress\s*\(/,
  'leaderboard reporting data must never overwrite authoritative student progress',
)

assert.match(
  source,
  /if \(initialProgress && initialProgress\.xp !== undefined\) \{\s*applyAuthoritativeProgress\(initialProgress\);\s*\} else \{\s*[\s\S]*?loadProgressFromDB\(userData\.id\);/,
  'a hydrated page must not race its D1 snapshot with a second automatic progress GET',
)
assert.match(
  source,
  /\}\s*loadLessons\(\);\s*loadBadges\(\);\s*loadProfile\(\);\s*\} else \{/,
  'authenticated student startup must load lessons independently of progress refresh',
)
assert.match(
  source,
  /Failed to load curriculum:[\s\S]*?Unable to load the curriculum/,
  'curriculum failures must render a visible retry state',
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

assert.doesNotMatch(
  source,
  /Auto-migrate|CREATE TABLE IF NOT EXISTS lesson_videos/,
  'normal page requests must not run lesson-content schema migrations',
)

console.log('Client progress invariants passed: page loads are read-only and Blockly audio is allowed.')