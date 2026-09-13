import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'
import { promisify } from 'node:util'
import { createServer } from 'vite'

const execFileAsync = promisify(execFile)
const projectRoot = process.cwd()
const wranglerPath = resolve(projectRoot, 'node_modules/wrangler/bin/wrangler.js')
const d1StateDirectory = await mkdtemp(resolve(tmpdir(), 'stemo-progress-reset-d1-'))

function sqlLiteral(value) {
  if (value === null) return 'NULL'
  if (typeof value === 'number') return String(value)
  return `'${String(value).replaceAll("'", "''")}'`
}

function bindSql(sql, values) {
  let valueIndex = 0
  const statement = sql.replace(/\?/g, () => {
    assert.ok(valueIndex < values.length, 'compare-and-swap SQL has an unexpected placeholder')
    return sqlLiteral(values[valueIndex++])
  })
  assert.equal(valueIndex, values.length, 'compare-and-swap SQL did not bind every value')
  return statement
}

async function executeD1(statement) {
  const { stdout } = await execFileAsync(process.execPath, [
    wranglerPath,
    'd1',
    'execute',
    'DB',
    '--local',
    '--persist-to',
    d1StateDirectory,
    '--command',
    statement,
    '--json',
  ], {
    cwd: projectRoot,
    maxBuffer: 1024 * 1024,
  })

  const results = JSON.parse(stdout)
  assert.ok(Array.isArray(results), 'Wrangler D1 command must return a result array')
  for (const result of results) {
    assert.equal(result.success, true, `Local D1 statement failed: ${JSON.stringify(result)}`)
  }
  return results
}

async function runCasRace(compareAndSwapSql, updates) {
  const seed = {
    studentId: 101,
    xp: 450,
    level: 1,
    completedLessons: JSON.stringify(['lesson-1', 'lesson-2', 'lesson-4', 'lesson-4-challenge']),
    earnedBadges: JSON.stringify(['first-steps', 'fast-starter']),
    streak: 6,
    revision: 'seed-revision',
  }
  const statements = [
    'DELETE FROM student_progress',
    `INSERT INTO student_progress (
      student_id, xp, level, completed_lessons, earned_badges, streak, updated_at
    ) VALUES (
      ${seed.studentId}, ${seed.xp}, ${seed.level}, ${sqlLiteral(seed.completedLessons)},
      ${sqlLiteral(seed.earnedBadges)}, ${seed.streak}, ${sqlLiteral(seed.revision)}
    )`,
  ]

  for (const update of updates) {
    statements.push(bindSql(compareAndSwapSql, [
      update.xp,
      update.level,
      JSON.stringify(update.completedLessons),
      JSON.stringify(update.earnedBadges),
      update.streak,
      update.nextRevision,
      seed.studentId,
      update.expectedRevision,
    ]))
    statements.push('SELECT changes() AS changes')
  }
  statements.push(`
    SELECT xp, level, completed_lessons, earned_badges, streak, updated_at
    FROM student_progress
    WHERE student_id = ${seed.studentId}
  `)

  const results = await executeD1(`${statements.join(';\n')};`)
  const changes = results
    .filter((result) => result.results?.[0] && Object.hasOwn(result.results[0], 'changes'))
    .map((result) => result.results[0].changes)
  const finalRow = results.at(-1).results[0]
  return { changes, finalRow }
}

const tests = []
function test(name, body) {
  tests.push({ name, body })
}

let vite

test('local D1 rejects a stale save after a reset wins the compare-and-swap race', async () => {
  const { progressCompareAndSwapSql } = await vite.ssrLoadModule('/src/index.tsx')
  assert.equal(typeof progressCompareAndSwapSql, 'string')

  const { changes, finalRow } = await runCasRace(progressCompareAndSwapSql, [
    {
      xp: 0,
      level: 1,
      completedLessons: [],
      earnedBadges: [],
      streak: 0,
      expectedRevision: 'seed-revision',
      nextRevision: 'reset-revision',
    },
    {
      xp: 999999,
      level: 999,
      completedLessons: ['lesson-1', 'lesson-2', 'lesson-4', 'lesson-4-challenge'],
      earnedBadges: ['forged'],
      streak: 999,
      expectedRevision: 'seed-revision',
      nextRevision: 'stale-save-revision',
    },
  ])

  assert.deepEqual(changes, [1, 0])
  assert.deepEqual(finalRow, {
    xp: 0,
    level: 1,
    completed_lessons: '[]',
    earned_badges: '[]',
    streak: 0,
    updated_at: 'reset-revision',
  })
})

test('local D1 lets a reset retry after a save wins the first compare-and-swap race', async () => {
  const { progressCompareAndSwapSql } = await vite.ssrLoadModule('/src/index.tsx')

  const { changes, finalRow } = await runCasRace(progressCompareAndSwapSql, [
    {
      xp: 500,
      level: 2,
      completedLessons: ['lesson-1', 'lesson-2', 'lesson-4', 'lesson-4-challenge', 'lesson-5'],
      earnedBadges: ['first-steps', 'fast-starter'],
      streak: 6,
      expectedRevision: 'seed-revision',
      nextRevision: 'save-revision',
    },
    {
      xp: 0,
      level: 1,
      completedLessons: [],
      earnedBadges: [],
      streak: 0,
      expectedRevision: 'seed-revision',
      nextRevision: 'stale-reset-revision',
    },
    {
      xp: 0,
      level: 1,
      completedLessons: [],
      earnedBadges: [],
      streak: 0,
      expectedRevision: 'save-revision',
      nextRevision: 'retry-reset-revision',
    },
  ])

  assert.deepEqual(changes, [1, 0, 1])
  assert.deepEqual(finalRow, {
    xp: 0,
    level: 1,
    completed_lessons: '[]',
    earned_badges: '[]',
    streak: 0,
    updated_at: 'retry-reset-revision',
  })
})

try {
  await executeD1(`
    CREATE TABLE student_progress (
      student_id INTEGER PRIMARY KEY,
      xp INTEGER NOT NULL DEFAULT 0,
      level INTEGER NOT NULL DEFAULT 1,
      completed_lessons TEXT NOT NULL DEFAULT '[]',
      earned_badges TEXT NOT NULL DEFAULT '[]',
      streak INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `)
  vite = await createServer({ appType: 'custom', server: { middlewareMode: true } })
  for (const { name, body } of tests) {
    await body()
    console.log(`✓ ${name}`)
  }
  console.log(`Local D1 progress reset checks passed (${tests.length} tests).`)
} finally {
  await vite?.close()
  await rm(d1StateDirectory, { recursive: true, force: true })
}