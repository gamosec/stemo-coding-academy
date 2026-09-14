import assert from 'node:assert/strict'
import { createServer } from 'vite'

const JWT_SECRET = 'progress-reset-test-secret'

function clone(value) {
  return value ? JSON.parse(JSON.stringify(value)) : value
}

function normalizedSql(sql) {
  return sql.replace(/\s+/g, ' ').trim().toLowerCase()
}

class ProgressTestDatabase {
  constructor({ progress = {}, memberships = {} } = {}) {
    this.users = new Map([
      ['1', { id: 1, role: 'admin' }],
      ['201', { id: 201, role: 'teacher' }],
      ['202', { id: 202, role: 'teacher' }],
      ['101', { id: 101, role: 'student' }],
      ['102', { id: 102, role: 'student' }],
    ])
    this.progress = new Map(
      Object.entries(progress).map(([studentId, row]) => [String(studentId), clone(row)]),
    )
    this.memberships = new Map(Object.entries(memberships))
    this.deferFirstProgressUpdate = false
    this.delayedUpdateStarted = null
    this.resolveDelayedUpdateStarted = null
    this.delayedUpdateReleased = null
    this.resolveDelayedUpdate = null
  }

  deferNextProgressUpdate() {
    this.deferFirstProgressUpdate = true
    this.delayedUpdateStarted = new Promise((resolve) => {
      this.resolveDelayedUpdateStarted = resolve
    })
    this.delayedUpdateReleased = new Promise((resolve) => {
      this.resolveDelayedUpdate = resolve
    })
  }

  async waitForDeferredProgressUpdate() {
    await this.delayedUpdateStarted
  }

  releaseDeferredProgressUpdate() {
    this.resolveDelayedUpdate()
  }

  progressFor(studentId) {
    return clone(this.progress.get(String(studentId)))
  }

  prepare(sql) {
    const database = this
    const query = normalizedSql(sql)
    let parameters = []

    return {
      bind(...values) {
        parameters = values
        return this
      },
      async first() {
        if (query.includes("from users where id = ? and role = 'student'")) {
          const user = database.users.get(String(parameters[0]))
          return user?.role === 'student' ? clone(user) : null
        }
        if (query.includes('from class_students cs join classes cl')) {
          const [studentId, teacherId] = parameters.map(String)
          return database.memberships.get(studentId) === teacherId
            ? { student_id: Number(studentId) }
            : null
        }
        if (query.includes('from student_progress where student_id = ?')) {
          return database.progressFor(parameters[0]) || null
        }
        throw new Error(`Unhandled D1 first query: ${query}`)
      },
      async all() {
        if (query.includes('from assigned_lessons al join class_students cs')) {
          return { results: [] }
        }
        throw new Error(`Unhandled D1 all query: ${query}`)
      },
      async run() {
        if (query.startsWith('update student_progress set xp=?')) {
          if (database.deferFirstProgressUpdate) {
            database.deferFirstProgressUpdate = false
            database.resolveDelayedUpdateStarted()
            await database.delayedUpdateReleased
          }

          const [xp, level, completedLessons, earnedBadges, streak, revision, studentId, expectedRevision] = parameters
          const current = database.progress.get(String(studentId))
          if (!current || String(current.updated_at) !== String(expectedRevision)) {
            return { meta: { changes: 0 } }
          }

          database.progress.set(String(studentId), {
            ...current,
            xp,
            level,
            completed_lessons: completedLessons,
            earned_badges: earnedBadges,
            streak,
            updated_at: revision,
          })
          return { meta: { changes: 1 } }
        }

        if (query.startsWith('insert or ignore into student_progress')) {
          const [studentId, xp, level, completedLessons, earnedBadges, streak, revision] = parameters
          if (database.progress.has(String(studentId))) return { meta: { changes: 0 } }
          database.progress.set(String(studentId), {
            student_id: Number(studentId),
            xp,
            level,
            completed_lessons: completedLessons,
            earned_badges: earnedBadges,
            streak,
            updated_at: revision,
          })
          return { meta: { changes: 1 } }
        }

        throw new Error(`Unhandled D1 run query: ${query}`)
      },
    }
  }
}

function seededProgress(completedLessons = ['lesson-1', 'lesson-2', 'lesson-4', 'lesson-4-challenge']) {
  return {
    student_id: 101,
    xp: 450,
    level: 1,
    completed_lessons: JSON.stringify(completedLessons),
    earned_badges: JSON.stringify(['first-steps', 'fast-starter']),
    streak: 6,
    updated_at: '2026-01-01T00:00:00.000Z|seed-revision',
  }
}

function fixture(overrides = {}) {
  return new ProgressTestDatabase({
    progress: {
      101: seededProgress(),
      102: {
        ...seededProgress(['lesson-1', 'lesson-2']),
        student_id: 102,
        updated_at: '2026-01-01T00:00:00.000Z|second-student-seed',
      },
    },
    memberships: { 101: '201', 102: '202' },
    ...overrides,
  })
}

async function tokenFor({ id, role }) {
  const encode = (value) => Buffer.from(value).toString('base64url')
  const header = encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payload = encode(JSON.stringify({
    id,
    username: `${role}-${id}`,
    role,
    full_name: `${role} test user`,
    exp: Date.now() + 60_000,
  }))
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(JWT_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`${header}.${payload}`),
  )
  return `${header}.${payload}.${Buffer.from(signature).toString('base64url')}`
}

function request(app, db, path, { actor, method = 'POST', body } = {}) {
  const headers = { cookie: `stemo_token=${actor}` }
  if (body !== undefined) headers['content-type'] = 'application/json'
  return app.request(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  }, { DB: db, JWT_SECRET, AI: {} })
}

async function json(response) {
  return response.json()
}

const tests = []
function test(name, body) {
  tests.push({ name, body })
}

let app

test('teacher can reset one lesson and its challenge without touching other work', async () => {
  const db = fixture()
  const teacher = await tokenFor({ id: 201, role: 'teacher' })

  const response = await request(app, db, '/api/teacher/students/101/reset-progress', {
    actor: teacher,
    body: { lesson_id: 'lesson-4-challenge' },
  })
  const result = await json(response)

  assert.equal(response.status, 200)
  assert.equal(result.success, true)
  assert.equal(result.lesson_id, 'lesson-4')
  assert.deepEqual(result.completed_lessons, ['lesson-1', 'lesson-2'])
  assert.equal(result.xp, 150)
  assert.equal(result.streak, 6)
  assert.notEqual(result.progress_revision, '2026-01-01T00:00:00.000Z|seed-revision')
})

test('teacher cannot reset a student outside their class', async () => {
  const db = fixture()
  const teacher = await tokenFor({ id: 201, role: 'teacher' })

  const response = await request(app, db, '/api/teacher/students/102/reset-progress', {
    actor: teacher,
    body: { lesson_id: 'all' },
  })
  const result = await json(response)

  assert.equal(response.status, 403)
  assert.equal(result.error, 'Student not in your class')
  assert.deepEqual(JSON.parse(db.progressFor(102).completed_lessons), ['lesson-1', 'lesson-2'])
})

test('admin can reset all progress for any student', async () => {
  const db = fixture()
  const admin = await tokenFor({ id: 1, role: 'admin' })

  const response = await request(app, db, '/api/teacher/students/102/reset-progress', {
    actor: admin,
    body: { lesson_id: 'all' },
  })
  const result = await json(response)

  assert.equal(response.status, 200)
  assert.equal(result.success, true)
  assert.equal(result.lesson_id, 'all')
  assert.equal(result.xp, 0)
  assert.equal(result.level, 1)
  assert.equal(result.streak, 0)
  assert.deepEqual(result.completed_lessons, [])
  assert.deepEqual(result.earned_badges, [])
})

test('an overlapping stale save returns 409 with the reset state', async () => {
  const db = fixture()
  const student = await tokenFor({ id: 101, role: 'student' })
  const teacher = await tokenFor({ id: 201, role: 'teacher' })
  const staleRevision = db.progressFor(101).updated_at
  db.deferNextProgressUpdate()

  const savePromise = request(app, db, '/api/progress', {
    actor: student,
    body: {
      progress_revision: staleRevision,
      completed_lessons: ['lesson-1', 'lesson-2', 'lesson-4', 'lesson-4-challenge'],
      xp: 999999,
      level: 999,
      streak: 999,
      earned_badges: ['forged'],
    },
  })
  await db.waitForDeferredProgressUpdate()

  const resetResponse = await request(app, db, '/api/teacher/students/101/reset-progress', {
    actor: teacher,
    body: { lesson_id: 'all' },
  })
  const reset = await json(resetResponse)
  db.releaseDeferredProgressUpdate()

  const saveResponse = await savePromise
  const save = await json(saveResponse)
  assert.equal(resetResponse.status, 200)
  assert.equal(saveResponse.status, 409)
  assert.equal(save.error, 'stale_progress')
  assert.deepEqual(save.completed_lessons, [])
  assert.equal(save.xp, 0)
  assert.equal(save.progress_revision, reset.progress_revision)
})

test('a reloaded tab gets the new revision while another open tab is rejected as stale', async () => {
  const db = fixture()
  const student = await tokenFor({ id: 101, role: 'student' })
  const teacher = await tokenFor({ id: 201, role: 'teacher' })

  const firstTab = await json(await request(app, db, '/api/progress/101', {
    actor: student,
    method: 'GET',
  }))
  const staleTab = await json(await request(app, db, '/api/progress/101', {
    actor: student,
    method: 'GET',
  }))
  assert.equal(firstTab.progress_revision, staleTab.progress_revision)

  const resetResponse = await request(app, db, '/api/teacher/students/101/reset-progress', {
    actor: teacher,
    body: { lesson_id: 'all' },
  })
  assert.equal(resetResponse.status, 200)

  const reloadedTab = await json(await request(app, db, '/api/progress/101', {
    actor: student,
    method: 'GET',
  }))
  const staleSaveResponse = await request(app, db, '/api/progress', {
    actor: student,
    body: {
      progress_revision: staleTab.progress_revision,
      completed_lessons: staleTab.completed_lessons,
    },
  })
  const staleSave = await json(staleSaveResponse)

  assert.notEqual(reloadedTab.progress_revision, staleTab.progress_revision)
  assert.deepEqual(reloadedTab.completed_lessons, [])
  assert.equal(staleSaveResponse.status, 409)
  assert.equal(staleSave.error, 'stale_progress')
  assert.deepEqual(staleSave.completed_lessons, reloadedTab.completed_lessons)
  assert.equal(staleSave.progress_revision, reloadedTab.progress_revision)
})

test('a first challenge completion is atomic and a replay cannot add XP', async () => {
  const recentRevision = `${new Date().toISOString()}|recent-seed`
  const db = fixture({
    progress: {
      101: {
        ...seededProgress(['lesson-1', 'lesson-2', 'lesson-3']),
        xp: 250,
        updated_at: recentRevision,
      },
    },
  })
  const student = await tokenFor({ id: 101, role: 'student' })
  const completed = ['lesson-1', 'lesson-2', 'lesson-3', 'lesson-4', 'lesson-4-challenge']

  const firstResponse = await request(app, db, '/api/progress', {
    actor: student,
    body: {
      progress_revision: recentRevision,
      completed_lessons: completed,
      xp: 999999,
    },
  })
  const first = await json(firstResponse)

  assert.equal(firstResponse.status, 200)
  assert.deepEqual(first.completed_lessons, completed)
  assert.equal(first.xp, 550)

  const replayResponse = await request(app, db, '/api/progress', {
    actor: student,
    body: {
      progress_revision: first.progress_revision,
      completed_lessons: completed,
      xp: 999999,
    },
  })
  const replay = await json(replayResponse)

  assert.equal(replayResponse.status, 200)
  assert.deepEqual(replay.completed_lessons, completed)
  assert.equal(replay.xp, 550)
})

const vite = await createServer({ appType: 'custom', server: { middlewareMode: true } })
try {
  ({ default: app } = await vite.ssrLoadModule('/src/index.tsx'))
  for (const { name, body } of tests) {
    await body()
    console.log(`✓ ${name}`)
  }
  console.log(`Progress reset API regression checks passed (${tests.length} tests).`)
} finally {
  await vite.close()
}