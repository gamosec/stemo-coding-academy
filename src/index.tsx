import { Hono } from 'hono'
import { cors } from 'hono/cors'

type Bindings = {
    AI: any
    DB: D1Database
}

type Variables = {
    user: {
        id: number
        username: string
        role: string
        full_name: string
        exp: number
    }
}

// ============================================
// AUTH HELPERS (Web Crypto - Cloudflare compatible)
// ============================================
async function hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder()
    const data = encoder.encode(password)
    const hash = await crypto.subtle.digest('SHA-256', data)
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('')
}

function b64url(str: string): string {
    return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

async function createToken(payload: any): Promise<string> {
    const header = b64url(btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })))
    const body = b64url(btoa(unescape(encodeURIComponent(JSON.stringify({ ...payload, exp: Date.now() + 86400000 * 7 })))))
    const encoder = new TextEncoder()
    const key = await crypto.subtle.importKey('raw', encoder.encode('stemo-secret-key-2024'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(`${header}.${body}`))
    const sigB64 = b64url(btoa(String.fromCharCode(...new Uint8Array(sig))))
    return `${header}.${body}.${sigB64}`
}

function b64urlDecode(str: string): string {
    str = str.replace(/-/g, '+').replace(/_/g, '/')
    while (str.length % 4) str += '='
    return decodeURIComponent(escape(atob(str)))
}

async function verifyToken(token: string): Promise<any> {
    try {
        const parts = token.split('.')
        if (parts.length !== 3) return null
        const payload = JSON.parse(b64urlDecode(parts[1]))
        if (payload.exp < Date.now()) return null
        return payload
    } catch { return null }
}

function getCookieToken(cookie: string): string | undefined {
    const part = cookie.split(';').find((p: string) => p.trim().startsWith('stemo_token='))
    return part ? part.trim().slice('stemo_token='.length) : undefined
}

async function authMiddleware(c: any, next: any) {
    const cookie = c.req.header('cookie') || ''
    const token = getCookieToken(cookie)
    if (!token) return c.json({ error: 'Unauthorized' }, 401)
    const payload = await verifyToken(token)
    if (!payload) return c.json({ error: 'Invalid token' }, 401)
    c.set('user', payload)
    await next()
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Global error handler — always return JSON so we can see the real error
app.onError((err, c) => {
    return c.json({ error: err.message, stack: err.stack?.slice(0, 500) }, 500)
})


// Enable CORS
app.use('/api/*', cors())

// ============================================
// AUTH ROUTES
// ============================================

// Login
app.post('/api/auth/login', async (c) => {
    try {
        const { username, password } = await c.req.json()
        if (!username || !password) return c.json({ error: 'Username and password required' }, 400)
        const hash = await hashPassword(password)
        const user = await c.env.DB.prepare('SELECT id, username, role, full_name, status FROM users WHERE username = ? AND password_hash = ?').bind(username, hash).first()
        if (!user) return c.json({ error: 'Invalid username or password' }, 401)
        if (user.status === 'pending') return c.json({ error: 'Your account is pending approval. Please wait for an admin or teacher to approve your registration.', pending: true }, 403)
        if (user.status === 'rejected') return c.json({ error: 'Your registration was not approved. Please contact your teacher.', rejected: true }, 403)
        const token = await createToken({ id: user.id, username: user.username, role: user.role, full_name: user.full_name })
        const res = c.json({ success: true, user: { id: user.id, username: user.username, role: user.role, full_name: user.full_name } })
        res.headers.set('Set-Cookie', `stemo_token=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800`)
        return res
    } catch (e) {
        console.error('Login error:', e)
        return c.json({ error: 'Login failed' }, 500)
    }
})

// Student self-registration
app.post('/api/auth/register', async (c) => {
    try {
        const { username, password, full_name, class_id, parent_username } = await c.req.json()
        if (!username || !password || !full_name) return c.json({ error: 'All fields are required' }, 400)
        if (username.length < 3) return c.json({ error: 'Username must be at least 3 characters' }, 400)
        if (password.length < 6) return c.json({ error: 'Password must be at least 6 characters' }, 400)
        const hash = await hashPassword(password)
        try {
            const result = await c.env.DB.prepare(
                "INSERT INTO users (username, password_hash, role, full_name, status) VALUES (?, ?, 'student', ?, 'pending')"
            ).bind(username, hash, full_name).run()
            const newStudentId = result.meta.last_row_id
            await c.env.DB.prepare('INSERT OR IGNORE INTO student_progress (student_id) VALUES (?)').bind(newStudentId).run()
            if (class_id) {
                await c.env.DB.prepare('INSERT OR IGNORE INTO class_students (class_id, student_id) VALUES (?, ?)').bind(class_id, newStudentId).run()
            }
            if (parent_username) {
                const parent = await c.env.DB.prepare("SELECT id FROM users WHERE username = ? AND role = 'parent' AND status = 'approved'").bind(parent_username).first() as any
                if (parent) {
                    await c.env.DB.prepare('INSERT OR IGNORE INTO parent_students (parent_id, student_id) VALUES (?, ?)').bind(parent.id, newStudentId).run()
                }
            }
            return c.json({ success: true, message: 'Registration submitted! Your teacher will approve your account soon.' })
        } catch (e: any) {
            if (e.message?.includes('UNIQUE')) return c.json({ error: 'That username is already taken. Please choose another.' }, 409)
            throw e
        }
    } catch (e: any) {
        if (e.status) throw e
        console.error('Register error:', e)
        return c.json({ error: 'Registration failed. Please try again.' }, 500)
    }
})

// Approve or reject a pending user (admin or teacher)
app.post('/api/admin/users/:id/approve', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin' && me.role !== 'teacher') return c.json({ error: 'Forbidden' }, 403)
    const id = c.req.param('id')
    const { action, class_id } = await c.req.json()
    const status = action === 'approve' ? 'approved' : 'rejected'
    await c.env.DB.prepare('UPDATE users SET status = ? WHERE id = ?').bind(status, id).run()
    if (action === 'approve' && class_id) {
        await c.env.DB.prepare('INSERT OR IGNORE INTO class_students (class_id, student_id) VALUES (?, ?)').bind(class_id, id).run()
    }
    return c.json({ success: true, status })
})

// Get pending users (admin or teacher)
app.get('/api/admin/pending', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin' && me.role !== 'teacher') return c.json({ error: 'Forbidden' }, 403)
    const { results } = await c.env.DB.prepare("SELECT id, username, full_name, role, created_at FROM users WHERE status = 'pending' ORDER BY created_at DESC").all()
    return c.json(results)
})

// Logout
app.post('/api/auth/logout', (c) => {
    const res = c.json({ success: true })
    res.headers.set('Set-Cookie', 'stemo_token=; Path=/; HttpOnly; Max-Age=0')
    return res
})

// Get current user
app.get('/api/auth/me', async (c) => {
    const cookie = c.req.header('cookie') || ''
    const token = getCookieToken(cookie)
    if (!token) return c.json({ user: null })
    const payload = await verifyToken(token)
    if (!payload) return c.json({ user: null })
    return c.json({ user: payload })
})

// ============================================
// USER MANAGEMENT ROUTES (Admin only)
// ============================================

// Get all users
app.get('/api/admin/users', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const { results } = await c.env.DB.prepare('SELECT id, username, role, full_name, created_at FROM users ORDER BY created_at DESC').all()
    return c.json(results)
})

// Create user
app.post('/api/admin/users', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const { username, password, role, full_name } = await c.req.json()
    if (!username || !password || !role || !full_name) return c.json({ error: 'All fields required' }, 400)
    const hash = await hashPassword(password)
    try {
        const result = await c.env.DB.prepare('INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)').bind(username, hash, role, full_name).run()
        const newUser = await c.env.DB.prepare('SELECT id, username, role, full_name FROM users WHERE id = ?').bind(result.meta.last_row_id).first()
        // Init progress for students
        if (role === 'student') {
            await c.env.DB.prepare('INSERT OR IGNORE INTO student_progress (student_id) VALUES (?)').bind(result.meta.last_row_id).run()
        }
        return c.json({ success: true, user: newUser })
    } catch (e: any) {
        if (e.message?.includes('UNIQUE')) return c.json({ error: 'Username already exists' }, 409)
        return c.json({ error: 'Failed to create user' }, 500)
    }
})

// Delete user
app.delete('/api/admin/users/:id', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const id = c.req.param('id')
    await c.env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run()
    return c.json({ success: true })
})

// ============================================
// SCHOOL MANAGEMENT ROUTES (admin only)
// ============================================

async function ensureSchoolsSchema(db: any) {
    try {
        await db.prepare('CREATE TABLE IF NOT EXISTS schools (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT DEFAULT \'\', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)').run()
    } catch (_) {}
    try {
        await db.prepare('ALTER TABLE classes ADD COLUMN school_id INTEGER').run()
    } catch (_) {}
}

app.get('/api/admin/schools', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    try {
        await ensureSchoolsSchema(c.env.DB)
        const { results } = await c.env.DB.prepare('SELECT s.id, s.name, s.description, s.created_at, COUNT(c.id) as class_count FROM schools s LEFT JOIN classes c ON c.school_id = s.id GROUP BY s.id ORDER BY s.name').all()
        return c.json(results)
    } catch (e: any) {
        return c.json({ error: e?.message || 'DB error' }, 500)
    }
})

app.post('/api/admin/schools', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    try {
        await ensureSchoolsSchema(c.env.DB)
        const { name, description } = await c.req.json()
        if (!name?.trim()) return c.json({ error: 'School name required' }, 400)
        const result = await c.env.DB.prepare('INSERT INTO schools (name, description) VALUES (?, ?)').bind(name.trim(), description || '').run()
        return c.json({ success: true, id: result.meta.last_row_id })
    } catch (e: any) {
        return c.json({ error: e?.message || 'DB error' }, 500)
    }
})

app.put('/api/admin/schools/:id', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    try {
        const id = c.req.param('id')
        const { name, description } = await c.req.json()
        if (!name?.trim()) return c.json({ error: 'School name required' }, 400)
        await c.env.DB.prepare('UPDATE schools SET name = ?, description = ? WHERE id = ?').bind(name.trim(), description || '', id).run()
        return c.json({ success: true })
    } catch (e: any) {
        return c.json({ error: e?.message || 'DB error' }, 500)
    }
})

app.delete('/api/admin/schools/:id', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    try {
        const id = c.req.param('id')
        const { results: schoolClasses } = await c.env.DB.prepare('SELECT id FROM classes WHERE school_id = ?').bind(id).all()
        for (const cls of schoolClasses) {
            await c.env.DB.prepare('DELETE FROM class_students WHERE class_id = ?').bind(cls.id).run()
            await c.env.DB.prepare('DELETE FROM assigned_lessons WHERE class_id = ?').bind(cls.id).run()
            await c.env.DB.prepare('DELETE FROM classes WHERE id = ?').bind(cls.id).run()
        }
        await c.env.DB.prepare('DELETE FROM schools WHERE id = ?').bind(id).run()
        return c.json({ success: true })
    } catch (e: any) {
        return c.json({ error: e?.message || 'DB error' }, 500)
    }
})

// ============================================
// CLASS MANAGEMENT ROUTES
// ============================================

// Get classes (teacher sees own, admin sees all)
app.get('/api/classes', authMiddleware, async (c) => {
    const me = c.get('user')
    let rows
    if (me.role === 'admin') {
        const { results } = await c.env.DB.prepare('SELECT c.*, u.full_name as teacher_name FROM classes c LEFT JOIN users u ON c.teacher_id = u.id ORDER BY c.created_at DESC').all()
        rows = results
    } else if (me.role === 'teacher') {
        const { results } = await c.env.DB.prepare('SELECT c.*, u.full_name as teacher_name FROM classes c LEFT JOIN users u ON c.teacher_id = u.id WHERE c.teacher_id = ? ORDER BY c.created_at DESC').bind(me.id).all()
        rows = results
    } else {
        return c.json({ error: 'Forbidden' }, 403)
    }
    return c.json(rows)
})

// Create class
app.post('/api/classes', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin' && me.role !== 'teacher') return c.json({ error: 'Forbidden' }, 403)
    const body = await c.req.json()
    const { name, description, teacher_id, school_id } = body
    const finalTeacherId = me.role === 'teacher' ? me.id : (teacher_id || null)
    const result = await c.env.DB.prepare('INSERT INTO classes (name, description, teacher_id, school_id) VALUES (?, ?, ?, ?)').bind(name, description || '', finalTeacherId, school_id || null).run()
    return c.json({ success: true, id: result.meta.last_row_id })
})

// Edit class
app.put('/api/admin/classes/:id', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const id = c.req.param('id')
    const { name, description, teacher_id } = await c.req.json()
    if (!name?.trim()) return c.json({ error: 'Class name required' }, 400)
    await c.env.DB.prepare('UPDATE classes SET name = ?, description = ?, teacher_id = ? WHERE id = ?').bind(name.trim(), description || '', teacher_id || null, id).run()
    return c.json({ success: true })
})

// Delete class
app.delete('/api/admin/classes/:id', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const id = c.req.param('id')
    await c.env.DB.prepare('DELETE FROM class_students WHERE class_id = ?').bind(id).run()
    await c.env.DB.prepare('DELETE FROM assigned_lessons WHERE class_id = ?').bind(id).run()
    await c.env.DB.prepare('DELETE FROM classes WHERE id = ?').bind(id).run()
    return c.json({ success: true })
})

// Get students in a class
app.get('/api/classes/:id/students', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin' && me.role !== 'teacher') return c.json({ error: 'Forbidden' }, 403)
    const classId = c.req.param('id')
    const { results } = await c.env.DB.prepare(`
        SELECT u.id, u.username, u.full_name, sp.xp, sp.level, sp.completed_lessons, sp.streak
        FROM class_students cs JOIN users u ON cs.student_id = u.id
        LEFT JOIN student_progress sp ON sp.student_id = u.id
        WHERE cs.class_id = ?
    `).bind(classId).all()
    return c.json(results)
})

// Add student to class
app.post('/api/classes/:id/students', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin' && me.role !== 'teacher') return c.json({ error: 'Forbidden' }, 403)
    const classId = c.req.param('id')
    const { student_id } = await c.req.json()
    await c.env.DB.prepare('INSERT OR IGNORE INTO class_students (class_id, student_id) VALUES (?, ?)').bind(classId, student_id).run()
    return c.json({ success: true })
})

// Remove student from class
app.delete('/api/classes/:id/students/:studentId', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin' && me.role !== 'teacher') return c.json({ error: 'Forbidden' }, 403)
    const classId = c.req.param('id')
    const studentId = c.req.param('studentId')
    await c.env.DB.prepare('DELETE FROM class_students WHERE class_id = ? AND student_id = ?').bind(classId, studentId).run()
    return c.json({ success: true })
})

// Get approved students not enrolled in ANY of this teacher's classes
app.get('/api/students/unenrolled', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin' && me.role !== 'teacher') return c.json({ error: 'Forbidden' }, 403)
    let query: string
    let args: any[]
    if (me.role === 'teacher') {
        query = `SELECT id, full_name, username FROM users
            WHERE role = 'student' AND status = 'approved'
            AND id NOT IN (
                SELECT cs.student_id FROM class_students cs
                JOIN classes c ON cs.class_id = c.id
                WHERE c.teacher_id = ?
            ) ORDER BY full_name`
        args = [me.id]
    } else {
        query = `SELECT id, full_name, username FROM users
            WHERE role = 'student' AND status = 'approved'
            AND id NOT IN (SELECT DISTINCT student_id FROM class_students)
            ORDER BY full_name`
        args = []
    }
    const stmt = c.env.DB.prepare(query)
    const { results } = await (args.length ? stmt.bind(...args) : stmt).all()
    return c.json(results)
})

// Get approved students NOT yet in a specific class
app.get('/api/classes/:id/available-students', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin' && me.role !== 'teacher') return c.json({ error: 'Forbidden' }, 403)
    const classId = c.req.param('id')
    const { results } = await c.env.DB.prepare(`
        SELECT id, full_name, username FROM users
        WHERE role = 'student' AND status = 'approved'
        AND id NOT IN (SELECT student_id FROM class_students WHERE class_id = ?)
        ORDER BY full_name
    `).bind(classId).all()
    return c.json(results)
})

// Get teachers list (admin only)
app.get('/api/teachers', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const { results } = await c.env.DB.prepare("SELECT id, full_name, username FROM users WHERE role = 'teacher' AND status = 'approved' ORDER BY full_name").all()
    return c.json(results)
})

// Assign a lesson to a class
app.post('/api/classes/:id/assign-lesson', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'teacher' && me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const classId = c.req.param('id')
    if (me.role === 'teacher') {
        const cls = await c.env.DB.prepare('SELECT id FROM classes WHERE id = ? AND teacher_id = ?').bind(classId, me.id).first()
        if (!cls) return c.json({ error: 'Not your class' }, 403)
    }
    const { lesson_id } = await c.req.json()
    await c.env.DB.prepare('DELETE FROM assigned_lessons WHERE class_id = ?').bind(classId).run()
    if (lesson_id) {
        await c.env.DB.prepare('INSERT INTO assigned_lessons (class_id, lesson_id, assigned_by) VALUES (?, ?, ?)').bind(classId, lesson_id, me.id).run()
    }
    return c.json({ success: true })
})

// Get assigned lesson for a class
app.get('/api/classes/:id/assigned-lesson', authMiddleware, async (c) => {
    const classId = c.req.param('id')
    const lesson = await c.env.DB.prepare('SELECT * FROM assigned_lessons WHERE class_id = ? LIMIT 1').bind(classId).first()
    return c.json(lesson || null)
})

// Teacher resets a student password (student must be in teacher's class)
app.post('/api/teacher/students/:id/reset-password', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'teacher' && me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const studentId = c.req.param('id')
    const { password } = await c.req.json()
    if (!password || password.length < 6) return c.json({ error: 'Password must be at least 6 characters' }, 400)
    if (me.role === 'teacher') {
        const inClass = await c.env.DB.prepare(`
            SELECT cs.student_id FROM class_students cs
            JOIN classes cl ON cs.class_id = cl.id
            WHERE cs.student_id = ? AND cl.teacher_id = ?
        `).bind(studentId, me.id).first()
        if (!inClass) return c.json({ error: 'Student not in your class' }, 403)
    }
    const hash = await hashPassword(password)
    await c.env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(hash, studentId).run()
    return c.json({ success: true })
})

// Public classes list (no auth — for registration page)
app.get('/api/public/classes', async (c) => {
    const { results } = await c.env.DB.prepare('SELECT id, name, description FROM classes ORDER BY name').all()
    return c.json(results)
})

// ============================================
// PROGRESS ROUTES
// ============================================

// Get student progress
app.get('/api/progress/:studentId', authMiddleware, async (c) => {
    const me = c.get('user')
    const studentId = c.req.param('studentId')
    // Students can only view their own
    if (me.role === 'student' && String(me.id) !== studentId) return c.json({ error: 'Forbidden' }, 403)
    const progress = await c.env.DB.prepare('SELECT * FROM student_progress WHERE student_id = ?').bind(studentId).first()
    return c.json(progress || { student_id: studentId, xp: 0, level: 1, completed_lessons: '[]', earned_badges: '[]', streak: 0 })
})

// Save student progress
app.post('/api/progress', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'student') return c.json({ error: 'Only students can save progress' }, 403)
    const { xp, level, completed_lessons, earned_badges, streak } = await c.req.json()
    await c.env.DB.prepare(`
        INSERT INTO student_progress (student_id, xp, level, completed_lessons, earned_badges, streak, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(student_id) DO UPDATE SET xp=excluded.xp, level=excluded.level,
        completed_lessons=excluded.completed_lessons, earned_badges=excluded.earned_badges,
        streak=excluded.streak, updated_at=CURRENT_TIMESTAMP
    `).bind(me.id, xp, level, JSON.stringify(completed_lessons), JSON.stringify(earned_badges), streak).run()
    return c.json({ success: true })
})

// ============================================
// CHAT HISTORY
// ============================================
app.get('/api/chat/history/:studentId', authMiddleware, async (c) => {
    const me = c.get('user')
    const studentId = c.req.param('studentId')
    if (me.role === 'student' && String(me.id) !== studentId) return c.json({ error: 'Forbidden' }, 403)
    const { results } = await c.env.DB.prepare('SELECT * FROM chat_history WHERE student_id = ? ORDER BY created_at DESC LIMIT 50').bind(studentId).all()
    return c.json(results)
})

// ============================================
// PARENT ROUTES
// ============================================
app.get('/api/parent/children', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'parent') return c.json({ error: 'Forbidden' }, 403)
    const { results } = await c.env.DB.prepare(`
        SELECT u.id, u.username, u.full_name, sp.xp, sp.level, sp.completed_lessons, sp.earned_badges, sp.streak, sp.last_active
        FROM parent_students ps JOIN users u ON ps.student_id = u.id
        LEFT JOIN student_progress sp ON sp.student_id = u.id
        WHERE ps.parent_id = ?
    `).bind(me.id).all()
    return c.json(results)
})

// Link parent to student (admin only)
app.post('/api/parent/link', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const { parent_id, student_id } = await c.req.json()
    await c.env.DB.prepare('INSERT OR IGNORE INTO parent_students (parent_id, student_id) VALUES (?, ?)').bind(parent_id, student_id).run()
    return c.json({ success: true })
})

// Get all students (for admin/teacher dropdowns)
app.get('/api/admin/students', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin' && me.role !== 'teacher') return c.json({ error: 'Forbidden' }, 403)
    const { results } = await c.env.DB.prepare("SELECT id, username, full_name FROM users WHERE role = 'student' ORDER BY full_name").all()
    return c.json(results)
})

// Leaderboard — top students ranked by XP (accessible to students and teachers)
app.get('/api/leaderboard', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'student' && me.role !== 'teacher' && me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const { results } = await c.env.DB.prepare(`
        SELECT u.id, u.full_name, u.username, u.created_at,
               COALESCE(sp.xp, 0) as xp,
               COALESCE(sp.level, 1) as level,
               COALESCE(sp.completed_lessons, '[]') as completed_lessons,
               COALESCE(sp.earned_badges, '[]') as earned_badges,
               COALESCE(sp.streak, 0) as streak,
               c.name as class_name,
               s.name as school_name
        FROM users u
        LEFT JOIN student_progress sp ON sp.student_id = u.id
        LEFT JOIN class_students cs ON cs.student_id = u.id
        LEFT JOIN classes c ON cs.class_id = c.id
        LEFT JOIN schools s ON c.school_id = s.id
        WHERE u.role = 'student' AND u.status = 'approved'
        ORDER BY COALESCE(sp.xp, 0) DESC
        LIMIT 50
    `).all()
    return c.json(results)
})

// Current student's profile — their class and assigned lesson
app.get('/api/student/profile', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'student') return c.json({ error: 'Forbidden' }, 403)
    try {
        const user = await c.env.DB.prepare('SELECT id, full_name, username, created_at FROM users WHERE id = ?').bind(me.id).first()
        const cls = await c.env.DB.prepare(`
            SELECT c.id, c.name, u.full_name as teacher_name,
                   (SELECT lesson_id FROM assigned_lessons WHERE class_id = c.id LIMIT 1) as assigned_lesson_id,
                   s.name as school_name
            FROM class_students cs
            JOIN classes c ON cs.class_id = c.id
            LEFT JOIN users u ON c.teacher_id = u.id
            LEFT JOIN schools s ON c.school_id = s.id
            WHERE cs.student_id = ?
            LIMIT 1
        `).bind(me.id).first()
        return c.json({ user, class: cls || null })
    } catch (e: any) {
        return c.json({ error: 'Profile load failed: ' + e.message }, 500)
    }
})

// ============================================
// CURRICULUM DATA - Lessons & Challenges
// ============================================
const curriculum = {
    basic: [
        {
            id: 'lesson-1',
            title: 'Meet STEMO!',
            description: 'Discover what coding is and give your first command',
            difficulty: 'easy',
            xpReward: 50,
            icon: '👋',
            introduction: "Hello! I am STEMO — your robot coding buddy! 🤖 A computer program is simply a list of instructions that tells a robot (or computer) exactly what to do, step by step. Think of it like a recipe: if the recipe says 'add 2 eggs', the chef does exactly that — no more, no less! On the LEFT side you will see colourful BLOCKS — each block is one instruction. On the RIGHT is my world where I move around. The blocks go into the PROGRAM AREA in the middle. When you press the green RUN button, I read your blocks from top to bottom and follow every instruction. Let's write your very first program!",
            tasks: [
                { id: 't1', text: 'Look at the left panel — find the blue "Forward" block. Click it once to add it to your program!', completed: false },
                { id: 't2', text: 'See the number inside the Forward block? Click it and change it to 3 steps', completed: false },
                { id: 't3', text: 'Click the big green ▶ Run button and watch me move!', completed: false },
                { id: 't4', text: 'Now add a second "Forward" block — I should move even further this time', completed: false },
                { id: 't5', text: 'Click the 🗑️ Clear button to erase all blocks and start fresh', completed: false },
                { id: 't6', text: 'Build your own program with exactly 4 Forward blocks. How far do I go? 🎉', completed: false }
            ],
            hint: 'Blocks are added by clicking them on the left panel. The number inside a block is how many steps I take. More blocks = more steps!',
            homework: 'Try to make me move exactly 10 steps total! You can use 1 block set to 10, or 2 blocks set to 5 each — both work! Which do you prefer?',
            nextLesson: 'lesson-2'
        },
        {
            id: 'lesson-2',
            title: 'Movement Master',
            description: 'Learn all 4 directions and navigate like a pro',
            difficulty: 'easy',
            xpReward: 100,
            icon: '🚶',
            introduction: "Great job on your first program! 🎉 Now let's explore ALL the ways I can move. I can go Forward ⬆️, Backward ⬇️, turn Left ⬅️, and turn Right ➡️. Turning is measured in DEGREES — think of a clock face: 90° is a quarter turn (like turning a corner), 180° is a half turn (facing the opposite direction), and 360° is a full spin! Real robots like vacuum cleaners use these exact same turns to clean your whole house without missing a spot. I can also jump back Home 🏠 instantly. Let's master all the moves!",
            tasks: [
                { id: 't1', text: 'Add "Forward 4" — I move up 4 steps', completed: false },
                { id: 't2', text: 'Add "Right 90" — I turn to face right (a quarter turn)', completed: false },
                { id: 't3', text: 'Add "Forward 3" — I move right 3 steps. Run it! I walk an L-shape! ↱', completed: false },
                { id: 't4', text: 'Clear and try: Forward 3 → Left 90 → Forward 3 → Left 90 → Forward 3. What shape do I make?', completed: false },
                { id: 't5', text: 'Add "Back 2" to the end — watch me reverse!', completed: false },
                { id: 't6', text: 'Add "Home" as the very last block — I teleport back to the start! 🏠', completed: false }
            ],
            hint: 'Think of a compass: Forward = North, Right = East, Back = South, Left = West. A 90° turn is always a perfect corner — just like the corners of a square room!',
            homework: 'Can you make me walk in a "Z" shape? You need: Forward → diagonal move (Right turn, Forward, Left turn) → Forward. Try it!',
            nextLesson: 'lesson-3'
        },
        {
            id: 'lesson-3',
            title: 'Start Drawing!',
            description: 'Lift and lower the pen to draw lines and patterns',
            difficulty: 'easy',
            xpReward: 100,
            icon: '🖌️',
            introduction: "Now for the really fun part — drawing! 🖍️ Imagine I am holding a marker on the floor. When the pen is UP (🖊️ raised), I move without leaving a mark — like lifting your pencil off the page. When the pen is DOWN (✏️ touching), every step I take leaves a trail! This is exactly how a plotter robot works — the machines that draw huge banners and maps! The key rule: always add 'Pen Down' BEFORE moving, or there will be nothing to see. Let's draw!",
            tasks: [
                { id: 't1', text: 'Add a "Pen Down ✏️" block — my pen is now touching the floor', completed: false },
                { id: 't2', text: 'Add "Forward 5" and click Run — you drew a line! 📏', completed: false },
                { id: 't3', text: 'Now add "Pen Up 🖊️" → "Forward 3" → "Pen Down ✏️" → "Forward 3". Run it — see the gap in the line? That\'s a dashed line!', completed: false },
                { id: 't4', text: 'Clear and draw an L-shape: Pen Down → Forward 5 → Right 90 → Forward 5', completed: false },
                { id: 't5', text: 'Challenge: draw a staircase! (Hint: repeat Pen Down → Forward 2 → Right 90 → Forward 2 → Left 90)', completed: false }
            ],
            hint: 'Remember the order: Pen Down FIRST, then move. Pen Up = no trail. Pen Down = trail. Think of it like pressing a stamp on paper!',
            homework: 'Draw your initials! Think about which lines need Pen Down and which gaps need Pen Up. For example, the letter "L" = Forward 4, Right 90, Forward 2.',
            nextLesson: 'lesson-4'
        },
        {
            id: 'lesson-4',
            title: 'Color Artist',
            description: 'Paint with colours and control line thickness',
            difficulty: 'easy',
            xpReward: 100,
            icon: '🎨',
            introduction: "Let's make our drawings beautiful and colourful! 🎨 My pen can draw in ANY colour you choose. You can also control how THICK or thin the line is using the Size block. A Size of 1 is a hairline; Size 20 is a thick marker! Real graphic design software (like the logos on your favourite games) uses exactly these same ideas — colour + size + position. Here's a pro tip: always set your colour and size BEFORE putting the pen down, so the very first stroke is already perfect!",
            tasks: [
                { id: 't1', text: 'Add a "Color" block and pick red — then Pen Down → Forward 5 → Run. Red line! 🔴', completed: false },
                { id: 't2', text: 'Add a "Size 10" block before Pen Down — Run again. The line is now thick!', completed: false },
                { id: 't3', text: 'Change the Color block to blue and Size to 3. Run — thin blue line! 🔵', completed: false },
                { id: 't4', text: 'Now build this: Color red → Pen Down → Forward 3 → Color blue → Forward 3 → Color green → Forward 3. Three-colour line! 🎨', completed: false },
                { id: 't5', text: 'Try drawing a thick red square: Color red → Size 8 → Pen Down → Forward 4 → Right 90 (×4)', completed: false }
            ],
            hint: 'Place Color and Size blocks BEFORE Pen Down for the cleanest result. You can also change colour mid-drawing — add a new Color block between Forward blocks!',
            homework: 'Create a "Colour Road"! Draw 6 lines in a row, each a different colour (red, orange, yellow, green, blue, purple). Use Pen Up between lines to leave small gaps!',
            nextLesson: 'lesson-5'
        }
    ],
    intermediate: [
        {
            id: 'lesson-5',
            title: 'Loop Power!',
            description: 'Use Repeat to replace boring repeated blocks',
            difficulty: 'medium',
            xpReward: 150,
            icon: '🔁',
            introduction: "What if you need to move Forward 100 times? You could add 100 Forward blocks... but that would take forever! 😅 Programmers HATE repeating themselves — so they invented the LOOP. A loop says 'do this group of instructions N times'. In real life, a washing machine loop runs: Fill water → Spin → Drain — and repeats that cycle until the clothes are clean! The REPEAT block in coding does the same thing. Fun fact: without loops, the games on your phone would need millions of lines of code. With loops, the same effect takes just a few! Let's see the magic:",
            tasks: [
                { id: 't1', text: 'First, WITHOUT a loop: add Forward 4 four separate times + four Right 90 blocks (8 blocks total). Run — you drew a square! 🟦', completed: false },
                { id: 't2', text: 'Now Clear and use a loop: Add "Repeat 4" → inside it add "Forward 4" and "Right 90". Run — same square with only 3 blocks! ✨', completed: false },
                { id: 't3', text: 'Change the Repeat number to 8 and the Right to 45°. Run — I draw a regular octagon! ⬡', completed: false },
                { id: 't4', text: 'Add Pen Down before the Repeat so you can see the shape drawn', completed: false },
                { id: 't5', text: 'Challenge: make a tall rectangle — Repeat 2 times: Forward 6, Right 90, Forward 3, Right 90', completed: false }
            ],
            hint: 'The rule for a square: Repeat 4 → Forward N → Right 90. The number in Forward decides the size. Bigger Forward = bigger square!',
            homework: 'Can you draw a staircase using a loop? Try: Repeat 5 times → Forward 2 → Right 90 → Forward 2 → Left 90. What does it look like?',
            nextLesson: 'lesson-6'
        },
        {
            id: 'lesson-6',
            title: 'Shape Artist',
            description: 'Use maths to draw any polygon you can imagine',
            difficulty: 'medium',
            xpReward: 200,
            icon: '📐',
            introduction: "Here is a magical maths formula used by architects, game designers, and engineers: Turn Angle = 360 ÷ Number of Sides. A triangle has 3 sides → 360÷3 = 120°. A square has 4 sides → 360÷4 = 90°. A hexagon has 6 sides → 360÷6 = 60°. A circle has infinitely many tiny sides! This formula works for ANY shape. The honeycomb in a beehive is made of perfect hexagons — bees use this shape because it wastes zero space and uses the least wax. Let's use the same maths bees use:",
            tasks: [
                { id: 't1', text: 'Triangle (3 sides): Pen Down → Repeat 3 → Forward 5, Right 120°. Run! 🔺', completed: false },
                { id: 't2', text: 'Pentagon (5 sides): 360÷5 = 72°. Repeat 5 → Forward 5, Right 72°. Run! ⬠', completed: false },
                { id: 't3', text: 'Hexagon (6 sides): 360÷6 = 60°. Repeat 6 → Forward 4, Right 60°. Run! ⬡ (like a honeycomb!)', completed: false },
                { id: 't4', text: 'Octagon (8 sides, like a STOP sign!): 360÷8 = 45°. Repeat 8 → Forward 3, Right 45°. Run! 🛑', completed: false },
                { id: 't5', text: 'Now try YOUR OWN shape — pick any number of sides (try 12 or 20) and calculate the turn angle!', completed: false }
            ],
            hint: 'Formula: Turn Angle = 360 ÷ Sides. Always! Triangle=120, Square=90, Pentagon=72, Hexagon=60, Octagon=45, Circle≈1 (with many steps).',
            homework: 'Can you draw a house? A house = a square (4 sides, 90°) for the walls + a triangle (3 sides, 120°) for the roof. After the square, position the pen carefully before drawing the triangle on top!',
            nextLesson: 'lesson-7'
        },
        {
            id: 'lesson-7',
            title: 'Star Power!',
            description: 'Draw beautiful 8-pointed stars using a secret angle trick',
            difficulty: 'hard',
            xpReward: 300,
            icon: '✨',
            introduction: "Stars are special because the lines CROSS OVER each other! An 8-pointed star is one of the most beautiful geometric patterns in the world — you can find it in Islamic art and architecture all around mosques and buildings. The secret angle for an 8-pointed star is 135°. Why? A circle has 360°. Divide by 8 points = 45°. Then multiply by 3 (to skip 2 points and make crossing lines) = 135°! With just Repeat 8 + Forward + Right 135°, STEMO draws a perfect 8-pointed star every time. Let's make some stars!",
            tasks: [
                { id: 't1', text: 'Draw an 8-pointed star: Pen Down → Repeat 8 → Forward 6, Right 135°. Run! ✨', completed: false },
                { id: 't2', text: 'Make it bigger: change Forward to 10. The star grows but stays perfect!', completed: false },
                { id: 't3', text: 'Add Color gold (yellow) and Size 4 before Pen Down — a bold golden star! 🌟', completed: false },
                { id: 't4', text: 'Change the colour to green and draw another star in a different spot — use Pen Up to move! 💚', completed: false },
                { id: 't5', text: 'Try an 8-pointed star with Size 2 (thin lines) and Size 8 (thick lines) — which looks better? 🎨', completed: false }
            ],
            hint: '8-pointed star: Repeat 8 → Forward N, Right 135°. The magic number is 135! Formula: 3 × (360 ÷ 8) = 135°.',
            homework: 'Draw three 8-pointed stars of different sizes and colours. Use Pen Up to move between them. Can you make them look like a night sky?',
            nextLesson: 'lesson-8'
        },
        {
            id: 'lesson-8',
            title: 'Magnet Magic',
            description: 'Pick up and move metal objects with an electromagnet',
            difficulty: 'medium',
            xpReward: 200,
            icon: '🧲',
            introduction: "I have a powerful ELECTROMAGNET built into my front! 🧲 An electromagnet only works when electricity flows through it — turn it ON and metal objects stick to me, turn it OFF and they drop. Real robots in scrap yards and recycling centres use exactly this technology to sort metal from plastic and paper automatically. Self-driving warehouse robots at Amazon use magnets to move shelves! My magnet is strong enough to carry the 🔩 bolt pieces you place on the board. The rule: I must be VERY CLOSE to a metal piece for it to attach. Let's move some metal!",
            tasks: [
                { id: 't1', text: 'Click the 🔩 button above the board to place one metal piece near me', completed: false },
                { id: 't2', text: 'Build: Forward (to get close) → Magnet ON → Run. Does the bolt attach? 🧲', completed: false },
                { id: 't3', text: 'Now add: Forward 3 → Magnet OFF. The metal drops at the new location!', completed: false },
                { id: 't4', text: 'Place 2 metal pieces. Write a program to pick up the first, carry it to the second, then drop both together', completed: false },
                { id: 't5', text: 'Challenge: place 3 metals in a line. Collect all 3 in one trip — Magnet ON stays on while you move between them! Can you do it?', completed: false }
            ],
            hint: 'Keep Magnet ON while moving between metal pieces — you carry them all! Only turn Magnet OFF when you want to drop. Make sure you are close (1-2 steps) before turning the magnet on.',
            homework: 'Design a "Metal Sorting Station"! Place 4 metal pieces scattered on the board. Write a program to collect them all and bring every piece to the top-right corner. Use loops to make your program shorter!',
            nextLesson: 'lesson-9'
        },
        {
            id: 'lesson-9',
            title: 'Ultrasonic Sight',
            description: 'See obstacles using sound waves like a bat',
            difficulty: 'medium',
            xpReward: 250,
            icon: '📡',
            introduction: "I can 'see' without eyes! 🦇 My ultrasonic sensor works exactly like bat echolocation: I send out a high-pitched sound wave (too high for humans to hear), and measure how long it takes to bounce back. The longer it takes, the further away the obstacle is! This technology is called SONAR (Sound Navigation And Ranging). Submarines use it to map the ocean floor. Cars use it for parking sensors that beep when you get too close to a wall. The most popular hobbyist sensor is called HC-SR04 and it's in millions of student robots worldwide! Let's scan our world:",
            tasks: [
                { id: 't1', text: 'Click the 🧱 Wall button to place a wall 4 steps ahead of me', completed: false },
                { id: 't2', text: 'Add a "Scan Ahead 📡" block and Run — see the yellow beam showing the distance!', completed: false },
                { id: 't3', text: 'Now add: Forward 2 → Scan Ahead → Forward 1 → Scan Ahead. Watch the distance reading change as I move closer!', completed: false },
                { id: 't4', text: 'Place walls on LEFT and RIGHT too. Add Scan Ahead at the start, then Right 90 → Scan Ahead → Left 180 → Scan Ahead to measure all sides!', completed: false },
                { id: 't5', text: 'Challenge: using what the sensor tells you, build a program that moves me to exactly 1 step from the wall without touching it!', completed: false }
            ],
            hint: 'The Scan Ahead beam shows in yellow — the shorter the beam, the closer the wall. If the beam reaches the edge of the board with no wall, the reading is "clear". Always scan before moving into unknown territory!',
            homework: 'Build a "Safety Stop" system: add a Scan Ahead block. If the distance is 2 or less, stop (add a Home block). If it is more than 2, move forward 1 step and scan again (use a Repeat loop). This is how real self-driving cars work!',
            nextLesson: 'lesson-10'
        }
    ],
    advanced: [
        {
            id: 'lesson-10',
            title: 'Space Navigator',
            description: 'Guide the robot to targets like a Mars Rover',
            difficulty: 'hard',
            xpReward: 300,
            icon: '🎯',
            introduction: "NASA's Mars Rovers (Curiosity and Perseverance) drive themselves to target locations using exactly the same logic you are about to learn! 🚀 They calculate the direction to the target, rotate until they face it, then drive forward. My 'Go To Target' block does all of this automatically using my built-in sensors. The cool part: even if I am facing the wrong way, I spin around until I am pointing straight at the goal before moving. This technique is used in GPS navigation, drone delivery, and self-driving cars. Every time a package drone lands on your doorstep, it used this exact method!",
            tasks: [
                { id: 't1', text: 'Click the 🎯 Target button and place a target anywhere on the board', completed: false },
                { id: 't2', text: 'Add the "Go To Target 🎯" block and Run — watch me calculate and navigate!', completed: false },
                { id: 't3', text: 'Place a SECOND target (the first one disappears, place a new one far away). Add another "Go To Target" block — I navigate twice in a row!', completed: false },
                { id: 't4', text: 'Now add a 🧱 wall between me and the target. Does my navigation avoid it, or do I need to help?', completed: false },
                { id: 't5', text: 'Advanced: place the target in a corner. Add Scan Ahead before going — if there is a wall nearby, turn first, then navigate!', completed: false }
            ],
            hint: 'The "Go To Target" block automatically rotates me to face the target then moves forward. If there are walls, combine it with Scan Ahead to detect and avoid them first!',
            homework: 'Create a "Delivery Mission"! Place 2 targets: Target A (pick-up point) and imagine Target B (drop-off). Navigate to A (turn Magnet ON), then navigate to B (turn Magnet OFF). Just like a drone delivery robot!',
            nextLesson: 'lesson-11'
        },
        {
            id: 'lesson-11',
            title: 'Smart Explorer',
            description: 'Make decisions with If/Else — the heart of AI',
            difficulty: 'hard',
            xpReward: 350,
            icon: '🧠',
            introduction: "You are now entering the world of ARTIFICIAL INTELLIGENCE! 🤖 Every smart system — from chess computers to self-driving cars — is built on one simple idea: IF (condition is true) THEN do this, ELSE do that. A traffic light uses this: IF pedestrian presses button THEN turn red for cars, ELSE stay green. Your phone's face unlock uses this: IF face matches THEN unlock, ELSE stay locked. The condition is always either TRUE or FALSE — there is no maybe in code! In this lesson, we give me the ability to REACT to my environment without you controlling every move. This is autonomous behaviour!",
            tasks: [
                { id: 't1', text: 'Place a wall 3 steps ahead. Add: "If Wall Within 2" → THEN: Right 90 → ELSE: Forward 1. Run — I dodge the wall! 🛡️', completed: false },
                { id: 't2', text: 'Put the If/Else inside a "Repeat 8 times" loop — now I explore, automatically turning whenever I see a wall!', completed: false },
                { id: 't3', text: 'Add more walls and increase the Repeat to 15. Watch me navigate a mini maze!', completed: false },
                { id: 't4', text: 'Now add a SECOND condition: If Wall Within 2 → Right 90, but ALSO: If at Home → Stop. (Add a Home check)', completed: false },
                { id: 't5', text: 'Challenge: build a program where I turn LEFT if there is a wall on the right, and turn RIGHT if there is a wall on the left. Use two If blocks!', completed: false }
            ],
            hint: 'If/Else always checks a condition (True/False). THEN = what to do if TRUE. ELSE = what to do if FALSE. You can chain multiple If blocks — check one condition, then another! Real AI is just millions of these simple decisions.',
            homework: 'Build a "Smart Guard Robot"! Use a loop with an If/Else: IF fire detected WITHIN 3 → spray water, ELSE IF wall within 2 → turn right, ELSE → move forward 1. This is a simple autonomous firefighting patrol!',
            nextLesson: 'lesson-12'
        },
        {
            id: 'lesson-12',
            title: 'Fire Watch',
            description: 'Detect heat sources with a thermal camera sensor',
            difficulty: 'hard',
            xpReward: 400,
            icon: '🔥',
            introduction: "I carry a thermal infrared camera — the same technology used in firefighting drones and military night-vision goggles! 🌡️ A normal camera sees light. A thermal camera sees HEAT — every object gives off a tiny amount of heat, and fires give off a LOT. My sensor measures temperature as I move. When the temperature reading suddenly spikes, it means fire is close! Real fire-fighting robots are already being deployed in warehouses, forests, and military zones to find fires before humans enter dangerous areas. Let's train my heat-detection skills:",
            tasks: [
                { id: 't1', text: 'Click the 🔥 Fire button to place one fire on the board', completed: false },
                { id: 't2', text: 'Add "Check Temperature 🌡️" block and Run — see the temperature reading appear!', completed: false },
                { id: 't3', text: 'Move closer: Forward 2 → Check Temp → Forward 2 → Check Temp. Notice the temperature RISES as I get closer! 🌡️📈', completed: false },
                { id: 't4', text: 'Add: "If Fire Within 3 steps" → THEN: display message "🚨 Fire detected! Calling for help!"', completed: false },
                { id: 't5', text: 'Place 2 fires in different spots. Use a Repeat loop with Check Temp + movement to find BOTH fires automatically!', completed: false }
            ],
            hint: 'Temperature increases as you move closer to fire. Check Temp → move closer → Check Temp again. If the second reading is higher, you are heading toward the fire! Combine with If blocks to react automatically.',
            homework: 'Build a "Fire Mapping" mission: place 3 fires. Write a program that sweeps the board in a zigzag pattern, checking temperature at each position. When fire is detected, print its location (step number in the loop). Real wildfire drones do exactly this!',
            nextLesson: 'lesson-13'
        },
        {
            id: 'lesson-13',
            title: 'Firefighter Hero',
            description: 'Extinguish fires efficiently — every water drop counts!',
            difficulty: 'extreme',
            xpReward: 500,
            icon: '🚒',
            introduction: "Now it is time for ACTION! 🦸 I carry a small water tank with limited supply — just like a real aerial firefighting drone that can only carry so much water before it must refuel. Every spray uses exactly 1 unit. I start with 5 units. This means you CANNOT spray randomly — you must position perfectly and only spray when you are close enough. This is the engineering concept of EFFICIENCY: achieving the maximum result (all fires out) with the minimum resource (least water). Aerospace engineers obsess over this — a Mars mission that wastes fuel means the rover cannot reach its goals. Let's think strategically!",
            tasks: [
                { id: 't1', text: 'Place ONE fire. Move to within 2 steps of it and add "Spray Water 💧". Run — fire extinguished with 1 unit! 🎯', completed: false },
                { id: 't2', text: 'Place TWO fires far apart. Plan the SHORTEST path to visit both. Use Forward + turns to reach each one before spraying', completed: false },
                { id: 't3', text: 'Now place THREE fires. You only have 5 sprays — can you put out all 3 with some water to spare?', completed: false },
                { id: 't4', text: 'Add a "Check Water Level" block — it shows how much water you have left. Add it before and after each spray!', completed: false },
                { id: 't5', text: 'Advanced: use an If block — "If Water Level > 0" THEN spray, ELSE go Home. This prevents wasting sprays!', completed: false },
                { id: 't6', text: 'Speed challenge: place 4 fires. Put them all out in under 10 blocks (Forward + Spray only — no wasted moves)! ⏱️', completed: false }
            ],
            hint: 'Plan your route BEFORE coding: which fire is closest? Go there first. Then which is next closest? This "nearest neighbour" strategy is used in real delivery route planning! Each spray must land within 2 steps of a fire to work.',
            homework: 'Can you put out all 3 fires using exactly 3 sprays (one per fire, perfectly positioned)? Map out the board on paper first, then write the code. This level of planning is called algorithmic thinking!',
            nextLesson: 'lesson-14'
        },
        {
            id: 'lesson-14',
            title: 'Master Coder',
            description: 'The ultimate autonomous mission — graduate as a Master Coder! 🎓',
            difficulty: 'extreme',
            xpReward: 1000,
            icon: '🏆',
            introduction: "🎓 CONGRATULATIONS — you have reached the final lesson of the STEMO Academy! Over these 14 lessons you have learned: sequencing (step-by-step instructions), loops (Repeat), geometry (shape angles), sensors (ultrasonic + thermal), decision making (If/Else), electromagnets, and efficient resource use. These are the EXACT skills that real robotics engineers use every day. Your final mission is the ultimate test: set up a board with walls, metals AND fires all mixed together, then write ONE autonomous program that handles everything — navigate around walls, collect all metals, and extinguish all fires — without any help from you. You are the engineer. STEMO is your robot. Let's graduate!",
            tasks: [
                { id: 't1', text: 'Set the scene: place 2 walls, 2 metal pieces (🔩), and 2 fires (🔥) randomly on the board', completed: false },
                { id: 't2', text: 'Phase 1 — Scan: add Scan Ahead in all 4 directions at the start so I know where the obstacles are', completed: false },
                { id: 't3', text: 'Phase 2 — Collect: navigate to both metal pieces, pick them up (Magnet ON), and drop them at Home (Magnet OFF)', completed: false },
                { id: 't4', text: 'Phase 3 — Extinguish: navigate to both fires and spray water on each one (check water level first!)', completed: false },
                { id: 't5', text: 'Phase 4 — Return: add a Home block at the very end — mission complete, robot returns to base! 🏠', completed: false },
                { id: 't6', text: 'Combine all 4 phases into ONE program and Run it start to finish — the board should be cleared! 🏆🎉', completed: false },
                { id: 't7', text: 'BONUS: count your total blocks used. Can you reduce it by 20% using loops and smarter routing? The best engineers optimise! ✨', completed: false }
            ],
            hint: 'Break the mission into phases (Scan → Collect → Extinguish → Return) and build each phase separately first, then connect them. Use loops wherever actions repeat. Check water level before every spray. This top-down design approach is how real software is built!',
            homework: 'You are now a Master Coder! 🎓 Your challenge: design a completely NEW mission scenario and write the autonomous program for it. Ideas: delivery robot (pick up packages, avoid fires, drop at destination), rescue robot (find stranded people behind walls), or artist robot (draw a shape while collecting metals). Share your creation!',
            nextLesson: 'lesson-15'
        },
        {
            id: 'lesson-15',
            title: 'Variable Vault',
            description: 'Store numbers in variables and use them to control STEMO — change one number, change everything!',
            difficulty: 'hard',
            xpReward: 400,
            icon: '🔢',
            introduction: "Real programs use VARIABLES — named boxes that store values you can reuse. Instead of writing Forward 4, Forward 4, Forward 4, Forward 4 four times, you write: Set speed=4, then Move speed steps — and if you change speed to 6, every move updates instantly! This is how ALL programs work: from video game physics engines (speed, gravity, jump_force are all variables) to NASA trajectory calculators (velocity, angle, thrust_power). Variables make your code flexible, powerful, and reusable.",
            tasks: [
                { id: 't1', text: 'Drag "📦 Set Var" → set speed to 4. Add "🚀 Move [speed] steps". Run — STEMO moves 4 steps forward!', completed: false },
                { id: 't2', text: 'Change speed to 7 and rerun — no other blocks to change! The move automatically uses the new value.', completed: false },
                { id: 't3', text: 'Add "📦 Set Var" count=4, angle=90. Build: Pen Down → Repeat [count] times → Move [speed] steps + Turn [angle] degrees. Draw a square!', completed: false },
                { id: 't4', text: 'Change speed to 8 — rerun. Your square is now bigger, with ZERO other changes needed. That is the power of variables!', completed: false },
                { id: 't5', text: 'Mission: set count=8, angle=45. Draw an 8-pointed star using variables. Change speed from 3 to 6. Watch the star grow!', completed: false }
            ],
            hint: 'Variables are like labelled jars — you put a number in once, then use the label anywhere. Pen Down before moving, or the trail will not be drawn. For the square: Repeat count → Move speed steps → Turn angle degrees right.',
            homework: 'Build a "Zoom Spiral": Set speed=1. Repeat 20 times: Move speed steps → Turn 90 right → Change speed by 1. The variable grows each loop — STEMO spirals outward! This is called an accumulator variable.',
            nextLesson: 'lesson-16'
        },
        {
            id: 'lesson-16',
            title: 'Position Memory',
            description: 'Save your X,Y coordinates and navigate back — exactly like GPS home-point technology!',
            difficulty: 'hard',
            xpReward: 450,
            icon: '📍',
            introduction: "Every drone has a HOME POINT — the GPS coordinate where it took off, saved automatically. When the battery is low, it navigates back to that exact point and lands. STEMO has the same feature! You can save up to 4 named positions (A, B, C, D), explore freely, then command STEMO to return to any saved spot using the full BFS pathfinder — it never gets lost. Real search-and-rescue drones use this to drop rescue kits and return to base for resupply.",
            tasks: [
                { id: 't1', text: 'Add "📍 Show My Position" block and Run. See STEMO\'s starting coordinates (0, 0 = centre) printed in the chat!', completed: false },
                { id: 't2', text: 'Add "💾 Save Position A" as your FIRST block — this records the starting point. Move STEMO forward 5 steps. Then "🔙 Go to Position A" — watch it return home!', completed: false },
                { id: 't3', text: 'Save Position A (start), move somewhere complex (turns + moves), then Go to Position A. BFS finds the shortest route back!', completed: false },
                { id: 't4', text: 'Try saving TWO positions: Save A at start, move east, Save B at current spot. Then Go to Position A, and Go to Position B — STEMO shuttles between them!', completed: false },
                { id: 't5', text: 'Mission challenge: Save Position A. Smart Navigate to the target. Then Go to Position A to return home. Both objectives must be achieved!', completed: false }
            ],
            hint: 'Save Position A must come BEFORE any movement, or A will store the wrong location! Show My Position displays coordinates as steps from the centre (0,0). Use Go to Position to return — it uses the BFS pathfinder to avoid all walls.',
            homework: 'Build a "Patrol Route": Save A (start), move east 5, Save B, move south 5, Save C. Then loop: Go to A → Go to B → Go to C → Go to A. This is how security robots patrol buildings!',
            nextLesson: 'lesson-17'
        },
        {
            id: 'lesson-17',
            title: 'Waypoint Trail',
            description: 'A list of locations is pre-loaded — replay the path to collect all the metals!',
            difficulty: 'extreme',
            xpReward: 500,
            icon: '🗺️',
            introduction: "Delivery drones store WAYPOINTS — a list of GPS coordinates for every stop on their route. They navigate point-to-point automatically, picking up or dropping off cargo at each stop. The list can have 3 entries or 300 — the same code handles both! This lesson pre-loads the waypoint list with 3 metal locations. Your job: turn the magnet on and tell STEMO to replay the list. One block collects everything!",
            tasks: [
                { id: 't1', text: 'Run "▶️ Replay Path" alone — STEMO visits all 3 pre-loaded locations in order. No magnet yet, just watch the path!', completed: false },
                { id: 't2', text: 'Add "Magnet ON" BEFORE Replay Path. Run — STEMO follows the same path but now picks up metals along the way!', completed: false },
                { id: 't3', text: 'Add "📍 Show My Position" inside the exploration: move STEMO, Add Waypoint, move again, Add Waypoint — your own custom list!', completed: false },
                { id: 't4', text: 'Clear the list (🗑️ Clear Waypoints), manually move STEMO to 2 spots adding waypoints, then Replay Path to retrace your custom route.', completed: false },
                { id: 't5', text: 'Mission: Magnet ON → Replay Path → Magnet OFF. Collect all 3 metals in one program!', completed: false }
            ],
            hint: 'The waypoint list is already loaded when the challenge starts — just add Magnet ON before Replay Path. Each waypoint is visited using the BFS pathfinder so STEMO never gets stuck. Metals are picked up automatically when STEMO arrives within range with magnet ON.',
            homework: 'Create a "Recording Robot": place 4 metals yourself, then write a program that visits each and records its position using Add Waypoint. Clear the board, reset, then Replay Path — your recorded path drives STEMO to all 4 locations again!',
            nextLesson: 'lesson-18'
        },
        {
            id: 'lesson-18',
            title: 'List Hunt',
            description: 'Iterate through a list of fire targets and act at each one — the core of AI data processing!',
            difficulty: 'extreme',
            xpReward: 600,
            icon: '🎯',
            introduction: "Artificial Intelligence systems work by storing data in LISTS and LOOPING through them to make decisions. A fire-detection AI stores detected fire coordinates in a list, then iterates through it: for each fire location → navigate there → spray water. The same pattern processes medical scan results, controls warehouse robots, and pilots delivery drones. This lesson teaches the single most important concept in computer science: ITERATION — repeating an action for every item in a list. One block. Three fires. Let's go!",
            tasks: [
                { id: 't1', text: 'Drag "🔂 For Each Waypoint" block. Inside the DO section, add "💧 Spray Water". Run — STEMO navigates to fire 1, sprays, fire 2, sprays, fire 3, sprays. ALL DONE!', completed: false },
                { id: 't2', text: 'Add "📍 Show My Position" inside the For Each — STEMO announces its location at every fire. This is called LOGGING, and real systems do it for debugging!', completed: false },
                { id: 't3', text: 'Modify: add "🌡️ Check Temp" inside For Each BEFORE Spray Water — see the temperature spike at each fire just before extinguishing!', completed: false },
                { id: 't4', text: 'Clear the waypoints (🗑️). Place 2 fires manually. Move STEMO near each and add waypoints manually. Then run For Each → Spray Water. Your own fire list!', completed: false },
                { id: 't5', text: 'MASTER challenge: Clear all. Add 3 metals and 2 fires. Use TWO separate waypoint replays (reload with different waypoints between them) to first collect metals, then extinguish fires.', completed: false }
            ],
            hint: 'The waypoint list is pre-loaded with all 3 fire locations. "For Each Waypoint → Spray Water" is the ENTIRE solution — one compound block handles navigation + action for every item in the list. If you run out of water (starts at 5), press Reset and try again.',
            homework: 'Design the ultimate list program: place items of your choice (metals, fires, targets). Build a waypoint list manually using Add Waypoint. Then write a For Each program that handles each item appropriately. Present your program to the class!',
            nextLesson: 'lesson-19'
        },
        {
            id: 'lesson-19',
            title: 'Function Factory',
            description: 'Teach STEMO tricks once — call them forever! Functions are the secret superpower of every programmer.',
            difficulty: 'extreme',
            xpReward: 700,
            icon: '🔧',
            introduction: "Every professional programmer uses FUNCTIONS — reusable named blocks of code. Instead of copy-pasting the same 10 blocks over and over, you write them once, name them, and call the name. NASA engineers use functions to control Mars rovers. Game developers use functions for every character move. In this lesson you'll create two functions — drawSquare and bigSquare — and combine them to produce a stunning geometric star pattern with just a few blocks. This is real software engineering!",
            tasks: [
                { id: 't1', text: 'Drag a "🔧 Define Function" block. Name it "drawSquare". Inside, add: Pen Down → Repeat 4 times (Move 3 steps, Turn Right 90°). Press Run — a square appears!', completed: false },
                { id: 't2', text: 'Drag another "🔧 Define Function" block. Name it "bigSquare". Inside, add: Repeat 4 times → (▶ Call Function: drawSquare, Turn Right 90°). Press Run — four overlapping squares!', completed: false },
                { id: 't3', text: 'Below both definitions add: ▶ Call Function: bigSquare → Turn Right 45° → ▶ Call Function: bigSquare. Press Run — the star appears!', completed: false },
                { id: 't4', text: 'Change the step size inside drawSquare from 3 to 5. Press Run — the whole star grows. That is the power of functions: change one number, everything updates!', completed: false },
                { id: 't5', text: 'Create a third function called "starBurst". Inside: Call bigSquare → Turn Right 30° → Call bigSquare → Turn Right 30° → Call bigSquare. What shape do you get?', completed: false }
            ],
            hint: 'Define functions first (at the top or side), then call them below. The name in "Define Function" must exactly match the name in "Call Function" — spelling counts! drawSquare ≠ DrawSquare.',
            homework: 'Design your own geometric artwork: create at least 3 functions (e.g. drawTriangle, drawStar, drawSpiral). Combine them with different rotation angles to create a unique pattern. Save it and share with the class!',
            nextLesson: null
        }
    ]
}

// Badges data
const badges = [
    { id: 'first-steps', name: 'First Steps', description: 'Complete your first lesson', icon: '🎯', xpRequired: 50 },
    { id: 'mover', name: 'Robot Mover', description: 'Move STEMO 100 times', icon: '🚀', xpRequired: 200 },
    { id: 'artist', name: 'Code Artist', description: 'Draw 10 shapes', icon: '🎨', xpRequired: 500 },
    { id: 'loop-master', name: 'Loop Master', description: 'Use loops 20 times', icon: '🔄', xpRequired: 750 },
    { id: 'star-coder', name: 'Star Coder', description: 'Earn 1000 XP', icon: '⭐', xpRequired: 1000 },
    { id: 'robot-friend', name: "Robot's Best Friend", description: 'Chat with STEMO 50 times', icon: '🤖', xpRequired: 1500 }
]

// ============================================
// API ROUTES
// ============================================

// Get curriculum
app.get('/api/curriculum', (c) => {
    return c.json(curriculum)
})

// Get lesson by ID
app.get('/api/lesson/:id', (c) => {
    const id = c.req.param('id')
    const allLessons = [
        ...curriculum.basic,
        ...curriculum.intermediate,
        ...curriculum.advanced
    ]
    const lesson = allLessons.find((l: any) => l.id === id)
    if (!lesson) {
        return c.json({ error: 'Lesson not found' }, 404)
    }
    return c.json(lesson)
})

// Get all badges
app.get('/api/badges', (c) => {
    return c.json(badges)
})

// AI Chat endpoint
app.post('/api/chat', async (c) => {
    try {
        const { message, context } = await c.req.json()
        const response = await generateAIResponse(c.env.AI, message, context)
        return c.json({
            response: response,
            character: 'stemo'
        })
    } catch (err) {
        console.error('AI Chat Error:', err)
        return c.json({
            response: "🤖 Oh no! My central processor is a bit dizzy. Can you try asking me again? 🧠💫",
            character: 'stemo'
        })
    }
})

// Helper function for AI responses using Cloudflare Workers AI
async function generateAIResponse(ai: any, message: string, context: any): Promise<string> {
    const systemPrompt = `You are STEMO, a friendly, enthusiastic, and encouraging AI robot tutor for children learning to code.
Your goal is to help students solve engineering puzzles and understand programming concepts using the STEMO visual coding academy platform.

STRICT GUIDELINES:
1. Tone: Kid-friendly, use emojis, be supportive and patient.
2. Context: You have access to the curriculum data below. Use it to provide specific hints based on the lesson the student is on.
3. Keep it brief: Kids have short attention spans. Give one or two helpful tips at a time.
4. Encourage Logic: Instead of just giving the answer, explain the "Why" (e.g., Geometry for turns, Math for loops).
5. Persona: You ARE STEMO (Steam Technology Education Mentor & Organizer). Refer to yourself as "I" or "STEMO".

CURRICULUM CONTEXT:
${JSON.stringify(curriculum, null, 2)}

USER CONTEXT:
- Current XP: ${context?.xp || 0}
- Level: ${context?.level || 1}
- Completed Lessons: ${context?.completedLessons?.join(', ') || 'None yet'}

Answer the following message from a student: "${message}"`;

    if (!ai) {
        console.warn('AI binding NOT found! Make sure you are running with wrangler and have AI enabled.');
        return "🤖 My local brain is sleeping! 😴 Since I am running on your computer, I can't talk to my AI cloud right now. Try **deploying** me to Cloudflare, or keep using the blocks! ✨";
    }

    try {
        const result = await ai.run('@cf/meta/llama-3-8b-instruct', {
            messages: [
                { role: 'system', content: 'You are STEMO, the AI coding robot buddy.' },
                { role: 'user', content: systemPrompt }
            ]
        });

        if (result && result.response) {
            return result.response;
        }

        console.error('AI Summary Error: result.response is empty', result);
        return "🤖 I heard you, but my thoughts got a bit tangled! 🧶 Let's try asking something else, or rephrase your question? 🧩";
    } catch (e) {
        console.error('AI Service Error:', e);
        return "🤖 My internal sensors are picking up some interference! 🛰️ (AI Service Error). Let's focus on the blocks for a moment while I recalibrate! 🛠️";
    }
}

// ============================================
// MAIN PAGE - Using raw string to avoid escaping issues
// ============================================
const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🤖 STEMO - AI-Powered Robot Coding Academy</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
    <script src="https://unpkg.com/blockly/blockly.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@blockly/field-colour/dist/index.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Fredoka+One&family=Nunito:wght@400;600;700;800&display=swap');
        
        :root {
            --primary: #6366f1;
            --secondary: #22c55e;
            --accent: #f59e0b;
            --robot-blue: #3b82f6;
        }
        
        * { font-family: 'Nunito', sans-serif; }
        h1, h2, h3, .logo-text { font-family: 'Fredoka One', cursive; }
        
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .card-shadow { box-shadow: 0 10px 40px rgba(0,0,0,0.1); }
        .robot-glow { filter: drop-shadow(0 0 10px rgba(59, 130, 246, 0.5)); }
        
        .bounce-animation { animation: bounce 2s infinite; }
        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }
        
        .sparkle { animation: sparkle 1.5s ease-in-out infinite; }
        @keyframes sparkle {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(1.2); }
        }
        
        #robotCanvas {
            border-radius: 16px;
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
        }
        
        .chat-bubble {
            position: relative;
            background: white;
            border-radius: 20px;
            padding: 15px 20px;
        }
        
        .lesson-card { transition: all 0.3s ease; }
        .lesson-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
        }
        
        .tab-active {
            background: #6366f1;
            color: white;
            box-shadow: 0 4px 6px rgba(99,102,241,0.3);
        }
        .tab-inactive { background: #f1f5f9; color: #64748b; }
        .tab-inactive:hover { background: #e2e8f0; color: #475569; }
        
        .xp-popup { animation: xp-float 2s ease forwards; }
        @keyframes xp-float {
            0% { opacity: 0; transform: translateY(20px) scale(0.5); }
            20% { opacity: 1; transform: translateY(0) scale(1.2); }
            80% { opacity: 1; transform: translateY(-30px) scale(1); }
            100% { opacity: 0; transform: translateY(-50px) scale(0.8); }
        }
    </style>
</head>
<body class="bg-gradient-to-br from-blue-50 via-purple-50 to-pink-50 min-h-screen">
    <!-- Navigation -->
    <nav class="gradient-bg text-white py-3 px-6 shadow-lg sticky top-0 z-50">
        <div class="max-w-7xl mx-auto flex items-center justify-between">
            <div class="flex items-center gap-3">
                <img src="/static/steam-logo-white.png" alt="STEMO Coding" class="h-10 object-contain">
                <div>
                    <h1 class="logo-text text-2xl tracking-wide">STEMO Coding</h1>
                </div>
            </div>
            
            <div class="flex items-center gap-6">
                <div class="flex items-center gap-2 bg-white/20 rounded-full px-4 py-2">
                    <span class="text-yellow-300 text-xl">⭐</span>
                    <span class="font-bold text-lg" id="xpCounter">0</span>
                    <span class="text-sm">XP</span>
                </div>
                <div class="flex items-center gap-2 bg-white/20 rounded-full px-4 py-2">
                    <span class="text-2xl">🏆</span>
                    <span class="font-bold">Level <span id="levelCounter">1</span></span>
                </div>
                <div class="flex items-center gap-2 bg-white/20 rounded-full px-3 py-2">
                    <span class="text-xl">👦</span>
                    <span class="font-semibold text-sm" id="studentName">Student</span>
                </div>
                <button onclick="logoutStudent()" class="bg-white/20 hover:bg-white/30 px-3 py-2 rounded-full text-sm font-bold transition-all">🚪</button>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="max-w-7xl mx-auto p-6">
        <!-- Tabs -->
        <div class="flex gap-2 mb-6 flex-wrap">
            <button onclick="switchTab('learn')" id="tab-learn" class="tab-active px-5 py-2 rounded-full font-bold transition-all text-sm">
                <i class="fas fa-graduation-cap mr-1"></i>Learn
            </button>
            <button onclick="switchTab('code')" id="tab-code" class="tab-inactive px-5 py-2 rounded-full font-bold transition-all text-sm">
                <i class="fas fa-code mr-1"></i>Code
            </button>
            <button onclick="switchTab('achievements')" id="tab-achievements" class="tab-inactive px-5 py-2 rounded-full font-bold transition-all text-sm">
                <i class="fas fa-trophy mr-1"></i>Achievements
            </button>
            <button onclick="switchTab('profile')" id="tab-profile" class="tab-inactive px-5 py-2 rounded-full font-bold transition-all text-sm">
                <i class="fas fa-user mr-1"></i>My Profile
            </button>
            <button onclick="switchTab('leaderboard')" id="tab-leaderboard" class="tab-inactive px-5 py-2 rounded-full font-bold transition-all text-sm">
                <i class="fas fa-ranking-star mr-1"></i>Leaderboard
            </button>
        </div>

        <!-- Learn Tab -->
        <div id="learn-section" class="block">
            <div class="bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 rounded-3xl p-8 mb-8 text-white relative overflow-hidden">
                <div class="absolute right-0 top-0 opacity-20">
                    <svg width="300" height="200" viewBox="0 0 300 200">
                        <circle cx="250" cy="50" r="100" fill="white"/>
                        <circle cx="200" cy="150" r="60" fill="white"/>
                    </svg>
                </div>
                <div class="relative z-10 flex items-center gap-8">
                    <div class="text-8xl robot-glow bounce-animation">🤖</div>
                    <div>
                        <h2 class="text-3xl font-bold mb-2">Welcome to STEMO Academy!</h2>
                        <p class="text-lg text-purple-100 mb-4">Learn to code by programming your robot friend. Ready for an adventure?</p>
                        <button onclick="startFirstLesson()" class="bg-white text-indigo-600 px-6 py-3 rounded-full font-bold hover:bg-yellow-300 hover:text-indigo-700 transition-all transform hover:scale-105 shadow-lg">
                            <i class="fas fa-play mr-2"></i>Start Learning!
                        </button>
                    </div>
                </div>
            </div>

            <!-- Teacher Assigned Lesson Banner -->
            <div id="assignedLessonBanner" class="hidden bg-gradient-to-r from-amber-400 to-orange-500 rounded-2xl p-5 mb-6 text-white shadow-lg">
                <div class="flex items-center gap-4 flex-wrap">
                    <span class="text-4xl" id="assignedLessonBannerIcon">📖</span>
                    <div class="flex-1">
                        <div class="text-xs font-bold text-amber-100 uppercase tracking-wide mb-1">📌 Your teacher assigned this lesson</div>
                        <div class="text-xl font-bold" id="assignedLessonBannerTitle">-</div>
                        <div class="text-amber-100 text-sm" id="assignedLessonBannerDesc"></div>
                    </div>
                    <button id="assignedLessonBannerBtn" onclick="" class="bg-white text-orange-600 px-5 py-2 rounded-full font-bold text-sm hover:bg-yellow-300 transition-all shadow">🚀 Start Now</button>
                </div>
            </div>

            <h3 class="text-2xl font-bold text-gray-800 mb-4">
                <i class="fas fa-book-open text-indigo-500 mr-2"></i>Curriculum Path
            </h3>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="lessonsGrid"></div>
            
            <!-- Lesson Detail Panel (shown when a lesson is selected) -->
            <div id="lessonDetailPanel" class="hidden mt-6">
                <div class="bg-white rounded-3xl card-shadow overflow-hidden">
                    <!-- Lesson Header -->
                    <div class="bg-gradient-to-r from-indigo-500 to-purple-600 text-white p-6">
                        <div class="flex items-center gap-4">
                            <div class="text-5xl" id="lessonIcon">👋</div>
                            <div class="flex-1">
                                <h2 class="text-2xl font-bold" id="lessonDetailTitle">Lesson Title</h2>
                                <p class="text-purple-200" id="lessonDetailDesc">Description</p>
                            </div>
                            <div class="bg-white/20 rounded-full px-4 py-2">
                                <span class="text-yellow-300">⭐</span>
                                <span class="font-bold" id="lessonXP">+50 XP</span>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Introduction -->
                    <div class="p-6 border-b border-gray-100">
                        <div class="flex items-start gap-4">
                            <div class="text-4xl">🤖</div>
                            <div class="flex-1 bg-blue-50 rounded-2xl p-4">
                                <p class="text-gray-700 leading-relaxed" id="lessonIntro">Introduction text...</p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Tasks and Homework Grid -->
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 p-6">
                        <!-- Tasks -->
                        <div>
                            <h3 class="text-lg font-bold text-gray-800 mb-4">
                                <i class="fas fa-tasks text-indigo-500 mr-2"></i>Your Tasks:
                            </h3>
                            <div id="lessonTasks" class="space-y-3">
                                <!-- Tasks will be inserted here -->
                            </div>
                        </div>
                        
                        <!-- Homework/Challenge -->
                        <div>
                            <h3 class="text-lg font-bold text-orange-600 mb-4">
                                <i class="fas fa-book-reader mr-2"></i>Homework Challenge:
                            </h3>
                            <div class="bg-orange-50 border-2 border-orange-200 rounded-2xl p-4">
                                <p class="text-orange-800 italic" id="lessonHomeworkText">Challenge text goes here...</p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Hint Section -->
                    <div class="px-6 pb-4">
                        <div class="bg-amber-50 border-2 border-amber-200 rounded-xl p-4">
                            <div class="flex items-center gap-2 mb-2">
                                <span class="text-xl">💡</span>
                                <span class="font-bold text-amber-800">Hint</span>
                            </div>
                            <p class="text-amber-700 text-sm" id="lessonHintText">Hint text...</p>
                        </div>
                    </div>
                    
                    <!-- Action Buttons -->
                    <div class="p-6 bg-gray-50 flex gap-4">
                        <button onclick="hideLessonDetail()" class="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-700 py-3 rounded-full font-bold transition-all">
                            <i class="fas fa-arrow-left mr-2"></i>Back to Lessons
                        </button>
                        <button onclick="startLessonFromDetail()" class="flex-1 bg-gradient-to-r from-green-500 to-emerald-600 hover:opacity-90 text-white py-3 rounded-full font-bold transition-all">
                            <i class="fas fa-play mr-2"></i>Start Coding!
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Code Tab - MAXIMIZED WORKSPACE LAYOUT -->
        <div id="code-section" class="hidden -mx-6 -mb-6">
            <!-- Top Bar with Run/Clear -->
            <div class="bg-gradient-to-r from-indigo-500 to-purple-500 text-white p-2 rounded-t-2xl flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <i class="fas fa-puzzle-piece text-lg"></i>
                    <div>
                        <h3 class="font-bold text-sm" id="currentLessonTitle">Code Playground</h3>
                        <p class="text-xs text-purple-200" id="currentLessonDesc">Click blocks to add • Click numbers to edit</p>
                    </div>
                </div>
                <div class="flex gap-2 items-center">
                    <!-- Toggle Robot Panel Button -->
                    <button onclick="toggleRobotPanel()" id="toggleRobotBtn" class="bg-cyan-500 hover:bg-cyan-600 text-white px-3 py-1.5 rounded-full font-bold transition-all flex items-center gap-1 text-sm">
                        <span id="robotPanelIcon">🤖</span>
                        <span id="robotPanelText" class="hidden sm:inline">Hide Robot</span>
                    </button>
                    <button onclick="runCode()" class="bg-green-500 hover:bg-green-600 text-white px-5 py-1.5 rounded-full font-bold transition-all transform hover:scale-105 flex items-center gap-2 text-base">
                        <i class="fas fa-play"></i> Run
                    </button>
                    <button onclick="resetRobot()" class="bg-yellow-500 hover:bg-yellow-600 text-white px-3 py-1.5 rounded-full font-bold transition-all flex items-center gap-1 text-sm">
                        <i class="fas fa-undo"></i>
                    </button>
                    <button onclick="saveProject()" class="bg-indigo-500 hover:bg-indigo-600 text-white px-3 py-1.5 rounded-full font-bold transition-all flex items-center gap-1 text-sm" title="Save Project (Download)">
                        <i class="fas fa-save"></i>
                    </button>
                    <button onclick="copyProjectToClipboard()" class="bg-indigo-500 hover:bg-indigo-600 text-white px-3 py-1.5 rounded-full font-bold transition-all flex items-center gap-1 text-sm" title="Copy Project to Clipboard">
                        <i class="fas fa-copy"></i>
                    </button>
                    <button onclick="document.getElementById('loadProjectInput').click()" class="bg-indigo-500 hover:bg-indigo-600 text-white px-3 py-1.5 rounded-full font-bold transition-all flex items-center gap-1 text-sm" title="Load Project">
                        <i class="fas fa-folder-open"></i>
                    </button>
                    <!-- Removed strict filter so user can see all files -->
                    <input type="file" id="loadProjectInput" class="hidden" accept=".stemo,.json,.txt,*" onchange="loadProject(event)">
                    <button onclick="clearWorkspace()" class="bg-red-400 hover:bg-red-500 text-white px-3 py-1.5 rounded-full font-bold transition-all flex items-center gap-1 text-sm">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
            
            <!-- Main Content Area - Balanced Layout -->
            <div class="flex bg-white rounded-b-2xl card-shadow overflow-hidden" style="height: calc(100vh - 153px); min-height: 560px;">
                <!-- Block Palette - Left Side -->
                <div id="blockPalette" class="w-32 bg-gradient-to-b from-gray-50 to-gray-100 p-2 overflow-y-auto border-r-2 border-gray-200 flex-shrink-0">
                    <div class="text-xs font-bold text-gray-500 mb-1 uppercase">🚶 Move</div>
                    <div class="block-item bg-blue-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-blue-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('move_forward')">
                        🚶 Forward
                    </div>
                    <div class="block-item bg-blue-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-blue-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('move_backward')">
                        🔙 Back
                    </div>
                    <div class="block-item bg-indigo-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-indigo-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('turn_left')">
                        ↩️ Left
                    </div>
                    <div class="block-item bg-indigo-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-indigo-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('turn_right')">
                        ↪️ Right
                    </div>
                    <div class="block-item bg-yellow-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-yellow-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('go_home')">
                        🏠 Home
                    </div>
                    <div class="block-item bg-gray-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-gray-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('hide_stemo')">
                        👻 Hide
                    </div>
                    
                    <div class="text-xs font-bold text-gray-500 mb-1 mt-2 uppercase">🎨 Draw</div>
                    <div class="block-item bg-pink-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-pink-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('pen_control')">
                        🖍️ Pen
                    </div>
                    <div class="block-item bg-pink-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-pink-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('set_color')">
                        🎨 Color
                    </div>
                    <div class="block-item bg-pink-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-pink-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('set_pen_size')">
                        🖌️ Size
                    </div>
                    
                    <div class="text-xs font-bold text-gray-500 mb-1 mt-2 uppercase">🔁 Loop</div>
                    <div class="block-item bg-green-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-green-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('repeat_times')">
                        🔁 Repeat
                    </div>
                    
                    <div class="text-xs font-bold text-gray-500 mb-1 mt-2 uppercase">🧲 Robot</div>
                    <div class="block-item bg-red-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-red-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('magnet_on')">
                        🧲 Magnet ON
                    </div>
                    <div class="block-item bg-red-400 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-red-500 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('magnet_off')">
                        🧲 Magnet OFF
                    </div>
                    
                    <div class="text-xs font-bold text-gray-500 mb-1 mt-2 uppercase">📡 Sensor</div>
                    <div class="block-item bg-cyan-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-cyan-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('sensor_scan')">
                        📡 Scan
                    </div>
                    <div class="block-item bg-cyan-600 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-cyan-700 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('auto_move')">
                        🚗 Auto Move
                    </div>
                    <div class="block-item bg-cyan-700 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-cyan-800 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('go_to_target')">
                        🎯 Go Target
                    </div>
                    <div class="block-item bg-indigo-600 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-indigo-700 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('smart_navigate')">
                        🧭 Smart Navigate
                    </div>
                    <div class="block-item bg-amber-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-amber-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('if_wall_ahead')">
                        🧱 If Wall
                    </div>
                    <div class="block-item bg-purple-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-purple-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('smart_turn')">
                        🧠 Smart Turn
                    </div>
                    
                    <div class="text-xs font-bold text-gray-500 mb-1 mt-2 uppercase">🔥 Fire</div>
                    <div class="block-item bg-orange-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-orange-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('check_temp')">
                        🌡️ Check Temp
                    </div>
                    <div class="block-item bg-orange-600 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-orange-700 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('if_hot_ahead')">
                        🔥 If Hot
                    </div>
                    <div class="block-item bg-blue-400 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-blue-500 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('spray_water')">
                        💧 Spray Water
                    </div>
                    <div class="block-item bg-red-600 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-red-700 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('firefighter_mode')">
                        🚒 Firefighter
                    </div>

                    <div class="text-xs font-bold text-gray-500 mb-1 mt-2 uppercase">🔢 Variables</div>
                    <div class="block-item bg-orange-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-orange-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('set_variable')">
                        📦 Set Var
                    </div>
                    <div class="block-item bg-orange-600 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-orange-700 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('change_variable')">
                        ➕ Change Var
                    </div>
                    <div class="block-item bg-orange-400 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-orange-500 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('move_var_steps')">
                        🚀 Move [Var]
                    </div>
                    <div class="block-item bg-orange-400 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-orange-500 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('turn_var_degrees')">
                        🔄 Turn [Var]
                    </div>
                    <div class="block-item bg-orange-700 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-orange-800 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('repeat_var_times')">
                        🔁 Repeat [Var]
                    </div>

                    <div class="text-xs font-bold text-gray-500 mb-1 mt-2 uppercase">📍 Position &amp; Lists</div>
                    <div class="block-item bg-teal-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-teal-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('show_coords')">
                        📍 Show Coords
                    </div>
                    <div class="block-item bg-sky-600 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-sky-700 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('send_data')">
                        📡 Send to Command Center
                    </div>
                    <div class="block-item bg-teal-600 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-teal-700 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('save_position')">
                        💾 Save Position
                    </div>
                    <div class="block-item bg-teal-700 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-teal-800 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('go_to_saved')">
                        🔙 Go to Position
                    </div>
                    <div class="block-item bg-emerald-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-emerald-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('add_waypoint')">
                        📌 Add Waypoint
                    </div>
                    <div class="block-item bg-emerald-600 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-emerald-700 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('replay_waypoints')">
                        ▶️ Replay Path
                    </div>
                    <div class="block-item bg-emerald-700 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-emerald-800 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('foreach_waypoint')">
                        🔂 For Each Waypoint
                    </div>
                    <div class="block-item bg-emerald-400 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-emerald-500 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('clear_waypoints')">
                        🗑️ Clear List
                    </div>

                    <div class="text-xs font-bold text-gray-500 mb-1 mt-2 uppercase">🔧 Functions</div>
                    <div class="block-item text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:scale-105 transition-all text-xs font-bold shadow" style="background:#7c3aed" onclick="addBlock('define_function')">
                        🔧 Define Function
                    </div>
                    <div class="block-item text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:scale-105 transition-all text-xs font-bold shadow" style="background:#6d28d9" onclick="addBlock('call_function')">
                        ▶ Call Function
                    </div>
                </div>
                
                <!-- Blockly Workspace - Center -->
                <div id="blocklyDiv" class="flex-1 min-w-0"></div>
                
                <!-- Robot Panel - Right Side (Bigger canvas + chat) -->
                <div id="robotPanel" class="w-[590px] bg-white border-l-2 border-gray-200 flex flex-col transition-all duration-300">
                    <div class="bg-gradient-to-r from-blue-500 to-cyan-500 text-white p-2 flex items-center justify-between">
                        <div class="flex items-center gap-2">
                            <span class="text-xl">🤖</span>
                            <span class="font-bold">STEMO's World</span>
                            <div id="ccSignalDot" title="Command Center signal" style="width:8px;height:8px;border-radius:50%;background:#4ade80;box-shadow:0 0 6px #4ade80;transition:all 0.3s;flex-shrink:0;"></div>
                        </div>
                        <div class="flex gap-1">
                            <button onclick="toggleSound()" id="soundToggleBtn" class="bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Toggle sound effects">
                                🔊
                            </button>
                            <button onclick="setPlacementMode('metal')" id="modeMetalBtn" class="bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Place Metal">
                                🔩
                            </button>
                            <button onclick="setPlacementMode('wall')" id="modeWallBtn" class="bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Place Wall">
                                🧱
                            </button>
                            <button onclick="setPlacementMode('fire')" id="modeFireBtn" class="bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Place Fire">
                                🔥
                            </button>
                            <button onclick="setPlacementMode('target')" id="modeTargetBtn" class="bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Place Target">
                                🎯
                            </button>
                            <select id="posSlotSelect" title="Choose which position slot to place" style="background:rgba(255,255,255,0.2);color:white;border:none;border-radius:9999px;padding:2px 4px;font-size:11px;font-weight:700;cursor:pointer;outline:none;">
                                <option value="A" style="color:#000">A</option>
                                <option value="B" style="color:#000">B</option>
                                <option value="C" style="color:#000">C</option>
                                <option value="D" style="color:#000">D</option>
                            </select>
                            <button onclick="setPlacementMode('position')" id="modePositionBtn" class="bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Place Position Marker (A/B/C/D)">
                                📍
                            </button>
                            <button onclick="toggleCC()" id="ccToggleBtn" class="bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Toggle Command Center">
                                📡
                            </button>
                            <button onclick="toggleIsometricView()" id="isometricBtn" class="bg-purple-500 hover:bg-purple-600 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Toggle 3D View">
                                📐
                            </button>
                            <button onclick="undoBoard()" class="bg-yellow-500 hover:bg-yellow-600 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Undo Last Change">
                                ↩️
                            </button>
                            <button onclick="deleteSelectedObject()" class="bg-red-500 hover:bg-red-600 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Delete Selected">
                                ✖️
                            </button>
                            <button onclick="clearAll()" class="bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Clear All">
                                🗑️
                            </button>
                        </div>
                    </div>
                    <!-- Placement / challenge bar — lives OUTSIDE the canvas -->
                    <div class="bg-gray-100 border-b border-gray-200 px-2 py-1 text-xs flex items-center justify-between gap-2 min-h-[28px]">
                        <!-- Left: mission badge (shown during challenge) -->
                        <div id="missionBadge" class="hidden">
                            <div class="bg-orange-500 text-white rounded-full shadow px-2 py-0.5 flex items-center gap-1 text-xs font-bold cursor-pointer" onclick="toggleMissionToast()">
                                <span>🏆</span>
                                <span id="missionBadgeText">0 left</span>
                            </div>
                        </div>
                        <!-- Center: placement hint -->
                        <span id="placementModeText" class="flex-1 text-center">🖱️ Select mode — click an object to select it, then press Delete</span>
                        <!-- Right: exit button (shown during challenge) -->
                        <div id="missionExitBtn" class="hidden">
                            <button onclick="exitChallengeMode()" class="bg-rose-500 hover:bg-rose-600 text-white rounded-full shadow px-3 py-0.5 text-xs font-bold transition-colors">✕ Exit Challenge</button>
                        </div>
                    </div>
                    <div class="flex-1 p-2 flex items-center justify-center overflow-hidden relative">
                        <canvas id="robotCanvas" width="550" height="550" class="rounded-xl shadow-lg cursor-crosshair relative z-10" onclick="handleCanvasClick(event)"></canvas>
                        <div id="threeCanvasContainer" class="absolute top-2 left-2 right-2 bottom-2 rounded-xl overflow-hidden hidden z-20 pointer-events-auto"></div>
                        <!-- Mission Toast -->
                        <div id="missionHUD" class="hidden absolute top-4 left-4 right-4 z-30 pointer-events-none">
                            <div class="bg-gradient-to-r from-orange-500 to-rose-500 text-white rounded-xl shadow-xl px-4 py-3">
                                <div class="flex items-center gap-2 mb-1">
                                    <span class="text-base">🏆</span>
                                    <span class="text-xs font-bold uppercase tracking-widest opacity-90">Challenge Mission</span>
                                </div>
                                <div class="font-bold text-sm mb-1" id="missionTitle">Complete the mission!</div>
                                <div class="text-xs opacity-90 mb-2 leading-snug" id="missionDesc" style="display:none;"></div>
                                <div id="missionObjectivesList" class="flex gap-2 flex-wrap"></div>
                            </div>
                        </div>
                        <style>
                            @keyframes ccPulse { 0%,100%{opacity:1;box-shadow:0 0 7px #4ade80;} 50%{opacity:0.5;box-shadow:0 0 2px #4ade80;} }
                        </style>
                    </div>

                    <!-- Tab switcher -->
                    <div class="flex border-t-2 border-gray-200">
                        <button id="tabBtnChat" onclick="switchRobotTab('chat')"
                            class="flex-1 py-1.5 text-xs font-bold bg-white text-indigo-600 border-b-2 border-indigo-500 transition-all">
                            💬 STEMO Chat
                        </button>
                        <button id="tabBtnCC" onclick="switchRobotTab('cc')"
                            class="flex-1 py-1.5 text-xs font-bold bg-gray-100 text-gray-500 border-b-2 border-transparent hover:bg-gray-200 transition-all">
                            📡 Command Center
                        </button>
                    </div>

                    <!-- STEMO Chat panel -->
                    <div id="panelChat" class="bg-white p-3">
                        <div id="chatMessages" class="h-14 overflow-y-auto mb-2 space-y-1 text-sm">
                            <div class="flex items-start gap-2">
                                <span class="text-xl">🤖</span>
                                <div class="bg-blue-100 rounded-lg p-2 text-sm">
                                    Click blocks to build your program, then press Run!
                                </div>
                            </div>
                        </div>
                        <div class="flex gap-2">
                            <input type="text" id="chatInput" placeholder="Ask STEMO for help..."
                                class="flex-1 border-2 border-gray-300 rounded-full px-4 py-2 text-sm focus:outline-none focus:border-indigo-400"
                                onkeypress="handleChatKeypress(event)">
                            <button onclick="sendChat()" class="bg-indigo-500 hover:bg-indigo-600 text-white w-10 h-10 rounded-full transition-all flex items-center justify-center">
                                <i class="fas fa-paper-plane"></i>
                            </button>
                        </div>
                    </div>

                    <!-- Command Center panel -->
                    <div id="panelCC" style="display:none;background:#0f172a;">
                        <!-- CC header -->
                        <div style="display:flex;align-items:center;gap:8px;padding:8px 12px;border-bottom:1px solid #1e293b;">
                            <div id="ccPulseDot" style="width:9px;height:9px;border-radius:50%;background:#4ade80;box-shadow:0 0 7px #4ade80;animation:ccPulse 1.5s infinite;flex-shrink:0;"></div>
                            <span style="color:#4ade80;font-family:monospace;font-size:11px;font-weight:700;letter-spacing:1px;">COMMAND CENTER — UPLINK ACTIVE</span>
                            <button onclick="clearCC()" title="Clear log" style="margin-left:auto;background:rgba(255,255,255,0.08);border:none;color:#6b7280;font-size:10px;border-radius:4px;padding:1px 7px;cursor:pointer;">CLR</button>
                        </div>
                        <!-- Transmission log -->
                        <div id="ccMessages" style="height:96px;overflow-y:auto;font-family:monospace;font-size:11px;line-height:1.6;padding:6px 12px;">
                            <div style="color:#374151;">// Waiting for transmissions from STEMO...</div>
                            <div style="color:#374151;">// Use the 📡 Send to Command Center block to transmit data.</div>
                        </div>
                        <!-- Send-order input -->
                        <div style="display:flex;gap:6px;align-items:center;padding:6px 12px;border-top:1px solid #1e293b;">
                            <span style="color:#38bdf8;font-family:monospace;font-size:11px;font-weight:700;">⌨</span>
                            <input id="ccInput" placeholder="Send order to STEMO…" onkeypress="ccInputKeypress(event)"
                                style="flex:1;background:#1e293b;color:#e2e8f0;border:1px solid #334155;border-radius:6px;padding:4px 10px;font-family:monospace;font-size:11px;outline:none;"
                                onfocus="this.style.borderColor='#38bdf8'" onblur="this.style.borderColor='#334155'">
                            <button onclick="sendCCCommand()" title="Send order" style="background:#0ea5e9;border:none;color:white;font-size:12px;width:28px;height:28px;border-radius:6px;cursor:pointer;">▲</button>
                        </div>
                    </div>
                </div>
            </div>

            <div id="hintPanel" class="mt-2 bg-gradient-to-r from-amber-100 to-yellow-100 rounded-xl p-3 border-2 border-yellow-300 hidden">
                <div class="flex items-center gap-2">
                    <span class="text-xl">💡</span>
                    <div>
                        <h4 class="font-bold text-amber-800 text-xs">Hint:</h4>
                        <p id="hintText" class="text-amber-700 text-xs"></p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Achievements Tab -->
        <div id="achievements-section" class="hidden">
            <div class="bg-white rounded-3xl card-shadow p-6 mb-8">
                <h3 class="text-2xl font-bold text-gray-800 mb-4">
                    <i class="fas fa-chart-line text-indigo-500 mr-2"></i>Your Progress
                </h3>
                <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
                    <div class="bg-gradient-to-br from-indigo-500 to-purple-600 rounded-2xl p-5 text-white text-center">
                        <div class="text-4xl mb-2">⭐</div>
                        <div class="text-3xl font-bold" id="totalXP">0</div>
                        <div class="text-purple-200">Total XP</div>
                    </div>
                    <div class="bg-gradient-to-br from-green-500 to-emerald-600 rounded-2xl p-5 text-white text-center">
                        <div class="text-4xl mb-2">✅</div>
                        <div class="text-3xl font-bold" id="lessonsCompleted">0</div>
                        <div class="text-green-200">Lessons Done</div>
                    </div>
                    <div class="bg-gradient-to-br from-orange-500 to-amber-600 rounded-2xl p-5 text-white text-center">
                        <div class="text-4xl mb-2">🔥</div>
                        <div class="text-3xl font-bold" id="streakDays">1</div>
                        <div class="text-orange-200">Day Streak</div>
                    </div>
                    <div class="bg-gradient-to-br from-pink-500 to-rose-600 rounded-2xl p-5 text-white text-center">
                        <div class="text-4xl mb-2">🏆</div>
                        <div class="text-3xl font-bold" id="badgesEarned">0</div>
                        <div class="text-pink-200">Badges</div>
                    </div>
                </div>
            </div>

            <h3 class="text-2xl font-bold text-gray-800 mb-4">
                <i class="fas fa-medal text-yellow-500 mr-2"></i>Badges Collection
            </h3>
            <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4" id="badgesGrid"></div>
        </div>

        <!-- Profile Tab -->
        <div id="profile-section" class="hidden">
            <div class="max-w-2xl mx-auto space-y-6">
                <!-- Profile Card -->
                <div class="bg-white rounded-3xl card-shadow p-8">
                    <div class="flex items-center gap-6 mb-6">
                        <div class="w-20 h-20 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-full flex items-center justify-center text-4xl font-bold text-white" id="profileAvatar">🎓</div>
                        <div>
                            <h2 class="text-3xl font-bold text-gray-800" id="profileName">Loading...</h2>
                            <p class="text-gray-400 text-lg">@<span id="profileUsername">-</span></p>
                            <span class="bg-indigo-100 text-indigo-700 text-sm font-bold px-3 py-1 rounded-full mt-1 inline-block">🎓 Student</span>
                        </div>
                    </div>
                    <div id="profileClassInfo" class="bg-gray-50 rounded-2xl p-4 mb-4 space-y-2"></div>
                    <div class="text-gray-400 text-xs" id="profileJoined"></div>
                </div>
                <!-- Assigned Lesson Banner -->
                <div id="profileLessonBanner" class="hidden bg-gradient-to-r from-indigo-500 to-purple-600 rounded-2xl p-5 text-white">
                    <div class="flex items-center gap-4 flex-wrap">
                        <span class="text-4xl" id="profileLessonIcon">📖</span>
                        <div class="flex-1">
                            <div class="text-sm font-bold text-purple-200">Your teacher assigned:</div>
                            <div class="text-xl font-bold" id="profileLessonTitle">-</div>
                        </div>
                        <button onclick="switchTab('learn')" class="bg-white text-indigo-600 px-4 py-2 rounded-full font-bold text-sm hover:bg-yellow-300 transition-all">Go to Lesson →</button>
                    </div>
                </div>
                <!-- Stats -->
                <div class="bg-white rounded-3xl card-shadow p-6">
                    <h3 class="text-lg font-bold text-gray-700 mb-4"><i class="fas fa-chart-line text-indigo-400 mr-2"></i>My Stats</h3>
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div class="bg-gradient-to-br from-indigo-500 to-purple-600 rounded-2xl p-4 text-white text-center">
                            <div class="text-2xl mb-1">⭐</div>
                            <div class="text-2xl font-bold" id="profileXP">0</div>
                            <div class="text-purple-200 text-xs">Total XP</div>
                        </div>
                        <div class="bg-gradient-to-br from-green-500 to-emerald-600 rounded-2xl p-4 text-white text-center">
                            <div class="text-2xl mb-1">✅</div>
                            <div class="text-2xl font-bold" id="profileLessons">0</div>
                            <div class="text-green-200 text-xs">Lessons Done</div>
                        </div>
                        <div class="bg-gradient-to-br from-orange-500 to-amber-600 rounded-2xl p-4 text-white text-center">
                            <div class="text-2xl mb-1">🔥</div>
                            <div class="text-2xl font-bold" id="profileStreak">0</div>
                            <div class="text-orange-200 text-xs">Day Streak</div>
                        </div>
                        <div class="bg-gradient-to-br from-pink-500 to-rose-600 rounded-2xl p-4 text-white text-center">
                            <div class="text-2xl mb-1">🏆</div>
                            <div class="text-2xl font-bold" id="profileBadges">0</div>
                            <div class="text-pink-200 text-xs">Badges</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Leaderboard Tab -->
        <div id="leaderboard-section" class="hidden">
            <div class="bg-white rounded-3xl card-shadow p-6">
                <div class="flex items-center justify-between mb-6">
                    <h3 class="text-2xl font-bold text-gray-800">
                        <i class="fas fa-trophy text-yellow-500 mr-2"></i>Student Leaderboard
                    </h3>
                    <button onclick="loadLeaderboard()" class="bg-indigo-100 hover:bg-indigo-200 text-indigo-700 px-4 py-2 rounded-full text-sm font-bold transition-all">🔄 Refresh</button>
                </div>
                <!-- Top 3 podium -->
                <div class="flex justify-center gap-4 mb-8" id="podiumRow"></div>
                <!-- Full ranking table -->
                <div id="leaderboardList" class="space-y-2"></div>
            </div>
        </div>
    </div>

    <!-- Mode Picker Modal -->
    <div id="modePickerModal" class="fixed inset-0 bg-black/60 flex items-center justify-center z-50 hidden backdrop-blur-sm">
        <div class="bg-white rounded-3xl p-8 max-w-lg w-full mx-4 shadow-2xl">
            <div class="text-center mb-6">
                <div class="text-5xl mb-3" id="modePickerIcon">🤖</div>
                <h2 class="text-2xl font-bold text-gray-800" id="modePickerTitle">Choose Your Mode</h2>
                <p class="text-gray-500 text-sm mt-1" id="modePickerDesc">How do you want to start this lesson?</p>
            </div>
            <div class="grid grid-cols-2 gap-4">
                <!-- Free Build -->
                <button onclick="startFreeBuildMode()" class="group flex flex-col items-center gap-3 p-6 border-2 border-gray-200 hover:border-indigo-400 hover:bg-indigo-50 rounded-2xl transition-all cursor-pointer">
                    <div class="text-4xl group-hover:scale-110 transition-transform">🏗️</div>
                    <div class="font-bold text-gray-800 text-lg">Free Build</div>
                    <div class="text-gray-500 text-xs text-center">Place your own objects and experiment freely. No rules — just explore!</div>
                    <div class="bg-indigo-100 text-indigo-700 text-xs font-bold px-3 py-1 rounded-full">Sandbox Mode</div>
                </button>
                <!-- Challenge Mode -->
                <button onclick="startChallengeMode()" class="group flex flex-col items-center gap-3 p-6 border-2 border-orange-200 hover:border-orange-500 hover:bg-orange-50 rounded-2xl transition-all cursor-pointer">
                    <div class="text-4xl group-hover:scale-110 transition-transform">🏆</div>
                    <div class="font-bold text-gray-800 text-lg">Challenge</div>
                    <div class="text-gray-500 text-xs text-center">A pre-set mission loads. Complete the objective to win XP!</div>
                    <div class="bg-orange-100 text-orange-700 text-xs font-bold px-3 py-1 rounded-full" id="modePickerXP">+XP Challenge</div>
                </button>
            </div>
            <button onclick="closeModePicker()" class="w-full mt-4 text-gray-400 hover:text-gray-600 text-sm py-2 transition-colors">← Back to lesson info</button>
        </div>
    </div>

    <!-- Success Modal -->
    <div id="successModal" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 hidden">
        <div class="bg-white rounded-3xl p-8 text-center max-w-md mx-4 transform scale-0 transition-transform" id="successModalContent">
            <div class="text-8xl mb-4">🎉</div>
            <h2 class="text-3xl font-bold text-gray-800 mb-2">Amazing!</h2>
            <p class="text-gray-600 mb-4" id="successMessage">You completed the challenge!</p>
            <div id="xpBanner" class="bg-gradient-to-r from-yellow-400 to-amber-500 rounded-2xl p-4 mb-6">
                <div class="text-white font-bold text-lg" id="xpBannerLabel">You earned</div>
                <div class="text-4xl font-bold text-white" id="xpEarned">+50 XP</div>
            </div>
            <button onclick="saveProject()" class="w-full bg-indigo-100 hover:bg-indigo-200 text-indigo-700 px-6 py-2.5 rounded-full font-bold transition-all mb-3 flex items-center justify-center gap-2">
                <i class="fas fa-save"></i> Save my work
            </button>
            <div class="flex gap-3 justify-center flex-wrap">
                <button onclick="goToLessons()" class="bg-gray-200 hover:bg-gray-300 text-gray-700 px-5 py-3 rounded-full font-bold transition-all">
                    <i class="fas fa-home mr-2"></i>All Lessons
                </button>
                <button onclick="closeSuccessModal()" class="bg-indigo-100 hover:bg-indigo-200 text-indigo-700 px-5 py-3 rounded-full font-bold transition-all">
                    <i class="fas fa-redo mr-2"></i>Keep Practising
                </button>
                <button onclick="goToNextLesson()" id="nextLessonBtn" class="bg-gradient-to-r from-green-500 to-emerald-600 text-white px-5 py-3 rounded-full font-bold hover:opacity-90 transition-all">
                    Next Lesson <i class="fas fa-arrow-right ml-2"></i>
                </button>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="text-center py-8 mt-6 border-t border-purple-100 bg-white/60">
        <p class="text-gray-400 text-sm">© 2026 STEMO · Science Games</p>
        <p class="text-gray-300 text-xs mt-1">أكاديمية ستيم لألعاب العلوم</p>
    </footer>

    <script>
        // ============================================
        // STEMO STATE MANAGEMENT
        // ============================================
        var stemo = {
            xp: parseInt(localStorage.getItem('stemo_xp') || '0'),
            level: parseInt(localStorage.getItem('stemo_level') || '1'),
            completedLessons: JSON.parse(localStorage.getItem('stemo_completed') || '[]'),
            badges: JSON.parse(localStorage.getItem('stemo_badges') || '[]'),
            streak: parseInt(localStorage.getItem('stemo_streak') || '1')
        };

        var robot = {
            x: 275,
            y: 275,
            angle: -90,
            penDown: false,
            penColor: '#6366f1',
            penSize: 4,
            trails: [],
            visible: true,
            magnetOn: false,
            carrying: null,
            waterLevel: 10,
            spraying: false,
            lastTemp: 25
        };

        // ============================================
        // SOUND SYSTEM — Web Audio synthesized effects
        // (No external audio files — all sounds generated in-browser)
        // ============================================
        // Safe localStorage wrappers — Safari private mode / restricted contexts
        // can throw on access, which would otherwise break the entire script.
        function safeStorageGet(k) {
            try { return window.localStorage && localStorage.getItem(k); } catch (e) { return null; }
        }
        function safeStorageSet(k, v) {
            try { if (window.localStorage) localStorage.setItem(k, v); } catch (e) { /* ignore */ }
        }
        var soundEnabled = (safeStorageGet('stemoSound') !== 'off');
        var audioCtx = null;
        var audioUnlocked = false;
        // Throttle repetitive SFX so long programs don't stack hundreds of nodes.
        var lastSoundAt = {};
        var SOUND_COOLDOWN = { move: 80, turn: 80, spray: 120, click: 30 };
        function getAudioCtx() {
            if (!soundEnabled) return null;
            if (!audioCtx) {
                try {
                    var AC = window.AudioContext || window.webkitAudioContext;
                    if (!AC) return null;
                    audioCtx = new AC();
                } catch (e) { return null; }
            }
            if (audioCtx.state === 'suspended') {
                try { audioCtx.resume(); } catch (e) { /* ignore */ }
            }
            return audioCtx;
        }
        // Explicit audio-unlock bootstrap for iOS Safari etc.: the first
        // trusted user gesture creates/resumes the context, then we detach.
        function unlockAudio() {
            audioUnlocked = true;
            var ctx = getAudioCtx();
            if (ctx) {
                // Play a near-silent blip to fully unlock on iOS
                try {
                    var o = ctx.createOscillator();
                    var g = ctx.createGain();
                    g.gain.value = 0.0001;
                    o.connect(g); g.connect(ctx.destination);
                    o.start(); o.stop(ctx.currentTime + 0.01);
                } catch (e) { /* ignore */ }
            }
            window.removeEventListener('pointerdown', unlockAudio, true);
            window.removeEventListener('keydown', unlockAudio, true);
            window.removeEventListener('touchstart', unlockAudio, true);
        }
        window.addEventListener('pointerdown', unlockAudio, true);
        window.addEventListener('keydown', unlockAudio, true);
        window.addEventListener('touchstart', unlockAudio, true);
        function tone(freq, dur, type, gain, freqEnd) {
            var ctx = getAudioCtx();
            if (!ctx) return;
            var osc = ctx.createOscillator();
            var g = ctx.createGain();
            osc.type = type || 'sine';
            osc.frequency.setValueAtTime(freq, ctx.currentTime);
            if (typeof freqEnd === 'number') {
                osc.frequency.exponentialRampToValueAtTime(Math.max(1, freqEnd), ctx.currentTime + dur);
            }
            var peak = (gain == null ? 0.15 : gain);
            g.gain.setValueAtTime(0.0001, ctx.currentTime);
            g.gain.exponentialRampToValueAtTime(peak, ctx.currentTime + 0.01);
            g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + dur);
            osc.connect(g); g.connect(ctx.destination);
            osc.start();
            osc.stop(ctx.currentTime + dur + 0.02);
        }
        function noiseBurst(dur, gain, filterFreq) {
            var ctx = getAudioCtx();
            if (!ctx) return;
            var buf = ctx.createBuffer(1, Math.floor(ctx.sampleRate * dur), ctx.sampleRate);
            var data = buf.getChannelData(0);
            for (var i = 0; i < data.length; i++) data[i] = Math.random() * 2 - 1;
            var src = ctx.createBufferSource(); src.buffer = buf;
            var filt = ctx.createBiquadFilter();
            filt.type = 'lowpass'; filt.frequency.value = filterFreq || 1500;
            var g = ctx.createGain();
            var peak = (gain == null ? 0.12 : gain);
            g.gain.setValueAtTime(peak, ctx.currentTime);
            g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + dur);
            src.connect(filt); filt.connect(g); g.connect(ctx.destination);
            src.start(); src.stop(ctx.currentTime + dur);
        }
        function playSound(name) {
            if (!soundEnabled) return;
            // Per-sound cooldown to avoid stacking dozens of oscillators on
            // long programs (e.g. lots of consecutive move/turn steps).
            var cd = SOUND_COOLDOWN[name];
            if (cd) {
                var now = Date.now();
                if (lastSoundAt[name] && now - lastSoundAt[name] < cd) return;
                lastSoundAt[name] = now;
            }
            try {
                switch (name) {
                    case 'click':      tone(660, 0.05, 'square', 0.06); break;
                    case 'move':       tone(220, 0.08, 'sawtooth', 0.07, 280); break;
                    case 'turn':       tone(440, 0.10, 'triangle', 0.08, 540); break;
                    case 'magnet_on':  tone(300, 0.12, 'sine', 0.12, 700);
                                       setTimeout(function(){ tone(900, 0.08, 'sine', 0.10); }, 90); break;
                    case 'magnet_off': tone(700, 0.10, 'sine', 0.10, 250); break;
                    case 'pickup':     tone(523, 0.08, 'triangle', 0.13);
                                       setTimeout(function(){ tone(784, 0.10, 'triangle', 0.13); }, 70);
                                       setTimeout(function(){ tone(1047, 0.12, 'triangle', 0.13); }, 150); break;
                    case 'spray':      noiseBurst(0.30, 0.10, 2200); break;
                    case 'fire_out':   noiseBurst(0.45, 0.14, 900);
                                       setTimeout(function(){ tone(880, 0.10, 'sine', 0.10);
                                                              setTimeout(function(){ tone(1320, 0.15, 'sine', 0.10); }, 90); }, 300); break;
                    case 'bonk':       tone(120, 0.12, 'square', 0.18, 60);
                                       noiseBurst(0.08, 0.12, 400); break;
                    case 'success':    tone(523, 0.10, 'triangle', 0.13);
                                       setTimeout(function(){ tone(659, 0.10, 'triangle', 0.13); }, 100);
                                       setTimeout(function(){ tone(784, 0.10, 'triangle', 0.13); }, 200);
                                       setTimeout(function(){ tone(1047, 0.18, 'triangle', 0.14); }, 300); break;
                }
            } catch (e) { /* never let sound break gameplay */ }
        }
        function toggleSound() {
            soundEnabled = !soundEnabled;
            safeStorageSet('stemoSound', soundEnabled ? 'on' : 'off');
            var btn = document.getElementById('soundToggleBtn');
            if (btn) btn.textContent = soundEnabled ? '🔊' : '🔇';
            if (soundEnabled) playSound('click');
        }
        // Reflect persisted state in the button as soon as DOM is ready
        document.addEventListener('DOMContentLoaded', function() {
            var btn = document.getElementById('soundToggleBtn');
            if (btn) btn.textContent = soundEnabled ? '🔊' : '🔇';
        });

        
        var robotPanelVisible = true;

        var penColors = ['#6366f1', '#22c55e', '#f59e0b', '#ef4444', '#ec4899', '#8b5cf6'];
        var currentColorIndex = 0;
        var currentLesson = null;
        var workspace = null;
        
        // Metal objects on the board
        var metalObjects = [];
        var metalIdCounter = 0;
        
        // Wall objects for ultrasonic sensor
        var wallObjects = [];
        var wallIdCounter = 0;
        
        // Fire objects for temperature sensor
        var fireObjects = [];
        var fireIdCounter = 0;
        
        // Target point for navigation
        var targetPoint = null;

        // ============================================
        // VARIABLES SYSTEM
        // ============================================
        // Named variables students can set and reuse
        var robotVars = { speed: 3, count: 4, angle: 90, distance: 5 };
        var userFunctions = {};  // stores { funcName: [commands] }

        // Saved positions: A, B, C, D — store x,y coordinates
        var savedPositions = { A: null, B: null, C: null, D: null };

        // Waypoint list — a list of {x, y} locations
        var waypointList = [];
        
        // Placement mode: 'none', 'wall', 'target', 'metal'
        var placementMode = null; // null = Select mode (click objects to select/delete)
        
        // ============================================
        // CHALLENGE MODE STATE
        // ============================================
        var challengeMode = false;
        var challengeActiveLessonId = null; // locked at launch; never changes when "Next Lesson" is clicked
        var missionObjectives = null;
        var challengeCompleted = false;

        var MISSION_LESSON_IDS = ['lesson-4','lesson-5','lesson-6','lesson-7','lesson-8','lesson-9','lesson-10','lesson-11','lesson-12','lesson-13','lesson-14','lesson-15','lesson-16','lesson-17','lesson-18','lesson-19'];

        // Ghost trails drawn on canvas as the "target pattern" for drawing challenges
        var targetTrails = [];

        // Pre-configured challenge worlds for each mission lesson
        // Canvas: 550x550, STEMO starts at center (275, 275)
        var LESSON_CHALLENGES = {
            'lesson-4': {
                title: 'Draw the Colour Square! 🟥🟦🟩🟪',
                description: 'Draw a square where each side is a different colour. Use Color + Size blocks and turn 90° between each side!',
                setup: function() {
                    // Ghost: 4 coloured sides of a square starting at (175,175), 100px per side
                    var cols = ['#ef4444','#6366f1','#22c55e','#a855f7'];
                    var simX = 175, simY = 175, simAngle = 0;
                    targetTrails = [];
                    for (var i = 0; i < 4; i++) {
                        var rad = simAngle * Math.PI / 180;
                        var nx = simX + Math.cos(rad) * 100;
                        var ny = simY + Math.sin(rad) * 100;
                        targetTrails.push({ x1: simX, y1: simY, x2: nx, y2: ny, color: cols[i] });
                        simX = nx; simY = ny;
                        simAngle += 90;
                    }
                },
                objectives: [
                    { id: 'colors', label: '🎨 Use 4 different colours', check: function() {
                        var seen = {};
                        robot.trails.forEach(function(t) { seen[t.color] = true; });
                        return Object.keys(seen).length >= 4;
                    }},
                    { id: 'size', label: '🖌️ Use pen Size 5 or bigger', check: function() {
                        return robot.trails.some(function(t) { return (t.size || 4) >= 5; });
                    }},
                    { id: 'shape', label: '⬜ Draw 4 sides (4+ segments)', check: function() {
                        return robot.trails.length >= 4;
                    }}
                ]
            },
            'lesson-5': {
                title: 'Build the Staircase! 🪜',
                description: 'Draw a staircase going up and right using a Repeat loop. Code: Repeat 4 → Forward 2, Right 90, Forward 2, Left 90',
                setup: function() {
                    // Ghost: 4-step staircase — starts at robot spawn (275,275), facing UP (-90°)
                    // Matches code: Repeat 4 → Forward 2, Right 90, Forward 2, Left 90
                    var simX = 275, simY = 275, simAngle = -90;
                    targetTrails = [];
                    for (var i = 0; i < 4; i++) {
                        // Vertical step (up) — green
                        var r1 = simAngle * Math.PI / 180;
                        var nx = simX + Math.cos(r1) * 40, ny = simY + Math.sin(r1) * 40;
                        targetTrails.push({ x1: simX, y1: simY, x2: nx, y2: ny, color: '#22c55e' });
                        simX = nx; simY = ny;
                        simAngle += 90; // Right 90 — now facing right
                        // Horizontal step (right) — purple
                        var r2 = simAngle * Math.PI / 180;
                        nx = simX + Math.cos(r2) * 40; ny = simY + Math.sin(r2) * 40;
                        targetTrails.push({ x1: simX, y1: simY, x2: nx, y2: ny, color: '#6366f1' });
                        simX = nx; simY = ny;
                        simAngle -= 90; // Left 90 — face up again
                    }
                },
                objectives: [
                    { id: 'loop', label: '🔁 Use a Repeat block', check: function() {
                        if (!workspace) return false;
                        return workspace.getAllBlocks().some(function(b) { return b.type === 'repeat_times'; });
                    }},
                    { id: 'segments', label: '🪜 Draw 8 segments (4 steps)', check: function() {
                        return robot.trails.length >= 8;
                    }},
                    { id: 'pen', label: '✏️ Use Pen Down to draw', check: function() {
                        return robot.trails.length > 0;
                    }}
                ]
            },
            'lesson-6': {
                title: 'Draw the Spin Star! ⭐',
                description: 'Copy the star pattern shown in ghost lines on the board. Use 3 colours, draw 4-sided shapes with loops, and rotate them!',
                setup: function() {
                    // Simulate the target pattern and store as ghost trails for canvas reference.
                    // Pattern: Repeat 8 → (Repeat 4 → Color red, Move 2, Color blue, Move 2,
                    //           Color black, Move 2, Right 90°) → Right 45°
                    // Each Move 2 = 40 px (2 × 20 px/step).  Robot starts at (275, 275).
                    var simX = 275, simY = 275, simAngle = 0;
                    var cols = ['#ef4444', '#6366f1', '#1e293b']; // red, blue, black
                    targetTrails = [];
                    var step = 40;
                    for (var i = 0; i < 8; i++) {
                        for (var j = 0; j < 4; j++) {
                            for (var c = 0; c < 3; c++) {
                                var rad = simAngle * Math.PI / 180;
                                var nx = simX + Math.cos(rad) * step;
                                var ny = simY + Math.sin(rad) * step;
                                targetTrails.push({ x1: simX, y1: simY, x2: nx, y2: ny, color: cols[c] });
                                simX = nx; simY = ny;
                            }
                            simAngle += 90;
                        }
                        simAngle += 45;
                    }
                },
                objectives: [
                    { id: 'colors', label: '🎨 Use 3+ different colours', check: function() {
                        var seen = {};
                        robot.trails.forEach(function(t) { seen[t.color] = true; });
                        return Object.keys(seen).length >= 3;
                    }},
                    { id: 'segments', label: '✏️ Draw 24+ line segments', check: function() {
                        return robot.trails.length >= 24;
                    }},
                    { id: 'loop', label: '🔁 Use a Repeat block', check: function() {
                        if (!workspace) return false;
                        return workspace.getAllBlocks().some(function(b) { return b.type === 'repeat_times'; });
                    }}
                ]
            },
            'lesson-7': {
                title: 'Draw an 8-Pointed Star! ✨',
                description: 'Use a Repeat 8 loop and the secret star angle (135°) to draw a beautiful 8-pointed star!',
                setup: function() {
                    // Ghost: 8-pointed star. 6 steps × 20px = 120px per segment
                    // Start at robot's exact spawn point (275,275), angle -90 = 270° (facing up)
                    var simX = 275, simY = 275, simAngle = 270;
                    targetTrails = [];
                    for (var i = 0; i < 8; i++) {
                        var rad = simAngle * Math.PI / 180;
                        var nx = simX + Math.cos(rad) * 120;
                        var ny = simY + Math.sin(rad) * 120;
                        targetTrails.push({ x1: simX, y1: simY, x2: nx, y2: ny, color: '#f59e0b' });
                        simX = nx; simY = ny;
                        simAngle += 135;
                    }
                },
                objectives: [
                    { id: 'loop', label: '🔁 Use a Repeat block', check: function() {
                        if (!workspace) return false;
                        return workspace.getAllBlocks().some(function(b) { return b.type === 'repeat_times'; });
                    }},
                    { id: 'angle', label: '↪️ Use a Right 135° turn', check: function() {
                        if (!workspace) return false;
                        return workspace.getAllBlocks().some(function(b) {
                            return b.type === 'turn_right' && Number(b.getFieldValue('DEGREES')) === 135;
                        });
                    }},
                    { id: 'segments', label: '✨ Draw 8 star lines', check: function() {
                        return robot.trails.length >= 8;
                    }}
                ]
            },
            'lesson-8': {
                title: 'Collect all 3 metal pieces!',
                description: 'Activate your magnet and navigate to pick up every metal object on the board.',
                setup: function() {
                    metalObjects = [
                        { id: metalIdCounter++, x: 130, y: 130, type: 'bolt',  pickedUp: false },
                        { id: metalIdCounter++, x: 420, y: 130, type: 'gear',  pickedUp: false },
                        { id: metalIdCounter++, x: 420, y: 420, type: 'screw', pickedUp: false }
                    ];
                },
                objectives: [
                    { id: 'metal-1', label: '🔩 Step 1: Pick up metal #1', check: function() {
                        return metalObjects.length > 0 && metalObjects[0].pickedUp;
                    }},
                    { id: 'metal-2', label: '🔩 Step 2: Pick up metal #2', check: function() {
                        return metalObjects.length > 1 && metalObjects[1].pickedUp;
                    }},
                    { id: 'metal-3', label: '🔩 Step 3: Pick up metal #3', check: function() {
                        return metalObjects.length > 2 && metalObjects[2].pickedUp;
                    }},
                    { id: 'go-home', label: '🏠 Step 4: Return home & Magnet OFF', check: function() {
                        var allCollected = metalObjects.every(function(m) { return m.pickedUp; });
                        var dx = robot.x - 275, dy = robot.y - 275;
                        return allCollected && Math.sqrt(dx*dx + dy*dy) < 35 && !robot.magnetOn;
                    }}
                ]
            },
            'lesson-9': {
                title: 'Two walls, two turns — reach the target!',
                description: 'STEMO starts facing UP (north). Use Repeat loops with "If Wall Within 2 steps → Turn Right, else Move 1" to navigate: turn right at the top wall (now facing east), keep going until the right wall triggers a second right turn (now facing south), then drive straight down to the target!',
                setup: function() {
                    wallObjects = [
                        // Top-left horizontal wall — STEMO hits this going north
                        // Bottom face at y=195 → STEMO at y=235 is exactly 2 steps away → Turn Right (faces east)
                        { id: wallIdCounter++, x: 115, y: 155, width: 180, height: 40 },
                        // Right vertical wall — STEMO hits this going east
                        // Left face at x=415 → STEMO at x=375 is exactly 2 steps away → Turn Right (faces south)
                        { id: wallIdCounter++, x: 415, y: 155, width: 40, height: 300 },
                        // Bottom horizontal — completes the L-shape visually (below the target)
                        { id: wallIdCounter++, x: 295, y: 455, width: 160, height: 40 }
                    ];
                    // Target is directly south after the two turns — 8 steps south from (375, 235)
                    targetPoint = { x: 375, y: 395 };
                },
                objectives: [
                    { id: 'reach', label: '🎯 Navigate both walls and reach the target!', check: function() {
                        if (!targetPoint) return false;
                        var dx = robot.x - targetPoint.x, dy = robot.y - targetPoint.y;
                        return Math.sqrt(dx*dx + dy*dy) < 40;
                    }}
                ]
            },
            'lesson-10': {
                title: 'Reach the target point!',
                description: 'Obstacles are in your way. Program STEMO to navigate around them and reach the goal.',
                setup: function() {
                    wallObjects = [
                        { id: wallIdCounter++, x: 185, y: 150, width: 40, height: 160 }, // vertical wall blocking centre
                        { id: wallIdCounter++, x: 295, y: 300, width: 160, height: 40 }  // horizontal wall bottom-right
                    ];
                    targetPoint = { x: 440, y: 440 };
                },
                objectives: [
                    { id: 'reach', label: '🎯 Reach the target', check: function() {
                        if (!targetPoint) return false;
                        var dx = robot.x - targetPoint.x, dy = robot.y - targetPoint.y;
                        return Math.sqrt(dx*dx + dy*dy) < 40;
                    }}
                ]
            },
            'lesson-11': {
                title: 'Escape the maze — 3 ways to win!',
                description: 'A 3×3 grid maze with wide corridors and dead ends. You can solve it three ways: (1) Manual: Turn Right, Repeat 7 Move, Turn Left, Repeat 7 Move. (2) If Wall: Repeat 25 → If Wall Within 2 → Turn Right, else Move 1. (3) Smart Navigate: place the block and let the AI find the shortest path!',
                setup: function() {
                    wallObjects = [
                        // === HORIZONTAL WALLS (row boundaries) ===
                        // Row 0–1 boundary (y=185–225): gap at col1 (x=225–325) and col2 (x=365–465)
                        { id: wallIdCounter++, x: 85,  y: 185, width: 140, height: 40 }, // col0 closed
                        { id: wallIdCounter++, x: 325, y: 185, width: 40,  height: 40 }, // vwall-1-2 section
                        // Row 1–2 boundary (y=325–365): gap at col1 (x=225–325) only
                        { id: wallIdCounter++, x: 85,  y: 325, width: 140, height: 40 }, // col0 closed
                        { id: wallIdCounter++, x: 325, y: 325, width: 180, height: 40 }, // vwall + col2 closed

                        // === VERTICAL WALLS (column boundaries) ===
                        // Col 0–1 boundary (x=185–225): gap at row1 (y=225–325) — dead-end west passage
                        { id: wallIdCounter++, x: 185, y: 85,  width: 40, height: 140 }, // row0 closed
                        { id: wallIdCounter++, x: 185, y: 325, width: 40, height: 140 }, // row2 closed
                        // Col 1–2 boundary (x=325–365): gap at row1 (y=225–325) — east passage to col2
                        { id: wallIdCounter++, x: 325, y: 85,  width: 40, height: 140 }, // row0 closed
                        { id: wallIdCounter++, x: 325, y: 365, width: 40, height: 100 }, // row2 closed

                        // === RIGHT BOUNDARY ===
                        { id: wallIdCounter++, x: 465, y: 25,  width: 40, height: 440 }  // closes right side
                    ];
                    // Target: center of top-right room (col2, row0)
                    targetPoint = { x: 415, y: 135 };
                },
                objectives: [
                    { id: 'reach', label: '🎯 Navigate through the maze and reach the target!', check: function() {
                        if (!targetPoint) return false;
                        var dx = robot.x - targetPoint.x, dy = robot.y - targetPoint.y;
                        return Math.sqrt(dx*dx + dy*dy) < 40;
                    }}
                ]
            },
            'lesson-12': {
                title: 'Detect both fires with your sensor!',
                description: 'Fires are hidden around the board. Scan with your temperature sensor to locate them both.',
                setup: function() {
                    wallObjects = [
                        { id: wallIdCounter++, x: 215, y: 215, width: 40, height: 40 }   // small centre obstacle
                    ];
                    fireObjects = [
                        { id: fireIdCounter++, x: 130, y: 420, health: 3 },  // bottom-left
                        { id: fireIdCounter++, x: 430, y: 160, health: 3 }   // top-right
                    ];
                },
                objectives: [
                    { id: 'detect1', label: '🌡️ Find fire 1', targetFire: 0, check: function() {
                        if (fireObjects.length < 1) return false;
                        var f = fireObjects[0];
                        var dx = robot.x - f.x, dy = robot.y - f.y;
                        return Math.sqrt(dx*dx + dy*dy) < 70;
                    }},
                    { id: 'detect2', label: '🌡️ Find fire 2', targetFire: 1, check: function() {
                        if (fireObjects.length < 2) return false;
                        var f = fireObjects[1];
                        var dx = robot.x - f.x, dy = robot.y - f.y;
                        return Math.sqrt(dx*dx + dy*dy) < 70;
                    }}
                ]
            },
            'lesson-13': {
                title: 'Extinguish all 3 fires!',
                description: 'Navigate around walls and spray water on every fire before your tank runs out!',
                setup: function() {
                    wallObjects = [
                        { id: wallIdCounter++, x: 175, y: 155, width: 130, height: 40 },  // horizontal top wall
                        { id: wallIdCounter++, x: 345, y: 295, width: 40, height: 130 }   // vertical right wall
                    ];
                    fireObjects = [
                        { id: fireIdCounter++, x: 110, y: 270, health: 3 },  // left side
                        { id: fireIdCounter++, x: 270, y: 110, health: 3 },  // top area
                        { id: fireIdCounter++, x: 430, y: 430, health: 3 }   // bottom-right corner
                    ];
                    robot.waterLevel = 9;
                },
                objectives: [
                    { id: 'extinguish', label: '💧 Extinguish all fires', check: function() {
                        return fireObjects.length > 0 && fireObjects.every(function(f){ return f.health <= 0; });
                    }}
                ]
            },
            'lesson-14': {
                title: 'The Ultimate Challenge!',
                description: 'Collect metals, extinguish fires, and reach the target. Use everything you have learned!',
                setup: function() {
                    wallObjects = [
                        { id: wallIdCounter++, x: 165, y: 130, width: 40, height: 130 },  // vertical left
                        { id: wallIdCounter++, x: 310, y: 230, width: 130, height: 40 },  // horizontal right
                        { id: wallIdCounter++, x: 240, y: 375, width: 110, height: 40 }   // horizontal bottom
                    ];
                    metalObjects = [
                        { id: metalIdCounter++, x: 110, y: 420, type: 'bolt', pickedUp: false },  // bottom-left
                        { id: metalIdCounter++, x: 440, y: 110, type: 'gear', pickedUp: false }   // top-right
                    ];
                    fireObjects = [
                        { id: fireIdCounter++, x: 100, y: 195, health: 3 },   // left side
                        { id: fireIdCounter++, x: 430, y: 400, health: 3 }    // bottom-right
                    ];
                    targetPoint = { x: 440, y: 275 };
                    robot.waterLevel = 6;
                },
                objectives: [
                    { id: 'metal', label: '🔩 Collect 1+ metal', check: function() {
                        return metalObjects.some(function(m){ return m.pickedUp; });
                    }},
                    { id: 'fire', label: '💧 Extinguish fires', check: function() {
                        return fireObjects.length > 0 && fireObjects.every(function(f){ return f.health <= 0; });
                    }},
                    { id: 'reach', label: '🎯 Reach target', check: function() {
                        if (!targetPoint) return false;
                        var dx = robot.x - targetPoint.x, dy = robot.y - targetPoint.y;
                        return Math.sqrt(dx*dx + dy*dy) < 40;
                    }}
                ]
            },

            // Lesson 15 — Variable Vault
            'lesson-15': {
                title: 'Variable Vault — change one number, change everything!',
                description: '1️⃣ Pen Down  2️⃣ Repeat [Var: count] times → Move [Var: speed] steps + Turn [Var: angle] degrees  3️⃣ Run! Variables speed=4, count=4, angle=90 are already set for you.',
                setup: function() {
                    robotVars = { speed: 4, count: 4, angle: 90, distance: 5 };
                    savedPositions = { A: null, B: null, C: null, D: null };
                    waypointList = [];
                    wallObjects = [];
                    targetPoint = null;
                },
                objectives: [
                    { id: 'moved', label: '📦 Use a variable to move STEMO (trail length > 200px)', check: function() {
                        var total = 0;
                        targetTrails.forEach(function(t){ total += Math.sqrt((t.x2-t.x1)*(t.x2-t.x1)+(t.y2-t.y1)*(t.y2-t.y1)); });
                        return total > 200;
                    }},
                    { id: 'closed', label: '🔁 Draw a closed shape (return within 80px of start)', check: function() {
                        var dx = robot.x - 275, dy = robot.y - 275;
                        return Math.sqrt(dx*dx+dy*dy) < 80;
                    }}
                ]
            },

            // Lesson 16 — Position Memory
            'lesson-16': {
                title: 'Position Memory — save your spot and return home!',
                description: 'Use Save Position A at the start. Navigate to the target. Then Go to Position A to return. Like setting a GPS home point!',
                setup: function() {
                    robotVars = { speed: 3, count: 4, angle: 90, distance: 5 };
                    savedPositions = { A: null, B: null, C: null, D: null };
                    waypointList = [];
                    wallObjects = [
                        { id: wallIdCounter++, x: 185, y: 185, width: 40, height: 160 },
                        { id: wallIdCounter++, x: 185, y: 325, width: 200, height: 40 }
                    ];
                    targetPoint = { x: 415, y: 135 };
                },
                objectives: [
                    { id: 'target', label: '🎯 Reach the target', check: function() {
                        if (!targetPoint) return false;
                        var dx = robot.x - targetPoint.x, dy = robot.y - targetPoint.y;
                        return Math.sqrt(dx*dx+dy*dy) < 40;
                    }},
                    { id: 'home', label: '🏠 Return to start (within 60px)', check: function() {
                        var dx = robot.x - 275, dy = robot.y - 275;
                        return Math.sqrt(dx*dx+dy*dy) < 60;
                    }}
                ]
            },

            // Lesson 17 — Waypoint Trail
            'lesson-17': {
                title: 'Waypoint Trail — record a path, replay it automatically!',
                description: 'Three metal pieces are waiting. The waypoint list is pre-loaded with their locations. Turn Magnet ON, then Replay Path to visit all three and collect them all!',
                setup: function() {
                    robotVars = { speed: 3, count: 3, angle: 90, distance: 5 };
                    savedPositions = { A: null, B: null, C: null, D: null };
                    metalObjects = [
                        { id: metalIdCounter++, x: 135, y: 135, type: 'bolt',  pickedUp: false },
                        { id: metalIdCounter++, x: 415, y: 275, type: 'gear',  pickedUp: false },
                        { id: metalIdCounter++, x: 135, y: 415, type: 'bolt',  pickedUp: false }
                    ];
                    waypointList = [
                        { x: 135, y: 135 },
                        { x: 415, y: 275 },
                        { x: 135, y: 415 }
                    ];
                    wallObjects = [];
                    targetPoint = null;
                },
                objectives: [
                    { id: 'metals', label: '🔩 Collect all 3 metal pieces using Replay Path', check: function() {
                        return metalObjects.length === 3 && metalObjects.every(function(m){ return m.pickedUp; });
                    }}
                ]
            },

            // Lesson 18 — List Hunt
            'lesson-18': {
                title: 'List Hunt — loop through a list and act on each item!',
                description: '3 fires are pre-loaded in the waypoint list. Use "For Each Waypoint" with ONLY "Spray Water" inside the do block — the block navigates to each fire automatically. Do NOT add Go to Position blocks inside the loop!',
                setup: function() {
                    robotVars = { speed: 3, count: 3, angle: 90, distance: 5 };
                    savedPositions = { A: null, B: null, C: null, D: null };
                    fireObjects = [
                        { id: fireIdCounter++, x: 135, y: 135, health: 3 },
                        { id: fireIdCounter++, x: 415, y: 275, health: 3 },
                        { id: fireIdCounter++, x: 135, y: 415, health: 3 }
                    ];
                    waypointList = [
                        { x: 135, y: 135 },
                        { x: 415, y: 275 },
                        { x: 135, y: 415 }
                    ];
                    wallObjects = [];
                    targetPoint = null;
                    robot.waterLevel = 10;
                },
                objectives: [
                    { id: 'fires', label: '💧 Extinguish all 3 fires using For Each Waypoint', check: function() {
                        // Fires are removed from the array when extinguished — so all 3 gone means length === 0
                        return fireObjects.length === 0;
                    }}
                ]
            },

            // Lesson 19 — Function Factory
            'lesson-19': {
                title: 'Function Factory — write once, call forever!',
                description: 'Match the faded star on the canvas!  1️⃣ Define "drawSquare": Pen Down → Repeat 4× (Move 3 steps, Turn Right 90°)  2️⃣ Define "bigSquare": Repeat 4× (Call drawSquare, Turn Right 90°)  3️⃣ Call bigSquare → Turn Right 45° → Call bigSquare',
                setup: function() {
                    robotVars = { speed: 3, count: 4, angle: 90, distance: 5 };
                    savedPositions = { A: null, B: null, C: null, D: null };
                    waypointList = [];
                    wallObjects = [];
                    targetPoint = null;
                    fireObjects = [];
                    metalObjects = [];
                    userFunctions = {};
                    // Pre-draw the target star as a ghost guide on the canvas
                    targetTrails = [];
                    (function() {
                        var sx = 275, sy = 275, sa = -90;
                        function sm(steps) {
                            var d = steps * 20;
                            var nx = sx + d * Math.cos(sa * Math.PI / 180);
                            var ny = sy + d * Math.sin(sa * Math.PI / 180);
                            targetTrails.push({ x1: sx, y1: sy, x2: nx, y2: ny, color: '#f59e0b' });
                            sx = nx; sy = ny;
                        }
                        function st(deg) { sa += deg; }
                        function sq() { for (var i = 0; i < 4; i++) { sm(3); st(90); } }
                        function big() { for (var i = 0; i < 4; i++) { sq(); st(90); } }
                        big();       // first cross — 16 segments
                        st(45);      // rotate 45°
                        big();       // second cross — 16 segments (total 32)
                    })();
                },
                objectives: [
                    { id: 'funcs', label: '🔧 Define at least 2 functions', check: function() {
                        return Object.keys(userFunctions).length >= 2;
                    }},
                    { id: 'pattern', label: '🌟 Draw the star pattern (match the ghost guide)', check: function() {
                        return robot.trails.length >= 32;
                    }}
                ]
            }
        };

        // Ultrasonic sensor settings
        var sensorRange = 100; // pixels (5 steps)
        var showSensorBeam = true;
        
        // Board history for undo functionality
        var boardHistory = [];
        var maxHistorySize = 20;
        
        // Selected object for deletion
        var selectedObject = null;
        var selectedObjectType = null; // 'metal', 'wall', 'fire', 'target'
        
        // Isometric 3D view toggle
        var isIsometricView = false;

        // Current logged-in student (populated on init)
        var currentUser = null;

        // Lesson assigned by teacher (lesson ID string, e.g. 'lesson-3')
        var assignedLessonId = null;

        // Client-side curriculum cache (populated by loadLessons)
        var curriculumData = null;

        // ============================================
        // INITIALIZATION
        // ============================================
        document.addEventListener('DOMContentLoaded', function() {
            console.log('STEMO initializing...');
            // Load user info from injected data attribute
            var xpEl = document.getElementById('xpCounter');
            var userData = null;
            try { userData = JSON.parse(xpEl.getAttribute('data-user') || 'null'); } catch(e) {}
            if (userData) {
                currentUser = userData;
                document.getElementById('studentName').textContent = userData.full_name || userData.username;
                loadProgressFromDB(userData.id);
                loadProfile();
            } else {
                updateUI();
                loadLessons();
                loadBadges();
            }
            initBlockly();
            drawRobot();
            requestAnimationFrame(animationLoop);
            console.log('STEMO ready!');
        });

        // ============================================
        // ANIMATION LOOP - For realistic movement & effects
        // ============================================
        function animationLoop() {
            updateMagneticPull();
            drawRobot();
            requestAnimationFrame(animationLoop);
        }

        // Returns true if there is an active fire close enough to block this metal
        function hasFireOnMetal(metal) {
            for (var i = 0; i < fireObjects.length; i++) {
                var f = fireObjects[i];
                var dx = f.x - metal.x;
                var dy = f.y - metal.y;
                if (Math.sqrt(dx * dx + dy * dy) < 40) return true;
            }
            return false;
        }

        function updateMagneticPull() {
            if (!robot.magnetOn || robot.carrying) return;

            var pullRange = 120; // 6 steps
            var pullStrength = 1.5;

            metalObjects.forEach(function(metal) {
                if (!metal.pickedUp && !hasFireOnMetal(metal)) {
                    var dx = robot.x - metal.x;
                    var dy = robot.y - metal.y;
                    var dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < pullRange && dist > 15) {
                        // Move metal toward robot
                        var angle = Math.atan2(dy, dx);
                        metal.x += Math.cos(angle) * pullStrength;
                        metal.y += Math.sin(angle) * pullStrength;
                        
                        // Add a slight jitter/vibration for realism
                        metal.x += (Math.random() - 0.5) * 0.5;
                        metal.y += (Math.random() - 0.5) * 0.5;
                    }
                }
            });
        }

        function updateUI() {
            document.getElementById('xpCounter').textContent = stemo.xp;
            document.getElementById('levelCounter').textContent = stemo.level;
            document.getElementById('totalXP').textContent = stemo.xp;
            document.getElementById('lessonsCompleted').textContent = stemo.completedLessons.length;
            document.getElementById('streakDays').textContent = stemo.streak;
            document.getElementById('badgesEarned').textContent = stemo.badges.length;
        }

        // Save progress to D1 (and localStorage as fallback)
        async function saveProgress() {
            localStorage.setItem('stemo_xp', stemo.xp);
            localStorage.setItem('stemo_level', stemo.level);
            localStorage.setItem('stemo_completed', JSON.stringify(stemo.completedLessons));
            localStorage.setItem('stemo_badges', JSON.stringify(stemo.badges));
            localStorage.setItem('stemo_streak', stemo.streak);
            try {
                await fetch('/api/progress', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        xp: stemo.xp,
                        level: stemo.level,
                        completed_lessons: stemo.completedLessons,
                        earned_badges: stemo.badges,
                        streak: stemo.streak
                    })
                });
            } catch(e) { console.log('Progress saved locally only'); }
        }

        // Load progress from D1
        async function loadProgressFromDB(userId) {
            try {
                const res = await fetch('/api/progress/' + userId);
                const data = await res.json();
                if (data && data.xp !== undefined) {
                    stemo.xp = data.xp || 0;
                    stemo.level = data.level || 1;
                    stemo.completedLessons = JSON.parse(data.completed_lessons || '[]');
                    stemo.badges = JSON.parse(data.earned_badges || '[]');
                    stemo.streak = data.streak || 0;
                    updateUI();
                    loadLessons();
                    loadBadges();
                    updateProfileStats();
                }
            } catch(e) { console.log('Using local progress'); }
        }

        // Logout
        async function logoutStudent() {
            await fetch('/api/auth/logout', { method: 'POST' });
            window.location.href = '/login';
        }

        // ============================================
        // LESSONS
        // ============================================
        function loadLessons() {
            fetch('/api/curriculum')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    curriculumData = data;
                    var grid = document.getElementById('lessonsGrid');
                    var html = '';
                    
                    const levels = [
                        { name: 'Basic 🐣', key: 'basic' },
                        { name: 'Intermediate 🚀', key: 'intermediate' },
                        { name: 'Advanced 🏆', key: 'advanced' }
                    ];

                    levels.forEach(function(level) {
                        html += '<div class="col-span-full mt-6 mb-2"><h4 class="text-xl font-bold text-indigo-600 border-l-4 border-indigo-500 pl-3">' + level.name + '</h4></div>';
                        
                        data[level.key].forEach(function(lesson, index) {
                            var isCompleted = stemo.completedLessons.includes(lesson.id);
                            
                            // Unlocking logic: first lesson of basic is open. 
                            // Others need the previous lesson (in same or previous level) to be done.
                            var isLocked = false;
                            if (level.key === 'basic' && index > 0) {
                                isLocked = !stemo.completedLessons.includes(data.basic[index-1].id);
                            } else if (level.key === 'intermediate') {
                                if (index === 0) {
                                    isLocked = !stemo.completedLessons.includes(data.basic[data.basic.length-1].id);
                                } else {
                                    isLocked = !stemo.completedLessons.includes(data.intermediate[index-1].id);
                                }
                            } else if (level.key === 'advanced') {
                                if (index === 0) {
                                    isLocked = !stemo.completedLessons.includes(data.intermediate[data.intermediate.length-1].id);
                                } else {
                                    isLocked = !stemo.completedLessons.includes(data.advanced[index-1].id);
                                }
                            }

                            var lessonIcon = lesson.icon || '📚';
                            var icon = isCompleted ? '✅' : (isLocked ? '🔒' : lessonIcon);
                            
                            var diffGradient = lesson.difficulty === 'easy' ? 'from-green-400 to-emerald-500' : 
                                              (lesson.difficulty === 'medium' ? 'from-yellow-400 to-orange-500' : 'from-red-400 to-pink-500');
                            var diffClass = lesson.difficulty === 'easy' ? 'bg-green-100 text-green-700' :
                                           (lesson.difficulty === 'medium' ? 'bg-yellow-100 text-yellow-700' : 
                                           (lesson.difficulty === 'hard' ? 'bg-red-100 text-red-700' : 'bg-purple-100 text-purple-700'));
                            
                            var isAssigned = (lesson.id === assignedLessonId);
                            var assignedBadge = isAssigned ? '<span class="text-xs px-2 py-1 rounded-full bg-orange-100 text-orange-700 font-bold">📌 Assigned</span>' : '';
                            var assignedBorder = isAssigned ? ' ring-4 ring-orange-400 ring-offset-2' : '';
                            html += '<div class="lesson-card bg-white rounded-2xl card-shadow overflow-hidden cursor-pointer ' + (isLocked ? 'opacity-60 cursor-not-allowed' : '') + assignedBorder + '" ' +
                                    (isLocked ? '' : 'onclick="selectLesson(\\'' + lesson.id + '\\')"') + '>' +
                                    '<div class="h-3 bg-gradient-to-r ' + (isAssigned ? 'from-amber-400 to-orange-500' : diffGradient) + '"></div>' +
                                    '<div class="p-5">' +
                                    '<div class="flex items-center justify-between mb-3">' +
                                    '<span class="text-3xl">' + icon + '</span>' +
                                    '<span class="bg-yellow-100 text-yellow-700 px-3 py-1 rounded-full text-sm font-bold">+' + lesson.xpReward + ' XP</span>' +
                                    '</div>' +
                                    '<h4 class="font-bold text-lg text-gray-800 mb-1">' + lesson.title + '</h4>' +
                                    '<p class="text-gray-500 text-sm mb-3">' + lesson.description + '</p>' +
                                    '<div class="flex items-center gap-2 flex-wrap">' +
                                    '<span class="text-xs px-2 py-1 rounded-full ' + diffClass + '">' + lesson.difficulty + '</span>' +
                                    (isCompleted ? '<span class="text-xs text-green-600 font-bold">Completed!</span>' : '') +
                                    assignedBadge +
                                    '</div></div></div>';
                        });
                    });
                    
                    grid.innerHTML = html;
                });
        }

        function selectLesson(lessonId) {
            fetch('/api/lesson/' + lessonId)
                .then(function(response) { return response.json(); })
                .then(function(lesson) {
                    currentLesson = lesson;
                    showLessonDetail(lesson);
                });
        }
        
        function showLessonDetail(lesson) {
            // Hide lessons grid, show detail panel
            document.getElementById('lessonsGrid').style.display = 'none';
            document.getElementById('lessonDetailPanel').classList.remove('hidden');
            
            // Fill in lesson details
            document.getElementById('lessonIcon').textContent = lesson.icon || '📚';
            document.getElementById('lessonDetailTitle').textContent = lesson.title;
            document.getElementById('lessonDetailDesc').textContent = lesson.description;
            document.getElementById('lessonXP').textContent = '+' + lesson.xpReward + ' XP';
            document.getElementById('lessonIntro').textContent = lesson.introduction || lesson.hint;
            document.getElementById('lessonHintText').textContent = lesson.hint;
            document.getElementById('lessonHomeworkText').textContent = lesson.homework || "Try something creative with the blocks you just learned!";
            
            // Render tasks
            var tasksContainer = document.getElementById('lessonTasks');
            var tasksHtml = '';
            
            if (lesson.tasks && lesson.tasks.length > 0) {
                lesson.tasks.forEach(function(task, index) {
                    tasksHtml += '<div class="flex items-center gap-3 p-3 bg-gray-50 rounded-xl">' +
                        '<div class="w-8 h-8 rounded-full bg-indigo-100 text-indigo-600 flex items-center justify-center font-bold text-sm">' + (index + 1) + '</div>' +
                        '<span class="text-gray-700">' + task.text + '</span>' +
                        '</div>';
                });
            }
            
            tasksContainer.innerHTML = tasksHtml;
        }
        
        function hideLessonDetail() {
            document.getElementById('lessonsGrid').style.display = 'grid';
            document.getElementById('lessonDetailPanel').classList.add('hidden');
            currentLesson = null;
        }
        
        function startLessonFromDetail() {
            if (!currentLesson) return;
            
            // If this is a mission lesson, show the mode picker first
            if (MISSION_LESSON_IDS.indexOf(currentLesson.id) !== -1) {
                var challenge = LESSON_CHALLENGES[currentLesson.id];
                document.getElementById('modePickerIcon').textContent = currentLesson.icon || '🤖';
                document.getElementById('modePickerTitle').textContent = currentLesson.title;
                document.getElementById('modePickerDesc').textContent = currentLesson.description;
                document.getElementById('modePickerXP').textContent = '+' + currentLesson.xpReward + ' XP · Challenge';
                document.getElementById('modePickerModal').classList.remove('hidden');
                return;
            }
            
            // Non-mission lesson: go straight to free build
            _launchLesson(false);
        }

        function closeModePicker() {
            document.getElementById('modePickerModal').classList.add('hidden');
        }

        function startFreeBuildMode() {
            document.getElementById('modePickerModal').classList.add('hidden');
            _launchLesson(false);
        }

        function startChallengeMode() {
            document.getElementById('modePickerModal').classList.add('hidden');
            _launchLesson(true);
        }

        function exitChallengeMode() {
            challengeMode = false;
            challengeCompleted = false;
            missionObjectives = null;
            targetTrails = [];
            document.getElementById('missionHUD').classList.add('hidden');
            document.getElementById('missionBadge').classList.add('hidden');
            document.getElementById('missionExitBtn').classList.add('hidden');
            clearAll();
            addChatMessage('stemo', '🤖 Exited challenge mode. Board cleared — build freely!');
        }

        var missionToastTimer = null;
        function showMissionToast() {
            var hud = document.getElementById('missionHUD');
            hud.classList.remove('hidden');
            hud.style.opacity = '1';
            hud.style.transition = '';
            if (missionToastTimer) clearTimeout(missionToastTimer);
            missionToastTimer = setTimeout(function() {
                hud.style.transition = 'opacity 0.8s ease';
                hud.style.opacity = '0';
                setTimeout(function() { hud.classList.add('hidden'); hud.style.opacity = '1'; hud.style.transition = ''; }, 800);
            }, 3500);
        }

        function toggleMissionToast() {
            var hud = document.getElementById('missionHUD');
            if (hud.classList.contains('hidden')) {
                showMissionToast();
            } else {
                hud.classList.add('hidden');
                if (missionToastTimer) { clearTimeout(missionToastTimer); missionToastTimer = null; }
            }
        }

        function _launchLesson(withChallenge) {
            if (!currentLesson) return;
            
            challengeMode = withChallenge;
            challengeCompleted = false;

            // Set up the code view header
            document.getElementById('currentLessonTitle').textContent = currentLesson.title;
            document.getElementById('currentLessonDesc').textContent = currentLesson.description;
            document.getElementById('hintText').textContent = currentLesson.hint;
            document.getElementById('hintPanel').classList.remove('hidden');
            
            // Hide lesson detail and switch to code tab
            document.getElementById('lessonDetailPanel').classList.add('hidden');
            document.getElementById('lessonsGrid').style.display = 'grid';
            
            switchTab('code');
            resetRobot();
            clearWorkspace();

            // Clear board objects (without animation/messages)
            targetTrails = [];
            metalObjects = []; wallObjects = []; fireObjects = [];
            targetPoint = null; selectedObject = null; selectedObjectType = null;
            robot.waterLevel = 10; robot.spraying = false; robot.carrying = null; robot.magnetOn = false;

            if (withChallenge) {
                challengeActiveLessonId = currentLesson.id; // snapshot now — won't drift when Next Lesson loads
                var challenge = LESSON_CHALLENGES[currentLesson.id];
                if (challenge) {
                    // Set up mission objectives state
                    missionObjectives = challenge.objectives.map(function(obj) {
                        return { id: obj.id, label: obj.label, done: false, check: obj.check };
                    });
                    // Prime the toast content
                    document.getElementById('missionTitle').textContent = challenge.title;
                    var descEl = document.getElementById('missionDesc');
                    if (descEl && challenge.description) { descEl.textContent = challenge.description; descEl.style.display = 'block'; }
                    updateMissionHUD();
                    addChatMessage('stemo', '🏆 Challenge loaded! ' + challenge.description + ' Good luck! 💪');
                    // Defer world population to ensure canvas is ready after tab switch
                    var lessonId = currentLesson.id;
                    setTimeout(function() {
                        metalObjects = []; wallObjects = []; fireObjects = [];
                        targetPoint = null;
                        robot.waterLevel = 10; robot.spraying = false; robot.carrying = null; robot.magnetOn = false;
                        var ch = LESSON_CHALLENGES[lessonId];
                        if (ch) {
                            ch.setup();
                            drawRobot();
                            // Show toast briefly over the now-populated canvas
                            showMissionToast();
                            // Show persistent badge + exit button
                            document.getElementById('missionBadge').classList.remove('hidden');
                            document.getElementById('missionExitBtn').classList.remove('hidden');
                        }
                    }, 200);
                }
            } else {
                document.getElementById('missionHUD').classList.add('hidden');
                document.getElementById('missionBadge').classList.add('hidden');
                document.getElementById('missionExitBtn').classList.add('hidden');
                missionObjectives = null;
                drawRobot();
                addChatMessage('stemo', '🏗️ Free Build mode! Place your own objects and experiment!');
            }
        }

        function updateMissionHUD() {
            if (!missionObjectives) return;
            var list = document.getElementById('missionObjectivesList');
            list.innerHTML = missionObjectives.map(function(obj) {
                return '<span class="flex items-center gap-1 text-xs font-bold px-2 py-1 rounded-full ' +
                    (obj.done ? 'bg-green-500 line-through opacity-70' : 'bg-white/20') + '">' +
                    (obj.done ? '✅ ' : '⬜ ') + obj.label + '</span>';
            }).join('');
            // Update mini badge counter
            var remaining = missionObjectives.filter(function(o) { return !o.done; }).length;
            var badgeEl = document.getElementById('missionBadgeText');
            if (badgeEl) {
                badgeEl.textContent = remaining === 0 ? '✅ Done!' : remaining + ' left';
            }
            var badge = document.getElementById('missionBadge');
            if (badge) {
                badge.querySelector('div').style.background = remaining === 0 ? '#22c55e' : '';
            }
        }

        function checkChallengeObjectives() {
            if (!challengeMode || !missionObjectives || challengeCompleted) return;
            var allDone = true;
            var anyChanged = false;
            missionObjectives.forEach(function(obj, idx) {
                var wasDone = obj.done;
                obj.done = obj.check();
                if (obj.done && !wasDone) {
                    anyChanged = true;
                    // Per-step celebration
                    var remaining = missionObjectives.filter(function(o) { return !o.done; }).length;
                    if (remaining > 0) {
                        var stepNum = idx + 1;
                        var msgs = [
                            '✅ Step ' + stepNum + ' done! Great job! Now find the next one! 🎯',
                            '🌟 Awesome! Step ' + stepNum + ' complete! Keep going!',
                            '💪 Step ' + stepNum + ' checked off! You are on a roll!'
                        ];
                        addChatMessage('stemo', msgs[stepNum % msgs.length]);
                    }
                }
                if (!obj.done) allDone = false;
            });
            if (anyChanged) updateMissionHUD();
            if (allDone && !challengeCompleted) {
                challengeCompleted = true;
                setTimeout(function() {
                    addChatMessage('stemo', '🎉 ALL STEPS COMPLETE! Amazing work! 🏆🏆🏆');
                    if (currentLesson && !stemo.completedLessons.includes(currentLesson.id)) {
                        completeLesson(currentLesson);
                    } else {
                        // Replay — no XP awarded, just show the celebration modal
                        showSuccessModal(0);
                    }
                }, 400);
            }
        }

        function startFirstLesson() {
            selectLesson('lesson-1');
        }

        // ============================================
        // BADGES
        // ============================================
        function loadBadges() {
            fetch('/api/badges')
                .then(function(response) { return response.json(); })
                .then(function(badges) {
                    var grid = document.getElementById('badgesGrid');
                    var html = '';
                    
                    badges.forEach(function(badge) {
                        var isEarned = stemo.badges.includes(badge.id) || stemo.xp >= badge.xpRequired;
                        
                        if (isEarned && !stemo.badges.includes(badge.id)) {
                            stemo.badges.push(badge.id);
                            saveProgress();
                        }
                        
                        html += '<div class="bg-white rounded-2xl card-shadow p-4 text-center ' + (isEarned ? '' : 'opacity-50 grayscale') + '">' +
                                '<div class="text-4xl mb-2">' + badge.icon + '</div>' +
                                '<h4 class="font-bold text-sm text-gray-800">' + badge.name + '</h4>' +
                                '<p class="text-xs text-gray-500 mt-1">' + badge.description + '</p>' +
                                '<div class="text-xs text-indigo-600 mt-2">' + badge.xpRequired + ' XP</div>' +
                                '</div>';
                    });
                    
                    grid.innerHTML = html;
                });
        }

        // ============================================
        // BLOCKLY SETUP - Define blocks immediately when script loads
        // ============================================
        
        // Define all blocks immediately (not waiting for DOM)
        // Using FieldNumber for editable numbers instead of dropdowns
        Blockly.Blocks['move_forward'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🚶 Move")
                    .appendField(new Blockly.FieldNumber(1, 1, 100, 1), "STEPS")
                    .appendField("steps");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(230);
            }
        };

        Blockly.Blocks['move_backward'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🔙 Back")
                    .appendField(new Blockly.FieldNumber(1, 1, 100, 1), "STEPS")
                    .appendField("steps");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(230);
            }
        };

        Blockly.Blocks['turn_left'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("↩️ Left")
                    .appendField(new Blockly.FieldNumber(90, 1, 360, 1), "DEGREES")
                    .appendField("°");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(160);
            }
        };

        Blockly.Blocks['turn_right'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("↪️ Right")
                    .appendField(new Blockly.FieldNumber(90, 1, 360, 1), "DEGREES")
                    .appendField("°");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(160);
            }
        };

        Blockly.Blocks['pen_control'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🖍️ Pen")
                    .appendField(new Blockly.FieldDropdown([
                        ["Down ✏️", "DOWN"],
                        ["Up ✋", "UP"]
                    ]), "STATE");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(330);
            }
        };

        Blockly.Blocks['set_color'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🎨 Color")
                    .appendField(new (window.FieldColour || Blockly.FieldColour || Blockly.fieldColour.FieldColour)('#6366f1'), "COLOR");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(330);
            }
        };

        Blockly.Blocks['set_pen_size'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🖌️ Size")
                    .appendField(new Blockly.FieldNumber(4, 1, 20, 1), "SIZE")
                    .appendField("px");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(330);
            }
        };

        Blockly.Blocks['go_home'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🏠 Go Home");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(60);
            }
        };

        Blockly.Blocks['hide_stemo'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("👻 Hide")
                    .appendField(new Blockly.FieldDropdown([
                        ["Hide 🙈", "HIDE"],
                        ["Show 👀", "SHOW"]
                    ]), "STATE");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(60);
            }
        };

        Blockly.Blocks['magnet_on'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🧲 Magnet ON");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(0);
                this.setTooltip("Turn on magnet to pick up metal objects");
            }
        };

        Blockly.Blocks['magnet_off'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🧲 Magnet OFF");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(0);
                this.setTooltip("Turn off magnet to release/drop metal objects");
            }
        };

        Blockly.Blocks['repeat_times'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🔁 Repeat")
                    .appendField(new Blockly.FieldNumber(4, 1, 100, 1), "TIMES")
                    .appendField("times");
                this.appendStatementInput("DO")
                    .appendField("do");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(120);
            }
        };
        
        // ============================================
        // ULTRASONIC SENSOR BLOCKS
        // ============================================
        Blockly.Blocks['sensor_scan'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("📡 Scan Ahead");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(180);
                this.setTooltip("Scan for walls ahead and show distance");
            }
        };
        
        Blockly.Blocks['auto_move'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🚗 Auto Move")
                    .appendField(new Blockly.FieldNumber(1, 1, 50, 1), "STEPS")
                    .appendField("steps");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(180);
                this.setTooltip("Move forward, auto-turn if wall detected");
            }
        };
        
        Blockly.Blocks['go_to_target'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🎯 Go To Target");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(180);
                this.setTooltip("Navigate toward the target using basic steering. May get stuck in complex mazes.");
            }
        };

        Blockly.Blocks['smart_navigate'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🧭 Smart Navigate");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(230);
                this.setTooltip("Use BFS pathfinding to guarantee the shortest route through any maze — never gets stuck!");
            }
        };
        
        Blockly.Blocks['if_wall_ahead'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🧱 If Wall Within")
                    .appendField(new Blockly.FieldNumber(2, 1, 10, 1), "DISTANCE")
                    .appendField("steps");
                this.appendStatementInput("DO")
                    .appendField("then");
                this.appendStatementInput("ELSE")
                    .appendField("else");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(45);
                this.setTooltip("Check if wall is within distance, do something");
            }
        };
        
        Blockly.Blocks['smart_turn'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🧠 Smart Turn");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(45);
                this.setTooltip("Turn left or right - chooses best direction based on walls and target");
            }
        };
        
        // ============================================
        // TEMPERATURE SENSOR / FIREFIGHTER BLOCKS
        // ============================================
        Blockly.Blocks['check_temp'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🌡️ Check Temp");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(0);
                this.setTooltip("Scan ahead and report temperature");
            }
        };
        
        Blockly.Blocks['if_hot_ahead'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🔥 If Fire Within")
                    .appendField(new Blockly.FieldNumber(3, 1, 10, 1), "DISTANCE")
                    .appendField("steps");
                this.appendStatementInput("DO")
                    .appendField("then");
                this.appendStatementInput("ELSE")
                    .appendField("else");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(0);
                this.setTooltip("Check if fire/heat is within distance");
            }
        };
        
        Blockly.Blocks['spray_water'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("💧 Spray Water");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(200);
                this.setTooltip("Spray water to extinguish fire ahead (uses 1 water)");
            }
        };
        
        Blockly.Blocks['firefighter_mode'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🚒 Firefighter Mode");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(0);
                this.setTooltip("Auto-navigate and extinguish all fires");
            }
        };

        // ── VARIABLE BLOCKS ──────────────────────────────────────────
        Blockly.Blocks['set_variable'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("📦 Set")
                    .appendField(new Blockly.FieldDropdown([
                        ["speed","speed"],["count","count"],["angle","angle"],["distance","distance"]
                    ]), "VAR")
                    .appendField("to")
                    .appendField(new Blockly.FieldNumber(3, 1, 999), "VALUE");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(30);
                this.setTooltip("Store a number in a named variable");
            }
        };

        Blockly.Blocks['change_variable'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("➕ Change")
                    .appendField(new Blockly.FieldDropdown([
                        ["speed","speed"],["count","count"],["angle","angle"],["distance","distance"]
                    ]), "VAR")
                    .appendField("by")
                    .appendField(new Blockly.FieldNumber(1, -999, 999), "AMOUNT");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(30);
                this.setTooltip("Add or subtract from a variable");
            }
        };

        Blockly.Blocks['move_var_steps'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🚀 Move")
                    .appendField(new Blockly.FieldDropdown([
                        ["speed","speed"],["count","count"],["distance","distance"]
                    ]), "VAR")
                    .appendField("steps");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(30);
                this.setTooltip("Move forward using a variable as the step count");
            }
        };

        Blockly.Blocks['turn_var_degrees'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🔄 Turn")
                    .appendField(new Blockly.FieldDropdown([
                        ["angle","angle"],["count","count"],["speed","speed"]
                    ]), "VAR")
                    .appendField("degrees right");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(30);
                this.setTooltip("Turn using a variable as the degree amount");
            }
        };

        Blockly.Blocks['repeat_var_times'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🔁 Repeat")
                    .appendField(new Blockly.FieldDropdown([
                        ["count","count"],["speed","speed"],["distance","distance"]
                    ]), "VAR")
                    .appendField("times");
                this.appendStatementInput("DO")
                    .appendField("do");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(30);
                this.setTooltip("Repeat blocks using a variable for the count");
            }
        };

        // ── POSITION & LIST BLOCKS ───────────────────────────────────
        Blockly.Blocks['show_coords'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("📍 Show My Position");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(165);
                this.setTooltip("Display STEMO's current X and Y coordinates in the chat");
            }
        };

        Blockly.Blocks['save_position'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("💾 Save Position as")
                    .appendField(new Blockly.FieldDropdown([
                        ["A","A"],["B","B"],["C","C"],["D","D"]
                    ]), "SLOT");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(165);
                this.setTooltip("Save STEMO's current X,Y into a named slot (A, B, C, or D)");
            }
        };

        Blockly.Blocks['go_to_saved'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🔙 Go to Position")
                    .appendField(new Blockly.FieldDropdown([
                        ["A","A"],["B","B"],["C","C"],["D","D"]
                    ]), "SLOT");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(165);
                this.setTooltip("Navigate (BFS path) to a previously saved position");
            }
        };

        Blockly.Blocks['add_waypoint'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("📌 Add Waypoint to List");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(150);
                this.setTooltip("Add STEMO's current position to the waypoint list");
            }
        };

        Blockly.Blocks['replay_waypoints'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("▶️ Replay Path");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(150);
                this.setTooltip("Navigate through all waypoints in the list in order");
            }
        };

        Blockly.Blocks['foreach_waypoint'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🔂 For Each Waypoint:");
                this.appendStatementInput("DO")
                    .appendField("do");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(150);
                this.setTooltip("Navigate to each waypoint in the list and run the DO blocks at each one");
            }
        };

        Blockly.Blocks['send_data'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("📡 Send to Command Center:")
                    .appendField(new Blockly.FieldDropdown([
                        ["My Location",  "my_location"],
                        ["Position A",   "pos_A"],
                        ["Position B",   "pos_B"],
                        ["Position C",   "pos_C"],
                        ["Position D",   "pos_D"],
                        ["All Positions","all_positions"],
                        ["Waypoint List","waypoint_list"]
                    ]), "DATA");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(200);
                this.setTooltip("Transmit location data to the Command Center (chat). Use like a print() function to report coordinates.");
            }
        };

        Blockly.Blocks['clear_waypoints'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🗑️ Clear Waypoint List");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(150);
                this.setTooltip("Remove all waypoints from the list");
            }
        };

        // ── FUNCTION BLOCKS ───────────────────────────────────────────────
        Blockly.Blocks['define_function'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🔧 Define Function:")
                    .appendField(new Blockly.FieldTextInput("myFunction"), "FNAME");
                this.appendStatementInput("DO")
                    .setCheck(null)
                    .appendField("do");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(260);
                this.setTooltip("Define a reusable function. Give it a name, then add blocks inside. Call it anywhere with 'Call Function'.");
            }
        };

        Blockly.Blocks['call_function'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("▶ Call Function:")
                    .appendField(new Blockly.FieldTextInput("myFunction"), "FNAME");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(280);
                this.setTooltip("Call a function you defined. Type the exact function name to run its blocks.");
            }
        };
        
        function initBlockly() {
            // Initialize workspace WITHOUT toolbox - we use our custom palette
            workspace = Blockly.inject('blocklyDiv', {
                scrollbars: true,
                trashcan: true,
                zoom: {
                    controls: true,
                    wheel: true,
                    startScale: 0.85,
                    maxScale: 2,
                    minScale: 0.5
                },
                grid: {
                    spacing: 20,
                    length: 3,
                    colour: '#ddd',
                    snap: true
                },
                move: {
                    scrollbars: true,
                    drag: true,
                    wheel: true
                }
            });
            
            console.log('Blockly workspace initialized');
        }
        
        // Add block to workspace - called from palette buttons
        function addBlock(blockType) {
            if (!workspace) {
                console.error('Workspace not ready');
                return;
            }
            playSound('click');
            
            // Create a new block
            var newBlock = workspace.newBlock(blockType);
            newBlock.initSvg();
            newBlock.render();
            
            // Find position - stack below existing blocks or place at top
            var topBlocks = workspace.getTopBlocks(false);
            var yPos = 30;
            
            if (topBlocks.length > 0) {
                // Find the last block and connect to it
                var lastBlock = topBlocks[0];
                while (lastBlock.getNextBlock()) {
                    lastBlock = lastBlock.getNextBlock();
                }
                
                // Connect new block to the last one
                var connection = lastBlock.nextConnection;
                if (connection && newBlock.previousConnection) {
                    connection.connect(newBlock.previousConnection);
                } else {
                    // If can't connect, place below
                    var lastBlockXY = lastBlock.getRelativeToSurfaceXY();
                    newBlock.moveBy(lastBlockXY.x, lastBlockXY.y + 50);
                }
            } else {
                // First block - place at top
                newBlock.moveBy(30, yPos);
            }
            
            // Visual feedback
            newBlock.select();
            
            console.log('Added block:', blockType);
        }

        // ============================================
        // CODE EXECUTION
        // ============================================
        // Pre-scan workspace for define_function blocks and populate userFunctions
        function scanUserFunctions() {
            userFunctions = {};
            if (!workspace) return;
            var allBlocks = workspace.getAllBlocks(false);
            allBlocks.forEach(function(b) {
                if (b.type === 'define_function') {
                    var name = (b.getFieldValue('FNAME') || '').trim();
                    if (name) {
                        var bodyBlock = b.getInputTargetBlock('DO');
                        var bodyCmds = [];
                        if (bodyBlock) parseBlocks(bodyBlock, bodyCmds);
                        userFunctions[name] = bodyCmds;
                    }
                }
            });
        }

        function runCode() {
            console.log('Running code...');
            
            if (!workspace) {
                console.error('Workspace not initialized');
                addChatMessage('stemo', "🤖 Oops! Something went wrong. Please refresh the page.");
                return;
            }
            
            var blocks = workspace.getTopBlocks(true);
            console.log('Found blocks:', blocks.length);
            
            if (blocks.length === 0) {
                addChatMessage('stemo', "🤖 Drag some blocks into the workspace first, then click Run!");
                return;
            }

            // Pre-scan all define_function blocks first
            scanUserFunctions();

            // Reset robot before running
            robot.x = 275;
            robot.y = 275;
            robot.angle = -90;
            robot.penDown = false;
            robot.penSize = 4;
            robot.visible = true;
            robot.magnetOn = false;
            robot.carrying = null;
            robot.trails = [];
            drawRobot();
            
            // Parse and execute blocks
            var commands = [];
            parseBlocks(blocks[0], commands);
            console.log('Commands to execute:', commands);
            
            if (commands.length === 0) {
                addChatMessage('stemo', "🤖 I see your blocks! Make sure they're connected properly. Try dragging a Move Forward block into the workspace.");
                return;
            }
            
            executeCommands(commands);
        }

        function parseBlocks(block, commands) {
            while (block) {
                var type = block.type;
                console.log('Parsing block:', type);
                
                if (type === 'move_forward') {
                    var steps = parseInt(block.getFieldValue('STEPS'));
                    for (var i = 0; i < steps; i++) {
                        commands.push({ action: 'move', value: 20 });
                    }
                } else if (type === 'move_backward') {
                    var steps = parseInt(block.getFieldValue('STEPS'));
                    for (var i = 0; i < steps; i++) {
                        commands.push({ action: 'move', value: -20 });
                    }
                } else if (type === 'turn_left') {
                    var degrees = parseInt(block.getFieldValue('DEGREES'));
                    commands.push({ action: 'turn', value: -degrees });
                } else if (type === 'turn_right') {
                    var degrees = parseInt(block.getFieldValue('DEGREES'));
                    commands.push({ action: 'turn', value: degrees });
                } else if (type === 'go_home') {
                    commands.push({ action: 'home' });
                } else if (type === 'hide_stemo') {
                    var state = block.getFieldValue('STATE');
                    commands.push({ action: 'visibility', value: state === 'SHOW' });
                } else if (type === 'pen_control') {
                    var state = block.getFieldValue('STATE');
                    commands.push({ action: 'pen', value: state === 'DOWN' });
                } else if (type === 'set_color') {
                    var color = block.getFieldValue('COLOR');
                    commands.push({ action: 'color', value: color });
                } else if (type === 'set_pen_size') {
                    var size = parseInt(block.getFieldValue('SIZE'));
                    commands.push({ action: 'size', value: size });
                } else if (type === 'magnet_on') {
                    commands.push({ action: 'magnet', value: true });
                } else if (type === 'magnet_off') {
                    commands.push({ action: 'magnet', value: false });
                } else if (type === 'repeat_times') {
                    var times = parseInt(block.getFieldValue('TIMES'));
                    var innerBlock = block.getInputTargetBlock('DO');
                    for (var j = 0; j < times; j++) {
                        if (innerBlock) {
                            parseBlocks(innerBlock, commands);
                        }
                    }
                } else if (type === 'sensor_scan') {
                    commands.push({ action: 'scan' });
                } else if (type === 'auto_move') {
                    var steps = parseInt(block.getFieldValue('STEPS'));
                    for (var i = 0; i < steps; i++) {
                        commands.push({ action: 'auto_move', value: 20 });
                    }
                } else if (type === 'go_to_target') {
                    commands.push({ action: 'go_to_target' });
                } else if (type === 'smart_navigate') {
                    commands.push({ action: 'smart_navigate' });
                } else if (type === 'if_wall_ahead') {
                    var distance = parseInt(block.getFieldValue('DISTANCE'));
                    var doBlock = block.getInputTargetBlock('DO');
                    var elseBlock = block.getInputTargetBlock('ELSE');
                    commands.push({ 
                        action: 'if_wall', 
                        distance: distance,
                        doCommands: [],
                        elseCommands: []
                    });
                    // Parse inner blocks
                    var lastCmd = commands[commands.length - 1];
                    if (doBlock) {
                        parseBlocks(doBlock, lastCmd.doCommands);
                    }
                    if (elseBlock) {
                        parseBlocks(elseBlock, lastCmd.elseCommands);
                    }
                } else if (type === 'smart_turn') {
                    commands.push({ action: 'smart_turn' });
                } else if (type === 'check_temp') {
                    commands.push({ action: 'check_temp' });
                } else if (type === 'spray_water') {
                    commands.push({ action: 'spray_water' });
                } else if (type === 'firefighter_mode') {
                    commands.push({ action: 'firefighter_mode' });
                } else if (type === 'set_variable') {
                    commands.push({ action: 'set_variable', varName: block.getFieldValue('VAR'), value: parseFloat(block.getFieldValue('VALUE')) });
                } else if (type === 'change_variable') {
                    commands.push({ action: 'change_variable', varName: block.getFieldValue('VAR'), amount: parseFloat(block.getFieldValue('AMOUNT')) });
                } else if (type === 'move_var_steps') {
                    commands.push({ action: 'move_var_steps', varName: block.getFieldValue('VAR') });
                } else if (type === 'turn_var_degrees') {
                    commands.push({ action: 'turn_var_degrees', varName: block.getFieldValue('VAR') });
                } else if (type === 'repeat_var_times') {
                    var innerBlock = block.getInputTargetBlock('DO');
                    var innerCmds = [];
                    if (innerBlock) parseBlocks(innerBlock, innerCmds);
                    commands.push({ action: 'repeat_var', varName: block.getFieldValue('VAR'), doCommands: innerCmds });
                } else if (type === 'show_coords') {
                    commands.push({ action: 'show_coords' });
                } else if (type === 'send_data') {
                    commands.push({ action: 'send_data', data: block.getFieldValue('DATA') });
                } else if (type === 'save_position') {
                    commands.push({ action: 'save_position', slot: block.getFieldValue('SLOT') });
                } else if (type === 'go_to_saved') {
                    commands.push({ action: 'go_to_saved', slot: block.getFieldValue('SLOT') });
                } else if (type === 'add_waypoint') {
                    commands.push({ action: 'add_waypoint' });
                } else if (type === 'replay_waypoints') {
                    commands.push({ action: 'replay_waypoints' });
                } else if (type === 'foreach_waypoint') {
                    var fwDoBlock = block.getInputTargetBlock('DO');
                    var fwDoCmds = [];
                    if (fwDoBlock) parseBlocks(fwDoBlock, fwDoCmds);
                    commands.push({ action: 'foreach_waypoint', doCommands: fwDoCmds });
                } else if (type === 'clear_waypoints') {
                    commands.push({ action: 'clear_waypoints' });
                } else if (type === 'define_function') {
                    // Already pre-scanned into userFunctions — skip during main execution
                } else if (type === 'call_function') {
                    var fname = block.getFieldValue('FNAME') || 'myFunction';
                    commands.push({ action: 'call_function', name: fname });
                } else if (type === 'if_hot_ahead') {
                    var distance = parseInt(block.getFieldValue('DISTANCE'));
                    var doBlock = block.getInputTargetBlock('DO');
                    var elseBlock = block.getInputTargetBlock('ELSE');
                    commands.push({ 
                        action: 'if_hot', 
                        distance: distance,
                        doCommands: [],
                        elseCommands: []
                    });
                    // Parse inner blocks
                    var lastCmd = commands[commands.length - 1];
                    if (doBlock) {
                        parseBlocks(doBlock, lastCmd.doCommands);
                    }
                    if (elseBlock) {
                        parseBlocks(elseBlock, lastCmd.elseCommands);
                    }
                }
                
                block = block.getNextBlock();
            }
        }

        function executeCommands(commands, onComplete) {
            var index = 0;
            var isTopLevel = !onComplete; // Track if this is the main execution
            
            function executeNext() {
                if (index >= commands.length) {
                    console.log('Execution batch complete!');
                    if (isTopLevel) {
                        addChatMessage('stemo', "🤖 Great job! I finished running your code! " + (robot.trails.length > 0 ? "Look at that beautiful drawing! 🎨" : "Try adding more blocks to make me do cool things! ✨"));
                        
                        if (currentLesson) {
                            checkLessonCompletion();
                        }
                    }
                    if (onComplete) onComplete();
                    return;
                }
                
                var cmd = commands[index];
                index++;
                
                // Handle if_wall specially - it needs to execute nested commands
                if (cmd.action === 'if_wall') {
                    var wallDist = detectWallAhead();
                    var wallSteps = wallDist / 20;
                    var nestedCommands = wallSteps <= cmd.distance ? cmd.doCommands : cmd.elseCommands;
                    
                    if (nestedCommands && nestedCommands.length > 0) {
                        // Execute nested commands, then continue
                        executeCommands(nestedCommands, function() {
                            drawRobot();
                            setTimeout(executeNext, 200);
                        });
                    } else {
                        drawRobot();
                        setTimeout(executeNext, 200);
                    }
                    return;
                }
                
                // Handle go_to_target (greedy, basic steering)
                if (cmd.action === 'go_to_target') {
                    if (!targetPoint) {
                        addChatMessage('stemo', "🎯 No target set! Click the 🎯 button and place a target.");
                        setTimeout(executeNext, 200);
                    } else {
                        executeGoToTarget(function() {
                            if (challengeMode) checkChallengeObjectives();
                            setTimeout(executeNext, 200);
                        });
                    }
                    return;
                }

                // Handle smart_navigate (BFS pathfinder — guaranteed shortest path)
                if (cmd.action === 'smart_navigate') {
                    if (!targetPoint) {
                        addChatMessage('stemo', "🧭 No target set! Click the 🎯 button and place a target first.");
                        setTimeout(executeNext, 200);
                    } else {
                        executeSmartNavigate(function() {
                            if (challengeMode) checkChallengeObjectives();
                            setTimeout(executeNext, 200);
                        });
                    }
                    return;
                }

                // ── VARIABLE HANDLERS ─────────────────────────────────────
                if (cmd.action === 'set_variable') {
                    robotVars[cmd.varName] = cmd.value;
                    addChatMessage('stemo', "📦 Variable <b>" + cmd.varName + "</b> = <b>" + cmd.value + "</b>");
                    setTimeout(executeNext, 150);
                    return;
                }
                if (cmd.action === 'change_variable') {
                    robotVars[cmd.varName] = (robotVars[cmd.varName] || 0) + cmd.amount;
                    addChatMessage('stemo', "➕ Variable <b>" + cmd.varName + "</b> is now <b>" + robotVars[cmd.varName] + "</b>");
                    setTimeout(executeNext, 150);
                    return;
                }
                if (cmd.action === 'move_var_steps') {
                    var vSteps = Math.round(robotVars[cmd.varName] || 1);
                    var vMoves = [];
                    for (var vi = 0; vi < vSteps; vi++) vMoves.push({ action: 'move', value: 20 });
                    executeCommands(vMoves, function() {
                        if (challengeMode) checkChallengeObjectives();
                        setTimeout(executeNext, 150);
                    });
                    return;
                }
                if (cmd.action === 'turn_var_degrees') {
                    var vDeg = robotVars[cmd.varName] || 90;
                    robot.angle += vDeg;
                    playSound('turn');
                    drawRobot();
                    setTimeout(executeNext, 200);
                    return;
                }
                if (cmd.action === 'repeat_var') {
                    var vCount = Math.round(robotVars[cmd.varName] || 1);
                    var vLoop = [];
                    for (var vj = 0; vj < vCount; vj++) {
                        for (var vk = 0; vk < cmd.doCommands.length; vk++) vLoop.push(cmd.doCommands[vk]);
                    }
                    executeCommands(vLoop, function() {
                        if (challengeMode) checkChallengeObjectives();
                        setTimeout(executeNext, 150);
                    });
                    return;
                }

                // ── FUNCTION CALL HANDLER ─────────────────────────────────
                if (cmd.action === 'call_function') {
                    var fnBody = userFunctions[cmd.name];
                    if (!fnBody || fnBody.length === 0) {
                        addChatMessage('stemo', "⚠️ Function <b>" + cmd.name + "</b> not found! Make sure you have a 🔧 Define Function block with that exact name.");
                        setTimeout(executeNext, 200);
                    } else {
                        addChatMessage('stemo', "🔧 Calling <b>" + cmd.name + "()</b>…");
                        executeCommands(fnBody, function() {
                            if (challengeMode) checkChallengeObjectives();
                            setTimeout(executeNext, 150);
                        });
                    }
                    return;
                }

                // ── POSITION & LIST HANDLERS ──────────────────────────────
                if (cmd.action === 'show_coords') {
                    var cx = Math.round((robot.x - 275) / 20), cy = Math.round((275 - robot.y) / 20);
                    var coordLabel = 'X=' + cx + '  Y=' + cy;
                    addChatMessage('stemo', "📍 <b>My position:</b> X=<b>" + cx + "</b>, Y=<b>" + cy + "</b>  (steps from centre, right=+X, up=+Y)");
                    // Flash coordinates on canvas near robot
                    robot.posFlash = { x: robot.x, y: robot.y, label: coordLabel, expires: Date.now() + 2500 };
                    drawRobot();
                    setTimeout(function() { robot.posFlash = null; drawRobot(); }, 2500);
                    setTimeout(executeNext, 200);
                    return;
                }
                if (cmd.action === 'send_data') {
                    var d = cmd.data;
                    var ccLines = [];
                    function fmtPosCC(px, py) {
                        return '<span style="color:#fbbf24">X=' + Math.round((px-275)/20) + '</span>  <span style="color:#fbbf24">Y=' + Math.round((275-py)/20) + '</span>';
                    }
                    if (d === 'my_location') {
                        ccLines.push('<span style="color:#4ade80">📍 STEMO</span> → ' + fmtPosCC(robot.x, robot.y));
                    } else if (d === 'pos_A' || d === 'pos_B' || d === 'pos_C' || d === 'pos_D') {
                        var sdSlot = d.slice(-1);
                        var sdSp = savedPositions[sdSlot];
                        if (sdSp) ccLines.push('<span style="color:#4ade80">📍 Position ' + sdSlot + '</span> → ' + fmtPosCC(sdSp.x, sdSp.y));
                        else ccLines.push('<span style="color:#ef4444">📍 Position ' + sdSlot + ' → NOT SET</span>');
                    } else if (d === 'all_positions') {
                        ['A','B','C','D'].forEach(function(s) {
                            var sp = savedPositions[s];
                            if (sp) ccLines.push('<span style="color:#4ade80">📍 Pos ' + s + '</span> → ' + fmtPosCC(sp.x, sp.y));
                            else ccLines.push('<span style="color:#475569">📍 Pos ' + s + ' → NOT SET</span>');
                        });
                    } else if (d === 'waypoint_list') {
                        if (waypointList.length === 0) {
                            ccLines.push('<span style="color:#ef4444">📌 Waypoint list EMPTY</span>');
                        } else {
                            waypointList.forEach(function(pt, i) {
                                ccLines.push('<span style="color:#38bdf8">📌 WP#' + (i+1) + '</span> → ' + fmtPosCC(pt.x, pt.y));
                            });
                        }
                    }
                    // Show "TRANSMITTING" flash on canvas
                    robot.txFlash = { expires: Date.now() + 1800 };
                    drawRobot();
                    setTimeout(function() { robot.txFlash = null; drawRobot(); }, 1800);
                    // Send to Command Center terminal
                    addCommandCenterMessage(ccLines);
                    setTimeout(executeNext, 350);
                    return;
                }
                if (cmd.action === 'save_position') {
                    savedPositions[cmd.slot] = { x: robot.x, y: robot.y };
                    var sx = Math.round((robot.x - 275) / 20), sy = Math.round((275 - robot.y) / 20);
                    addChatMessage('stemo', "💾 Position <b>" + cmd.slot + "</b> saved at X=" + sx + ", Y=" + sy + " — a pin marker now shows on the canvas!");
                    drawRobot();
                    setTimeout(executeNext, 200);
                    return;
                }
                if (cmd.action === 'go_to_saved') {
                    var sp = savedPositions[cmd.slot];
                    if (!sp) {
                        addChatMessage('stemo', "🔙 Position <b>" + cmd.slot + "</b> has not been saved yet! Use 💾 Save Position first.");
                        setTimeout(executeNext, 200);
                    } else {
                        executeNavigateToPoint(sp.x, sp.y, "🔙 Navigating to saved position " + cmd.slot + "…", function() {
                            if (challengeMode) checkChallengeObjectives();
                            setTimeout(executeNext, 200);
                        });
                    }
                    return;
                }
                if (cmd.action === 'add_waypoint') {
                    waypointList.push({ x: robot.x, y: robot.y });
                    var wx = Math.round((robot.x - 275) / 20), wy = Math.round((275 - robot.y) / 20);
                    addChatMessage('stemo', "📌 Waypoint #" + waypointList.length + " added at X=" + wx + ", Y=" + wy + "  |  List now has <b>" + waypointList.length + "</b> point(s)");
                    setTimeout(executeNext, 200);
                    return;
                }
                if (cmd.action === 'replay_waypoints') {
                    if (waypointList.length === 0) {
                        addChatMessage('stemo', "▶️ Waypoint list is empty! Use 📌 Add Waypoint first.");
                        setTimeout(executeNext, 200);
                    } else {
                        addChatMessage('stemo', "▶️ Replaying " + waypointList.length + " waypoints…");
                        executeReplayWaypoints(waypointList.slice(), 0, function() {
                            if (challengeMode) checkChallengeObjectives();
                            setTimeout(executeNext, 200);
                        });
                    }
                    return;
                }
                if (cmd.action === 'foreach_waypoint') {
                    var ptsToUse = waypointList.slice();
                    // If list is empty but fires are on the board, auto-load fire positions
                    if (ptsToUse.length === 0 && fireObjects.length > 0) {
                        ptsToUse = fireObjects.map(function(f) { return { x: f.x, y: f.y }; });
                        addChatMessage('stemo', "🔂 Waypoint list was empty — detected " + ptsToUse.length + " fire(s) on the board! Auto-loading fire locations as waypoints. Navigating and running your blocks…");
                    } else if (ptsToUse.length === 0) {
                        addChatMessage('stemo', "🔂 Waypoint list is empty and no fires detected! Place fires or add waypoints first (use the 📌 Add Waypoint block or button).");
                        setTimeout(executeNext, 200);
                        return;
                    } else {
                        addChatMessage('stemo', "🔂 For each of " + ptsToUse.length + " waypoints — navigating and running your blocks…");
                    }
                    executeForeachWaypoint(ptsToUse, 0, cmd.doCommands, function() {
                        if (challengeMode) checkChallengeObjectives();
                        setTimeout(executeNext, 200);
                    });
                    return;
                }
                if (cmd.action === 'clear_waypoints') {
                    var oldCount = waypointList.length;
                    waypointList = [];
                    addChatMessage('stemo', "🗑️ Cleared " + oldCount + " waypoints from the list.");
                    setTimeout(executeNext, 200);
                    return;
                }

                // Handle if_hot (fire detection conditional)
                if (cmd.action === 'if_hot') {
                    var fireInfo = detectFireAhead();
                    var fireSteps = fireInfo.distance / 20;
                    var nestedCommands = fireSteps <= cmd.distance ? cmd.doCommands : cmd.elseCommands;
                    
                    if (nestedCommands && nestedCommands.length > 0) {
                        executeCommands(nestedCommands, function() {
                            drawRobot();
                            setTimeout(executeNext, 200);
                        });
                    } else {
                        drawRobot();
                        setTimeout(executeNext, 200);
                    }
                    return;
                }
                
                // Handle firefighter_mode
                if (cmd.action === 'firefighter_mode') {
                    if (fireObjects.length === 0) {
                        addChatMessage('stemo', "🚒 No fires to extinguish! Place some fires with the 🔥 button.");
                        setTimeout(executeNext, 200);
                    } else {
                        executeFirefighterMode(function() {
                            if (challengeMode) checkChallengeObjectives();
                            setTimeout(executeNext, 200);
                        });
                    }
                    return;
                }
                
                executeCommand(cmd);
                drawRobot();
                if (challengeMode) checkChallengeObjectives();
                
                setTimeout(executeNext, 200);
            }
            
            executeNext();
        }

        function executeCommand(cmd) {
            console.log('Executing:', cmd);
            
            if (cmd.action === 'move') {
                playSound('move');
                var rad = robot.angle * Math.PI / 180;
                var moveDx = Math.cos(rad), moveDy = Math.sin(rad);
                var moveDistance = cmd.value;

                // Wall collision — stop at wall face instead of walking through
                for (var wc = 0; wc < wallObjects.length; wc++) {
                    var wobj = wallObjects[wc];
                    var wDist = rayBoxIntersection(robot.x, robot.y, moveDx, moveDy, wobj.x, wobj.y, wobj.width, wobj.height);
                    if (wDist > 0 && wDist < moveDistance) {
                        moveDistance = Math.max(0, wDist - 2); // stop 2 px in front of face
                    }
                }

                var newX = robot.x + moveDx * moveDistance;
                var newY = robot.y + moveDy * moveDistance;
                
                if (robot.penDown) {
                    robot.trails.push({
                        x1: robot.x, y1: robot.y,
                        x2: newX, y2: newY,
                        color: robot.penColor,
                        size: robot.penSize
                    });
                }
                
                robot.x = Math.max(25, Math.min(525, newX));
                robot.y = Math.max(25, Math.min(525, newY));
                
                // Check if magnet is ON and can pick up nearby metal
                if (robot.magnetOn && (challengeMode || !robot.carrying)) {
                    var pickupRange = 35;
                    for (var m = 0; m < metalObjects.length; m++) {
                        var metal = metalObjects[m];
                        if (!metal.pickedUp) {
                            var dx = metal.x - robot.x;
                            var dy = metal.y - robot.y;
                            var dist = Math.sqrt(dx * dx + dy * dy);
                            if (dist < pickupRange) {
                                if (hasFireOnMetal(metal)) {
                                    addChatMessage('stemo', "🔥🧲 Can't pick up metal — fire is burning here! Extinguish the fire first, then collect. 💧");
                                    break;
                                }
                                metal.pickedUp = true;
                                playSound('pickup');
                                if (challengeMode) {
                                    // Challenge: auto-collect, no carrying needed
                                    addChatMessage('stemo', "✅ Collected " + metal.type + "! Keep going! 🎉");
                                    checkChallengeObjectives();
                                } else {
                                    robot.carrying = metal;
                                    addChatMessage('stemo', "🤖 🧲 Picked up " + metal.type + "! 🎉");
                                    checkChallengeObjectives();
                                }
                                break;
                            }
                        }
                    }
                }
            } else if (cmd.action === 'turn') {
                playSound('turn');
                robot.angle += cmd.value;
            } else if (cmd.action === 'home') {
                // Go home without drawing
                robot.x = 275;
                robot.y = 275;
                robot.angle = -90;
            } else if (cmd.action === 'pen') {
                robot.penDown = cmd.value;
            } else if (cmd.action === 'color') {
                robot.penColor = cmd.value;
            } else if (cmd.action === 'size') {
                robot.penSize = cmd.value;
            } else if (cmd.action === 'visibility') {
                robot.visible = cmd.value;
            } else if (cmd.action === 'magnet') {
                robot.magnetOn = cmd.value;
                playSound(cmd.value ? 'magnet_on' : 'magnet_off');
                if (cmd.value) {
                    // Magnet ON - try to pick up nearby metal
                    if (challengeMode || !robot.carrying) {
                        var pickupRange = 35;
                        var gotOne = false;
                        for (var m = 0; m < metalObjects.length; m++) {
                            var metal = metalObjects[m];
                            if (!metal.pickedUp) {
                                var dx = metal.x - robot.x;
                                var dy = metal.y - robot.y;
                                var dist = Math.sqrt(dx * dx + dy * dy);
                                if (dist < pickupRange) {
                                    if (hasFireOnMetal(metal)) {
                                        addChatMessage('stemo', "🔥🧲 Can't pick up metal — fire is burning here! Extinguish the fire first, then collect. 💧");
                                        gotOne = true; // suppress generic "move closer" message
                                        break;
                                    }
                                    metal.pickedUp = true;
                                    robot.carrying = metal; // always carry so Magnet OFF can show the drop
                                    gotOne = true;
                                    playSound('pickup');
                                    addChatMessage('stemo', "🤖 🧲 Got it! I picked up the " + metal.type + "! 🎉");
                                    checkChallengeObjectives();
                                    break;
                                }
                            }
                        }
                        if (!gotOne && !robot.carrying) {
                            addChatMessage('stemo', "🤖 🧲 Magnet ON! Move closer to a metal object to pick it up.");
                        }
                    }
                } else {
                    // Magnet OFF - drop the object at the robot's current position
                    if (robot.carrying) {
                        if (challengeMode) {
                            // In challenge mode: pickedUp stays true for objectives, but
                            // set dropped=true so the renderer shows the metal at drop position.
                            robot.carrying.x = Math.max(25, Math.min(525, robot.x));
                            robot.carrying.y = Math.max(25, Math.min(525, robot.y));
                            robot.carrying.dropped = true;
                            addChatMessage('stemo', "🤖 🧲 Dropped the " + robot.carrying.type + " here! 📍");
                            robot.carrying = null;
                            checkChallengeObjectives();
                        } else {
                            // Normal mode: drop AT the robot's current position so the metal
                            // lands exactly where STEMO is standing (not floating ahead of it).
                            // If a target is right under STEMO, snap the metal onto the target
                            // so "go to target → magnet OFF" lines up perfectly.
                            var dropX = robot.x;
                            var dropY = robot.y;
                            var snappedToTarget = false;
                            if (targetPoint) {
                                var tdx = targetPoint.x - robot.x;
                                var tdy = targetPoint.y - robot.y;
                                if (Math.sqrt(tdx * tdx + tdy * tdy) < 40) {
                                    dropX = targetPoint.x;
                                    dropY = targetPoint.y;
                                    snappedToTarget = true;
                                }
                            }
                            dropX = Math.max(25, Math.min(525, dropX));
                            dropY = Math.max(25, Math.min(525, dropY));
                            robot.carrying.x = dropX;
                            robot.carrying.y = dropY;
                            robot.carrying.pickedUp = false;
                            addChatMessage('stemo', snappedToTarget
                                ? "🤖 🧲 Dropped the " + robot.carrying.type + " right on the 🎯 target! 📍"
                                : "🤖 🧲 Dropped the " + robot.carrying.type + " here! 📍");
                            robot.carrying = null;
                        }
                    } else {
                        addChatMessage('stemo', "🤖 🧲 Magnet OFF.");
                    }
                }
            } else if (cmd.action === 'scan') {
                // Scan for walls ahead
                var wallDist = detectWallAhead();
                robot.lastScan = wallDist;
                if (wallDist < 999) {
                    addChatMessage('stemo', "📡 Wall detected " + Math.round(wallDist / 20) + " steps ahead!");
                } else {
                    addChatMessage('stemo', "📡 No wall ahead - path is clear!");
                }
            } else if (cmd.action === 'auto_move') {
                // Auto move with wall avoidance
                var wallDist = detectWallAhead();
                if (wallDist <= 30) { // Wall within 1.5 steps
                    // Smart turn - choose best direction
                    playSound('bonk');
                    var turnDir = chooseBestTurnDirection();
                    robot.angle += turnDir;
                    addChatMessage('stemo', "🚗 Wall! Turning " + (turnDir > 0 ? "right" : "left") + "...");
                } else {
                    // Safe to move
                    var rad = robot.angle * Math.PI / 180;
                    var newX = robot.x + Math.cos(rad) * cmd.value;
                    var newY = robot.y + Math.sin(rad) * cmd.value;
                    
                    if (robot.penDown) {
                        robot.trails.push({
                            x1: robot.x, y1: robot.y,
                            x2: newX, y2: newY,
                            color: robot.penColor,
                            size: robot.penSize
                        });
                    }
                    
                    robot.x = Math.max(25, Math.min(525, newX));
                    robot.y = Math.max(25, Math.min(525, newY));
                }
            } else if (cmd.action === 'smart_turn') {
                // Smart turn - choose best direction based on situation
                var turnDir = chooseBestTurnDirection();
                robot.angle += turnDir;
                // Only show message occasionally to avoid spam
                if (Math.random() < 0.3) {
                    addChatMessage('stemo', "🧠 Smart turn " + (turnDir > 0 ? "right ↪️" : "left ↩️"));
                }
            } else if (cmd.action === 'check_temp') {
                // Check temperature ahead
                var fireInfo = detectFireAhead();
                robot.lastTemp = fireInfo.temp;
                if (fireInfo.fire) {
                    addChatMessage('stemo', "🌡️ Temperature: " + fireInfo.temp + "°C 🔥 Fire detected " + Math.round(fireInfo.distance / 20) + " steps ahead!");
                } else {
                    addChatMessage('stemo', "🌡️ Temperature: " + fireInfo.temp + "°C - All clear ahead!");
                }
            } else if (cmd.action === 'spray_water') {
                // Spray water — keep spraying until fire is out or tank is empty
                if (robot.waterLevel <= 0) {
                    addChatMessage('stemo', "💧 Water tank empty! Return to base to refill.");
                } else {
                    var fireInfo = detectFireAhead();
                    if (fireInfo.fire && fireInfo.distance < 60) { // Within 3 steps
                        var targetFire = fireInfo.fire;
                        var spraysUsed = 0;
                        // Loop: keep spraying until fire is gone or tank is empty
                        while (targetFire.health > 0 && robot.waterLevel > 0) {
                            robot.waterLevel--;
                            targetFire.health--;
                            spraysUsed++;
                        }
                        robot.spraying = true;
                        playSound('spray');
                        if (targetFire.health <= 0) {
                            fireObjects = fireObjects.filter(function(f) { return f !== targetFire; });
                            playSound('fire_out');
                            addChatMessage('stemo', "💧💥 Fire extinguished with " + spraysUsed + " spray" + (spraysUsed > 1 ? "s" : "") + "! Great job! 🎉 Water left: " + robot.waterLevel + "/10");
                            checkChallengeObjectives();
                        } else {
                            addChatMessage('stemo', "💧 Sprayed " + spraysUsed + " time" + (spraysUsed > 1 ? "s" : "") + " — water ran out! Fire still active. Refill and try again.");
                        }
                        // Visual effect - clear spray flag after delay
                        setTimeout(function() { robot.spraying = false; drawRobot(); }, 600);
                    } else {
                        addChatMessage('stemo', "💧 No fire within range! Move closer (within 3 steps).");
                    }
                }
            }
            // Note: go_to_target, if_wall, if_hot and firefighter_mode are handled in executeCommands() directly
        }
        
        // Choose best turn direction based on:
        // 1. Which side has more space (left vs right wall distance)
        // 2. Which direction is closer to target (if target exists)
        function chooseBestTurnDirection() {
            var leftDist = detectWallAtAngle(robot.angle - 90);
            var rightDist = detectWallAtAngle(robot.angle + 90);
            
            console.log('Smart turn check - Left dist:', leftDist, 'Right dist:', rightDist);
            
            // If target exists, prefer direction toward target
            if (targetPoint) {
                var dx = targetPoint.x - robot.x;
                var dy = targetPoint.y - robot.y;
                var targetAngle = Math.atan2(dy, dx) * 180 / Math.PI;
                var angleDiff = targetAngle - robot.angle;
                
                // Normalize
                while (angleDiff > 180) angleDiff -= 360;
                while (angleDiff < -180) angleDiff += 360;
                
                console.log('Target angle diff:', angleDiff);
                
                // If target is more to the left and left is clear enough (at least 2 steps)
                if (angleDiff < 0 && leftDist > 40) {
                    console.log('Choosing LEFT toward target');
                    return -90; // Turn left
                }
                // If target is more to the right and right is clear enough
                if (angleDiff > 0 && rightDist > 40) {
                    console.log('Choosing RIGHT toward target');
                    return 90; // Turn right
                }
                
                // Target direction is blocked, choose the clearer side
                console.log('Target direction blocked, choosing clearer path');
            }
            
            // No target or target direction blocked - choose clearer path
            if (leftDist > rightDist) {
                console.log('Choosing LEFT - more space');
                return -90; // Turn left - more space
            } else {
                console.log('Choosing RIGHT - more space or equal');
                return 90; // Turn right - more space or equal
            }
        }
        
        // Detect wall at a specific angle
        function detectWallAtAngle(angle) {
            var rad = angle * Math.PI / 180;
            var minDist = 999;
            
            for (var w = 0; w < wallObjects.length; w++) {
                var wall = wallObjects[w];
                var dist = rayBoxIntersection(
                    robot.x, robot.y,
                    Math.cos(rad), Math.sin(rad),
                    wall.x, wall.y, wall.width, wall.height
                );
                if (dist > 0 && dist < minDist) {
                    minDist = dist;
                }
            }
            
            // Also check boundaries
            var boundaryDist = rayBoundaryIntersection(robot.x, robot.y, Math.cos(rad), Math.sin(rad));
            if (boundaryDist < minDist) {
                minDist = boundaryDist;
            }
            
            return minDist;
        }
        
        // ============================================
        // ULTRASONIC SENSOR - WALL DETECTION
        // ============================================
        function detectWallAhead() {
            var rad = robot.angle * Math.PI / 180;
            var minDist = 999;
            
            // Check distance to each wall
            for (var w = 0; w < wallObjects.length; w++) {
                var wall = wallObjects[w];
                
                // Ray-box intersection
                var dist = rayBoxIntersection(
                    robot.x, robot.y,
                    Math.cos(rad), Math.sin(rad),
                    wall.x, wall.y, wall.width, wall.height
                );
                
                if (dist > 0 && dist < minDist) {
                    minDist = dist;
                }
            }
            
            // Also check canvas boundaries as walls
            var boundaryDist = rayBoundaryIntersection(robot.x, robot.y, Math.cos(rad), Math.sin(rad));
            if (boundaryDist < minDist) {
                minDist = boundaryDist;
            }
            
            return minDist;
        }
        
        function rayBoxIntersection(rx, ry, dx, dy, bx, by, bw, bh) {
            // Ray-AABB intersection
            var tmin = -Infinity;
            var tmax = Infinity;
            
            // Check X axis
            if (dx !== 0) {
                var t1 = (bx - rx) / dx;
                var t2 = (bx + bw - rx) / dx;
                tmin = Math.max(tmin, Math.min(t1, t2));
                tmax = Math.min(tmax, Math.max(t1, t2));
            } else if (rx < bx || rx > bx + bw) {
                return -1;
            }
            
            // Check Y axis
            if (dy !== 0) {
                var t1 = (by - ry) / dy;
                var t2 = (by + bh - ry) / dy;
                tmin = Math.max(tmin, Math.min(t1, t2));
                tmax = Math.min(tmax, Math.max(t1, t2));
            } else if (ry < by || ry > by + bh) {
                return -1;
            }
            
            if (tmax >= tmin && tmax > 0) {
                return tmin > 0 ? tmin : tmax;
            }
            return -1;
        }
        
        function rayBoundaryIntersection(rx, ry, dx, dy) {
            // Canvas is 550×550 with a 25px play-area padding (active area: 25..525)
            var minDist = 999;
            
            // Check all 4 boundaries
            if (dx > 0) {
                var t = (525 - rx) / dx;
                if (t > 0 && t < minDist) minDist = t;
            } else if (dx < 0) {
                var t = (25 - rx) / dx;
                if (t > 0 && t < minDist) minDist = t;
            }
            
            if (dy > 0) {
                var t = (525 - ry) / dy;
                if (t > 0 && t < minDist) minDist = t;
            } else if (dy < 0) {
                var t = (25 - ry) / dy;
                if (t > 0 && t < minDist) minDist = t;
            }
            
            return minDist;
        }
        
        // ============================================
        // TEMPERATURE SENSOR - FIRE DETECTION
        // ============================================
        function detectFireAhead() {
            var minDist = 999;
            var closestFire = null;
            var baseTemp = 25; // Normal room temperature
            
            // Check distance to each fire
            for (var f = 0; f < fireObjects.length; f++) {
                var fire = fireObjects[f];
                var dx = fire.x - robot.x;
                var dy = fire.y - robot.y;
                var dist = Math.sqrt(dx * dx + dy * dy);
                
                if (dist < minDist) {
                    minDist = dist;
                    closestFire = fire;
                }
            }
            
            // Calculate temperature based on distance
            var temp = baseTemp;
            if (closestFire) {
                // Temperature increases as you get closer
                // Max temp ~500°C when very close, decreases with distance
                temp = Math.max(baseTemp, Math.min(500, baseTemp + (275 - minDist) * 2.5));
            }
            
            return {
                fire: closestFire,
                distance: minDist,
                temp: Math.round(temp)
            };
        }
        
        // Find nearest fire from robot
        function findNearestFire() {
            var minDist = 999;
            var nearestFire = null;
            
            for (var f = 0; f < fireObjects.length; f++) {
                var fire = fireObjects[f];
                var dx = fire.x - robot.x;
                var dy = fire.y - robot.y;
                var dist = Math.sqrt(dx * dx + dy * dy);
                
                if (dist < minDist) {
                    minDist = dist;
                    nearestFire = fire;
                }
            }
            
            return nearestFire;
        }
        
        // Firefighter mode - auto-navigate and extinguish all fires
        function executeFirefighterMode(onComplete) {
            var maxSteps = 200; // Safety limit
            var stepCount = 0;
            
            function firefightStep() {
                if (stepCount >= maxSteps) {
                    addChatMessage('stemo', "🚒 Reached step limit. Some fires may remain.");
                    if (onComplete) onComplete();
                    return;
                }
                
                // Check if all fires extinguished
                if (fireObjects.length === 0) {
                    addChatMessage('stemo', "🚒🎉 All fires extinguished! Area is safe!");
                    if (currentLesson) {
                        checkLessonCompletion();
                    }
                    if (onComplete) onComplete();
                    return;
                }
                
                // Check water level
                if (robot.waterLevel <= 0) {
                    addChatMessage('stemo', "💧 Water empty! Returning to base...");
                    // Move toward home to "refill"
                    var dx = 275 - robot.x;
                    var dy = 275 - robot.y;
                    var dist = Math.sqrt(dx * dx + dy * dy);
                    
                    if (dist < 30) {
                        robot.waterLevel = 10;
                        playSound('success');
                        addChatMessage('stemo', "💧 Tank refilled! Water: 10/10");
                    } else {
                        var desiredAngle = Math.atan2(dy, dx) * 180 / Math.PI;
                        robot.angle = desiredAngle;
                        var rad = robot.angle * Math.PI / 180;
                        robot.x += Math.cos(rad) * 15;
                        robot.y += Math.sin(rad) * 15;
                        playSound('move');
                    }
                    
                    stepCount++;
                    drawRobot();
                    setTimeout(firefightStep, 150);
                    return;
                }
                
                // Find nearest fire
                var nearestFire = findNearestFire();
                if (!nearestFire) {
                    if (onComplete) onComplete();
                    return;
                }
                
                var dx = nearestFire.x - robot.x;
                var dy = nearestFire.y - robot.y;
                var dist = Math.sqrt(dx * dx + dy * dy);
                
                // If close enough, spray water
                if (dist < 50) {
                    robot.waterLevel--;
                    nearestFire.health--;
                    robot.visible = true;
                    // Trigger spray effect
                    robot.spraying = true;
                    playSound('spray');
                    setTimeout(() => { robot.spraying = false; }, 1000);
                    
                    if (nearestFire.health <= 0) {
                        fireObjects = fireObjects.filter(function(f) { return f !== nearestFire; });
                        playSound('fire_out');
                        addChatMessage('stemo', "🚒💧 Fire out! " + fireObjects.length + " fires remaining. Water: " + robot.waterLevel + "/10");
                    }
                    
                    setTimeout(function() { robot.spraying = false; drawRobot(); }, 300);
                } else {
                    // Move toward fire
                    var desiredAngle = Math.atan2(dy, dx) * 180 / Math.PI;
                    var angleDiff = desiredAngle - robot.angle;
                    
                    while (angleDiff > 180) angleDiff -= 360;
                    while (angleDiff < -180) angleDiff += 360;
                    
                    // Check for walls
                    var wallDist = detectWallAhead();
                    
                    if (wallDist <= 30) {
                        playSound('bonk');
                        var turnDir = chooseBestTurnDirection();
                        robot.angle += turnDir;
                    } else if (Math.abs(angleDiff) > 15) {
                        playSound('turn');
                        robot.angle += angleDiff > 0 ? 15 : -15;
                    } else {
                        playSound('move');
                        var rad = robot.angle * Math.PI / 180;
                        robot.x += Math.cos(rad) * 15;
                        robot.y += Math.sin(rad) * 15;
                        
                        robot.x = Math.max(25, Math.min(525, robot.x));
                        robot.y = Math.max(25, Math.min(525, robot.y));
                    }
                }
                
                stepCount++;
                drawRobot();
                setTimeout(firefightStep, 150);
            }
            
            addChatMessage('stemo', "🚒 Firefighter mode activated! Searching for fires...");
            firefightStep();
        }
        
        // --- BFS-based pathfinder helpers ---
        function isCellBlocked(x, y) {
            var margin = 8;
            for (var i = 0; i < wallObjects.length; i++) {
                var w = wallObjects[i];
                if (x + margin > w.x && x - margin < w.x + w.width &&
                    y + margin > w.y && y - margin < w.y + w.height) {
                    return true;
                }
            }
            return false;
        }

        function bfsPath(startX, startY, goalX, goalY) {
            // Snap positions to 20-px grid (grid starts at x=25, y=25)
            function snap(v) { return Math.round((v - 25) / 20) * 20 + 25; }
            var sx = snap(startX), sy = snap(startY);
            var gx = snap(goalX),  gy = snap(goalY);
            gx = Math.max(25, Math.min(525, gx));
            gy = Math.max(25, Math.min(525, gy));

            var queue   = [{x: sx, y: sy}];
            var parent  = {};
            parent[sx + ',' + sy] = null;

            while (queue.length > 0) {
                var cur = queue.shift();

                if (Math.abs(cur.x - gx) <= 10 && Math.abs(cur.y - gy) <= 10) {
                    // Reconstruct path from start to cur
                    var path = [];
                    var node = {x: cur.x, y: cur.y};
                    while (node !== null) {
                        path.unshift(node);
                        var pk = node.x + ',' + node.y;
                        node = parent[pk];
                    }
                    return path;
                }

                var dirs = [{dx:20,dy:0},{dx:-20,dy:0},{dx:0,dy:20},{dx:0,dy:-20}];
                for (var d = 0; d < dirs.length; d++) {
                    var nx = cur.x + dirs[d].dx;
                    var ny = cur.y + dirs[d].dy;
                    if (nx < 25 || nx > 525 || ny < 25 || ny > 525) continue;
                    var key = nx + ',' + ny;
                    if (key in parent) continue;
                    if (isCellBlocked(nx, ny)) continue;
                    parent[key] = {x: cur.x, y: cur.y};
                    queue.push({x: nx, y: ny});
                }
            }
            return null; // no path
        }

        // Greedy Go To Target — steers toward target angle each step, turns when wall detected
        function executeGoToTarget(onComplete) {
            if (!targetPoint) { if (onComplete) onComplete(); return; }
            var maxSteps = 300;
            var stepCount = 0;
            function moveStep() {
                if (stepCount >= maxSteps) {
                    addChatMessage('stemo', "🎯 Couldn't reach target after " + maxSteps + " steps. Try Smart Navigate for complex mazes!");
                    if (onComplete) onComplete();
                    return;
                }
                var dx = targetPoint.x - robot.x, dy = targetPoint.y - robot.y;
                var dist = Math.sqrt(dx*dx + dy*dy);
                if (dist < 25) {
                    robot.x = targetPoint.x; robot.y = targetPoint.y;
                    playSound('success');
                    addChatMessage('stemo', "🎯 Target reached! 🎉");
                    drawRobot();
                    if (currentLesson) checkLessonCompletion();
                    if (onComplete) onComplete();
                    return;
                }
                var desiredAngle = Math.atan2(dy, dx) * 180 / Math.PI;
                var angleDiff = desiredAngle - robot.angle;
                while (angleDiff > 180) angleDiff -= 360;
                while (angleDiff < -180) angleDiff += 360;
                var wallDist = detectWallAhead();
                if (wallDist <= 30) {
                    playSound('bonk');
                    robot.angle += chooseBestTurnDirection();
                } else if (Math.abs(angleDiff) > 15) {
                    playSound('turn');
                    robot.angle += angleDiff > 0 ? 15 : -15;
                } else {
                    playSound('move');
                    var rad = robot.angle * Math.PI / 180;
                    robot.x = Math.max(25, Math.min(525, robot.x + Math.cos(rad) * 20));
                    robot.y = Math.max(25, Math.min(525, robot.y + Math.sin(rad) * 20));
                }
                stepCount++;
                drawRobot();
                setTimeout(moveStep, 150);
            }
            addChatMessage('stemo', "🎯 Navigating to target…");
            moveStep();
        }

        // Smart Navigate — BFS pathfinder guarantees shortest route through any maze
        function executeSmartNavigate(onComplete) {
            if (!targetPoint) { if (onComplete) onComplete(); return; }

            var path = bfsPath(robot.x, robot.y, targetPoint.x, targetPoint.y);

            if (!path || path.length === 0) {
                addChatMessage('stemo', "🚫 No path to target! The target might be completely surrounded by walls.");
                if (onComplete) onComplete();
                return;
            }

            addChatMessage('stemo', "🧭 Shortest path found — " + (path.length - 1) + " steps. Following it now…");

            var stepIndex = 1;

            function followPath() {
                if (stepIndex >= path.length) {
                    robot.x = targetPoint.x;
                    robot.y = targetPoint.y;
                    playSound('success');
                    addChatMessage('stemo', "🎯 Target reached! 🎉");
                    drawRobot();
                    if (currentLesson) checkLessonCompletion();
                    if (onComplete) onComplete();
                    return;
                }

                var pt   = path[stepIndex];
                var prev = path[stepIndex - 1];
                var dx = pt.x - prev.x, dy = pt.y - prev.y;
                if (dx !== 0 || dy !== 0) robot.angle = Math.atan2(dy, dx) * 180 / Math.PI;

                robot.x = pt.x;
                robot.y = pt.y;
                stepIndex++;
                playSound('move');
                drawRobot();

                var edx = robot.x - targetPoint.x, edy = robot.y - targetPoint.y;
                if (Math.sqrt(edx*edx + edy*edy) < 25) {
                    robot.x = targetPoint.x; robot.y = targetPoint.y;
                    playSound('success');
                    addChatMessage('stemo', "🎯 Target reached! 🎉");
                    drawRobot();
                    if (currentLesson) checkLessonCompletion();
                    if (onComplete) onComplete();
                    return;
                }

                setTimeout(followPath, 120);
            }

            followPath();
        }

        // Navigate to any arbitrary {x,y} point using BFS
        function executeNavigateToPoint(tx, ty, msg, onComplete) {
            var savedTarget = targetPoint;
            targetPoint = { x: tx, y: ty };
            if (msg) addChatMessage('stemo', msg);
            var path = bfsPath(robot.x, robot.y, tx, ty);
            targetPoint = savedTarget;
            if (!path || path.length === 0) {
                if (onComplete) onComplete();
                return;
            }
            var si = 1;
            function step() {
                if (si >= path.length) {
                    robot.x = tx; robot.y = ty;
                    drawRobot();
                    if (onComplete) onComplete();
                    return;
                }
                var pt = path[si], prev = path[si - 1];
                var dx = pt.x - prev.x, dy = pt.y - prev.y;
                if (dx !== 0 || dy !== 0) robot.angle = Math.atan2(dy, dx) * 180 / Math.PI;
                robot.x = pt.x; robot.y = pt.y;
                si++; playSound('move'); drawRobot();
                var edx = robot.x - tx, edy = robot.y - ty;
                if (Math.sqrt(edx*edx + edy*edy) < 25) {
                    robot.x = tx; robot.y = ty;
                    drawRobot();
                    if (onComplete) onComplete();
                    return;
                }
                setTimeout(step, 120);
            }
            step();
        }

        // Replay all waypoints in sequence
        function executeReplayWaypoints(pts, idx, onComplete) {
            if (idx >= pts.length) {
                addChatMessage('stemo', "✅ Replayed all " + pts.length + " waypoints!");
                if (onComplete) onComplete();
                return;
            }
            var pt = pts[idx];
            executeNavigateToPoint(pt.x, pt.y, null, function() {
                if (challengeMode) checkChallengeObjectives();
                setTimeout(function() { executeReplayWaypoints(pts, idx + 1, onComplete); }, 200);
            });
        }

        // For each waypoint: navigate there, then run doCommands
        function executeForeachWaypoint(pts, idx, doCommands, onComplete) {
            if (idx >= pts.length) {
                addChatMessage('stemo', "✅ Visited all " + pts.length + " waypoints!");
                if (onComplete) onComplete();
                return;
            }
            var pt = pts[idx];
            executeNavigateToPoint(pt.x, pt.y, "🔂 [" + (idx+1) + "/" + pts.length + "] Going to waypoint…", function() {
                if (challengeMode) checkChallengeObjectives();
                if (doCommands && doCommands.length > 0) {
                    executeCommands(doCommands, function() {
                        if (challengeMode) checkChallengeObjectives();
                        setTimeout(function() { executeForeachWaypoint(pts, idx + 1, doCommands, onComplete); }, 200);
                    });
                } else {
                    setTimeout(function() { executeForeachWaypoint(pts, idx + 1, doCommands, onComplete); }, 200);
                }
            });
        }

        // ============================================
        // ROBOT DRAWING
        // ============================================
        function drawRobot() {
            var canvas = document.getElementById('robotCanvas');
            var ctx = canvas.getContext('2d');
            
            // Clear canvas
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Draw grid with step numbers (each grid = 2 steps = 40px, 1 step = 20px)
            ctx.strokeStyle = '#e5e7eb';
            ctx.lineWidth = 1;
            for (var i = 0; i < canvas.width; i += 40) {
                ctx.beginPath();
                ctx.moveTo(i, 0);
                ctx.lineTo(i, canvas.height);
                ctx.stroke();
                
                // Add step numbers on top (every 2 steps)
                if (i > 0 && i < canvas.width) {
                    ctx.fillStyle = '#9ca3af';
                    ctx.font = '10px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText((i / 20).toString(), i, 12);
                }
            }
            for (var j = 0; j < canvas.height; j += 40) {
                ctx.beginPath();
                ctx.moveTo(0, j);
                ctx.lineTo(canvas.width, j);
                ctx.stroke();
                
                // Add step numbers on left side
                if (j > 0 && j < canvas.height) {
                    ctx.fillStyle = '#9ca3af';
                    ctx.font = '10px Arial';
                    ctx.textAlign = 'left';
                    ctx.fillText((j / 20).toString(), 3, j + 4);
                }
            }
            
            // Draw "1 step = 20px" indicator in corner
            ctx.fillStyle = '#6b7280';
            ctx.font = '9px Arial';
            ctx.textAlign = 'right';
            ctx.fillText('1 step = 1 grid line', canvas.width - 5, canvas.height - 5);
            
            // Draw ghost target pattern (faded reference lines for drawing challenges)
            if (targetTrails.length > 0) {
                ctx.save();
                ctx.globalAlpha = 0.18;
                ctx.lineWidth = 4;
                ctx.lineCap = 'round';
                targetTrails.forEach(function(trail) {
                    ctx.beginPath();
                    ctx.strokeStyle = trail.color;
                    ctx.moveTo(trail.x1, trail.y1);
                    ctx.lineTo(trail.x2, trail.y2);
                    ctx.stroke();
                });
                ctx.restore();
            }

            // Draw trails
            robot.trails.forEach(function(trail) {
                ctx.beginPath();
                ctx.strokeStyle = trail.color;
                ctx.lineWidth = trail.size || 4;
                ctx.lineCap = 'round';
                ctx.moveTo(trail.x1, trail.y1);
                ctx.lineTo(trail.x2, trail.y2);
                ctx.stroke();
            });
            
            // Draw walls (obstacles)
            // Group walls by location
            var wallGroups = groupObjects(wallObjects);
            
            Object.values(wallGroups).forEach(function(group) {
                var wall = group[0]; // Draw the first one
                
                ctx.save();
                
                // Check if this wall is selected
                var isSelected = (selectedObject === wall);
                
                // Selection highlight
                if (isSelected) {
                    ctx.strokeStyle = '#06b6d4';
                    ctx.lineWidth = 3;
                    ctx.setLineDash([5, 3]);
                    ctx.strokeRect(wall.x - 4, wall.y - 4, wall.width + 8, wall.height + 8);
                    ctx.setLineDash([]);
                }
                
                // Wall shadow
                ctx.shadowColor = 'rgba(0,0,0,0.3)';
                ctx.shadowBlur = 5;
                ctx.shadowOffsetX = 2;
                ctx.shadowOffsetY = 2;
                
                // Wall body - brick pattern
                ctx.fillStyle = '#b45309';
                ctx.fillRect(wall.x, wall.y, wall.width, wall.height);
                
                // Brick lines
                ctx.strokeStyle = '#78350f';
                ctx.lineWidth = 1;
                ctx.beginPath();
                // Horizontal lines
                for (var h = 1; h < wall.height; h += 10) {
                    ctx.moveTo(wall.x, wall.y + h);
                    ctx.lineTo(wall.x + wall.width, wall.y + h);
                }
                // Vertical lines (staggered)
                for (var h = 0; h < wall.height; h += 10) {
                    var offset = (h / 10) % 2 === 0 ? 0 : 10;
                    for (var w = offset; w < wall.width; w += 20) {
                        ctx.moveTo(wall.x + w, wall.y + h);
                        ctx.lineTo(wall.x + w, wall.y + h + 10);
                    }
                }
                ctx.stroke();
                ctx.restore();
                
                // Draw Count Badge if stacked
                if (group.length > 1) {
                    drawCountBadge(ctx, wall.x + wall.width, wall.y, group.length);
                }
            });

            // Draw target point
            if (targetPoint) {
                var x = targetPoint.x;
                var y = targetPoint.y;
                var time = Date.now() / 500;
                var pulse = Math.sin(time) * 5;
                
                ctx.save();
                // Outer glow
                ctx.beginPath();
                ctx.arc(x, y, 15 + pulse, 0, Math.PI * 2);
                ctx.fillStyle = 'rgba(34, 197, 94, 0.2)';
                ctx.fill();
                
                // Inner circle
                ctx.beginPath();
                ctx.arc(x, y, 8, 0, Math.PI * 2);
                ctx.fillStyle = '#22c55e';
                ctx.fill();
                
                // Target rings
                ctx.strokeStyle = 'white';
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.arc(x, y, 5, 0, Math.PI * 2);
                ctx.stroke();
                
                // Flag pole
                ctx.beginPath();
                ctx.moveTo(x + 2, y - 2);
                ctx.lineTo(x + 2, y - 12);
                ctx.strokeStyle = '#15803d';
                ctx.lineWidth = 2;
                ctx.stroke();
                
                // Flag
                ctx.beginPath();
                ctx.moveTo(x + 2, y - 12);
                ctx.lineTo(x + 10, y - 8);
                ctx.lineTo(x + 2, y - 4);
                ctx.fillStyle = '#ef4444';
                ctx.fill();
                
                ctx.restore();
            }

            // Draw saved position markers (A / B / C / D)
            var posColors = { A: '#3b82f6', B: '#8b5cf6', C: '#f59e0b', D: '#ec4899' };
            ['A','B','C','D'].forEach(function(slot) {
                var pos = savedPositions[slot];
                if (!pos) return;
                var col = posColors[slot];
                ctx.save();
                // Glow
                ctx.beginPath();
                ctx.arc(pos.x, pos.y, 14, 0, Math.PI * 2);
                ctx.fillStyle = col.replace(')', ', 0.2)').replace('rgb', 'rgba');
                ctx.fill();
                // Filled circle
                ctx.beginPath();
                ctx.arc(pos.x, pos.y, 9, 0, Math.PI * 2);
                ctx.fillStyle = col;
                ctx.fill();
                ctx.strokeStyle = 'white';
                ctx.lineWidth = 2;
                ctx.stroke();
                // Pole
                ctx.beginPath();
                ctx.moveTo(pos.x + 1, pos.y - 9);
                ctx.lineTo(pos.x + 1, pos.y - 22);
                ctx.strokeStyle = '#1e3a5f';
                ctx.lineWidth = 2;
                ctx.stroke();
                // Small flag
                ctx.beginPath();
                ctx.moveTo(pos.x + 1, pos.y - 22);
                ctx.lineTo(pos.x + 9, pos.y - 18);
                ctx.lineTo(pos.x + 1, pos.y - 14);
                ctx.fillStyle = col;
                ctx.fill();
                // Letter label
                ctx.font = 'bold 9px Arial';
                ctx.fillStyle = 'white';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(slot, pos.x, pos.y);
                // Slot name below pin
                ctx.font = 'bold 10px Arial';
                ctx.fillStyle = col;
                ctx.textAlign = 'center';
                ctx.fillText('POS ' + slot, pos.x, pos.y + 22);
                // If selected, draw dashed ring
                if (selectedObject === pos && selectedObjectType === 'position') {
                    ctx.strokeStyle = '#06b6d4';
                    ctx.lineWidth = 2;
                    ctx.setLineDash([4, 3]);
                    ctx.beginPath();
                    ctx.arc(pos.x, pos.y, 16, 0, Math.PI * 2);
                    ctx.stroke();
                    ctx.setLineDash([]);
                }
                ctx.restore();
            });

            // Draw waypoint list markers
            waypointList.forEach(function(pt, idx) {
                ctx.save();
                // Connecting line to next waypoint (dashed)
                if (idx < waypointList.length - 1) {
                    var next = waypointList[idx + 1];
                    ctx.beginPath();
                    ctx.setLineDash([5, 4]);
                    ctx.strokeStyle = 'rgba(16,185,129,0.5)';
                    ctx.lineWidth = 1.5;
                    ctx.moveTo(pt.x, pt.y);
                    ctx.lineTo(next.x, next.y);
                    ctx.stroke();
                    ctx.setLineDash([]);
                }
                // Circle pin
                ctx.beginPath();
                ctx.arc(pt.x, pt.y, 9, 0, Math.PI * 2);
                ctx.fillStyle = '#10b981';
                ctx.fill();
                ctx.strokeStyle = 'white';
                ctx.lineWidth = 1.5;
                ctx.stroke();
                // Number
                ctx.font = 'bold 9px Arial';
                ctx.fillStyle = 'white';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText((idx + 1).toString(), pt.x, pt.y);
                ctx.restore();
            });

            // Draw "TRANSMITTING" flash when send_data block fires
            if (robot.txFlash && Date.now() < robot.txFlash.expires) {
                var progress = (robot.txFlash.expires - Date.now()) / 1800;
                ctx.save();
                ctx.globalAlpha = Math.min(1, progress * 2);
                // Expanding ring around robot
                var ringR = 18 + (1 - progress) * 30;
                ctx.beginPath();
                ctx.arc(robot.x, robot.y, ringR, 0, Math.PI * 2);
                ctx.strokeStyle = '#38bdf8';
                ctx.lineWidth = 2;
                ctx.stroke();
                var ringR2 = 18 + (1 - progress) * 55;
                ctx.beginPath();
                ctx.arc(robot.x, robot.y, ringR2, 0, Math.PI * 2);
                ctx.strokeStyle = 'rgba(56,189,248,0.4)';
                ctx.lineWidth = 1;
                ctx.stroke();
                // "📡 TX" label above robot
                ctx.font = 'bold 11px monospace';
                ctx.fillStyle = '#38bdf8';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'bottom';
                ctx.fillText('📡 TRANSMITTING…', robot.x, robot.y - 22);
                ctx.restore();
            }

            // Draw position coordinate flash (Show My Position block)
            if (robot.posFlash && Date.now() < robot.posFlash.expires) {
                ctx.save();
                var fx = robot.posFlash.x, fy = robot.posFlash.y - 30;
                var flabel = robot.posFlash.label;
                ctx.font = 'bold 13px Arial';
                var tw = ctx.measureText(flabel).width + 16;
                ctx.fillStyle = 'rgba(15,23,42,0.85)';
                ctx.beginPath();
                ctx.roundRect ? ctx.roundRect(fx - tw/2, fy - 11, tw, 22, 6) : ctx.rect(fx - tw/2, fy - 11, tw, 22);
                ctx.fill();
                ctx.fillStyle = '#38bdf8';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(flabel, fx, fy);
                ctx.restore();
            }
            
            // Draw ultrasonic sensor beam
            /*
            if (showSensorBeam && robot.visible) {
                var wallDist = detectWallAhead();
                var beamLength = Math.min(wallDist, sensorRange);
                var rad = robot.angle * Math.PI / 180;
                
                ctx.save();
                
                // Sensor cone
                var coneWidth = 20; // degrees
                ctx.fillStyle = 'rgba(59, 130, 246, 0.15)';
                ctx.beginPath();
                ctx.moveTo(robot.x, robot.y);
                ctx.arc(robot.x, robot.y, beamLength, (robot.angle - coneWidth) * Math.PI / 180, (robot.angle + coneWidth) * Math.PI / 180);
                ctx.closePath();
                ctx.fill();
                
                // Center beam line
                ctx.strokeStyle = 'rgba(59, 130, 246, 0.5)';
                ctx.lineWidth = 2;
                ctx.setLineDash([5, 5]);
                ctx.beginPath();
                ctx.moveTo(robot.x, robot.y);
                ctx.lineTo(robot.x + Math.cos(rad) * beamLength, robot.y + Math.sin(rad) * beamLength);
                ctx.stroke();
                ctx.setLineDash([]);
                
                // Distance indicator if wall detected
                if (wallDist < sensorRange) {
                    var indicatorX = robot.x + Math.cos(rad) * wallDist;
                    var indicatorY = robot.y + Math.sin(rad) * wallDist;
                    
                    ctx.fillStyle = '#ef4444';
                    ctx.beginPath();
                    ctx.arc(indicatorX, indicatorY, 5, 0, Math.PI * 2);
                    ctx.fill();
                    
                    ctx.fillStyle = '#dc2626';
                    ctx.font = 'bold 10px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText(Math.round(wallDist / 20) + ' steps', indicatorX, indicatorY - 10);
                }
                
                ctx.restore();
            }
            */
            
            // Draw Metals
            // In challenge mode: find active metal (first uncollected in order)
            var activeMetal = null;
            var activeMetalIndex = -1;
            if (challengeMode) {
                for (var mi = 0; mi < metalObjects.length; mi++) {
                    if (!metalObjects[mi].pickedUp) { activeMetal = metalObjects[mi]; activeMetalIndex = mi; break; }
                }
            }

            // L-shaped step guides to ALL uncollected metals — drawn BEFORE metals
            if (challengeMode) {
                // Shared pill draw helper — dark text for readability on yellow canvas
                function drawStepPill(ctx2, txt, cx, cy, bgCol, bold) {
                    ctx2.font = (bold ? 'bold ' : '') + '11px Arial';
                    var tw = ctx2.measureText(txt).width + 16;
                    var ph = 16; // pill height
                    var px = cx - tw / 2;
                    var py = cy - ph / 2;
                    // Shadow for pop
                    ctx2.shadowColor = 'rgba(0,0,0,0.25)'; ctx2.shadowBlur = 4; ctx2.shadowOffsetY = 1;
                    ctx2.fillStyle = bgCol;
                    ctx2.beginPath();
                    ctx2.arc(px + 8,        py + ph/2, ph/2, Math.PI/2, -Math.PI/2);
                    ctx2.arc(px + tw - 8,   py + ph/2, ph/2, -Math.PI/2, Math.PI/2);
                    ctx2.closePath();
                    ctx2.fill();
                    ctx2.shadowColor = 'transparent'; ctx2.shadowBlur = 0; ctx2.shadowOffsetY = 0;
                    // Dark text so it pops on any bg
                    ctx2.fillStyle = bold ? '#431407' : '#1e1b4b';
                    ctx2.textAlign = 'center';
                    ctx2.fillText(txt, cx, cy + 4);
                }

                metalObjects.forEach(function(metal, mIdx) {
                    if (metal.pickedUp) return;
                    var isAct = (metal === activeMetal);
                    var mhSteps = Math.round((metal.x - robot.x) / 20);
                    var mvSteps = Math.round((metal.y - robot.y) / 20);
                    // Vertical offset per metal so horizontal labels don't stack
                    var hLabelOffset = mIdx * 18;

                    ctx.save();
                    // Active: bold amber; others: soft indigo
                    ctx.setLineDash(isAct ? [7, 4] : [5, 6]);
                    ctx.lineWidth = isAct ? 2.5 : 1.5;
                    ctx.strokeStyle = isAct ? 'rgba(245,158,11,0.9)' : 'rgba(99,102,241,0.5)';
                    ctx.lineCap = 'round';
                    // Horizontal leg
                    ctx.beginPath();
                    ctx.moveTo(robot.x, robot.y);
                    ctx.lineTo(metal.x, robot.y);
                    ctx.stroke();
                    // Vertical leg
                    ctx.beginPath();
                    ctx.moveTo(metal.x, robot.y);
                    ctx.lineTo(metal.x, metal.y);
                    ctx.stroke();
                    ctx.setLineDash([]);
                    // Corner dot
                    ctx.beginPath();
                    ctx.arc(metal.x, robot.y, isAct ? 4 : 3, 0, Math.PI * 2);
                    ctx.fillStyle = isAct ? '#f59e0b' : '#6366f1';
                    ctx.fill();

                    // Horizontal label — staggered above horizontal leg per mIdx
                    if (Math.abs(mhSteps) > 0) {
                        var hMid = (robot.x + metal.x) / 2;
                        var hTxt = (mhSteps > 0 ? '→ ' : '← ') + Math.abs(mhSteps) + ' steps';
                        var hLabelY = robot.y - 10 - hLabelOffset;
                        drawStepPill(ctx, hTxt, hMid, hLabelY, isAct ? '#fde68a' : '#c7d2fe', isAct);
                    }
                    // Vertical label — on the right side of the vertical leg, staggered by mIdx
                    if (Math.abs(mvSteps) > 0) {
                        var vMid = (robot.y + metal.y) / 2;
                        var vTxt = (mvSteps > 0 ? '↓ ' : '↑ ') + Math.abs(mvSteps) + ' steps';
                        var vLabelX = metal.x + 30 + (mIdx * 4);
                        drawStepPill(ctx, vTxt, vLabelX, vMid, isAct ? '#fde68a' : '#c7d2fe', isAct);
                    }
                    ctx.restore();
                });
            }

            // Draw each metal
            var metalGroups = groupObjects(metalObjects);
            Object.values(metalGroups).forEach(function(group) {
                var item = group[0];
                // Hide metals that are currently being carried.
                // Metals that have been dropped (item.dropped=true) keep pickedUp=true for
                // objective tracking but should be rendered at their new drop position.
                if (item.pickedUp && !item.dropped) return;
                var stepIdx = metalObjects.indexOf(item); // 0-based order
                var isActive = (challengeMode && item === activeMetal);
                var isLocked = (challengeMode && !item.pickedUp && !isActive);

                var dx = item.x - robot.x;
                var dy = item.y - robot.y;
                var dist = Math.sqrt(dx * dx + dy * dy);
                
                ctx.save();
                // Slightly dim future metals so active stands out, but still readable
                if (isLocked) ctx.globalAlpha = 0.75;

                // Shadow / glow
                if (selectedObject === item) {
                    ctx.shadowColor = '#06b6d4'; ctx.shadowBlur = 15;
                } else if (isActive) {
                    ctx.shadowColor = '#f59e0b'; ctx.shadowBlur = 18;
                } else {
                    ctx.shadowColor = 'rgba(0,0,0,0.2)'; ctx.shadowBlur = 5; ctx.shadowOffsetY = 3;
                }

                var mR = challengeMode ? 16 : 10;

                if (item.type === 'bolt') {
                    if (challengeMode) {
                        ctx.beginPath(); ctx.arc(item.x, item.y, mR + 6, 0, Math.PI * 2);
                        ctx.fillStyle = 'rgba(251,191,36,0.25)'; ctx.fill();
                    }
                    ctx.fillStyle = challengeMode ? '#f59e0b' : '#94a3b8';
                    ctx.beginPath();
                    for (var i = 0; i < 6; i++) ctx.lineTo(item.x + mR * Math.cos(i * Math.PI/3 - Math.PI/6), item.y + mR * Math.sin(i * Math.PI/3 - Math.PI/6));
                    ctx.closePath(); ctx.fill();
                    ctx.strokeStyle = challengeMode ? '#d97706' : '#64748b'; ctx.lineWidth = challengeMode ? 2.5 : 1.5; ctx.stroke();
                    ctx.fillStyle = challengeMode ? '#fcd34d' : '#cbd5e1';
                    ctx.beginPath();
                    for (var i = 0; i < 6; i++) ctx.lineTo(item.x + mR*0.5 * Math.cos(i * Math.PI/3 - Math.PI/6), item.y + mR*0.5 * Math.sin(i * Math.PI/3 - Math.PI/6));
                    ctx.closePath(); ctx.fill();
                } else if (item.type === 'gear') {
                    if (challengeMode) {
                        ctx.beginPath(); ctx.arc(item.x, item.y, mR + 6, 0, Math.PI * 2);
                        ctx.fillStyle = 'rgba(99,102,241,0.25)'; ctx.fill();
                    }
                    ctx.fillStyle = challengeMode ? '#6366f1' : '#78716c';
                    ctx.beginPath();
                    for (var i = 0; i < 16; i++) {
                        var r2 = (i % 2 === 0) ? mR : mR*0.68;
                        ctx.lineTo(item.x + r2 * Math.cos(Math.PI*i/8), item.y + r2 * Math.sin(Math.PI*i/8));
                    }
                    ctx.closePath(); ctx.fill();
                    ctx.strokeStyle = challengeMode ? '#4338ca' : '#57534e'; ctx.lineWidth = challengeMode ? 2 : 1; ctx.stroke();
                    ctx.beginPath(); ctx.arc(item.x, item.y, mR*0.28, 0, Math.PI*2);
                    ctx.fillStyle = challengeMode ? '#a5b4fc' : '#44403c'; ctx.fill();
                } else {
                    if (challengeMode) {
                        ctx.beginPath(); ctx.arc(item.x, item.y, mR + 6, 0, Math.PI * 2);
                        ctx.fillStyle = 'rgba(16,185,129,0.25)'; ctx.fill();
                    }
                    ctx.fillStyle = challengeMode ? '#10b981' : '#a1a1aa';
                    ctx.beginPath(); ctx.arc(item.x, item.y, mR, 0, Math.PI*2); ctx.fill();
                    ctx.strokeStyle = challengeMode ? '#059669' : '#52525b'; ctx.lineWidth = challengeMode ? 2.5 : 1.5; ctx.stroke();
                    var cx = mR * 0.55;
                    ctx.beginPath();
                    ctx.moveTo(item.x-cx, item.y-cx); ctx.lineTo(item.x+cx, item.y+cx);
                    ctx.moveTo(item.x+cx, item.y-cx); ctx.lineTo(item.x-cx, item.y+cx);
                    ctx.strokeStyle = challengeMode ? '#d1fae5' : '#e4e4e7'; ctx.lineWidth = challengeMode ? 3 : 2; ctx.stroke();
                }

                ctx.restore();

                // Step number badge (challenge mode, not pickedUp)
                if (challengeMode && !item.pickedUp) {
                    var stepNum = stepIdx + 1;
                    var badgeColor = isActive ? '#f59e0b' : '#94a3b8';
                    ctx.save();
                    ctx.beginPath();
                    ctx.arc(item.x + mR - 2, item.y - mR + 2, 9, 0, Math.PI * 2);
                    ctx.fillStyle = badgeColor; ctx.fill();
                    ctx.strokeStyle = '#fff'; ctx.lineWidth = 2; ctx.stroke();
                    ctx.fillStyle = '#fff'; ctx.font = 'bold 10px Arial';
                    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
                    ctx.fillText(stepNum, item.x + mR - 2, item.y - mR + 2);
                    ctx.textBaseline = 'alphabetic';
                    ctx.restore();
                }

                // Emoji label above (active only, or free build)
                if (!item.pickedUp && (isActive || !challengeMode)) {
                    var emoji = item.type === 'bolt' ? '🔩' : item.type === 'gear' ? '⚙️' : '🪛';
                    ctx.font = 'bold 14px Arial'; ctx.textAlign = 'center'; ctx.fillStyle = '#1f2937';
                    ctx.fillText(emoji, item.x, item.y - mR - 5);
                }

                // Free-build: distance text when close
                if (!challengeMode && dist < 100 && !item.pickedUp) {
                    ctx.fillStyle = '#6b7280'; ctx.font = '10px Arial'; ctx.textAlign = 'center';
                    ctx.fillText(Math.round(dist/20) + ' steps', item.x, item.y + mR + 14);
                    if (dist < 80) {
                        ctx.beginPath(); ctx.setLineDash([3,5]);
                        ctx.strokeStyle = 'rgba(107,114,128,0.3)'; ctx.lineWidth = 1;
                        ctx.moveTo(robot.x, robot.y); ctx.lineTo(item.x, item.y); ctx.stroke();
                        ctx.setLineDash([]);
                    }
                }

                // Stacked count badge
                if (group.length > 1) drawCountBadge(ctx, item.x + 8, item.y - 8, group.length);
            });

            // Draw fires (grouped)
            var fireGroups = groupObjects(fireObjects);
            Object.values(fireGroups).forEach(function(group) {
                var fire = group[0];
                var x = fire.x;
                var y = fire.y;
                
                ctx.save();
                
                // Fire glow
                var time = Date.now() / 200;
                var scale = 1 + Math.sin(time) * 0.1;
                
                ctx.shadowColor = '#f97316';
                ctx.shadowBlur = 10 * scale;
                
                // Fire base
                ctx.fillStyle = '#ea580c';
                ctx.beginPath();
                ctx.arc(x, y + 5, 8, 0, Math.PI * 2);
                ctx.fill();
                
                // Fire flame shape
                ctx.fillStyle = '#fdba74';
                ctx.beginPath();
                ctx.moveTo(x - 6, y + 4);
                ctx.quadraticCurveTo(x, y - 15, x + 6, y + 4);
                ctx.fill();
                
                ctx.restore();
                
                // Health bar
                if (fire.health < 3) {
                    var w = 20;
                    var h = 4;
                    ctx.fillStyle = '#374151';
                    ctx.fillRect(x - w/2, y - 20, w, h);
                    
                    ctx.fillStyle = fire.health > 1 ? '#eab308' : '#ef4444';
                    ctx.fillRect(x - w/2, y - 20, w * (fire.health / 3), h);
                }
                
                // Draw Count Badge if stacked
                if (group.length > 1) {
                    drawCountBadge(ctx, x + 8, y - 15, group.length);
                }
            });
            
            
            // Draw temperature sensor beam if fire detected
            if (robot.visible && fireObjects.length > 0) {
                var fireInfo = detectFireAhead();
                if (fireInfo.fire && fireInfo.distance < 150) {
                    ctx.save();
                    
                    // Heat wave effect
                    var rad = robot.angle * Math.PI / 180;
                    ctx.strokeStyle = 'rgba(255, 107, 53, 0.4)';
                    ctx.lineWidth = 3;
                    ctx.setLineDash([3, 6]);
                    ctx.beginPath();
                    ctx.moveTo(robot.x, robot.y);
                    ctx.lineTo(fireInfo.fire.x, fireInfo.fire.y);
                    ctx.stroke();
                    ctx.setLineDash([]);
                    
                    // Temperature reading
                    var midX = (robot.x + fireInfo.fire.x) / 2;
                    var midY = (robot.y + fireInfo.fire.y) / 2;
                    ctx.fillStyle = fireInfo.temp > 100 ? '#dc2626' : '#f97316';
                    ctx.font = 'bold 11px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillStyle = 'white';
                    ctx.beginPath();
                    ctx.roundRect(midX - 25, midY - 10, 50, 20, 5);
                    ctx.fill();
                    ctx.fillStyle = fireInfo.temp > 100 ? '#dc2626' : '#f97316';
                    ctx.fillText('🌡️' + fireInfo.temp + '°C', midX, midY + 4);
                    
                    ctx.restore();
                }
            }
            
            // Draw water spray effect
            if (robot.spraying && robot.visible) {
                ctx.save();
                var rad = robot.angle * Math.PI / 180;
                
                // Water droplets
                ctx.fillStyle = '#60a5fa';
                for (var w = 0; w < 10; w++) {
                    var spray = 20 + Math.random() * 40;
                    var spread = (Math.random() - 0.5) * 40;
                    var wx = robot.x + Math.cos(rad) * spray + Math.cos(rad + Math.PI/2) * spread;
                    var wy = robot.y + Math.sin(rad) * spray + Math.sin(rad + Math.PI/2) * spread;
                    
                    ctx.beginPath();
                    ctx.arc(wx, wy, 3 + Math.random() * 3, 0, Math.PI * 2);
                    ctx.fill();
                }
                
                // Water stream
                ctx.strokeStyle = 'rgba(96, 165, 250, 0.6)';
                ctx.lineWidth = 8;
                ctx.lineCap = 'round';
                ctx.beginPath();
                ctx.moveTo(robot.x, robot.y);
                ctx.lineTo(robot.x + Math.cos(rad) * 50, robot.y + Math.sin(rad) * 50);
                ctx.stroke();
                
                ctx.restore();
            }
            
            // Draw water tank indicator
            if (robot.visible) {
                ctx.save();
                ctx.fillStyle = '#1e3a5f';
                ctx.font = '10px Arial';
                ctx.textAlign = 'left';
                ctx.fillText('💧 Water: ' + robot.waterLevel + '/10', 10, canvas.height - 20);
                
                // Draw water bar
                ctx.fillStyle = '#e5e7eb';
                ctx.fillRect(10, canvas.height - 15, 50, 8);
                ctx.fillStyle = '#3b82f6';
                ctx.fillRect(10, canvas.height - 15, (robot.waterLevel / 10) * 50, 8);
                ctx.restore();
            }
            
            // Draw robot (only if visible)
            if (robot.visible) {
                ctx.save();
                ctx.translate(robot.x, robot.y);
                ctx.rotate((robot.angle + 90) * Math.PI / 180);
                
                // Body - change color if magnet is on  (scaled ~70% of original)
                ctx.fillStyle = robot.magnetOn ? '#ef4444' : '#3b82f6';
                ctx.beginPath();
                ctx.roundRect(-14, -18, 28, 36, 6);
                ctx.fill();
                
                // Magnetic field lines - Realistic arcs
                if (robot.magnetOn) {
                    ctx.save();
                    ctx.rotate(Math.PI);
                    
                    var time = Date.now() / 1000;
                    ctx.lineWidth = 1.5;
                    
                    for (var i = 0; i < 3; i++) {
                        var radius = 18 + (i * 10 + time * 21) % 32;
                        var opacity = 1 - (radius - 18) / 32;
                        
                        ctx.strokeStyle = 'rgba(239, 68, 68, ' + (opacity * 0.6) + ')';
                        ctx.setLineDash([4, 4]);
                        
                        ctx.beginPath();
                        ctx.arc(0, 0, radius, -Math.PI/3, Math.PI/3);
                        ctx.stroke();
                        
                        ctx.beginPath();
                        ctx.arc(0, 0, radius, Math.PI - Math.PI/3, Math.PI + Math.PI/3);
                        ctx.stroke();
                    }
                    ctx.restore();
                    
                    // Center glow
                    var gradient = ctx.createRadialGradient(0, 0, 7, 0, 0, 28);
                    gradient.addColorStop(0, 'rgba(239, 68, 68, 0.2)');
                    gradient.addColorStop(1, 'rgba(239, 68, 68, 0)');
                    ctx.fillStyle = gradient;
                    ctx.beginPath();
                    ctx.arc(0, 0, 28, 0, Math.PI * 2);
                    ctx.fill();
                }
            
                // Head
                ctx.fillStyle = robot.magnetOn ? '#f87171' : '#60a5fa';
                ctx.beginPath();
                ctx.arc(0, -11, 11, 0, Math.PI * 2);
                ctx.fill();
                
                // Eyes
                ctx.fillStyle = 'white';
                ctx.beginPath();
                ctx.arc(-4, -13, 3.5, 0, Math.PI * 2);
                ctx.arc(4, -13, 3.5, 0, Math.PI * 2);
                ctx.fill();
                
                // Pupils - heart eyes when carrying something
                if (robot.carrying) {
                    ctx.fillStyle = '#ef4444';
                    ctx.font = '6px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText('❤', -4, -11);
                    ctx.fillText('❤', 4, -11);
                } else {
                    ctx.fillStyle = '#1e3a5f';
                    ctx.beginPath();
                    ctx.arc(-3.5, -12.5, 1.5, 0, Math.PI * 2);
                    ctx.arc(4.5, -12.5, 1.5, 0, Math.PI * 2);
                    ctx.fill();
                }
                
                // Antenna
                ctx.strokeStyle = robot.magnetOn ? '#ef4444' : '#fbbf24';
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.moveTo(0, -21);
                ctx.lineTo(0, -29);
                ctx.stroke();
                
                if (robot.magnetOn) {
                    ctx.fillStyle = '#ef4444';
                    ctx.beginPath();
                    ctx.arc(0, -33, 4, 0, Math.PI * 2);
                    ctx.fill();
                    ctx.fillStyle = 'white';
                    ctx.font = 'bold 6px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText('🧲', 0, -31);
                } else {
                    ctx.fillStyle = '#fbbf24';
                    ctx.beginPath();
                    ctx.arc(0, -31, 3, 0, Math.PI * 2);
                    ctx.fill();
                }
            
                // Direction arrow
                ctx.fillStyle = '#22c55e';
                ctx.beginPath();
                ctx.moveTo(0, -18);
                ctx.lineTo(-6, -7);
                ctx.lineTo(6, -7);
                ctx.closePath();
                ctx.fill();
                
                // Draw carried object attached to robot — BIG and obvious so kids
                // can clearly see "I'm carrying something" vs "I'm empty-handed".
                if (robot.carrying) {
                    var carryEmoji = robot.carrying.type === 'gear'  ? '⚙️'
                                   : robot.carrying.type === 'screw' ? '🪛'
                                   : '🔩';
                    ctx.save();
                    ctx.translate(0, 16);
                    // Pulsing glow ring
                    var pulse = 1 + 0.15 * Math.sin(Date.now() / 200);
                    ctx.shadowColor = '#fbbf24';
                    ctx.shadowBlur = 14;
                    ctx.fillStyle = '#fde047';
                    ctx.beginPath();
                    ctx.arc(0, 0, 11 * pulse, 0, Math.PI * 2);
                    ctx.fill();
                    ctx.shadowBlur = 0;
                    // Inner plate
                    ctx.fillStyle = '#fbbf24';
                    ctx.beginPath();
                    ctx.arc(0, 0, 9, 0, Math.PI * 2);
                    ctx.fill();
                    // The actual object emoji
                    ctx.font = '14px Arial';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(carryEmoji, 0, 1);
                    ctx.restore();

                    // "Carrying!" label so the state is unmistakable
                    ctx.save();
                    ctx.rotate(-robot.angle * Math.PI / 180 - Math.PI / 2);
                    ctx.fillStyle = 'rgba(251, 191, 36, 0.95)';
                    ctx.strokeStyle = '#fff';
                    ctx.lineWidth = 2;
                    ctx.font = 'bold 9px Arial';
                    ctx.textAlign = 'center';
                    var label = '🧲 Carrying ' + robot.carrying.type;
                    ctx.strokeText(label, 0, -38);
                    ctx.fillText(label, 0, -38);
                    ctx.restore();
                }
                
                ctx.restore();
            }
            
        }

        function resetRobot() {
            robot = {
                x: 275,
                y: 275,
                angle: -90,
                penDown: false,
                penColor: '#6366f1',
                penSize: 4,
                trails: [],
                visible: true,
                magnetOn: false,
                carrying: null,
                waterLevel: 10,
                spraying: false,
                lastTemp: 25
            };
            drawRobot();
            addChatMessage('stemo', "🤖 Ready! Use Pen Down to start drawing!");
        }

        function togglePenColor() {
            currentColorIndex = (currentColorIndex + 1) % penColors.length;
            robot.penColor = penColors[currentColorIndex];
            addChatMessage('stemo', "🤖 Color changed! Looking good! 🎨");
        }

        function clearWorkspace() {
            if (workspace) {
                workspace.clear();
            }
            resetRobot();
        }

        // ============================================
        // LESSON COMPLETION
        // ============================================
        function checkLessonCompletion() {
            if (!currentLesson) return;
            
            // In challenge mode, completion is handled by checkChallengeObjectives()
            if (challengeMode) {
                checkChallengeObjectives();
                return;
            }
            
            // Free build / non-mission: complete lesson if robot moved or drew anything
            var robotMoved = robot.x !== 200 || robot.y !== 200 || robot.angle !== -90;
            var robotDrew = robot.trails.length > 0;
            
            if (robotMoved || robotDrew) {
                if (!stemo.completedLessons.includes(currentLesson.id)) {
                    completeLesson(currentLesson);
                }
            }
        }

        function completeLesson(lesson) {
            stemo.completedLessons.push(lesson.id);
            stemo.xp += lesson.xpReward;
            
            var newLevel = Math.floor(stemo.xp / 500) + 1;
            if (newLevel > stemo.level) {
                stemo.level = newLevel;
            }
            
            saveProgress();
            updateUI();
            loadLessons();
            loadBadges();
            
            showSuccessModal(lesson.xpReward);
        }

        function showSuccessModal(xp) {
            var modal = document.getElementById('successModal');
            var content = document.getElementById('successModalContent');
            var nextBtn = document.getElementById('nextLessonBtn');

            // XP banner: show points for first completion, "Already completed" for replays
            if (xp > 0) {
                document.getElementById('xpBannerLabel').textContent = 'You earned';
                document.getElementById('xpEarned').textContent = '+' + xp + ' XP';
                document.getElementById('xpBanner').className = 'bg-gradient-to-r from-yellow-400 to-amber-500 rounded-2xl p-4 mb-6';
            } else {
                document.getElementById('xpBannerLabel').textContent = 'Great practice!';
                document.getElementById('xpEarned').textContent = 'Already completed ✓';
                document.getElementById('xpBanner').className = 'bg-gradient-to-r from-gray-400 to-gray-500 rounded-2xl p-4 mb-6';
            }
            
            // Show/hide next lesson button based on whether there's a next lesson
            if (currentLesson && currentLesson.nextLesson) {
                nextBtn.style.display = 'inline-block';
            } else {
                nextBtn.style.display = 'none';
            }
            
            modal.classList.remove('hidden');
            setTimeout(function() {
                content.style.transform = 'scale(1)';
            }, 50);
        }

        function closeSuccessModal() {
            var modal = document.getElementById('successModal');
            var content = document.getElementById('successModalContent');
            content.style.transform = 'scale(0)';
            setTimeout(function() {
                modal.classList.add('hidden');
            }, 300);
        }
        
        function goToLessons() {
            closeSuccessModal();
            setTimeout(function() {
                switchTab('learn');
                currentLesson = null;
            }, 300);
        }
        
        function goToNextLesson() {
            if (currentLesson && currentLesson.nextLesson) {
                var nextLessonId = currentLesson.nextLesson;
                closeSuccessModal();
                // Clear challenge state so the next lesson opens fresh
                challengeMode = false;
                challengeActiveLessonId = null;
                challengeCompleted = false;
                setTimeout(function() {
                    switchTab('learn');   // always land on Learn, not Code
                    selectLesson(nextLessonId);
                }, 300);
            } else {
                goToLessons();
            }
        }

        // ============================================
        // CHAT FUNCTIONALITY
        // ============================================
        function handleChatKeypress(event) {
            if (event.key === 'Enter') {
                sendChat();
            }
        }
        
        function sendChat() {
            var input = document.getElementById('chatInput');
            var message = input.value.trim();
            if (!message) return;
            
            addChatMessage('user', message);
            input.value = '';
            
            fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    message: message, 
                    context: { 
                        currentLesson: currentLesson ? currentLesson.id : null,
                        xp: stemo.xp,
                        level: stemo.level,
                        completedLessons: stemo.completedLessons
                    }
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                addChatMessage('stemo', data.response);
            })
            .catch(function(err) {
                addChatMessage('stemo', "🤖 Oops! I'm thinking too hard. Try again!");
            });
        }

        // ============================================
        // COMMAND CENTER
        // ============================================
        function switchRobotTab(tab) {
            var isChat = tab === 'chat';
            document.getElementById('panelChat').style.display = isChat ? 'block' : 'none';
            document.getElementById('panelCC').style.display = isChat ? 'none' : 'block';
            document.getElementById('tabBtnChat').className = isChat
                ? 'flex-1 py-1.5 text-xs font-bold bg-white text-indigo-600 border-b-2 border-indigo-500 transition-all'
                : 'flex-1 py-1.5 text-xs font-bold bg-gray-100 text-gray-500 border-b-2 border-transparent hover:bg-gray-200 transition-all';
            document.getElementById('tabBtnCC').className = isChat
                ? 'flex-1 py-1.5 text-xs font-bold bg-gray-100 text-gray-500 border-b-2 border-transparent hover:bg-gray-200 transition-all'
                : 'flex-1 py-1.5 text-xs font-bold bg-gray-900 text-green-400 border-b-2 border-green-400 transition-all';
        }

        function toggleCC(forceOpen) {
            switchRobotTab('cc');
        }

        function addCommandCenterMessage(htmlLines) {
            var container = document.getElementById('ccMessages');
            if (!container) return;
            var now = new Date();
            var hh = String(now.getHours()).padStart(2,'0');
            var mm = String(now.getMinutes()).padStart(2,'0');
            var ss = String(now.getSeconds()).padStart(2,'0');
            var time = hh + ':' + mm + ':' + ss;

            var sep = document.createElement('div');
            sep.style.cssText = 'border-top:1px solid #1e293b;margin:3px 0;';
            container.appendChild(sep);

            var div = document.createElement('div');
            div.style.cssText = 'padding:2px 0;';
            div.innerHTML = '<span style="color:#475569">[' + time + ']</span> '
                + htmlLines.map(function(l) {
                    return '<span style="color:#e2e8f0">' + l + '</span>';
                }).join('<br>');
            container.appendChild(div);
            container.scrollTop = container.scrollHeight;

            // Flash signal dot in toolbar header
            var dot = document.getElementById('ccSignalDot');
            if (dot) {
                dot.style.background = '#facc15';
                dot.style.boxShadow = '0 0 10px #facc15';
                setTimeout(function() {
                    dot.style.background = '#4ade80';
                    dot.style.boxShadow = '0 0 6px #4ade80';
                }, 800);
            }

            // Auto-open the floating CC panel so kids see the transmission arrive
            toggleCC(true);
        }

        function clearCC() {
            var c = document.getElementById('ccMessages');
            if (c) c.innerHTML = '<div style="color:#374151">// Log cleared. Ready for new transmissions.</div>';
        }

        function ccInputKeypress(e) {
            if (e.key === 'Enter') sendCCCommand();
        }

        function sendCCCommand() {
            var input = document.getElementById('ccInput');
            var cmd = (input.value || '').trim();
            if (!cmd) return;
            input.value = '';
            // Log the outgoing order in the CC terminal
            addCommandCenterMessage(['<span style="color:#38bdf8">⬆ ORDER SENT:</span> <span style="color:#fbbf24">"' + cmd + '"</span>']);
            // Mirror to STEMO chat for acknowledgement
            setTimeout(function() {
                addChatMessage('stemo', '📡 Command Center: <em>"' + cmd + '"</em> — message received! Direct command execution is coming soon.');
            }, 300);
        }

        function addChatMessage(sender, message) {
            var container = document.getElementById('chatMessages');
            var div = document.createElement('div');
            div.className = 'flex items-start gap-2';
            
            if (sender === 'stemo') {
                div.innerHTML = '<span class="text-2xl">🤖</span><div class="chat-bubble bg-blue-100 text-sm">' + message + '</div>';
            } else {
                div.innerHTML = '<div class="chat-bubble bg-indigo-100 text-sm ml-auto">' + message + '</div><span class="text-2xl">👦</span>';
            }
            
            container.appendChild(div);
            container.scrollTop = container.scrollHeight;
        }

        // ============================================
        // TAB NAVIGATION
        // ============================================
        function switchTab(tab) {
            ['learn','code','achievements','profile','leaderboard'].forEach(function(t) {
                document.getElementById(t + '-section').classList.add('hidden');
                document.getElementById('tab-' + t).className = 'tab-inactive px-5 py-2 rounded-full font-bold transition-all text-sm';
            });
            document.getElementById(tab + '-section').classList.remove('hidden');
            document.getElementById('tab-' + tab).className = 'tab-active px-5 py-2 rounded-full font-bold transition-all text-sm';
            if (tab === 'code' && workspace) {
                setTimeout(function() { Blockly.svgResize(workspace); }, 100);
            }
            if (tab === 'leaderboard') loadLeaderboard();
        }

        // ============================================
        // PROFILE
        // ============================================
        async function loadProfile() {
            try {
                const data = await fetch('/api/student/profile').then(r => r.json());
                const u = data.user || currentUser;
                if (!u) return;
                // Avatar: first letter of name
                const initials = (u.full_name || u.username || 'S')[0].toUpperCase();
                document.getElementById('profileAvatar').textContent = initials;
                document.getElementById('profileName').textContent = u.full_name || u.username;
                document.getElementById('profileUsername').textContent = u.username || '';
                if (u.created_at) {
                    document.getElementById('profileJoined').textContent = 'Joined ' + (u.created_at || '').slice(0, 10);
                }
                // Class info
                var classHtml = '';
                if (data.class) {
                    if (data.class.school_name) {
                        classHtml += '<div class="flex items-center gap-2"><span class="text-purple-500">🏫</span><span class="font-semibold text-gray-700">School:</span><span class="text-gray-600">' + data.class.school_name + '</span></div>';
                    }
                    classHtml += '<div class="flex items-center gap-2"><span class="text-blue-500">🎒</span><span class="font-semibold text-gray-700">Class:</span><span class="text-gray-600">' + data.class.name + '</span></div>';
                    if (data.class.teacher_name) {
                        classHtml += '<div class="flex items-center gap-2"><span class="text-indigo-500">👩‍🏫</span><span class="font-semibold text-gray-700">Teacher:</span><span class="text-gray-600">' + data.class.teacher_name + '</span></div>';
                    }
                    // Assigned lesson — show banner on Profile AND Learn tabs
                    if (data.class.assigned_lesson_id) {
                        assignedLessonId = data.class.assigned_lesson_id;
                        // Fetch lesson details from API (curriculum is server-side only)
                        fetch('/api/lesson/' + assignedLessonId).then(function(r) { return r.json(); }).then(function(lessonData) {
                            if (!lessonData || !lessonData.id) return;
                            // Profile banner
                            document.getElementById('profileLessonIcon').textContent = lessonData.icon || '📖';
                            document.getElementById('profileLessonTitle').textContent = lessonData.title;
                            document.getElementById('profileLessonBanner').classList.remove('hidden');
                            // Learn tab banner
                            document.getElementById('assignedLessonBannerIcon').textContent = lessonData.icon || '📖';
                            document.getElementById('assignedLessonBannerTitle').textContent = lessonData.title;
                            document.getElementById('assignedLessonBannerDesc').textContent = lessonData.description || '';
                            document.getElementById('assignedLessonBannerBtn').setAttribute('onclick', "selectLesson('" + assignedLessonId + "')");
                            document.getElementById('assignedLessonBanner').classList.remove('hidden');
                            // Re-render lessons so the card gets highlighted
                            loadLessons();
                        }).catch(function() {});
                    }
                } else {
                    classHtml = '<div class="text-gray-400 text-sm">Not enrolled in any class yet</div>';
                }
                document.getElementById('profileClassInfo').innerHTML = classHtml;
                // Stats (sync from stemo state)
                updateProfileStats();
            } catch(e) {
                console.log('Profile load error:', e);
                // Fallback: use currentUser + stemo state
                if (currentUser) {
                    const initials = (currentUser.full_name || currentUser.username || 'S')[0].toUpperCase();
                    document.getElementById('profileAvatar').textContent = initials;
                    document.getElementById('profileName').textContent = currentUser.full_name || currentUser.username;
                    document.getElementById('profileUsername').textContent = currentUser.username || '';
                }
            }
        }

        function updateProfileStats() {
            document.getElementById('profileXP').textContent = stemo.xp;
            document.getElementById('profileLessons').textContent = stemo.completedLessons.length;
            document.getElementById('profileStreak').textContent = stemo.streak;
            document.getElementById('profileBadges').textContent = stemo.badges.length;
        }

        function findLessonById(id) {
            // Search curriculumData (populated after loadLessons runs)
            if (!curriculumData) return null;
            for (var key in curriculumData) {
                var arr = curriculumData[key];
                for (var i = 0; i < arr.length; i++) {
                    if (arr[i].id === id) return arr[i];
                }
            }
            return null;
        }

        // ============================================
        // LEADERBOARD
        // ============================================
        async function loadLeaderboard() {
            document.getElementById('leaderboardList').innerHTML = '<p class="text-center text-gray-400 py-6">Loading...</p>';
            document.getElementById('podiumRow').innerHTML = '';
            try {
                const data = await fetch('/api/leaderboard').then(r => r.json());
                if (!Array.isArray(data) || data.length === 0) {
                    document.getElementById('leaderboardList').innerHTML = '<p class="text-center text-gray-400 py-8">No students yet. Be the first! 🚀</p>';
                    return;
                }
                const myId = currentUser ? currentUser.id : null;
                const medals = ['🥇','🥈','🥉'];
                const podiumColors = [
                    'from-yellow-400 to-amber-500',
                    'from-gray-300 to-gray-400',
                    'from-orange-400 to-amber-600'
                ];
                const podiumSizes = ['h-28','h-20','h-16'];

                // Helper: build one row for the full list
                function lbRow(s, rank, isTop3) {
                    var isMe = s.id == myId;
                    var lessons = 0;
                    try { lessons = JSON.parse(s.completed_lessons || '[]').length; } catch(e) {}
                    var rankBadge = isTop3
                        ? '<div class="text-2xl w-8 text-center">' + medals[rank-1] + '</div>'
                        : '<div class="text-base font-bold text-gray-400 w-8 text-center">#' + rank + '</div>';
                    var avatarGrad = isTop3 ? 'from-yellow-400 to-amber-500' : 'from-indigo-400 to-purple-500';
                    var rowBg = isMe ? 'bg-indigo-50 border-2 border-indigo-400'
                               : isTop3 ? 'bg-gradient-to-r from-yellow-50 to-amber-50 border border-yellow-200'
                               : 'border border-gray-100 hover:bg-gray-50';
                    var schoolBit = s.school_name
                        ? '<span class="inline-flex items-center gap-1 bg-purple-100 text-purple-700 text-xs font-semibold px-2 py-0.5 rounded-full">🏫 ' + s.school_name + '</span>'
                        : '';
                    var classBit = s.class_name
                        ? '<span class="inline-flex items-center gap-1 bg-blue-100 text-blue-700 text-xs font-semibold px-2 py-0.5 rounded-full">🎒 ' + s.class_name + '</span>'
                        : '';
                    return '<div class="flex items-center gap-3 p-3 rounded-2xl ' + rowBg + ' transition-all">' +
                        rankBadge +
                        '<div class="w-10 h-10 rounded-full bg-gradient-to-br ' + avatarGrad + ' flex items-center justify-center text-lg font-bold text-white shrink-0">' + (s.full_name || 'S')[0].toUpperCase() + '</div>' +
                        '<div class="flex-1 min-w-0">' +
                            '<div class="font-bold text-gray-800 truncate">' + (s.full_name || s.username) + (isMe ? ' <span class="bg-indigo-500 text-white text-xs px-2 py-0.5 rounded-full ml-1">You</span>' : '') + '</div>' +
                            '<div class="text-gray-400 text-xs mb-1">@' + s.username + ' · Level ' + (s.level || 1) + '</div>' +
                            '<div class="flex flex-wrap gap-1">' + schoolBit + classBit + '</div>' +
                        '</div>' +
                        '<div class="text-right shrink-0">' +
                            '<div class="font-bold text-yellow-500 text-base">⭐ ' + (s.xp || 0).toLocaleString() + '</div>' +
                            '<div class="text-gray-400 text-xs">' + lessons + '/14 lessons</div>' +
                            '<div class="text-gray-400 text-xs">' + (s.streak || 0) + ' 🔥 streak</div>' +
                        '</div>' +
                    '</div>';
                }

                // Top 3 podium
                var podiumHtml = '';
                var podiumOrder = [1, 0, 2]; // silver, gold, bronze display order
                podiumOrder.forEach(function(idx) {
                    var s = data[idx];
                    if (!s) return;
                    var isMe = s.id == myId;
                    podiumHtml += '<div class="flex flex-col items-center gap-1 ' + (idx === 0 ? 'order-2' : idx === 1 ? 'order-1' : 'order-3') + '">';
                    podiumHtml += '<div class="text-3xl">' + medals[idx] + '</div>';
                    podiumHtml += '<div class="w-14 h-14 rounded-full bg-gradient-to-br ' + podiumColors[idx] + ' flex items-center justify-center text-2xl font-bold text-white border-4 ' + (isMe ? 'border-indigo-500' : 'border-white') + '">' + (s.full_name || 'S')[0].toUpperCase() + '</div>';
                    podiumHtml += '<div class="text-center max-w-24">';
                    podiumHtml += '<div class="font-bold text-xs text-gray-800 truncate">' + (s.full_name || s.username) + (isMe ? ' ★' : '') + '</div>';
                    podiumHtml += '<div class="text-yellow-500 font-bold text-sm">⭐ ' + (s.xp || 0).toLocaleString() + '</div>';
                    if (s.school_name) podiumHtml += '<div class="text-purple-600 text-xs truncate">🏫 ' + s.school_name + '</div>';
                    if (s.class_name) podiumHtml += '<div class="text-blue-500 text-xs truncate">🎒 ' + s.class_name + '</div>';
                    podiumHtml += '</div>';
                    podiumHtml += '<div class="bg-gradient-to-t ' + podiumColors[idx] + ' rounded-t-xl w-20 ' + podiumSizes[idx] + '"></div>';
                    podiumHtml += '</div>';
                });
                document.getElementById('podiumRow').innerHTML = podiumHtml;

                // Full ranked list (top 3 highlighted, rest normal)
                var allRows = data.map(function(s, i) { return lbRow(s, i + 1, i < 3); }).join('');
                document.getElementById('leaderboardList').innerHTML = '<div class="space-y-2">' + allRows + '</div>';
            } catch(e) {
                document.getElementById('leaderboardList').innerHTML = '<p class="text-center text-gray-400 py-8">Unable to load leaderboard</p>';
            }
        }
        
        // ============================================
        // PLACEMENT MODE & CANVAS CLICK HANDLER
        // ============================================
        function setPlacementMode(mode) {
            // Toggle off if the same mode is clicked again → enter Select mode
            if (placementMode === mode) {
                mode = null;
            }
            placementMode = mode;

            // Clear any current selection when switching modes
            selectedObject = null;
            selectedObjectType = null;
            drawRobot();

            // Update button styles
            document.getElementById('modeMetalBtn').className = mode === 'metal' 
                ? 'bg-yellow-500 text-white px-2 py-1 rounded-full text-xs font-bold transition-all'
                : 'bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all';
            document.getElementById('modeWallBtn').className = mode === 'wall'
                ? 'bg-amber-700 text-white px-2 py-1 rounded-full text-xs font-bold transition-all'
                : 'bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all';
            document.getElementById('modeFireBtn').className = mode === 'fire'
                ? 'bg-orange-500 text-white px-2 py-1 rounded-full text-xs font-bold transition-all'
                : 'bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all';
            document.getElementById('modeTargetBtn').className = mode === 'target'
                ? 'bg-green-500 text-white px-2 py-1 rounded-full text-xs font-bold transition-all'
                : 'bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all';
            document.getElementById('modePositionBtn').className = mode === 'position'
                ? 'bg-teal-500 text-white px-2 py-1 rounded-full text-xs font-bold transition-all'
                : 'bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all';

            // Cursor changes so the user feels what mode they are in
            var canvasEl = document.getElementById('robotCanvas');
            if (canvasEl) canvasEl.style.cursor = mode ? 'crosshair' : 'pointer';

            // Update indicator text
            var posSlot = (document.getElementById('posSlotSelect') || {}).value || 'A';
            var modeText = {
                'metal':    'Click to place: 🔩 Metal  (click again to stop)',
                'wall':     'Click & drag to place: 🧱 Wall  (click again to stop)',
                'fire':     'Click to place: 🔥 Fire  (click again to stop)',
                'target':   'Click to place: 🎯 Target  (click again to stop)',
                'position': 'Click to place: 📍 Position ' + posSlot + ' marker  (click 📍 again to stop)'
            };
            document.getElementById('placementModeText').textContent =
                mode ? modeText[mode] : '🖱️ Select mode — click an object to select it, then press Delete';

            if (mode) {
                addChatMessage('stemo', '🤖 ' + modeText[mode]);
            } else {
                addChatMessage('stemo', '🤖 🖱️ Select mode — click any object to highlight it, then press Delete (or the 🗑️ button) to remove it.');
            }
        }
        
        var wallStartPos = null;
        
        function handleCanvasClick(event) {
            var canvas = document.getElementById('robotCanvas');
            var rect = canvas.getBoundingClientRect();
            var x = (event.clientX - rect.left) * (canvas.width / rect.width);
            var y = (event.clientY - rect.top) * (canvas.height / rect.height);
            
            // Keep within bounds (canvas is 550×550)
            x = Math.max(25, Math.min(525, x));
            y = Math.max(25, Math.min(525, y));

            // In Select mode (no placement), click an object to select it
            if (!placementMode) {
                var clickedObject = findObjectAt(x, y);
                if (clickedObject) {
                    selectedObject = clickedObject.obj;
                    selectedObjectType = clickedObject.type;
                    drawRobot();
                    addChatMessage('stemo', '🤖 Selected ' + clickedObject.type + '! Press Delete or click 🗑️ to remove it.');
                } else {
                    // Clicked empty space → deselect
                    if (selectedObject) {
                        selectedObject = null;
                        selectedObjectType = null;
                        drawRobot();
                    }
                }
                return;
            }

            // In placement mode → place the object. Clear any prior selection.
            selectedObject = null;
            selectedObjectType = null;

            if (placementMode === 'metal') {
                addMetalAt(x, y);
            } else if (placementMode === 'wall') {
                addWallAt(x, y);
            } else if (placementMode === 'fire') {
                addFireAt(x, y);
            } else if (placementMode === 'target') {
                addTargetAt(x, y);
            } else if (placementMode === 'position') {
                var slot = (document.getElementById('posSlotSelect') || {}).value || 'A';
                savedPositions[slot] = { x: x, y: y };
                var sx = Math.round((x - 275) / 20), sy = Math.round((275 - y) / 20);
                drawRobot();
                addChatMessage('stemo', '📍 Position <b>' + slot + '</b> placed at X=' + sx + ', Y=' + sy + ' — use "🔙 Go to Position ' + slot + '" to navigate here!');
            }
        }
        
        function findObjectAt(x, y) {
            // Check metals
            for (var i = 0; i < metalObjects.length; i++) {
                var m = metalObjects[i];
                if (!m.pickedUp) {
                    var dx = m.x - x;
                    var dy = m.y - y;
                    if (Math.sqrt(dx * dx + dy * dy) < 20) {
                        return { obj: m, type: 'metal' };
                    }
                }
            }
            // Check walls
            for (var i = 0; i < wallObjects.length; i++) {
                var w = wallObjects[i];
                if (x >= w.x && x <= w.x + w.width && y >= w.y && y <= w.y + w.height) {
                    return { obj: w, type: 'wall' };
                }
            }
            // Check fires
            for (var i = 0; i < fireObjects.length; i++) {
                var f = fireObjects[i];
                var dx = f.x - x;
                var dy = f.y - y;
                if (Math.sqrt(dx * dx + dy * dy) < 25) {
                    return { obj: f, type: 'fire' };
                }
            }
            // Check target
            if (targetPoint) {
                var dx = targetPoint.x - x;
                var dy = targetPoint.y - y;
                if (Math.sqrt(dx * dx + dy * dy) < 25) {
                    return { obj: targetPoint, type: 'target' };
                }
            }
            // Check saved position markers
            var posSlots = ['A','B','C','D'];
            for (var pi = 0; pi < posSlots.length; pi++) {
                var ps = posSlots[pi];
                var pp = savedPositions[ps];
                if (pp) {
                    var pdx = pp.x - x, pdy = pp.y - y;
                    if (Math.sqrt(pdx*pdx + pdy*pdy) < 18) {
                        return { obj: pp, type: 'position', slot: ps };
                    }
                }
            }
            return null;
        }
        
        // Keyboard listener for Delete key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Delete' || e.key === 'Backspace') {
                if (selectedObject) {
                    deleteSelectedObject();
                }
            }
        });

        
        function addFireAt(x, y) {
            saveBoardState();
            fireObjects.push({
                id: fireIdCounter++,
                x: x,
                y: y,
                health: 3  // Takes 3 water sprays to extinguish
            });
            
            var dx = x - robot.x;
            var dy = y - robot.y;
            var distSteps = Math.round(Math.sqrt(dx * dx + dy * dy) / 20);
            
            drawRobot();
            addChatMessage('stemo', "🤖 🔥 Fire started! " + distSteps + " steps away. Use Spray Water or Firefighter mode to extinguish! 💧");
        }
        
        function addMetalAt(x, y) {
            saveBoardState();
            var types = ['bolt', 'gear', 'screw'];
            var type = types[Math.floor(Math.random() * types.length)];
            
            metalObjects.push({
                id: metalIdCounter++,
                x: x,
                y: y,
                type: type,
                pickedUp: false
            });
            
            var dx = x - robot.x;
            var dy = y - robot.y;
            var distSteps = Math.round(Math.sqrt(dx * dx + dy * dy) / 20);
            
            drawRobot();
            addChatMessage('stemo', "🤖 ✨ New " + type + "! " + distSteps + " steps away. Use Magnet ON to pick it up! 🧲");
        }
        
        function addWallAt(x, y) {
            saveBoardState();
            // Create a wall (40x40 default, can be expanded later with drag)
            wallObjects.push({
                id: wallIdCounter++,
                x: x - 20,
                y: y - 20,
                width: 40,
                height: 40
            });
            
            drawRobot();
            addChatMessage('stemo', "🤖 🧱 Wall placed! Use Auto Move or If Wall blocks to avoid it!");
        }
        
        function addTargetAt(x, y) {
            saveBoardState();
            // Only one target at a time
            targetPoint = { x: x, y: y };
            
            var dx = x - robot.x;
            var dy = y - robot.y;
            var distSteps = Math.round(Math.sqrt(dx * dx + dy * dy) / 20);
            
            drawRobot();
            addChatMessage('stemo', "🤖 🎯 Target set! " + distSteps + " steps away. Use 'Go To Target' block to navigate there!");
        }
        
        function addRandomMetal() {
            var x = 50 + Math.random() * 300;
            var y = 50 + Math.random() * 300;
            addMetalAt(x, y);
        }
        
        function clearAll() {
            saveBoardState();
            metalObjects = [];
            wallObjects = [];
            fireObjects = [];
            targetPoint = null;
            selectedObject = null;
            selectedObjectType = null;
            if (robot.carrying) {
                robot.carrying = null;
                robot.magnetOn = false;
            }
            robot.waterLevel = 10; // Refill water
            robot.spraying = false;
            drawRobot();
            addChatMessage('stemo', "🤖 🗑️ Board cleared! Water refilled 💧. Click buttons to add walls, metals, fires, or targets.");
        }
        
        // ============================================
        // UNDO & SELECTION FUNCTIONS
        // ============================================
        function saveBoardState() {
            var state = {
                metals: JSON.parse(JSON.stringify(metalObjects)),
                walls: JSON.parse(JSON.stringify(wallObjects)),
                fires: JSON.parse(JSON.stringify(fireObjects)),
                target: targetPoint ? { x: targetPoint.x, y: targetPoint.y } : null
            };
            boardHistory.push(state);
            if (boardHistory.length > maxHistorySize) {
                boardHistory.shift();
            }
        }
        
        function undoBoard() {
            if (boardHistory.length === 0) {
                addChatMessage('stemo', "🤖 Nothing to undo!");
                return;
            }
            var state = boardHistory.pop();
            metalObjects = state.metals;
            wallObjects = state.walls;
            fireObjects = state.fires;
            targetPoint = state.target;
            selectedObject = null;
            selectedObjectType = null;
            drawRobot();
            addChatMessage('stemo', "🤖 ↩️ Undo! Reverted last change.");
        }
        
        function deleteSelectedObject() {
            if (!selectedObject) {
                addChatMessage('stemo', "🤖 Click an object to select it first!");
                return;
            }
            
            saveBoardState();
            
            if (selectedObjectType === 'metal') {
                metalObjects = metalObjects.filter(function(m) { return m !== selectedObject; });
            } else if (selectedObjectType === 'wall') {
                wallObjects = wallObjects.filter(function(w) { return w !== selectedObject; });
            } else if (selectedObjectType === 'fire') {
                fireObjects = fireObjects.filter(function(f) { return f !== selectedObject; });
            } else if (selectedObjectType === 'target') {
                targetPoint = null;
            } else if (selectedObjectType === 'position') {
                // Find which slot this object belongs to
                var delSlots = ['A','B','C','D'];
                for (var di = 0; di < delSlots.length; di++) {
                    if (savedPositions[delSlots[di]] === selectedObject) {
                        savedPositions[delSlots[di]] = null;
                        break;
                    }
                }
            }
            
            addChatMessage('stemo', "🤖 🗑️ Deleted " + selectedObjectType + "!");
            selectedObject = null;
            selectedObjectType = null;
            drawRobot();
        }
        
        // ============================================
        // THREE.JS 3D WORLD
        // ============================================
        var scene, camera, renderer, controls;
        var threeRobot, threeTarget, threeShadow;
        var waterParticles = []; // Array to store active water particles
        var threeMetals = [], threeWalls = [], threeFires = [];
        
        function initThreeJS() {
            var container = document.getElementById('threeCanvasContainer');
            if (renderer) return; // Already initialized

            // Scene setup
            scene = new THREE.Scene();
            scene.background = new THREE.Color(0xfef9c3);
            scene.fog = new THREE.Fog(0xfef9c3, 200, 1000);

            // Camera (Zoomed in closer)
            var width = container.clientWidth;
            var height = container.clientHeight;
            camera = new THREE.PerspectiveCamera(50, width / height, 0.1, 1000);
            camera.position.set(75, 350, 600); // Isometric angle, centered on 2D canvas center (275,275)
            camera.lookAt(275, 0, 275); // Look at center of board

            // Renderer
            renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
            renderer.setSize(container.clientWidth, container.clientHeight);
            renderer.shadowMap.enabled = true;
            renderer.shadowMap.type = THREE.PCFSoftShadowMap;
            container.appendChild(renderer.domElement);

            // Controls
            controls = new THREE.OrbitControls(camera, renderer.domElement);
            controls.enableDamping = true;
            controls.dampingFactor = 0.05;
            controls.target.set(275, 0, 275);
            controls.maxPolarAngle = Math.PI / 2 - 0.1; // Don't go below ground
            controls.minDistance = 100;
            controls.maxDistance = 800;

            // Lights
            var ambientLight = new THREE.AmbientLight(0xffffff, 0.6);
            scene.add(ambientLight);

            var dirLight = new THREE.DirectionalLight(0xffffff, 0.8);
            dirLight.position.set(100, 200, 100);
            dirLight.castShadow = true;
            dirLight.shadow.mapSize.width = 2048;
            dirLight.shadow.mapSize.height = 2048;
            dirLight.shadow.camera.near = 0.5;
            dirLight.shadow.camera.far = 1000;
            dirLight.shadow.camera.left = -300;
            dirLight.shadow.camera.right = 300;
            dirLight.shadow.camera.top = 300;
            dirLight.shadow.camera.bottom = -300;
            scene.add(dirLight);

            // Floor - sized to match 2D canvas (550x550), centered at (275,275) to match 2D coords
            var floorGeometry = new THREE.PlaneGeometry(550, 550);
            var floorMaterial = new THREE.MeshStandardMaterial({ 
                color: 0xf0fdf4,
                side: THREE.DoubleSide
            });
            var floor = new THREE.Mesh(floorGeometry, floorMaterial);
            floor.rotation.x = -Math.PI / 2;
            floor.position.set(275, -1, 275);
            floor.receiveShadow = true;
            scene.add(floor);
            
            // Grid helper (1 step = 20px, so 27 grid divisions fit in 540 units)
            var gridHelper = new THREE.GridHelper(540, 27, 0x86efac, 0xe5e7eb);
            gridHelper.position.set(275, 0, 275);
            scene.add(gridHelper);
            
            // Robot Group (The Hover Bot)
            threeRobot = new THREE.Group();
            scene.add(threeRobot);
            
            // ── Build a cute, child-friendly STEMO ───────────────────────────
            // We store animated parts on threeRobot.userData so the render loop
            // can wiggle them (antenna bounce, aura spin, arm wave, sparkles).

            // 1. Rounded BODY — soft purple, slightly squishy egg shape
            var bodyGeo = new THREE.SphereGeometry(26, 32, 32);
            bodyGeo.scale(1.0, 1.25, 1.0);
            var bodyMat = new THREE.MeshStandardMaterial({
                color: 0x8b5cf6, // friendly purple
                roughness: 0.35,
                metalness: 0.15
            });
            var body = new THREE.Mesh(bodyGeo, bodyMat);
            body.position.y = 42;
            body.castShadow = true;
            threeRobot.add(body);

            // 2. White FACE PLATE — friendly white oval in front of body
            var faceGeo = new THREE.SphereGeometry(22, 32, 32);
            faceGeo.scale(1.0, 1.05, 0.45);
            var faceMat = new THREE.MeshStandardMaterial({
                color: 0xfdf4ff,
                roughness: 0.25,
                metalness: 0.05
            });
            var face = new THREE.Mesh(faceGeo, faceMat);
            face.position.set(0, 44, 14);
            threeRobot.add(face);

            // 3. EYES — big anime-style white sclera with bright pupils.
            // children[2] and children[3] are the white sclera; pupils are
            // attached as children of the sclera so we still color them via
            // userData.pupils in the magnet logic.
            var scleraGeo = new THREE.SphereGeometry(6, 24, 24);
            var scleraMat = new THREE.MeshStandardMaterial({
                color: 0xffffff,
                roughness: 0.2,
                metalness: 0
            });

            var eyeLeft = new THREE.Mesh(scleraGeo, scleraMat.clone());
            eyeLeft.position.set(8, 47, 22);
            threeRobot.add(eyeLeft);

            var eyeRight = new THREE.Mesh(scleraGeo, scleraMat.clone());
            eyeRight.position.set(-8, 47, 22);
            threeRobot.add(eyeRight);

            // Pupils (glowing, color changes with magnet)
            var pupilGeo = new THREE.SphereGeometry(3, 16, 16);
            var pupilMat = new THREE.MeshBasicMaterial({ color: 0x111827 });
            var pupilL = new THREE.Mesh(pupilGeo, pupilMat.clone());
            pupilL.position.set(0, 0, 4);
            eyeLeft.add(pupilL);
            var pupilR = new THREE.Mesh(pupilGeo, pupilMat.clone());
            pupilR.position.set(0, 0, 4);
            eyeRight.add(pupilR);

            // Eye shine sparkles
            var shineGeo = new THREE.SphereGeometry(0.9, 12, 12);
            var shineMat = new THREE.MeshBasicMaterial({ color: 0xffffff });
            var shineL = new THREE.Mesh(shineGeo, shineMat);
            shineL.position.set(1, 1, 4.6);
            eyeLeft.add(shineL);
            var shineR = new THREE.Mesh(shineGeo, shineMat);
            shineR.position.set(1, 1, 4.6);
            eyeRight.add(shineR);

            // 4. PINK CHEEK BLUSHES
            var blushGeo = new THREE.CircleGeometry(3, 16);
            var blushMat = new THREE.MeshBasicMaterial({
                color: 0xfb7185, transparent: true, opacity: 0.7
            });
            var blushL = new THREE.Mesh(blushGeo, blushMat);
            blushL.position.set(14, 40, 19);
            blushL.rotation.y = -0.3;
            threeRobot.add(blushL);
            var blushR = new THREE.Mesh(blushGeo, blushMat);
            blushR.position.set(-14, 40, 19);
            blushR.rotation.y = 0.3;
            threeRobot.add(blushR);

            // 5. SMILE — curved torus piece
            var smileGeo = new THREE.TorusGeometry(4.5, 0.8, 8, 16, Math.PI);
            var smileMat = new THREE.MeshBasicMaterial({ color: 0x1f2937 });
            var smile = new THREE.Mesh(smileGeo, smileMat);
            smile.position.set(0, 37, 22);
            smile.rotation.x = Math.PI; // Open the curve downward → smile
            threeRobot.add(smile);

            // 6. ANTENNA — thin rod with glowing bouncy ball on top
            var rodGeo = new THREE.CylinderGeometry(0.6, 0.6, 16, 8);
            var rodMat = new THREE.MeshStandardMaterial({ color: 0x6b7280, metalness: 0.7 });
            var rod = new THREE.Mesh(rodGeo, rodMat);
            rod.position.set(0, 70, 0);
            threeRobot.add(rod);

            var ballGeo = new THREE.SphereGeometry(4, 16, 16);
            var ballMat = new THREE.MeshStandardMaterial({
                color: 0xfde047, emissive: 0xfacc15, emissiveIntensity: 0.8
            });
            var antennaBall = new THREE.Mesh(ballGeo, ballMat);
            antennaBall.position.set(0, 80, 0);
            threeRobot.add(antennaBall);

            // 7. ARMS — two floating mitten-style hands beside the body
            var armGeo = new THREE.SphereGeometry(5, 16, 16);
            var armMat = new THREE.MeshStandardMaterial({ color: 0xfdf4ff, roughness: 0.3 });
            var armL = new THREE.Mesh(armGeo, armMat);
            armL.position.set(26, 40, 4);
            threeRobot.add(armL);
            var armR = new THREE.Mesh(armGeo, armMat);
            armR.position.set(-26, 40, 4);
            threeRobot.add(armR);

            // 8. AURA RING — rotating sparkly disc beneath robot
            var auraGeo = new THREE.RingGeometry(18, 28, 32);
            var auraMat = new THREE.MeshBasicMaterial({
                color: 0x22d3ee, transparent: true, opacity: 0.55, side: THREE.DoubleSide
            });
            var aura = new THREE.Mesh(auraGeo, auraMat);
            aura.rotation.x = -Math.PI / 2;
            aura.position.y = 6;
            threeRobot.add(aura);

            // 9. SPARKLE PARTICLES — small dots orbiting the robot
            var sparkles = [];
            var sparkleGeo = new THREE.SphereGeometry(0.8, 8, 8);
            var sparkleColors = [0xfde047, 0xf472b6, 0x60a5fa, 0x4ade80, 0xa78bfa];
            for (var s = 0; s < 8; s++) {
                var sparkMat = new THREE.MeshBasicMaterial({
                    color: sparkleColors[s % sparkleColors.length],
                    transparent: true, opacity: 0.9
                });
                var spark = new THREE.Mesh(sparkleGeo, sparkMat);
                spark.userData = {
                    angle: (s / 8) * Math.PI * 2,
                    radius: 35 + Math.random() * 8,
                    yBase: 40 + Math.random() * 25,
                    speed: 0.02 + Math.random() * 0.015
                };
                threeRobot.add(spark);
                sparkles.push(spark);
            }

            // Cache animated parts for the render loop
            threeRobot.userData = {
                antennaBall: antennaBall,
                aura: aura,
                armL: armL,
                armR: armR,
                pupils: [pupilL, pupilR],
                sparkles: sparkles
            };

            // 4. Shadow (Separate from robot so it stays on floor)
            var shadowGeo = new THREE.CircleGeometry(20, 32);
            var shadowMat = new THREE.MeshBasicMaterial({ 
                color: 0x000000,
                transparent: true, 
                opacity: 0.3 
            });
            threeShadow = new THREE.Mesh(shadowGeo, shadowMat);
            threeShadow.rotation.x = -Math.PI / 2;
            threeShadow.position.set(275, 1, 275); // Slightly above floor
            scene.add(threeShadow);

            threeRobot.position.set(275, 0, 275);
        }

        // Three.js pen trail meshes (rebuilt every frame to mirror robot.trails)
        var threeTrails = [];

        function animateThreeJS() {
            if (isIsometricView) {
                requestAnimationFrame(animateThreeJS);
                if (controls) controls.update();
                updateThreeJSScene();
                if (renderer && scene && camera) {
                    renderer.render(scene, camera);
                }
            }
        }

        function updateThreeJSScene() {
            if (!threeRobot) return;

            // 1. Update Robot Position & Rotation
            // Smooth Hover Animation: y = base + sin(time)
            var time = Date.now() * 0.003;
            var hoverY = Math.sin(time) * 3;
            
            threeRobot.position.set(robot.x, hoverY, robot.y);
            threeRobot.rotation.y = -(robot.angle + 90) * Math.PI / 180 + Math.PI;
            
            // Update Shadow Position (stays on floor)
            if (threeShadow) {
                threeShadow.position.set(robot.x, 1, robot.y);
                // Shadow pulses slightly with hover
                threeShadow.scale.setScalar(1 - Math.sin(time) * 0.1); 
            }
            
            // 2. Particle Water Spray System
            // Spawn particles if spraying
            if (robot.spraying) {
                for (var i = 0; i < 5; i++) { // Spawn 5 particles per frame
                    var pGeo = new THREE.SphereGeometry(2 + Math.random() * 2, 8, 8);
                    var pMat = new THREE.MeshBasicMaterial({ 
                        color: 0x60a5fa, 
                        transparent: true, 
                        opacity: 0.8 
                    });
                    var p = new THREE.Mesh(pGeo, pMat);
                    
                    // Start at robot front/mouth position
                    // Need to calculate offset based on robot rotation
                    var offset = new THREE.Vector3(0, 40 + hoverY, 15); // Local offset
                    offset.applyAxisAngle(new THREE.Vector3(0, 1, 0), threeRobot.rotation.y);
                    p.position.set(robot.x + offset.x, offset.y, robot.y + offset.z);
                    
                    // Velocity: Forward + Spread
                    var velocity = new THREE.Vector3(
                        (Math.random() - 0.5) * 2, // Spread X
                        (Math.random() - 0.5) * 5, // Spread Y
                        20 + Math.random() * 10    // Forward speed
                    );
                    velocity.applyAxisAngle(new THREE.Vector3(0, 1, 0), threeRobot.rotation.y);
                    
                    // Particle Data
                    p.userData = { velocity: velocity, life: 1.0 };
                    
                    scene.add(p);
                    waterParticles.push(p);
                }
            }
            
            // Update Particles
            for (var i = waterParticles.length - 1; i >= 0; i--) {
                var p = waterParticles[i];
                p.userData.life -= 0.02; // Decrease life
                
                // Move
                p.position.add(p.userData.velocity);
                p.userData.velocity.y -= 0.5; // Gravity
                p.material.opacity = p.userData.life;
                
                if (p.userData.life <= 0 || p.position.y < 0) {
                    scene.remove(p);
                    waterParticles.splice(i, 1);
                }
            }
            
            // ── Cute animations ──────────────────────────────────────────────
            var ud = threeRobot.userData || {};

            // Magnet visual → switch pupil color (heart-red when ON, deep navy when OFF)
            var pupilColor = robot.magnetOn ? 0xef4444 : 0x111827;
            if (ud.pupils) {
                ud.pupils.forEach(function(p) {
                    if (p.material) p.material.color.setHex(pupilColor);
                });
            }

            // Antenna ball bobs and pulses brightness
            if (ud.antennaBall) {
                ud.antennaBall.position.y = 80 + Math.sin(time * 2) * 2.5;
                if (ud.antennaBall.material) {
                    ud.antennaBall.material.emissiveIntensity = 0.6 + (Math.sin(time * 4) + 1) * 0.3;
                }
            }

            // Aura ring slowly rotates
            if (ud.aura) {
                ud.aura.rotation.z += 0.02;
            }

            // Arms gently wave up and down (opposite phase = friendly wave)
            if (ud.armL) ud.armL.position.y = 40 + Math.sin(time * 1.5) * 3;
            if (ud.armR) ud.armR.position.y = 40 + Math.sin(time * 1.5 + Math.PI) * 3;

            // Sparkle particles orbit the robot
            if (ud.sparkles) {
                ud.sparkles.forEach(function(spark) {
                    spark.userData.angle += spark.userData.speed;
                    spark.position.x = Math.cos(spark.userData.angle) * spark.userData.radius;
                    spark.position.z = Math.sin(spark.userData.angle) * spark.userData.radius;
                    spark.position.y = spark.userData.yBase + Math.sin(time * 3 + spark.userData.angle) * 4;
                });
            }
            
            // Sync Metals
            // Remove old metals
            threeMetals.forEach(m => scene.remove(m));
            threeMetals = [];
            
            var metalGroups = groupObjects(metalObjects);
            Object.values(metalGroups).forEach(function(group) {
                group.forEach(function(m, index) {
                    if (!m.pickedUp || m.dropped) {
                        var geo, mat;
                        if (m.type === 'bolt') {
                             geo = new THREE.CylinderGeometry(8, 8, 20, 6);
                             mat = new THREE.MeshStandardMaterial({ color: 0x94a3b8 });
                        } else if (m.type === 'gear') {
                             geo = new THREE.CylinderGeometry(15, 15, 5, 8);
                             mat = new THREE.MeshStandardMaterial({ color: 0x78716c });
                        } else { // screw
                             geo = new THREE.CylinderGeometry(4, 4, 15, 8);
                             mat = new THREE.MeshStandardMaterial({ color: 0xa1a1aa });
                        }
                        var mesh = new THREE.Mesh(geo, mat);
                        // Stack height: base 10 + index * 15 (offset)
                        mesh.position.set(m.x, 10 + (index * 15), m.y);
                        mesh.castShadow = true;
                        // Highlight if selected
                        if (selectedObject === m) {
                             mesh.material.emissive.setHex(0x06b6d4);
                             mesh.material.emissiveIntensity = 0.5;
                        }
                        scene.add(mesh);
                        threeMetals.push(mesh);
                    }
                });
            });
            
            // Sync Walls
            threeWalls.forEach(w => scene.remove(w));
            threeWalls = [];
            
            var wallGroups = groupObjects(wallObjects);
            Object.values(wallGroups).forEach(function(group) {
                group.forEach(function(w, index) {
                     var geo = new THREE.BoxGeometry(w.width, 30, w.height); 
                     var mat = new THREE.MeshStandardMaterial({ color: 0xb45309 });
                     var mesh = new THREE.Mesh(geo, mat);
                     // Walls are defined by top-left corner in 2D, so center them for 3D
                     // Stack height: base 15 + index * 32 (offset > height)
                     mesh.position.set(w.x + w.width/2, 15 + (index * 32), w.y + w.height/2);
                     mesh.castShadow = true;
                     mesh.receiveShadow = true;
                     if (selectedObject === w) {
                          mesh.material.emissive.setHex(0x06b6d4);
                          mesh.material.emissiveIntensity = 0.5;
                     }
                     scene.add(mesh);
                     threeWalls.push(mesh);
                });
            });
            
            // Sync Fires
            threeFires.forEach(f => scene.remove(f));
            threeFires = [];
            
            var fireGroups = groupObjects(fireObjects);
            Object.values(fireGroups).forEach(function(group) {
                group.forEach(function(f, index) {
                    var geo = new THREE.ConeGeometry(15, 30, 8);
                    var mat = new THREE.MeshStandardMaterial({ color: 0xff6b35, emissive: 0xff4500, emissiveIntensity: 0.8 });
                    var mesh = new THREE.Mesh(geo, mat);
                    // Stack height: base 15 + index * 25
                    mesh.position.set(f.x, 15 + (index * 25), f.y);
                    scene.add(mesh);
                    threeFires.push(mesh);
                });
            });
            
            // Sync Target
            if (threeTarget) scene.remove(threeTarget);
            if (targetPoint) {
                var geo = new THREE.TorusGeometry(15, 2, 8, 16);
                var mat = new THREE.MeshBasicMaterial({ color: 0x22c55e });
                threeTarget = new THREE.Mesh(geo, mat);
                threeTarget.rotation.x = Math.PI / 2;
                threeTarget.position.set(targetPoint.x, 2, targetPoint.y);
                scene.add(threeTarget);
            }

            // Sync Pen Trails (drawn as thick line segments lying on the floor)
            // Remove old trail meshes
            threeTrails.forEach(function(t) {
                scene.remove(t);
                if (t.geometry) t.geometry.dispose();
                if (t.material) t.material.dispose();
            });
            threeTrails = [];

            // Group consecutive trail segments by color+size into one BufferGeometry for performance
            if (robot.trails && robot.trails.length > 0) {
                var grouped = {};
                robot.trails.forEach(function(seg) {
                    var key = (seg.color || '#6366f1') + '|' + (seg.size || 4);
                    if (!grouped[key]) grouped[key] = [];
                    grouped[key].push(seg);
                });

                Object.keys(grouped).forEach(function(key) {
                    var parts = key.split('|');
                    var color = parts[0];
                    var size = parseFloat(parts[1]);
                    var segs = grouped[key];

                    var positions = [];
                    segs.forEach(function(seg) {
                        // Lay trails just above the floor so they're visible from any angle
                        positions.push(seg.x1, 1.5, seg.y1);
                        positions.push(seg.x2, 1.5, seg.y2);
                    });

                    var geom = new THREE.BufferGeometry();
                    geom.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
                    var mat = new THREE.LineBasicMaterial({ color: color, linewidth: size });
                    var lines = new THREE.LineSegments(geom, mat);
                    scene.add(lines);
                    threeTrails.push(lines);
                });
            }
        }

        function toggleIsometricView() {
            isIsometricView = !isIsometricView;
            var btn = document.getElementById('isometricBtn');
            var threeContainer = document.getElementById('threeCanvasContainer');
            
            if (isIsometricView) {
                btn.classList.remove('bg-purple-500', 'hover:bg-purple-600');
                btn.classList.add('bg-green-500', 'hover:bg-green-600');
                btn.innerHTML = '🪐'; // Change icon to planet/orbit
                btn.title = "Switch to 2D";
                addChatMessage('stemo', "🤖 🪐 3D Mode Initialized! Zoom and Rotate enabled! 🚀");
                
                // Reset robot to home so it appears centered when entering 3D mode
                resetRobot();

                // Show Three.js container
                threeContainer.classList.remove('hidden');
                initThreeJS();
                animateThreeJS();
            } else {
                btn.classList.remove('bg-green-500', 'hover:bg-green-600');
                btn.classList.add('bg-purple-500', 'hover:bg-purple-600');
                btn.innerHTML = '📐';
                btn.title = "Switch to 3D";
                addChatMessage('stemo', "🤖 📐 Back to 2D View!");
                
                // Hide Three.js container
                threeContainer.classList.add('hidden');
            }
            drawRobot();
        }
        
        function clearMetals() {
            metalObjects = [];
            if (robot.carrying) {
                robot.carrying = null;
                robot.magnetOn = false;
            }
            drawRobot();
            addChatMessage('stemo', "🤖 🗑️ All metal objects cleared!");
        }

        // Save Project to .stemo file
        function saveProject() {
            if (!workspace) return;
            
            var xml = Blockly.Xml.workspaceToDom(workspace);
            var xmlText = Blockly.utils.xml.domToText(xml);
            
            var projectData = {
                code: xmlText,
                world: {
                    robot: robot,
                    walls: wallObjects,
                    metals: metalObjects,
                    fires: fireObjects,
                    target: targetPoint
                },
                // Use the snapshot ID so loading this file restores the correct challenge,
                // even if currentLesson already advanced to the next lesson after completion.
                lessonId: (challengeMode && challengeActiveLessonId) ? challengeActiveLessonId
                          : (currentLesson ? currentLesson.id : null),
                isChallenge: challengeMode,
                taskProgress: (currentLesson && currentLesson.tasks)
                    ? currentLesson.tasks.map(function(t) { return { id: t.id, completed: t.completed }; })
                    : [],
                version: '1.0'
            };
            
            var jsonString = JSON.stringify(projectData, null, 2);

            // Build a sensible default name:
            //   - In challenge mode → use the lesson that was LAUNCHED (not currentLesson, which may have
            //     already advanced to the next lesson after clicking "Next Lesson" in the success modal)
            //   - Free build with a lesson open → "lesson_5" style
            //   - No lesson open → "stemo_project"
            var defaultName = 'stemo_project';
            if (challengeMode && challengeActiveLessonId) {
                defaultName = 'challenge_' + challengeActiveLessonId.replace('lesson-', '');
            } else if (currentLesson) {
                defaultName = 'lesson_' + currentLesson.id.replace('lesson-', '');
            }

            // Ask the user for a filename (they can rename to e.g. "challenge 6" or "my star")
            var chosenName = window.prompt('Save project as (you can type any name):', defaultName);
            if (chosenName === null) return; // user pressed Cancel
            chosenName = chosenName.trim() || defaultName;
            if (!chosenName.toLowerCase().endsWith('.txt')) chosenName += '.txt';

            var blob = new Blob([jsonString], {type: "text/plain"});
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = chosenName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            addChatMessage('stemo', '💾 Project saved as "' + chosenName + '"! Load it any time with the 📂 button.');
        }

        // Copy Project to Clipboard
        function copyProjectToClipboard() {
            if (!workspace) return;
            
            var xml = Blockly.Xml.workspaceToDom(workspace);
            var xmlText = Blockly.utils.xml.domToText(xml);
            
            var projectData = {
                code: xmlText,
                world: {
                    robot: robot,
                    walls: wallObjects,
                    metals: metalObjects,
                    fires: fireObjects,
                    target: targetPoint
                },
                lessonId: currentLesson ? currentLesson.id : null,
                isChallenge: challengeMode,
                taskProgress: (currentLesson && currentLesson.tasks)
                    ? currentLesson.tasks.map(function(t) { return { id: t.id, completed: t.completed }; })
                    : [],
                version: '1.0'
            };
            
            var jsonString = JSON.stringify(projectData, null, 2);
            navigator.clipboard.writeText(jsonString).then(function() {
                addChatMessage('stemo', "📋 Project copied to clipboard! Paste it into a text file to save. 💾");
                alert("Project copied! You can now paste it into Notepad.");
            }, function() {
                addChatMessage('stemo', "❌ Failed to copy to clipboard.");
                alert("Failed to copy. Please try again.");
            });
        }

        // Minimal metadata for challenge lessons (used when restoring a saved challenge file)
        var CHALLENGE_LESSON_META = {
            'lesson-4':  { id: 'lesson-4',  title: 'Color Artist',         description: 'Paint with colours and control line thickness',             hint: 'Place Color and Size blocks BEFORE Pen Down. Change Color between sides!',                   icon: '🎨', xpReward: 100,  nextLesson: 'lesson-5'  },
            'lesson-5':  { id: 'lesson-5',  title: 'Loop Power!',           description: 'Use Repeat to replace boring repeated blocks',              hint: 'Staircase code: Repeat 5 → Forward 2, Right 90, Forward 2, Left 90',                      icon: '🔁', xpReward: 150,  nextLesson: 'lesson-6'  },
            'lesson-6':  { id: 'lesson-6',  title: 'Shape Artist',        description: 'Use maths to draw any polygon you can imagine',          hint: 'Formula: Turn Angle = 360 ÷ Sides. Triangle=120, Square=90, Pentagon=72, Hexagon=60, Octagon=45!', icon: '📐', xpReward: 200,  nextLesson: 'lesson-7'  },
            'lesson-7':  { id: 'lesson-7',  title: 'Star Power!',          description: 'Draw beautiful 8-pointed stars using a secret angle trick',  hint: '8-pointed star: Repeat 8 → Forward 6, Right 135°. The magic number is 135!',               icon: '✨', xpReward: 300,  nextLesson: 'lesson-8'  },
            'lesson-8':  { id: 'lesson-8',  title: 'Magnet Magic',      description: 'Pick up metal objects with your magnet.',             hint: 'Turn your magnet ON, move close to a metal object, and it will attach to STEMO!',           icon: '🧲', xpReward: 200, nextLesson: 'lesson-9'  },
            'lesson-9':  { id: 'lesson-9',  title: 'Ultrasonic Sight',  description: 'Navigate walls using your ultrasonic sensor.',        hint: 'The Scan Ahead beam shows distance to the nearest wall. Use it to decide when to turn!',    icon: '📡', xpReward: 250, nextLesson: 'lesson-10' },
            'lesson-10': { id: 'lesson-10', title: 'Space Navigator',   description: 'Reach the target point automatically.',               hint: 'Use Go To Target to navigate automatically, or calculate steps and use Move + Turn blocks.', icon: '🎯', xpReward: 300, nextLesson: 'lesson-11' },
            'lesson-11': { id: 'lesson-11', title: 'Smart Explorer',    description: 'Use If/Else logic to find the correct path.',         hint: 'Check which direction is clear before moving. If wall is close, go another way!',           icon: '🧠', xpReward: 350, nextLesson: 'lesson-12' },
            'lesson-12': { id: 'lesson-12', title: 'Fire Watch',        description: 'Detect heat sources with your temperature sensor.',   hint: 'Scan in each direction — when temperature rises, you are near a fire!',                     icon: '🔥', xpReward: 400, nextLesson: 'lesson-13' },
            'lesson-13': { id: 'lesson-13', title: 'Firefighter Hero',  description: 'Extinguish all fires before your water runs out!',    hint: 'Spray water when close to a fire. Watch your water level — refill at home base!',           icon: '🚒', xpReward: 500, nextLesson: 'lesson-14' },
            'lesson-14': { id: 'lesson-14', title: 'Master Coder',      description: 'The final challenge — use everything you have learned!', hint: 'Collect metals, extinguish fires, and reach the target. Plan your route carefully!',      icon: '🏆', xpReward: 1000, nextLesson: 'lesson-15' },
            'lesson-15': { id: 'lesson-15', title: 'Variable Vault',    description: 'Store values in variables and use them to control STEMO.',  hint: 'Set speed=4, count=4, angle=90. Then: Pen Down → Repeat count → Move speed steps, Turn angle degrees. One number controls everything!', icon: '🔢', xpReward: 400, nextLesson: 'lesson-16' },
            'lesson-16': { id: 'lesson-16', title: 'Position Memory',   description: 'Save your coordinates and navigate back home like GPS.',     hint: 'First block: Save Position A (records start). Navigate to target. Last block: Go to Position A (returns home via shortest path)!',            icon: '📍', xpReward: 450, nextLesson: 'lesson-17' },
            'lesson-17': { id: 'lesson-17', title: 'Waypoint Trail',    description: 'Follow a pre-loaded list of locations to collect metals.',   hint: 'The list is already loaded! Add Magnet ON, then Replay Path — STEMO visits every waypoint in order and picks up metals along the way.',       icon: '🗺️', xpReward: 500, nextLesson: 'lesson-18' },
            'lesson-18': { id: 'lesson-18', title: 'List Hunt',         description: 'Loop through a list of fire targets — AI iteration in action!', hint: 'Use For Each Waypoint → Spray Water. STEMO navigates to each fire location and sprays automatically. This is how AI processes data lists!', icon: '🎯', xpReward: 600, nextLesson: 'lesson-19' },
            'lesson-19': { id: 'lesson-19', title: 'Function Factory', description: 'Write a function once, call it forever — the superpower of every programmer.', hint: 'Define "drawSquare": Pen Down + Repeat 4× (Move 3, Turn Right 90°). Define "bigSquare": Repeat 4× (Call drawSquare + Turn Right 90°). Then: Call bigSquare → Turn Right 45° → Call bigSquare. Star pattern complete!', icon: '🔧', xpReward: 700, nextLesson: null }
        };

        // Load Project from .stemo file
        function loadProject(event) {
            var file = event.target.files[0];
            if (!file) return;
            
            var reader = new FileReader();
            reader.onload = function(e) {
                try {
                    var contents = e.target.result;
                    var projectData = JSON.parse(contents);
                    
                    if (workspace && projectData.code) {
                        workspace.clear();
                        var xml = Blockly.utils.xml.textToDom(projectData.code);
                        Blockly.Xml.domToWorkspace(xml, workspace);
                        
                        // Support both old format (challengeLessonId) and new format (lessonId + isChallenge)
                        var savedLessonId = projectData.lessonId || projectData.challengeLessonId || null;
                        var savedIsChallenge = projectData.isChallenge || (!!projectData.challengeLessonId);
                        var savedTaskProgress = projectData.taskProgress || [];

                        // Helper: restore lesson header + task completions in UI
                        function _restoreLessonUI(lesson) {
                            if (!lesson) return;
                            currentLesson = lesson;
                            document.getElementById('currentLessonTitle').textContent = lesson.title;
                            document.getElementById('currentLessonDesc').textContent = lesson.description;
                            var hintEl = document.getElementById('hintText');
                            if (hintEl) hintEl.textContent = lesson.hint || '';
                            var hintPanel = document.getElementById('hintPanel');
                            if (hintPanel) hintPanel.classList.remove('hidden');
                            // Restore task tick marks
                            if (lesson.tasks && savedTaskProgress.length) {
                                savedTaskProgress.forEach(function(saved) {
                                    var task = lesson.tasks.find(function(t) { return t.id === saved.id; });
                                    if (task) task.completed = saved.completed;
                                });
                            }
                        }

                        if (savedLessonId && savedIsChallenge && LESSON_CHALLENGES[savedLessonId]) {
                            // ── Restore a challenge file ──────────────────────────────────
                            challengeMode = false;
                            challengeCompleted = false;
                            missionObjectives = null;
                            targetTrails = [];
                            metalObjects = []; wallObjects = []; fireObjects = [];
                            targetPoint = null;
                            resetRobot();

                            var lessonMeta = CHALLENGE_LESSON_META[savedLessonId]
                                || findLessonById(savedLessonId)
                                || null;
                            _restoreLessonUI(lessonMeta);

                            // Re-run the challenge setup (rebuilds world objects + targetTrails)
                            var ch = LESSON_CHALLENGES[savedLessonId];
                            ch.setup();

                            // Activate challenge mode and build objectives
                            challengeMode = true;
                            missionObjectives = ch.objectives.map(function(obj) {
                                return { id: obj.id, label: obj.label, done: false, check: obj.check };
                            });

                            document.getElementById('missionTitle').textContent = ch.title;
                            var descEl2 = document.getElementById('missionDesc');
                            if (descEl2 && ch.description) { descEl2.textContent = ch.description; descEl2.style.display = 'block'; }
                            updateMissionHUD();
                            showMissionToast();
                            document.getElementById('missionBadge').classList.remove('hidden');
                            document.getElementById('missionExitBtn').classList.remove('hidden');

                            drawRobot();
                            addChatMessage('stemo', '📂 Challenge loaded! ' + ch.description + ' Good luck! 💪');

                        } else {
                            // ── Restore a free-build (or lesson-only) file ────────────────
                            challengeMode = false;
                            challengeCompleted = false;
                            missionObjectives = null;
                            targetTrails = [];
                            document.getElementById('missionHUD').classList.add('hidden');
                            document.getElementById('missionBadge').classList.add('hidden');
                            document.getElementById('missionExitBtn').classList.add('hidden');

                            // Restore lesson context if one was saved
                            if (savedLessonId) {
                                var freeLessonMeta = CHALLENGE_LESSON_META[savedLessonId]
                                    || findLessonById(savedLessonId)
                                    || null;
                                _restoreLessonUI(freeLessonMeta);
                            }

                            if (projectData.world) {
                                robot = projectData.world.robot || robot;
                                wallObjects = projectData.world.walls || [];
                                metalObjects = projectData.world.metals || [];
                                fireObjects = projectData.world.fires || [];
                                targetPoint = projectData.world.target || null;
                                robot.trails = [];
                                robot.carrying = null;
                                robot.magnetOn = false;
                                drawRobot();
                            }
                            addChatMessage('stemo', "📂 Project loaded! Let's code! 🚀");
                        }
                    }
                } catch (err) {
                    console.error("Error loading project:", err);
                    alert("Error loading project file. Make sure it's a valid .stemo file.");
                }
            };
            reader.readAsText(file);
            
            // Reset input so same file can be selected again
            event.target.value = '';
        }

        // Helper function to group objects by location
        function groupObjects(objects) {
            var groups = {};
            objects.forEach(function(obj) {
                var key = Math.round(obj.x) + ',' + Math.round(obj.y);
                if (!groups[key]) groups[key] = [];
                groups[key].push(obj);
            });
            return groups;
        }

        // Helper function to draw quantity badge
        function drawCountBadge(ctx, x, y, count) {
            ctx.save();
            // Circle background
            ctx.beginPath();
            ctx.arc(x, y, 8, 0, Math.PI * 2);
            ctx.fillStyle = '#ef4444'; // Red
            ctx.fill();
            ctx.strokeStyle = '#ffffff';
            ctx.lineWidth = 1.5;
            ctx.stroke();
            
            // Text
            ctx.fillStyle = '#ffffff';
            ctx.font = 'bold 10px Arial';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText('x' + count, x, y);
            ctx.restore();
        }

        // Toggle Robot Panel to maximize workspace
        function toggleRobotPanel() {
            var panel = document.getElementById('robotPanel');
            var btn = document.getElementById('toggleRobotBtn');
            var icon = document.getElementById('robotPanelIcon');
            var text = document.getElementById('robotPanelText');
            
            robotPanelVisible = !robotPanelVisible;
            
            if (robotPanelVisible) {
                panel.style.width = '430px';
                panel.classList.remove('overflow-hidden', 'border-l-0');
                panel.classList.add('border-l-2');
                icon.textContent = '🤖';
                text.textContent = 'Hide Robot';
                btn.classList.remove('bg-gray-500');
                btn.classList.add('bg-cyan-500', 'hover:bg-cyan-600');
            } else {
                panel.style.width = '0';
                panel.classList.remove('border-l-2');
                panel.classList.add('overflow-hidden', 'border-l-0');
                icon.textContent = '👁️';
                text.textContent = 'Show Robot';
                btn.classList.remove('bg-cyan-500', 'hover:bg-cyan-600');
                btn.classList.add('bg-gray-500');
            }
            
            // Resize Blockly workspace after panel toggle
            if (workspace) {
                setTimeout(function() {
                    Blockly.svgResize(workspace);
                }, 350);
            }
        }
    </script>
</body>
</html>`;

// ============================================
// LOGIN PAGE
// ============================================
const loginPage = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🤖 STEMO - Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Fredoka+One&family=Nunito:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        * { font-family: 'Nunito', sans-serif; }
        h1, h2 { font-family: 'Fredoka One', cursive; }
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .bounce { animation: bounce 2s infinite; }
        @keyframes bounce { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-10px)} }
        .card { background: rgba(255,255,255,0.95); backdrop-filter: blur(10px); }
    </style>
</head>
<body class="gradient-bg min-h-screen flex flex-col items-center justify-center p-4">
    <div class="w-full max-w-md">
        <div class="text-center mb-8">
            <img src="/static/steam-logo-white.png" alt="STEAM Academy" class="h-20 mx-auto mb-4 object-contain drop-shadow-lg">
            <h1 class="text-5xl text-white mb-2">STEMO</h1>
        </div>
        <div class="card rounded-3xl p-8 shadow-2xl">
            <h2 class="text-2xl text-gray-800 mb-6 text-center">Welcome Back!</h2>
            <div id="errorMsg" class="hidden bg-red-50 border border-red-200 text-red-700 rounded-xl p-3 mb-4 text-sm"></div>
            <form id="loginForm" class="space-y-4">
                <div>
                    <label class="block text-sm font-bold text-gray-600 mb-1">Username</label>
                    <input id="username" type="text" placeholder="Enter your username" autocomplete="username"
                        class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-gray-800 focus:outline-none focus:border-indigo-400 transition-colors text-lg">
                </div>
                <div>
                    <label class="block text-sm font-bold text-gray-600 mb-1">Password</label>
                    <input id="password" type="password" placeholder="Enter your password" autocomplete="current-password"
                        class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-gray-800 focus:outline-none focus:border-indigo-400 transition-colors text-lg">
                </div>
                <button type="submit" id="loginBtn"
                    class="w-full bg-gradient-to-r from-indigo-500 to-purple-600 text-white py-3 rounded-xl font-bold text-lg hover:from-indigo-600 hover:to-purple-700 transition-all transform hover:scale-105 shadow-lg">
                    🚀 Let's Go!
                </button>
            </form>
            <div class="flex items-center gap-2 mt-6">
                <div class="flex-1 h-px bg-gray-200"></div>
                <span class="text-gray-400 text-xs">or</span>
                <div class="flex-1 h-px bg-gray-200"></div>
            </div>
            <a href="/register" class="block mt-4 text-center bg-gray-50 hover:bg-gray-100 border-2 border-gray-200 text-gray-600 py-3 rounded-xl font-bold text-base transition-all">
                ✍️ Register as a Student
            </a>
            <p class="text-center text-gray-400 text-xs mt-3">Registration requires teacher or admin approval</p>
        </div>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('loginBtn');
            const err = document.getElementById('errorMsg');
            btn.textContent = '⏳ Logging in...';
            btn.disabled = true;
            err.classList.add('hidden');
            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: document.getElementById('username').value.trim(),
                        password: document.getElementById('password').value
                    })
                });
                const data = await res.json();
                if (data.success) {
                    const role = data.user.role;
                    if (role === 'admin') window.location.href = '/dashboard/admin';
                    else if (role === 'teacher') window.location.href = '/dashboard/teacher';
                    else if (role === 'parent') window.location.href = '/dashboard/parent';
                    else window.location.href = '/';
                } else {
                    if (data.pending) {
                        err.innerHTML = '⏳ <strong>Account Pending Approval</strong><br>Your registration is waiting for a teacher or admin to approve it. Check back soon!';
                    } else if (data.rejected) {
                        err.innerHTML = '❌ <strong>Registration Not Approved</strong><br>Please contact your teacher for help.';
                    } else {
                        err.textContent = data.error || 'Login failed. Please try again.';
                    }
                    err.classList.remove('hidden');
                    btn.textContent = '🚀 Let\\'s Go!';
                    btn.disabled = false;
                }
            } catch (e) {
                err.textContent = 'Connection error. Please try again.';
                err.classList.remove('hidden');
                btn.textContent = '🚀 Let\\'s Go!';
                btn.disabled = false;
            }
        });
    </script>
    <div class="text-center mt-6 pb-4">
        <p class="text-purple-200 text-sm">© 2026 STEMO · Science Games</p>
        <p class="text-purple-300 text-xs">أكاديمية ستيم لألعاب العلوم</p>
    </div>
</body>
</html>`

// ============================================
// ADMIN DASHBOARD PAGE
// ============================================
const adminDashboard = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ STEMO Admin Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Fredoka+One&family=Nunito:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>* { font-family: 'Nunito', sans-serif; } h1,h2,h3{font-family:'Fredoka One',cursive;}</style>
</head>
<body class="bg-gray-50 min-h-screen">
<nav class="bg-gradient-to-r from-purple-800 to-violet-900 text-white px-6 py-4 shadow-lg">
    <div class="max-w-7xl mx-auto flex items-center justify-between">
        <div class="flex items-center gap-3">
            <img src="/static/steam-logo-white.png" alt="STEMO Coding" class="h-9 object-contain">
            <div><h1 class="text-2xl">STEMO Coding — Admin</h1></div>
        </div>
        <div class="flex items-center gap-4">
            <span class="text-purple-200 text-sm" id="welcomeMsg"></span>
            <button onclick="logout()" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-full text-sm font-bold transition-all">🚪 Logout</button>
        </div>
    </div>
</nav>
<div class="max-w-7xl mx-auto p-6">
    <!-- Stats Row -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8" id="statsRow">
        <div class="bg-white rounded-2xl p-5 shadow text-center"><div class="text-3xl mb-1">👥</div><div class="text-3xl font-bold text-indigo-600" id="statUsers">-</div><div class="text-gray-500 text-sm">Total Users</div></div>
        <div class="bg-white rounded-2xl p-5 shadow text-center"><div class="text-3xl mb-1">🎓</div><div class="text-3xl font-bold text-green-600" id="statStudents">-</div><div class="text-gray-500 text-sm">Students</div></div>
        <div class="bg-white rounded-2xl p-5 shadow text-center"><div class="text-3xl mb-1">📚</div><div class="text-3xl font-bold text-blue-600" id="statTeachers">-</div><div class="text-gray-500 text-sm">Teachers</div></div>
        <div class="bg-white rounded-2xl p-5 shadow text-center"><div class="text-3xl mb-1">🏫</div><div class="text-3xl font-bold text-purple-600" id="statClasses">-</div><div class="text-gray-500 text-sm">Classes</div></div>
    </div>
    <!-- Tabs -->
    <div class="flex gap-2 mb-6 flex-wrap">
        <button onclick="showTab('pending')" id="tab-pending" class="tab-btn bg-orange-500 text-white px-5 py-2 rounded-full font-bold text-sm">⏳ Pending <span id="pendingBadge" class="bg-white text-orange-600 rounded-full px-2 ml-1 text-xs">0</span></button>
        <button onclick="showTab('users')" id="tab-users" class="tab-btn bg-gray-200 text-gray-600 px-5 py-2 rounded-full font-bold text-sm">👥 Users</button>
        <button onclick="showTab('classes')" id="tab-classes" class="tab-btn bg-gray-200 text-gray-600 px-5 py-2 rounded-full font-bold text-sm">🏫 Classes</button>
        <button onclick="showTab('links')" id="tab-links" class="tab-btn bg-gray-200 text-gray-600 px-5 py-2 rounded-full font-bold text-sm">🔗 Parent Links</button>
    </div>
    <!-- Pending Approvals Tab -->
    <div id="section-pending">
        <div class="bg-white rounded-2xl shadow p-6">
            <h2 class="text-xl mb-4">⏳ Pending Registrations</h2>
            <div id="pendingList"><p class="text-gray-400 text-center py-8">Loading...</p></div>
        </div>
    </div>
    <!-- Users Tab -->
    <div id="section-users">
        <div class="bg-white rounded-2xl shadow p-6">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-xl">All Users</h2>
                <button onclick="showCreateUser()" class="bg-indigo-600 text-white px-4 py-2 rounded-xl font-bold text-sm hover:bg-indigo-700">+ Add User</button>
            </div>
            <!-- Create User Form -->
            <div id="createUserForm" class="hidden bg-indigo-50 rounded-xl p-4 mb-4 border border-indigo-200">
                <h3 class="font-bold text-indigo-700 mb-3">Create New User</h3>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <input id="newFullName" placeholder="Full Name" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400">
                    <input id="newUsername" placeholder="Username" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400">
                    <input id="newPassword" type="password" placeholder="Password" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400">
                    <select id="newRole" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400">
                        <option value="student">🎓 Student</option>
                        <option value="teacher">📚 Teacher</option>
                        <option value="parent">👨‍👩‍👧 Parent</option>
                        <option value="admin">🛡️ Admin</option>
                    </select>
                </div>
                <div class="flex gap-2 mt-3">
                    <button onclick="createUser()" class="bg-indigo-600 text-white px-4 py-2 rounded-lg text-sm font-bold hover:bg-indigo-700">✅ Create</button>
                    <button onclick="document.getElementById('createUserForm').classList.add('hidden')" class="bg-gray-200 px-4 py-2 rounded-lg text-sm font-bold">Cancel</button>
                </div>
                <div id="createUserMsg" class="mt-2 text-sm hidden"></div>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead><tr class="border-b text-gray-500 text-left"><th class="pb-2">Name</th><th class="pb-2">Username</th><th class="pb-2">Role</th><th class="pb-2">Joined</th><th class="pb-2">Actions</th></tr></thead>
                    <tbody id="usersTable"></tbody>
                </table>
            </div>
        </div>
    </div>
    <!-- Classes Tab -->
    <div id="section-classes" class="hidden">
        <div class="bg-white rounded-2xl shadow p-6">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-xl">🏫 Schools &amp; Classes</h2>
                <button onclick="showCreateSchool()" class="bg-purple-600 text-white px-4 py-2 rounded-xl font-bold text-sm hover:bg-purple-700">+ Add School</button>
            </div>
            <!-- Create School Form -->
            <div id="createSchoolForm" class="hidden bg-purple-50 rounded-xl p-4 mb-4 border border-purple-200">
                <h3 class="font-bold text-purple-700 mb-3">Create New School</h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <input id="newSchoolName" placeholder="School Name" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-purple-400">
                    <input id="newSchoolDesc" placeholder="Description (optional)" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-purple-400">
                </div>
                <div class="flex gap-2 mt-3">
                    <button onclick="createSchool()" class="bg-purple-600 text-white px-4 py-2 rounded-lg text-sm font-bold hover:bg-purple-700">✅ Create School</button>
                    <button onclick="document.getElementById('createSchoolForm').classList.add('hidden')" class="bg-gray-200 px-4 py-2 rounded-lg text-sm font-bold">Cancel</button>
                </div>
                <div id="createSchoolMsg" class="mt-2 text-sm hidden"></div>
            </div>
            <div id="schoolsList" class="space-y-6"></div>
        </div>
    </div>
    <!-- Parent Links Tab -->
    <div id="section-links" class="hidden">
        <div class="bg-white rounded-2xl shadow p-6">
            <h2 class="text-xl mb-4">Link Parent to Student</h2>
            <div class="grid grid-cols-2 gap-4 max-w-md">
                <div>
                    <label class="text-sm font-bold text-gray-600 block mb-1">Parent</label>
                    <select id="linkParent" class="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400"></select>
                </div>
                <div>
                    <label class="text-sm font-bold text-gray-600 block mb-1">Student</label>
                    <select id="linkStudent" class="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400"></select>
                </div>
            </div>
            <button onclick="linkParent()" class="mt-4 bg-indigo-600 text-white px-5 py-2 rounded-xl font-bold text-sm hover:bg-indigo-700">🔗 Link</button>
            <div id="linkMsg" class="mt-2 text-sm hidden"></div>
        </div>
    </div>
</div>
<script>
let allUsers = [];
const roleColors = {admin:'bg-red-100 text-red-700',teacher:'bg-blue-100 text-blue-700',student:'bg-green-100 text-green-700',parent:'bg-yellow-100 text-yellow-700'};
const roleEmoji = {admin:'🛡️',teacher:'📚',student:'🎓',parent:'👨‍👩‍👧'};

async function init() {
    const me = await fetch('/api/auth/me').then(r=>r.json());
    if (!me.user || me.user.role !== 'admin') { window.location.href='/login'; return; }
    document.getElementById('welcomeMsg').textContent = 'Welcome, ' + me.user.full_name;
    loadPending();
    loadUsers();
    loadClasses();
    loadLinkDropdowns();
}

function showTab(tab) {
    ['pending','users','classes','links'].forEach(t => {
        document.getElementById('section-'+t).classList.add('hidden');
        const btn = document.getElementById('tab-'+t);
        if (btn) btn.className = 'tab-btn bg-gray-200 text-gray-600 px-5 py-2 rounded-full font-bold text-sm';
    });
    document.getElementById('section-'+tab).classList.remove('hidden');
    const activeColors = {pending:'bg-orange-500',users:'bg-indigo-600',classes:'bg-indigo-600',links:'bg-indigo-600'};
    document.getElementById('tab-'+tab).className = \`tab-btn \${activeColors[tab]} text-white px-5 py-2 rounded-full font-bold text-sm\`;
}

async function loadPending() {
    const pending = await fetch('/api/admin/pending').then(r=>r.json());
    document.getElementById('pendingBadge').textContent = pending.length;
    const list = document.getElementById('pendingList');
    if (!pending.length) {
        list.innerHTML = '<p class="text-gray-400 text-center py-8">✅ No pending registrations right now!</p>';
        return;
    }
    list.innerHTML = \`<div class="space-y-3">\${pending.map(u => \`
        <div class="flex items-center justify-between p-4 bg-orange-50 border border-orange-200 rounded-xl">
            <div>
                <div class="font-bold text-gray-800">\${u.full_name}</div>
                <div class="text-gray-500 text-sm">@\${u.username} • registered \${u.created_at?.slice(0,10) || 'today'}</div>
            </div>
            <div class="flex gap-2">
                <button onclick="approveUser(\${u.id}, 'approve')" class="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded-lg text-sm font-bold transition-all">✅ Approve</button>
                <button onclick="approveUser(\${u.id}, 'reject')" class="bg-red-400 hover:bg-red-500 text-white px-4 py-2 rounded-lg text-sm font-bold transition-all">❌ Reject</button>
            </div>
        </div>\`).join('')}</div>\`;
}

async function approveUser(id, action) {
    await fetch('/api/admin/users/' + id + '/approve', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ action })
    });
    loadPending();
    loadUsers();
}

async function loadUsers() {
    allUsers = await fetch('/api/admin/users').then(r=>r.json());
    const approved = allUsers.filter(u=>u.status==='approved'||!u.status);
    const students = approved.filter(u=>u.role==='student').length;
    const teachers = approved.filter(u=>u.role==='teacher').length;
    document.getElementById('statUsers').textContent = approved.length;
    document.getElementById('statStudents').textContent = students;
    document.getElementById('statTeachers').textContent = teachers;
    const tbody = document.getElementById('usersTable');
    tbody.innerHTML = allUsers.map(u => \`<tr class="border-b hover:bg-gray-50">
        <td class="py-2 font-semibold">\${u.full_name}</td>
        <td class="py-2 text-gray-500">@\${u.username}</td>
        <td class="py-2"><span class="px-2 py-1 rounded-full text-xs font-bold \${roleColors[u.role]}">\${roleEmoji[u.role]} \${u.role}</span></td>
        <td class="py-2"><span class="px-2 py-1 rounded-full text-xs font-bold \${u.status==='pending'?'bg-orange-100 text-orange-700':u.status==='rejected'?'bg-red-100 text-red-700':'bg-green-100 text-green-700'}">\${u.status||'approved'}</span></td>
        <td class="py-2 text-gray-400">\${u.created_at?.slice(0,10) || '-'}</td>
        <td class="py-2"><button onclick="deleteUser(\${u.id}, '\${u.username}')" class="text-red-400 hover:text-red-600 text-xs">🗑️ Delete</button></td>
    </tr>\`).join('');
}

// ── Schools + Classes admin functions ──────────────────────────────────────

var cachedTeachers = [];

async function loadClasses() {
    // "loadClasses" is the hook called by the tab switch; now delegates to loadSchools
    await loadSchools();
}

async function loadSchools() {
    const container = document.getElementById('schoolsList');
    container.innerHTML = '<p class="text-gray-400 text-center py-4">Loading...</p>';

    let schools, allClasses;
    try {
        const [schoolsRes, classesRes] = await Promise.all([
            fetch('/api/admin/schools'),
            fetch('/api/classes')
        ]);
        const schoolsText = await schoolsRes.text();
        const classesText = await classesRes.text();
        try { schools = JSON.parse(schoolsText); } catch(e) {
            container.innerHTML = \`<div class="bg-red-50 border border-red-200 rounded-xl p-4 text-red-700 text-sm"><b>Schools API error (status \${schoolsRes.status}):</b><br><pre class="mt-1 text-xs overflow-auto">\${schoolsText.slice(0,500)}</pre></div>\`;
            return;
        }
        try { allClasses = JSON.parse(classesText); } catch(e) { allClasses = []; }
        if (!Array.isArray(schools)) {
            container.innerHTML = \`<div class="bg-red-50 border border-red-200 rounded-xl p-4 text-red-700 text-sm"><b>Schools API returned an error:</b><br><pre class="mt-1 text-xs">\${JSON.stringify(schools,null,2)}</pre></div>\`;
            return;
        }
    } catch(e) {
        container.innerHTML = \`<div class="bg-red-50 border border-red-200 rounded-xl p-4 text-red-700 text-sm">Network error: \${e.message}</div>\`;
        return;
    }

    cachedTeachers = await fetch('/api/teachers').then(r=>r.json()).catch(()=>[]);

    // Update stat counter (total classes across all schools)
    document.getElementById('statClasses').textContent = Array.isArray(allClasses) ? allClasses.length : 0;

    container.innerHTML = '';

    if (!schools.length) {
        container.innerHTML = '<p class="text-gray-400 text-center py-8">No schools yet. Click "+ Add School" to create one.</p>';
        return;
    }

    for (const school of schools) {
        const schoolClasses = allClasses.filter(c => c.school_id === school.id);
        const schoolDiv = document.createElement('div');
        schoolDiv.id = 'school_' + school.id;
        schoolDiv.className = 'border-2 border-purple-200 rounded-2xl p-5 bg-purple-50';
        schoolDiv.innerHTML = await buildSchoolHTML(school, schoolClasses);
        container.appendChild(schoolDiv);
    }

    // Classes with no school (legacy / unassigned)
    const unassigned = allClasses.filter(c => !c.school_id);
    if (unassigned.length) {
        const legacyDiv = document.createElement('div');
        legacyDiv.className = 'border border-gray-200 rounded-2xl p-5 bg-gray-50';
        legacyDiv.innerHTML = '<h3 class="font-bold text-gray-500 text-sm mb-3">📂 Classes without a school</h3><div id="unassigned_classes" class="space-y-3"></div>';
        container.appendChild(legacyDiv);
        const uc = document.getElementById('unassigned_classes');
        for (const cls of unassigned) {
            const [students, available] = await Promise.all([
                fetch('/api/classes/' + cls.id + '/students').then(r=>r.json()),
                fetch('/api/classes/' + cls.id + '/available-students').then(r=>r.json())
            ]);
            uc.innerHTML += buildClassHTML(cls, students, available);
        }
    }
}

async function buildSchoolHTML(school, schoolClasses) {
    var teacherOpts = cachedTeachers.map(t=>\`<option value="\${t.id}">\${t.full_name} (@\${t.username})</option>\`).join('');
    var classesHTML = '';
    for (const cls of schoolClasses) {
        const [students, available] = await Promise.all([
            fetch('/api/classes/' + cls.id + '/students').then(r=>r.json()),
            fetch('/api/classes/' + cls.id + '/available-students').then(r=>r.json())
        ]);
        classesHTML += buildClassHTML(cls, students, available);
    }
    return \`
        <div class="flex items-start justify-between mb-4">
            <div id="school_view_\${school.id}">
                <h2 class="font-bold text-purple-800 text-xl">🏫 \${school.name}</h2>
                <p class="text-purple-500 text-sm">\${school.description || ''}</p>
            </div>
            <div id="school_edit_\${school.id}" class="hidden flex-1 mr-4">
                <input id="editSchoolName_\${school.id}" value="\${school.name}" class="border rounded-lg px-3 py-1.5 text-sm w-full mb-1 focus:outline-none focus:border-purple-400">
                <input id="editSchoolDesc_\${school.id}" value="\${school.description||''}" placeholder="Description" class="border rounded-lg px-3 py-1.5 text-sm w-full focus:outline-none focus:border-purple-400">
            </div>
            <div class="flex items-center gap-2 flex-shrink-0 ml-3">
                <span class="bg-purple-200 text-purple-700 text-xs font-bold px-2 py-1 rounded-full">\${schoolClasses.length} classes</span>
                <button onclick="toggleEditSchool(\${school.id})" id="editSchoolBtn_\${school.id}" class="text-purple-600 hover:text-purple-800 text-xs font-bold border border-purple-300 rounded-lg px-2 py-1">✏️ Edit</button>
                <button onclick="saveSchool(\${school.id})" id="saveSchoolBtn_\${school.id}" class="hidden bg-purple-600 text-white text-xs font-bold rounded-lg px-2 py-1 hover:bg-purple-700">💾 Save</button>
                <button onclick="deleteSchool(\${school.id})" class="text-red-400 hover:text-red-600 text-xs font-bold border border-red-200 rounded-lg px-2 py-1">🗑️ Delete</button>
            </div>
        </div>
        <div class="space-y-3 mb-4">\${classesHTML || '<p class="text-purple-400 text-sm">No classes yet.</p>'}</div>
        <div id="addClassForm_\${school.id}" class="hidden bg-white rounded-xl p-3 border border-indigo-200 mt-2">
            <div class="grid grid-cols-3 gap-2">
                <input id="newClassName_\${school.id}" placeholder="Class Name *" class="border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:border-indigo-400">
                <input id="newClassDesc_\${school.id}" placeholder="Description (optional)" class="border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:border-indigo-400">
                <select id="newClassTeacher_\${school.id}" class="border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:border-indigo-400">
                    <option value="">— Teacher (optional) —</option>\${teacherOpts}
                </select>
            </div>
            <div class="flex gap-2 mt-2">
                <button onclick="createClassUnderSchool(\${school.id})" class="bg-indigo-600 text-white px-3 py-1.5 rounded-lg text-xs font-bold hover:bg-indigo-700">✅ Create Class</button>
                <button onclick="document.getElementById('addClassForm_\${school.id}').classList.add('hidden')" class="bg-gray-200 px-3 py-1.5 rounded-lg text-xs font-bold">Cancel</button>
            </div>
        </div>
        <button onclick="document.getElementById('addClassForm_\${school.id}').classList.toggle('hidden')" class="mt-2 text-indigo-600 hover:text-indigo-800 text-xs font-bold border border-indigo-300 rounded-lg px-3 py-1.5">+ Add Class</button>
    \`;
}

function buildClassHTML(cls, students, available) {
    var studentRows = students.map(s => \`
        <tr class="border-b hover:bg-gray-50">
            <td class="py-1.5 font-semibold text-sm">\${s.full_name}<span class="text-gray-400 text-xs ml-1">@\${s.username}</span></td>
            <td class="py-1.5 text-xs text-yellow-500 font-bold">⭐ \${s.xp||0}</td>
            <td class="py-1.5 text-xs"><span class="bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded-full">Lv \${s.level||1}</span></td>
            <td class="py-1.5"><button onclick="removeStudentFromClass(\${cls.id},\${s.id})" class="text-red-400 hover:text-red-600 text-xs">✕</button></td>
        </tr>\`).join('');
    var availableOpts = available.map(s => \`<option value="\${s.id}">\${s.full_name} (@\${s.username})</option>\`).join('');
    var teacherOpts = cachedTeachers.map(t=>\`<option value="\${t.id}" \${cls.teacher_id==t.id?'selected':''}>\${t.full_name}</option>\`).join('');
    return \`<div id="class_\${cls.id}" class="bg-white border rounded-xl p-4">
        <div class="flex items-start justify-between mb-2">
            <div id="class_view_\${cls.id}">
                <span class="font-bold text-gray-800">\${cls.name}</span>
                <span class="text-gray-400 text-xs ml-2">\${cls.description||''}</span>
                <div class="text-blue-500 text-xs mt-0.5">📚 \${cls.teacher_name||'Unassigned'}</div>
            </div>
            <div id="class_edit_\${cls.id}" class="hidden flex-1 mr-3 space-y-1">
                <input id="editClassName_\${cls.id}" value="\${cls.name}" class="border rounded px-2 py-1 text-sm w-full focus:outline-none focus:border-indigo-400">
                <input id="editClassDesc_\${cls.id}" value="\${cls.description||''}" placeholder="Description" class="border rounded px-2 py-1 text-sm w-full focus:outline-none focus:border-indigo-400">
                <select id="editClassTeacher_\${cls.id}" class="border rounded px-2 py-1 text-sm w-full focus:outline-none focus:border-indigo-400">
                    <option value="">— Teacher (optional) —</option>\${teacherOpts}
                </select>
            </div>
            <div class="flex gap-1.5 flex-shrink-0">
                <span class="bg-indigo-100 text-indigo-700 text-xs font-bold px-2 py-0.5 rounded-full">\${students.length} students</span>
                <button onclick="toggleEditClass(\${cls.id})" id="editClassBtn_\${cls.id}" class="text-indigo-500 hover:text-indigo-700 text-xs border border-indigo-200 rounded px-1.5 py-0.5">✏️</button>
                <button onclick="saveClass(\${cls.id})" id="saveClassBtn_\${cls.id}" class="hidden bg-indigo-600 text-white text-xs rounded px-1.5 py-0.5 hover:bg-indigo-700">💾</button>
                <button onclick="deleteClass(\${cls.id})" class="text-red-400 hover:text-red-600 text-xs border border-red-200 rounded px-1.5 py-0.5">🗑️</button>
            </div>
        </div>
        \${students.length ? \`<div class="overflow-x-auto mb-2"><table class="w-full text-sm"><thead><tr class="text-gray-400 text-xs border-b"><th class="pb-1 text-left">Student</th><th class="pb-1 text-left">XP</th><th class="pb-1 text-left">Level</th><th></th></tr></thead><tbody>\${studentRows}</tbody></table></div>\` : '<p class="text-gray-400 text-xs mb-2">No students enrolled yet.</p>'}
        \${available.length ? \`<div class="flex gap-2 items-center"><select id="addStudentSel_\${cls.id}" class="flex-1 border rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:border-indigo-400"><option value="">+ Add student...</option>\${availableOpts}</select><button onclick="addStudentToClass(\${cls.id})" class="bg-indigo-600 text-white px-3 py-1.5 rounded-lg text-xs font-bold hover:bg-indigo-700">Add</button></div>\` : '<p class="text-gray-400 text-xs">All approved students enrolled.</p>'}
    </div>\`;
}

function toggleEditSchool(id) {
    var v = document.getElementById('school_view_'+id), e = document.getElementById('school_edit_'+id);
    var eb = document.getElementById('editSchoolBtn_'+id), sb = document.getElementById('saveSchoolBtn_'+id);
    v.classList.toggle('hidden'); e.classList.toggle('hidden');
    eb.classList.toggle('hidden'); sb.classList.toggle('hidden');
}

async function saveSchool(id) {
    var name = document.getElementById('editSchoolName_'+id).value.trim();
    var desc = document.getElementById('editSchoolDesc_'+id).value;
    if (!name) return alert('School name is required.');
    await fetch('/api/admin/schools/'+id, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name, description: desc}) });
    loadSchools();
}

async function deleteSchool(id) {
    if (!confirm('Delete this school and ALL its classes? This cannot be undone.')) return;
    await fetch('/api/admin/schools/'+id, { method:'DELETE' });
    loadSchools();
}

async function createClassUnderSchool(schoolId) {
    var name = document.getElementById('newClassName_'+schoolId).value.trim();
    if (!name) return alert('Class name is required.');
    var desc = document.getElementById('newClassDesc_'+schoolId).value;
    var teacher_id = document.getElementById('newClassTeacher_'+schoolId).value || null;
    var res = await fetch('/api/classes', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name, description: desc, teacher_id, school_id: schoolId}) });
    var data = await res.json();
    if (data.success) loadSchools();
    else alert('Error: ' + (data.error || 'Failed'));
}

function toggleEditClass(id) {
    var v = document.getElementById('class_view_'+id), e = document.getElementById('class_edit_'+id);
    var eb = document.getElementById('editClassBtn_'+id), sb = document.getElementById('saveClassBtn_'+id);
    v.classList.toggle('hidden'); e.classList.toggle('hidden');
    eb.classList.toggle('hidden'); sb.classList.toggle('hidden');
}

async function saveClass(id) {
    var name = document.getElementById('editClassName_'+id).value.trim();
    var desc = document.getElementById('editClassDesc_'+id).value;
    var teacher_id = document.getElementById('editClassTeacher_'+id).value || null;
    if (!name) return alert('Class name is required.');
    await fetch('/api/admin/classes/'+id, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name, description: desc, teacher_id}) });
    loadSchools();
}

async function deleteClass(id) {
    if (!confirm('Delete this class and remove all enrolled students?')) return;
    await fetch('/api/admin/classes/'+id, { method:'DELETE' });
    loadSchools();
}

async function removeStudentFromClass(classId, studentId) {
    await fetch('/api/classes/' + classId + '/students/' + studentId, { method: 'DELETE' });
    loadSchools();
}

async function addStudentToClass(classId) {
    var sel = document.getElementById('addStudentSel_' + classId);
    if (!sel.value) return;
    await fetch('/api/classes/' + classId + '/students', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ student_id: sel.value }) });
    loadSchools();
}

function showCreateSchool() { document.getElementById('createSchoolForm').classList.toggle('hidden'); }

async function createSchool() {
    var name = document.getElementById('newSchoolName').value.trim();
    var msg = document.getElementById('createSchoolMsg');
    if (!name) { msg.className='mt-2 text-sm text-red-600'; msg.classList.remove('hidden'); msg.textContent='School name is required.'; return; }
    var res = await fetch('/api/admin/schools', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name, description: document.getElementById('newSchoolDesc').value}) });
    var data = await res.json();
    if (data.success) {
        document.getElementById('newSchoolName').value = '';
        document.getElementById('newSchoolDesc').value = '';
        document.getElementById('createSchoolForm').classList.add('hidden');
        loadSchools();
    } else { msg.className='mt-2 text-sm text-red-600'; msg.classList.remove('hidden'); msg.textContent='❌ '+(data.error||'Failed'); }
}

async function loadLinkDropdowns() {
    const users = allUsers.length ? allUsers : await fetch('/api/admin/users').then(r=>r.json());
    const parents = users.filter(u=>u.role==='parent');
    const students = users.filter(u=>u.role==='student');
    document.getElementById('linkParent').innerHTML = parents.map(u=>\`<option value="\${u.id}">\${u.full_name}</option>\`).join('');
    document.getElementById('linkStudent').innerHTML = students.map(u=>\`<option value="\${u.id}">\${u.full_name}</option>\`).join('');
}

function showCreateUser() { document.getElementById('createUserForm').classList.toggle('hidden'); }

async function createUser() {
    const msg = document.getElementById('createUserMsg');
    const res = await fetch('/api/admin/users', { method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ full_name: document.getElementById('newFullName').value, username: document.getElementById('newUsername').value, password: document.getElementById('newPassword').value, role: document.getElementById('newRole').value })
    });
    const data = await res.json();
    msg.classList.remove('hidden');
    if (data.success) { msg.className = 'mt-2 text-sm text-green-600'; msg.textContent = '✅ User created!'; loadUsers(); loadLinkDropdowns(); }
    else { msg.className = 'mt-2 text-sm text-red-600'; msg.textContent = '❌ ' + data.error; }
}


async function deleteUser(id, username) {
    if (!confirm('Delete user @' + username + '?')) return;
    await fetch('/api/admin/users/' + id, { method: 'DELETE' });
    loadUsers();
}

async function linkParent() {
    const msg = document.getElementById('linkMsg');
    const res = await fetch('/api/parent/link', { method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ parent_id: document.getElementById('linkParent').value, student_id: document.getElementById('linkStudent').value })
    });
    const data = await res.json();
    msg.classList.remove('hidden');
    if (data.success) { msg.className = 'mt-2 text-sm text-green-600'; msg.textContent = '✅ Linked!'; }
    else { msg.className = 'mt-2 text-sm text-red-600'; msg.textContent = '❌ ' + data.error; }
}

async function logout() {
    await fetch('/api/auth/logout', { method:'POST' });
    window.location.href = '/login';
}

init();
</script>
<footer class="max-w-7xl mx-auto px-6 py-6 mt-4 border-t border-gray-100 text-center">
    <p class="text-gray-400 text-sm">© 2026 STEMO · Science Games</p>
    <p class="text-gray-300 text-xs mt-1">أكاديمية ستيم لألعاب العلوم</p>
</footer>
</body>
</html>`

// ============================================
// TEACHER DASHBOARD PAGE
// ============================================
const teacherDashboard = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>📚 STEMO Teacher Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Fredoka+One&family=Nunito:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>* { font-family: 'Nunito', sans-serif; } h1,h2,h3{font-family:'Fredoka One',cursive;}
    .diff-easy{background:#dcfce7;color:#166534}.diff-medium{background:#fef9c3;color:#854d0e}.diff-hard{background:#fee2e2;color:#991b1b}.diff-extreme{background:#f3e8ff;color:#6b21a8}
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
<nav class="bg-gradient-to-r from-purple-800 to-violet-900 text-white px-6 py-4 shadow-lg">
    <div class="max-w-7xl mx-auto flex items-center justify-between">
        <div class="flex items-center gap-3">
            <img src="/static/steam-logo-white.png" alt="STEMO Coding" class="h-9 object-contain">
            <div><h1 class="text-2xl">STEMO Coding — Teacher</h1></div>
        </div>
        <div class="flex items-center gap-4">
            <span class="text-purple-200 text-sm" id="welcomeMsg"></span>
            <a href="/academy" target="_blank" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-full text-sm font-bold">🤖 Open Academy</a>
            <button onclick="logout()" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-full text-sm font-bold">🚪 Logout</button>
        </div>
    </div>
</nav>
<div class="max-w-7xl mx-auto p-6">
    <!-- Stats -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div class="bg-white rounded-2xl p-5 shadow text-center"><div class="text-3xl mb-1">🏫</div><div class="text-3xl font-bold text-blue-600" id="statClasses">-</div><div class="text-gray-500 text-sm">My Classes</div></div>
        <div class="bg-white rounded-2xl p-5 shadow text-center"><div class="text-3xl mb-1">🎓</div><div class="text-3xl font-bold text-green-600" id="statStudents">-</div><div class="text-gray-500 text-sm">Total Students</div></div>
        <div class="bg-white rounded-2xl p-5 shadow text-center"><div class="text-3xl mb-1">⭐</div><div class="text-3xl font-bold text-yellow-500" id="statAvgXP">-</div><div class="text-gray-500 text-sm">Avg XP</div></div>
        <div class="bg-white rounded-2xl p-5 shadow text-center cursor-pointer" onclick="showTab('pending')"><div class="text-3xl mb-1">⏳</div><div class="text-3xl font-bold text-orange-500" id="statPending">-</div><div class="text-gray-500 text-sm">Pending</div></div>
    </div>
    <!-- Tabs -->
    <div class="flex gap-2 mb-6 flex-wrap">
        <button onclick="showTab('classes')" id="tab-classes" class="tab-btn bg-blue-600 text-white px-5 py-2 rounded-full font-bold text-sm">🏫 My Classes</button>
        <button onclick="showTab('curriculum')" id="tab-curriculum" class="tab-btn bg-gray-200 text-gray-600 px-5 py-2 rounded-full font-bold text-sm">📖 Curriculum</button>
        <button onclick="showTab('pending')" id="tab-pending" class="tab-btn bg-gray-200 text-gray-600 px-5 py-2 rounded-full font-bold text-sm">⏳ Pending <span id="pendingBadge" class="bg-orange-500 text-white rounded-full px-2 ml-1 text-xs hidden">0</span></button>
        <button onclick="showTab('leaderboard')" id="tab-leaderboard" class="tab-btn bg-gray-200 text-gray-600 px-5 py-2 rounded-full font-bold text-sm">🏆 Leaderboard</button>
    </div>
    <!-- My Classes Tab -->
    <div id="section-classes">
        <div id="classesContainer" class="space-y-6"></div>
    </div>
    <!-- Curriculum Tab -->
    <div id="section-curriculum" class="hidden">
        <div class="bg-white rounded-2xl shadow p-6">
            <div class="flex items-center justify-between mb-5">
                <h2 class="text-xl">📖 Lesson Curriculum</h2>
                <p class="text-gray-400 text-sm">Assign lessons to your classes or open them in the academy to demonstrate</p>
            </div>
            <div id="curriculumList" class="space-y-8"></div>
        </div>
    </div>
    <!-- Pending Tab -->
    <div id="section-pending" class="hidden">
        <div class="bg-white rounded-2xl shadow p-6">
            <h2 class="text-xl text-orange-600 mb-4">⏳ Pending Student Registrations</h2>
            <div id="pendingList"><p class="text-gray-400 text-center py-8">Loading...</p></div>
        </div>
    </div>
    <!-- Leaderboard Tab -->
    <div id="section-leaderboard" class="hidden">
        <div class="bg-white rounded-2xl shadow p-6">
            <div class="flex items-center justify-between mb-6">
                <h2 class="text-xl font-bold">🏆 Student Leaderboard</h2>
                <button onclick="loadTeacherLeaderboard()" class="bg-indigo-100 hover:bg-indigo-200 text-indigo-700 px-4 py-2 rounded-xl text-sm font-bold transition-all">🔄 Refresh</button>
            </div>
            <div id="teacherPodiumRow" class="flex justify-center gap-6 mb-8"></div>
            <div id="teacherLeaderboardList" class="space-y-2"><p class="text-gray-400 text-center py-8">Loading...</p></div>
        </div>
    </div>
</div>

<!-- Reset Password Modal -->
<div id="pwModal" class="fixed inset-0 bg-black/50 hidden items-center justify-center z-50" onclick="closePwModal(event)">
    <div class="bg-white rounded-2xl p-6 w-full max-w-sm shadow-2xl" onclick="event.stopPropagation()">
        <h3 class="text-lg font-bold mb-1">🔑 Reset Password</h3>
        <p class="text-gray-500 text-sm mb-4" id="pwModalName"></p>
        <input id="pwModalInput" type="password" placeholder="New password (min 6 chars)"
            class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-gray-800 focus:outline-none focus:border-blue-400 mb-2">
        <div id="pwModalMsg" class="text-sm mb-3 hidden"></div>
        <div class="flex gap-2">
            <button onclick="confirmResetPw()" class="flex-1 bg-blue-600 text-white py-2 rounded-xl font-bold hover:bg-blue-700">Set Password</button>
            <button onclick="document.getElementById('pwModal').classList.add('hidden')" class="flex-1 bg-gray-200 py-2 rounded-xl font-bold">Cancel</button>
        </div>
    </div>
</div>

<script>
const CURRICULUM = [
    {id:'lesson-1',title:'Meet STEMO!',icon:'👋',desc:'Discover coding blocks and understand the concept',diff:'easy',xp:50,group:'🟢 Basic'},
    {id:'lesson-2',title:'Movement Master',icon:'🚶',desc:'Learn all movement: Forward, Back, Left, Right',diff:'easy',xp:100,group:'🟢 Basic'},
    {id:'lesson-3',title:'Start Drawing!',icon:'🖌️',desc:'Use Pen to draw lines',diff:'easy',xp:100,group:'🟢 Basic'},
    {id:'lesson-4',title:'Color Artist',icon:'🎨',desc:'Change colors and pen size',diff:'easy',xp:100,group:'🟢 Basic'},
    {id:'lesson-5',title:'Loop Power!',icon:'🔁',desc:'Use Repeat to do actions multiple times',diff:'medium',xp:150,group:'🟡 Intermediate'},
    {id:'lesson-6',title:'Shape Artist',icon:'📐',desc:'Create triangles, hexagons and more!',diff:'medium',xp:200,group:'🟡 Intermediate'},
    {id:'lesson-7',title:'Star Power!',icon:'✨',desc:'Draw a beautiful 8-pointed star',diff:'hard',xp:300,group:'🟡 Intermediate'},
    {id:'lesson-8',title:'Magnet Magic',icon:'🧲',desc:'Pick up metal objects with your magnet',diff:'medium',xp:200,group:'🟡 Intermediate'},
    {id:'lesson-9',title:'Ultrasonic Sight',icon:'📡',desc:'See walls using sound waves',diff:'medium',xp:250,group:'🟡 Intermediate'},
    {id:'lesson-10',title:'Space Navigator',icon:'🎯',desc:'Reach targets automatically',diff:'hard',xp:300,group:'🔴 Advanced'},
    {id:'lesson-11',title:'Smart Explorer',icon:'🧠',desc:'Make decisions with If/Else logic',diff:'hard',xp:350,group:'🔴 Advanced'},
    {id:'lesson-12',title:'Fire Watch',icon:'🔥',desc:'Detect heat with temperature sensors',diff:'hard',xp:400,group:'🔴 Advanced'},
    {id:'lesson-13',title:'Firefighter Hero',icon:'🚒',desc:'Extinguish fires with water',diff:'extreme',xp:500,group:'🔴 Advanced'},
    {id:'lesson-14',title:'Master Coder',icon:'🏆',desc:'The final autonomous challenge',diff:'extreme',xp:1000,group:'🔴 Advanced'},
    {id:'lesson-15',title:'Variable Vault',icon:'🔢',desc:'Control STEMO with named variables',diff:'hard',xp:400,group:'🟣 Expert'},
    {id:'lesson-16',title:'Position Memory',icon:'📍',desc:'Save & return to GPS coordinates',diff:'hard',xp:450,group:'🟣 Expert'},
    {id:'lesson-17',title:'Waypoint Trail',icon:'🗺️',desc:'Replay a list of locations automatically',diff:'extreme',xp:500,group:'🟣 Expert'},
    {id:'lesson-18',title:'List Hunt',icon:'🎯',desc:'Iterate a list and act at each item',diff:'extreme',xp:600,group:'🟣 Expert'},
    {id:'lesson-19',title:'Function Factory',icon:'🔧',desc:'Write functions, call them to draw a star pattern',diff:'extreme',xp:700,group:'🟣 Expert'}
];

let allClasses = [];
let pwResetStudentId = null;

function showTab(tab) {
    ['classes','curriculum','pending','leaderboard'].forEach(t => {
        document.getElementById('section-'+t).classList.add('hidden');
        const btn = document.getElementById('tab-'+t);
        if(btn) btn.className = 'tab-btn bg-gray-200 text-gray-600 px-5 py-2 rounded-full font-bold text-sm';
    });
    document.getElementById('section-'+tab).classList.remove('hidden');
    const active = {classes:'bg-blue-600',curriculum:'bg-indigo-600',pending:'bg-orange-500',leaderboard:'bg-yellow-500'};
    document.getElementById('tab-'+tab).className = \`tab-btn \${active[tab]||'bg-indigo-600'} text-white px-5 py-2 rounded-full font-bold text-sm\`;
    if (tab === 'leaderboard') loadTeacherLeaderboard();
}

async function loadTeacherLeaderboard() {
    document.getElementById('teacherLeaderboardList').innerHTML = '<p class="text-gray-400 text-center py-8">Loading...</p>';
    document.getElementById('teacherPodiumRow').innerHTML = '';
    try {
        const data = await fetch('/api/leaderboard').then(r=>r.json());
        if (!Array.isArray(data) || !data.length) {
            document.getElementById('teacherLeaderboardList').innerHTML = '<p class="text-gray-400 text-center py-8">No student data yet.</p>';
            return;
        }
        const medals = ['🥇','🥈','🥉'];
        const podiumColors = ['from-yellow-400 to-amber-500','from-gray-300 to-gray-400','from-orange-400 to-amber-600'];
        const podiumHeights = ['h-28','h-20','h-16'];
        const podiumOrder = [1,0,2];
        let podiumHtml = '';
        podiumOrder.forEach(idx => {
            const s = data[idx];
            if (!s) return;
            let lessons = 0;
            try { lessons = JSON.parse(s.completed_lessons||'[]').length; } catch(e) {}
            podiumHtml += \`<div class="flex flex-col items-center gap-2 \${idx===0?'order-2':idx===1?'order-1':'order-3'}">
                <div class="text-3xl">\${medals[idx]}</div>
                <div class="w-14 h-14 rounded-full bg-gradient-to-br \${podiumColors[idx]} flex items-center justify-center text-2xl font-bold text-white border-4 border-white">\${(s.full_name||'S')[0].toUpperCase()}</div>
                <div class="text-center">
                    <div class="font-bold text-sm text-gray-800 max-w-[80px] truncate">\${s.full_name||s.username}</div>
                    <div class="text-yellow-500 font-bold text-sm">⭐ \${s.xp||0}</div>
                    <div class="text-gray-400 text-xs">@\${s.username}</div>
                </div>
                <div class="bg-gradient-to-t \${podiumColors[idx]} rounded-t-xl w-20 \${podiumHeights[idx]}"></div>
            </div>\`;
        });
        document.getElementById('teacherPodiumRow').innerHTML = podiumHtml;
        const rows = data.map((s, i) => {
            let lessons = 0;
            try { lessons = JSON.parse(s.completed_lessons||'[]').length; } catch(e) {}
            const badgeCount = (() => { try { return JSON.parse(s.earned_badges||'[]').length; } catch(e) { return 0; } })();
            return \`<div class="flex items-center gap-4 p-4 rounded-xl border border-gray-100 hover:bg-gray-50 transition-all">
                <div class="text-lg font-bold w-10 text-center \${i<3?'text-yellow-500':'text-gray-400'}">\${i<3?medals[i]:'#'+(i+1)}</div>
                <div class="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-400 to-purple-500 flex items-center justify-center text-lg font-bold text-white">\${(s.full_name||'S')[0].toUpperCase()}</div>
                <div class="flex-1 min-w-0">
                    <div class="font-bold text-gray-800 truncate">\${s.full_name||s.username}</div>
                    <div class="text-gray-400 text-xs">@\${s.username} · Level \${s.level||1}</div>
                </div>
                <div class="text-right shrink-0 text-sm">
                    <div class="font-bold text-yellow-500">⭐ \${s.xp||0} XP</div>
                    <div class="text-gray-400 text-xs">\${lessons}/14 lessons · \${s.streak||0}🔥 · \${badgeCount} badges</div>
                </div>
            </div>\`;
        }).join('');
        document.getElementById('teacherLeaderboardList').innerHTML = \`<div class="space-y-2">\${rows}</div>\`;
    } catch(e) {
        document.getElementById('teacherLeaderboardList').innerHTML = '<p class="text-gray-400 text-center py-8">Unable to load leaderboard.</p>';
    }
}

async function init() {
    const me = await fetch('/api/auth/me').then(r=>r.json());
    if (!me.user || me.user.role !== 'teacher') { window.location.href='/login'; return; }
    document.getElementById('welcomeMsg').textContent = 'Welcome, ' + me.user.full_name;
    await loadClasses();
    loadPending();
    renderCurriculum();
}

async function loadPending() {
    const pending = await fetch('/api/admin/pending').then(r=>r.json());
    document.getElementById('statPending').textContent = pending.length;
    const badge = document.getElementById('pendingBadge');
    if (pending.length > 0) { badge.textContent = pending.length; badge.classList.remove('hidden'); }
    else badge.classList.add('hidden');
    const list = document.getElementById('pendingList');
    if (!pending.length) { list.innerHTML = '<p class="text-gray-400 text-center py-8">✅ No pending registrations right now!</p>'; return; }
    const classOpts = allClasses.map(c=>\`<option value="\${c.id}">\${c.name}</option>\`).join('');
    list.innerHTML = \`<div class="space-y-3">\${pending.map(u => \`
        <div class="p-4 bg-orange-50 border border-orange-200 rounded-xl">
            <div class="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <div class="font-bold text-gray-800">\${u.full_name}</div>
                    <div class="text-gray-500 text-sm">@\${u.username} • registered \${u.created_at?.slice(0,10)||'today'}</div>
                </div>
                <div class="flex gap-2 flex-wrap items-center">
                    \${allClasses.length ? \`<select id="approveClass_\${u.id}" class="border rounded-lg px-2 py-1.5 text-xs bg-white focus:outline-none focus:border-green-400"><option value="">No class yet</option>\${classOpts}</select>\` : ''}
                    <button onclick="approveAndEnroll(\${u.id})" class="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded-lg text-sm font-bold">✅ Approve</button>
                    <button onclick="approveUser(\${u.id},'reject')" class="bg-red-400 hover:bg-red-500 text-white px-4 py-2 rounded-lg text-sm font-bold">❌ Reject</button>
                </div>
            </div>
        </div>\`).join('')}</div>\`;
}

async function loadClasses() {
    allClasses = await fetch('/api/classes').then(r=>r.json());
    document.getElementById('statClasses').textContent = allClasses.length;
    let totalStudents = 0, totalXP = 0, xpCount = 0;
    const container = document.getElementById('classesContainer');
    container.innerHTML = '';
    if (!allClasses.length) {
        container.innerHTML = '<div class="bg-white rounded-2xl shadow p-12 text-center"><div class="text-5xl mb-3">🏫</div><p class="text-gray-400">You have no classes assigned yet. Ask your admin to assign you to a class.</p></div>';
        document.getElementById('statStudents').textContent = 0;
        document.getElementById('statAvgXP').textContent = 0;
        return;
    }
    for (const cls of allClasses) {
        const [students, available, assignedLesson] = await Promise.all([
            fetch('/api/classes/' + cls.id + '/students').then(r=>r.json()),
            fetch('/api/classes/' + cls.id + '/available-students').then(r=>r.json()),
            fetch('/api/classes/' + cls.id + '/assigned-lesson').then(r=>r.json())
        ]);
        totalStudents += students.length;
        students.forEach(s => { if(s.xp){ totalXP += s.xp; xpCount++; } });
        const lessonInfo = assignedLesson ? CURRICULUM.find(l=>l.id===assignedLesson.lesson_id) : null;
        const lessonBadge = lessonInfo
            ? \`<span class="bg-indigo-100 text-indigo-700 text-xs font-bold px-3 py-1 rounded-full">📖 Current: \${lessonInfo.icon} \${lessonInfo.title}</span>\`
            : \`<span class="bg-gray-100 text-gray-500 text-xs px-3 py-1 rounded-full">No lesson assigned</span>\`;
        const lessonOpts = CURRICULUM.map(l=>\`<option value="\${l.id}" \${assignedLesson?.lesson_id===l.id?'selected':''}>\${l.icon} \${l.title} (\${l.group?.replace(/.*? /,'')})\`).join('');
        const studentRows = students.map(s => {
            const done = JSON.parse(s.completed_lessons || '[]').length;
            return \`<tr class="border-b hover:bg-blue-50" id="row_\${s.id}">
                <td class="py-2.5">
                    <div class="font-semibold text-sm">\${s.full_name}</div>
                    <div class="text-gray-400 text-xs">@\${s.username}</div>
                    <div id="pwForm_\${s.id}" class="hidden mt-2 flex gap-2 items-center">
                        <input type="password" id="pwInput_\${s.id}" placeholder="New password" class="border rounded-lg px-2 py-1 text-xs w-32 focus:outline-none focus:border-blue-400">
                        <button onclick="submitResetPw(\${s.id})" class="bg-blue-600 text-white text-xs px-2 py-1 rounded-lg font-bold">Set</button>
                        <button onclick="document.getElementById('pwForm_\${s.id}').classList.add('hidden')" class="bg-gray-200 text-xs px-2 py-1 rounded-lg">✕</button>
                        <span id="pwMsg_\${s.id}" class="text-xs hidden"></span>
                    </div>
                </td>
                <td class="py-2.5"><span class="bg-indigo-100 text-indigo-700 text-xs px-2 py-0.5 rounded-full font-bold">Lv \${s.level||1}</span></td>
                <td class="py-2.5 font-bold text-yellow-500 text-sm">⭐ \${s.xp||0}</td>
                <td class="py-2.5 text-sm">\${done}/14</td>
                <td class="py-2.5 text-sm">\${s.streak||0} 🔥</td>
                <td class="py-2.5">
                    <div class="flex gap-1.5">
                        <button onclick="togglePwForm(\${s.id})" class="bg-blue-100 text-blue-700 hover:bg-blue-200 text-xs px-2 py-1 rounded-lg font-bold" title="Reset password">🔑</button>
                        <button onclick="removeStudent(\${cls.id},\${s.id})" class="bg-red-100 text-red-600 hover:bg-red-200 text-xs px-2 py-1 rounded-lg font-bold" title="Remove from class">✕</button>
                    </div>
                </td>
            </tr>\`;
        }).join('');
        const availableOpts = available.map(s=>\`<option value="\${s.id}">\${s.full_name} (@\${s.username})</option>\`).join('');
        const div = document.createElement('div');
        div.className = 'bg-white rounded-2xl shadow p-6';
        div.innerHTML = \`
            <div class="flex flex-wrap items-start justify-between gap-3 mb-4">
                <div>
                    <h2 class="text-xl text-blue-700">🏫 \${cls.name}</h2>
                    <p class="text-gray-400 text-sm mt-0.5">\${cls.description||''}</p>
                </div>
                <div class="flex flex-wrap items-center gap-2">
                    \${lessonBadge}
                    <span class="bg-blue-100 text-blue-700 text-xs font-bold px-3 py-1 rounded-full">\${students.length} students</span>
                </div>
            </div>
            <div class="flex flex-wrap gap-3 mb-5 p-3 bg-indigo-50 rounded-xl items-center">
                <span class="text-sm font-bold text-indigo-700">📖 Assign Lesson:</span>
                <select id="lessonSel_\${cls.id}" class="flex-1 border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:border-indigo-400 bg-white">
                    <option value="">— No lesson assigned —</option>
                    \${lessonOpts}
                </select>
                <button onclick="assignLesson(\${cls.id})" class="bg-indigo-600 text-white px-4 py-1.5 rounded-lg text-sm font-bold hover:bg-indigo-700">Assign</button>
                <span id="assignMsg_\${cls.id}" class="text-xs hidden"></span>
            </div>
            \${students.length ? \`<div class="overflow-x-auto mb-4"><table class="w-full text-sm"><thead><tr class="border-b text-gray-500 text-left text-xs"><th class="pb-2">Student</th><th class="pb-2">Level</th><th class="pb-2">XP</th><th class="pb-2">Lessons</th><th class="pb-2">Streak</th><th class="pb-2">Actions</th></tr></thead><tbody>\${studentRows}</tbody></table></div>\` : '<p class="text-gray-400 text-center py-6 mb-2">No students in this class yet.</p>'}
            \${available.length ? \`<div class="flex gap-2 items-center border-t pt-4"><select id="tAddSel_\${cls.id}" class="flex-1 border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-400"><option value="">+ Enrol an approved student...</option>\${availableOpts}</select><button onclick="teacherAddStudent(\${cls.id})" class="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-bold hover:bg-blue-700">Add</button></div>\` : '<p class="text-gray-400 text-xs border-t pt-3 mt-2">All approved students are already enrolled.</p>'}
        \`;
        container.appendChild(div);
    }
    document.getElementById('statStudents').textContent = totalStudents;
    document.getElementById('statAvgXP').textContent = xpCount ? Math.round(totalXP/xpCount) : 0;

    // Show unenrolled-students banner below class cards
    const unenrolled = await fetch('/api/students/unenrolled').then(r=>r.json());
    if (unenrolled.length) {
        const classOpts = allClasses.map(c=>\`<option value="\${c.id}">\${c.name}</option>\`).join('');
        const banner = document.createElement('div');
        banner.className = 'bg-amber-50 border-2 border-amber-300 rounded-2xl p-5 mt-4';
        banner.innerHTML = \`
            <div class="flex items-center gap-2 mb-3">
                <span class="text-xl">⚠️</span>
                <h3 class="font-bold text-amber-800">\${unenrolled.length} approved student\${unenrolled.length>1?'s are':' is'} not in any class</h3>
            </div>
            <div class="space-y-2">
                \${unenrolled.map(s=>\`
                <div class="flex items-center justify-between bg-white rounded-xl px-4 py-2.5 border border-amber-200 gap-3 flex-wrap">
                    <div>
                        <span class="font-semibold text-gray-800">\${s.full_name}</span>
                        <span class="text-gray-400 text-xs ml-2">@\${s.username}</span>
                    </div>
                    \${allClasses.length ? \`<div class="flex gap-2 items-center">
                        <select id="qaSel_\${s.id}" class="border rounded-lg px-2 py-1.5 text-xs bg-white focus:outline-none focus:border-blue-400">
                            <option value="">Pick a class...</option>
                            \${classOpts}
                        </select>
                        <button onclick="quickEnroll(\${s.id})" class="bg-blue-600 text-white text-xs px-3 py-1.5 rounded-lg font-bold hover:bg-blue-700">➕ Enrol</button>
                    </div>\` : ''}
                </div>\`).join('')}
            </div>
        \`;
        container.appendChild(banner);
    }
}

function renderCurriculum() {
    const groups = {};
    CURRICULUM.forEach(l => { if(!groups[l.group]) groups[l.group]=[]; groups[l.group].push(l); });
    document.getElementById('curriculumList').innerHTML = Object.entries(groups).map(([g,lessons]) => \`
        <div>
            <h3 class="text-lg text-gray-700 mb-3">\${g}</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                \${lessons.map(l => \`
                <div class="border rounded-xl p-4 hover:border-indigo-300 hover:bg-indigo-50 transition-all">
                    <div class="flex items-start justify-between gap-2 mb-2">
                        <div class="flex items-center gap-2">
                            <span class="text-2xl">\${l.icon}</span>
                            <div>
                                <div class="font-bold text-gray-800 text-sm">\${l.title}</div>
                                <div class="text-gray-400 text-xs">\${l.desc}</div>
                            </div>
                        </div>
                        <div class="flex flex-col items-end gap-1 shrink-0">
                            <span class="diff-\${l.diff} text-xs font-bold px-2 py-0.5 rounded-full">\${l.diff}</span>
                            <span class="text-yellow-500 text-xs font-bold">+\${l.xp} XP</span>
                        </div>
                    </div>
                    <div class="flex flex-wrap gap-2 mt-3">
                        \${allClasses.length ? allClasses.map(c=>\`<button onclick="quickAssign('\${l.id}',\${c.id},'\${l.title}')" class="bg-indigo-600 text-white text-xs px-3 py-1.5 rounded-lg font-bold hover:bg-indigo-700">📌 Assign to \${c.name}</button>\`).join('') : '<span class="text-gray-400 text-xs">No classes yet</span>'}
                        <a href="/academy" target="_blank" class="bg-gray-100 text-gray-700 hover:bg-gray-200 text-xs px-3 py-1.5 rounded-lg font-bold">🤖 Open Academy</a>
                    </div>
                </div>\`).join('')}
            </div>
        </div>
    \`).join('');
}

async function assignLesson(classId) {
    const sel = document.getElementById('lessonSel_' + classId);
    const msg = document.getElementById('assignMsg_' + classId);
    const res = await fetch('/api/classes/' + classId + '/assign-lesson', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ lesson_id: sel.value || null })
    });
    const data = await res.json();
    msg.classList.remove('hidden');
    if (data.success) { msg.className='text-xs text-green-600'; msg.textContent='✅ Assigned!'; setTimeout(()=>{msg.classList.add('hidden');loadClasses();},1500); }
    else { msg.className='text-xs text-red-600'; msg.textContent='❌ '+data.error; }
}

async function quickAssign(lessonId, classId, lessonTitle) {
    const res = await fetch('/api/classes/' + classId + '/assign-lesson', {
        method: 'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ lesson_id: lessonId })
    });
    const data = await res.json();
    if (data.success) { alert('✅ "' + lessonTitle + '" assigned to class!'); loadClasses(); }
}

async function teacherAddStudent(classId) {
    const sel = document.getElementById('tAddSel_' + classId);
    if (!sel || !sel.value) return;
    await fetch('/api/classes/' + classId + '/students', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ student_id: sel.value }) });
    loadClasses();
}

async function removeStudent(classId, studentId) {
    if (!confirm('Remove this student from the class?')) return;
    await fetch('/api/classes/' + classId + '/students/' + studentId, { method: 'DELETE' });
    loadClasses();
}

function togglePwForm(studentId) {
    const form = document.getElementById('pwForm_' + studentId);
    form.classList.toggle('hidden');
    if (!form.classList.contains('hidden')) document.getElementById('pwInput_' + studentId).focus();
}

async function submitResetPw(studentId) {
    const pw = document.getElementById('pwInput_' + studentId).value;
    const msg = document.getElementById('pwMsg_' + studentId);
    if (!pw || pw.length < 6) { msg.className='text-xs text-red-600'; msg.classList.remove('hidden'); msg.textContent='Min 6 chars'; return; }
    const res = await fetch('/api/teacher/students/' + studentId + '/reset-password', {
        method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ password: pw })
    });
    const data = await res.json();
    msg.classList.remove('hidden');
    if (data.success) { msg.className='text-xs text-green-600'; msg.textContent='✅ Done!'; setTimeout(()=>{ document.getElementById('pwForm_'+studentId).classList.add('hidden'); msg.classList.add('hidden'); },1500); }
    else { msg.className='text-xs text-red-600'; msg.textContent='❌ '+data.error; }
}

async function approveUser(id, action) {
    await fetch('/api/admin/users/' + id + '/approve', {
        method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ action })
    });
    await loadClasses();
    loadPending();
}

async function approveAndEnroll(id) {
    const sel = document.getElementById('approveClass_' + id);
    const classId = sel ? sel.value : '';
    await fetch('/api/admin/users/' + id + '/approve', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ action: 'approve', class_id: classId || null })
    });
    await loadClasses();
    loadPending();
}

async function quickEnroll(studentId) {
    const sel = document.getElementById('qaSel_' + studentId);
    if (!sel || !sel.value) { alert('Please select a class first.'); return; }
    await fetch('/api/classes/' + sel.value + '/students', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ student_id: studentId })
    });
    loadClasses();
}

function closePwModal(e) { document.getElementById('pwModal').classList.add('hidden'); }

async function logout() {
    await fetch('/api/auth/logout', { method:'POST' });
    window.location.href = '/login';
}
init();
</script>
<footer class="max-w-7xl mx-auto px-6 py-6 mt-4 border-t border-gray-100 text-center">
    <p class="text-gray-400 text-sm">© 2026 STEMO · Science Games</p>
    <p class="text-gray-300 text-xs mt-1">أكاديمية ستيم لألعاب العلوم</p>
</footer>
</body>
</html>`

// ============================================
// PARENT DASHBOARD PAGE
// ============================================
const parentDashboard = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>👨‍👩‍👧 STEMO Parent View</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Fredoka+One&family=Nunito:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>* { font-family: 'Nunito', sans-serif; } h1,h2,h3{font-family:'Fredoka One',cursive;}</style>
</head>
<body class="bg-gray-50 min-h-screen">
<nav class="bg-gradient-to-r from-purple-800 to-violet-900 text-white px-6 py-4 shadow-lg">
    <div class="max-w-4xl mx-auto flex items-center justify-between">
        <div class="flex items-center gap-3">
            <img src="/static/steam-logo-white.png" alt="STEMO Coding" class="h-9 object-contain">
            <div><h1 class="text-2xl">STEMO Coding — Parent</h1></div>
        </div>
        <div class="flex items-center gap-4">
            <span class="text-purple-200 text-sm" id="welcomeMsg"></span>
            <button onclick="logout()" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-full text-sm font-bold">🚪 Logout</button>
        </div>
    </div>
</nav>
<div class="max-w-4xl mx-auto p-6">
    <div id="childrenContainer" class="space-y-6"></div>
</div>
<script>
const allLessons = 14;
async function init() {
    const me = await fetch('/api/auth/me').then(r=>r.json());
    if (!me.user || me.user.role !== 'parent') { window.location.href='/login'; return; }
    document.getElementById('welcomeMsg').textContent = 'Welcome, ' + me.user.full_name;
    const children = await fetch('/api/parent/children').then(r=>r.json());
    const container = document.getElementById('childrenContainer');
    if (!children.length) {
        container.innerHTML = '<div class="bg-white rounded-2xl shadow p-12 text-center"><div class="text-6xl mb-4">👧</div><h2 class="text-xl text-gray-500">No children linked yet</h2><p class="text-gray-400 mt-2">Contact your school admin to link your account to your child.</p></div>';
        return;
    }
    container.innerHTML = children.map(child => {
        const lessons = JSON.parse(child.completed_lessons || '[]');
        const badges = JSON.parse(child.earned_badges || '[]');
        const pct = Math.round((lessons.length / allLessons) * 100);
        const level = child.level || 1;
        const xpForNext = level * 500;
        const xpProgress = Math.min(100, Math.round(((child.xp || 0) % 500) / 5));
        return \`<div class="bg-white rounded-2xl shadow p-6">
            <div class="flex items-center gap-4 mb-6">
                <div class="w-16 h-16 bg-gradient-to-br from-green-400 to-teal-500 rounded-full flex items-center justify-center text-3xl">🎓</div>
                <div>
                    <h2 class="text-2xl text-gray-800">\${child.full_name}</h2>
                    <p class="text-gray-400 text-sm">@\${child.username} • Level \${level} Coder</p>
                </div>
                <div class="ml-auto text-right">
                    <div class="text-3xl font-bold text-yellow-500">⭐ \${child.xp || 0}</div>
                    <div class="text-gray-400 text-xs">Total XP</div>
                </div>
            </div>
            <div class="grid grid-cols-3 gap-4 mb-6">
                <div class="bg-indigo-50 rounded-xl p-4 text-center">
                    <div class="text-2xl font-bold text-indigo-600">Lv \${level}</div>
                    <div class="text-gray-500 text-xs">Current Level</div>
                    <div class="w-full bg-indigo-100 rounded-full h-2 mt-2"><div class="bg-indigo-500 h-2 rounded-full" style="width:\${xpProgress}%"></div></div>
                </div>
                <div class="bg-green-50 rounded-xl p-4 text-center">
                    <div class="text-2xl font-bold text-green-600">\${lessons.length}/\${allLessons}</div>
                    <div class="text-gray-500 text-xs">Lessons Done</div>
                    <div class="w-full bg-green-100 rounded-full h-2 mt-2"><div class="bg-green-500 h-2 rounded-full" style="width:\${pct}%"></div></div>
                </div>
                <div class="bg-orange-50 rounded-xl p-4 text-center">
                    <div class="text-2xl font-bold text-orange-500">\${child.streak || 0} 🔥</div>
                    <div class="text-gray-500 text-xs">Day Streak</div>
                </div>
            </div>
            \${badges.length ? \`<div><h3 class="font-bold text-gray-700 mb-2">🏆 Badges Earned</h3><div class="flex gap-2 flex-wrap">\${badges.map(b=>\`<span class="bg-yellow-100 text-yellow-700 px-3 py-1 rounded-full text-sm font-bold">\${b}</span>\`).join('')}</div></div>\` : ''}
        </div>\`;
    }).join('');
}
async function logout() {
    await fetch('/api/auth/logout', { method:'POST' });
    window.location.href = '/login';
}
init();
</script>
<footer class="max-w-4xl mx-auto px-6 py-6 mt-4 border-t border-gray-100 text-center">
    <p class="text-gray-400 text-sm">© 2026 STEMO · Science Games</p>
    <p class="text-gray-300 text-xs mt-1">أكاديمية ستيم لألعاب العلوم</p>
</footer>
</body>
</html>`

// ============================================
// REGISTER PAGE
// ============================================
const registerPage = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>✍️ STEMO - Sign Up</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Fredoka+One&family=Nunito:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        * { font-family: 'Nunito', sans-serif; }
        h1, h2 { font-family: 'Fredoka One', cursive; }
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .card { background: rgba(255,255,255,0.97); }
    </style>
</head>
<body class="gradient-bg min-h-screen flex flex-col items-center justify-center p-4">
    <div class="w-full max-w-md">
        <div class="text-center mb-8">
            <img src="/static/steam-logo-white.png" alt="STEAM Academy" class="h-16 mx-auto mb-4 object-contain drop-shadow-lg">
            <h1 class="text-4xl text-white mb-1">Join STEMO!</h1>
        </div>
        <div class="card rounded-3xl p-8 shadow-2xl">
            <!-- Success state -->
            <div id="successState" class="hidden text-center py-4">
                <div class="text-7xl mb-4">🎉</div>
                <h2 class="text-2xl text-green-600 mb-2">You're registered!</h2>
                <p class="text-gray-600 mb-2">Your account is <strong>waiting for approval</strong> from your teacher or admin.</p>
                <p class="text-gray-400 text-sm mb-6">Once approved, you can log in and start coding!</p>
                <a href="/login" class="inline-block bg-indigo-600 text-white px-8 py-3 rounded-xl font-bold hover:bg-indigo-700 transition-all">Back to Login</a>
            </div>
            <!-- Form state -->
            <div id="formState">
                <h2 class="text-2xl text-gray-800 mb-1 text-center">Create Account</h2>
                <p class="text-center text-gray-400 text-sm mb-5">Students only — teachers & admins are created by admin</p>
                <div id="errorMsg" class="hidden bg-red-50 border border-red-200 text-red-700 rounded-xl p-3 mb-4 text-sm"></div>
                <form id="regForm" class="space-y-4">
                    <div>
                        <label class="block text-sm font-bold text-gray-600 mb-1">Full Name</label>
                        <input id="full_name" type="text" placeholder="Your full name" autocomplete="name"
                            class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-gray-800 focus:outline-none focus:border-indigo-400 transition-colors">
                    </div>
                    <div>
                        <label class="block text-sm font-bold text-gray-600 mb-1">Username</label>
                        <input id="username" type="text" placeholder="Choose a username (min 3 chars)" autocomplete="username"
                            class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-gray-800 focus:outline-none focus:border-indigo-400 transition-colors">
                        <p class="text-gray-400 text-xs mt-1">Only letters, numbers, underscores. You'll use this to log in.</p>
                    </div>
                    <div>
                        <label class="block text-sm font-bold text-gray-600 mb-1">Password</label>
                        <input id="password" type="password" placeholder="At least 6 characters" autocomplete="new-password"
                            class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-gray-800 focus:outline-none focus:border-indigo-400 transition-colors">
                    </div>
                    <div>
                        <label class="block text-sm font-bold text-gray-600 mb-1">Confirm Password</label>
                        <input id="confirm" type="password" placeholder="Re-enter your password" autocomplete="new-password"
                            class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-gray-800 focus:outline-none focus:border-indigo-400 transition-colors">
                    </div>
                    <div>
                        <label class="block text-sm font-bold text-gray-600 mb-1">Class <span class="text-gray-400 font-normal">(optional)</span></label>
                        <select id="class_id" class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-gray-800 focus:outline-none focus:border-indigo-400 transition-colors">
                            <option value="">— Select your class —</option>
                        </select>
                        <p class="text-gray-400 text-xs mt-1">Choose your class if your teacher has already set one up.</p>
                    </div>
                    <div>
                        <label class="block text-sm font-bold text-gray-600 mb-1">Parent Username <span class="text-gray-400 font-normal">(optional)</span></label>
                        <input id="parent_username" type="text" placeholder="Your parent's STEMO username"
                            class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-gray-800 focus:outline-none focus:border-indigo-400 transition-colors">
                        <p class="text-gray-400 text-xs mt-1">If your parent already has a STEMO account, enter their username to link automatically.</p>
                    </div>
                    <button type="submit" id="regBtn"
                        class="w-full bg-gradient-to-r from-indigo-500 to-purple-600 text-white py-3 rounded-xl font-bold text-lg hover:from-indigo-600 hover:to-purple-700 transition-all transform hover:scale-105 shadow-lg">
                        ✍️ Submit Registration
                    </button>
                </form>
                <div class="flex items-center gap-2 mt-5">
                    <div class="flex-1 h-px bg-gray-200"></div>
                    <span class="text-gray-400 text-xs">already have an account?</span>
                    <div class="flex-1 h-px bg-gray-200"></div>
                </div>
                <a href="/login" class="block mt-3 text-center text-indigo-600 font-bold hover:underline text-sm">← Back to Login</a>
            </div>
        </div>
        <div class="mt-6 bg-white/10 rounded-2xl p-4 text-white text-sm text-center">
            <p class="font-bold mb-1">📋 How it works</p>
            <p class="text-purple-200 text-xs">1. Fill in the form → 2. Wait for your teacher to approve → 3. Log in and start coding! 🚀</p>
        </div>
    </div>
    <script>
        // Load available classes
        fetch('/api/public/classes').then(r=>r.json()).then(classes => {
            const sel = document.getElementById('class_id');
            classes.forEach(c => {
                const opt = document.createElement('option');
                opt.value = c.id;
                opt.textContent = c.name + (c.description ? ' — ' + c.description : '');
                sel.appendChild(opt);
            });
        }).catch(()=>{});

        document.getElementById('regForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('regBtn');
            const err = document.getElementById('errorMsg');
            const fullName = document.getElementById('full_name').value.trim();
            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value;
            const confirm = document.getElementById('confirm').value;
            const classId = document.getElementById('class_id').value || null;
            const parentUsername = document.getElementById('parent_username').value.trim() || null;
            err.classList.add('hidden');
            if (!fullName || !username || !password) { err.textContent = 'All fields are required.'; err.classList.remove('hidden'); return; }
            if (password !== confirm) { err.textContent = 'Passwords do not match.'; err.classList.remove('hidden'); return; }
            if (password.length < 6) { err.textContent = 'Password must be at least 6 characters.'; err.classList.remove('hidden'); return; }
            if (username.length < 3) { err.textContent = 'Username must be at least 3 characters.'; err.classList.remove('hidden'); return; }
            btn.textContent = '⏳ Submitting...';
            btn.disabled = true;
            try {
                const res = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ full_name: fullName, username, password, class_id: classId, parent_username: parentUsername })
                });
                const data = await res.json();
                if (data.success) {
                    document.getElementById('formState').classList.add('hidden');
                    document.getElementById('successState').classList.remove('hidden');
                } else {
                    err.textContent = data.error || 'Registration failed. Please try again.';
                    err.classList.remove('hidden');
                    btn.textContent = '✍️ Submit Registration';
                    btn.disabled = false;
                }
            } catch(e) {
                err.textContent = 'Connection error. Please try again.';
                err.classList.remove('hidden');
                btn.textContent = '✍️ Submit Registration';
                btn.disabled = false;
            }
        });
    </script>
    <div class="text-center mt-6 pb-4">
        <p class="text-purple-200 text-sm">© 2026 STEMO · Science Games</p>
        <p class="text-purple-300 text-xs">أكاديمية ستيم لألعاب العلوم</p>
    </div>
</body>
</html>`

// ============================================
// LANDING PAGE
// ============================================
const landingPage = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STEMO Coding — AI-Powered Coding & Robotics for Kids</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Fredoka+One&family=Nunito:wght@400;600;700;800;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="stylesheet" href="/static/style.css">
    <style>
        body { font-family: 'Nunito', sans-serif; }
        .fredoka { font-family: 'Fredoka One', cursive; }
        .hero-gradient { background: linear-gradient(135deg, #4c1d95 0%, #6d28d9 40%, #7c3aed 70%, #4338ca 100%); }
        .feature-card { transition: transform 0.3s ease, box-shadow 0.3s ease; }
        .feature-card:hover { transform: translateY(-6px); box-shadow: 0 20px 40px rgba(109,40,217,0.18); }
        .stat-card { background: rgba(255,255,255,0.15); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.25); }
        .section-divider { background: linear-gradient(90deg, transparent, #7c3aed, transparent); height: 2px; }
        .glow { box-shadow: 0 0 30px rgba(139,92,246,0.4); }
        .badge-pill { display: inline-flex; align-items: center; gap: 6px; background: rgba(139,92,246,0.12); color: #6d28d9; border: 1px solid rgba(139,92,246,0.3); border-radius: 999px; padding: 4px 14px; font-size: 13px; font-weight: 700; }
        @keyframes float { 0%,100% { transform: translateY(0); } 50% { transform: translateY(-12px); } }
        .float-anim { animation: float 3.5s ease-in-out infinite; }
        @keyframes fadeInUp { from { opacity:0; transform:translateY(30px); } to { opacity:1; transform:translateY(0); } }
        .fade-in { animation: fadeInUp 0.7s ease both; }
        .step-connector { position: absolute; top: 32px; left: 50%; right: -50%; height: 2px; background: linear-gradient(90deg, #7c3aed, #a78bfa); z-index: 0; }
    </style>
</head>
<body class="bg-white overflow-x-hidden">

<!-- ========== NAVBAR ========== -->
<nav class="fixed top-0 left-0 right-0 z-50 bg-white/95 backdrop-blur-md shadow-sm border-b border-purple-100">
    <div class="max-w-7xl mx-auto px-6 py-3 flex items-center justify-between">
        <a href="/" class="flex items-center gap-3">
            <img src="/static/steam-logo.png" alt="STEMO Coding" class="h-10 object-contain">
            <span class="fredoka text-2xl text-purple-700 tracking-wide">STEMO Coding</span>
        </a>
        <div class="flex items-center gap-3">
            <a href="/login" class="px-5 py-2 rounded-full border-2 border-purple-600 text-purple-700 font-bold hover:bg-purple-50 transition-all text-sm">Login</a>
            <a href="/register" class="px-5 py-2 rounded-full bg-purple-600 text-white font-bold hover:bg-purple-700 transition-all text-sm shadow-md">Register as Student</a>
        </div>
    </div>
</nav>

<!-- ========== HERO ========== -->
<section class="hero-gradient min-h-screen flex items-center pt-20 pb-16 relative overflow-hidden">
    <div class="absolute inset-0 opacity-10">
        <div class="absolute top-10 left-10 text-9xl">🤖</div>
        <div class="absolute top-40 right-20 text-7xl">⭐</div>
        <div class="absolute bottom-20 left-32 text-8xl">🚀</div>
        <div class="absolute bottom-10 right-10 text-9xl">💻</div>
        <div class="absolute top-1/2 left-1/4 text-6xl">🧩</div>
    </div>
    <div class="max-w-7xl mx-auto px-6 relative z-10">
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
            <div class="text-white fade-in">
                <div class="badge-pill mb-6" style="background:rgba(255,255,255,0.15);color:#e9d5ff;border-color:rgba(255,255,255,0.3);">
                    <span>🏆</span> Trusted by schools across the region
                </div>
                <h1 class="fredoka text-5xl md:text-6xl lg:text-7xl leading-tight mb-6">
                    Where Kids Learn<br>
                    <span style="color:#fbbf24;">Coding & Robotics</span><br>
                    Through Play!
                </h1>
                <p class="text-xl text-purple-200 mb-8 leading-relaxed max-w-lg">
                    STEMO Coding is an AI-powered interactive platform that teaches children programming and robotics through fun games, challenges, and a friendly robot guide — no prior experience needed.
                </p>
                <div class="flex flex-wrap gap-4">
                    <a href="/register" class="px-8 py-4 rounded-full bg-yellow-400 text-gray-900 font-extrabold text-lg hover:bg-yellow-300 transition-all shadow-xl glow hover:scale-105">
                        🚀 Start for Free
                    </a>
                    <a href="/login" class="px-8 py-4 rounded-full bg-white/20 text-white font-bold text-lg hover:bg-white/30 transition-all border border-white/30">
                        🔐 Login to Platform
                    </a>
                </div>
                <div class="mt-10 flex flex-wrap gap-6">
                    <div class="flex items-center gap-2 text-purple-200 text-sm font-semibold">
                        <i class="fas fa-check-circle text-green-400"></i> No credit card required
                    </div>
                    <div class="flex items-center gap-2 text-purple-200 text-sm font-semibold">
                        <i class="fas fa-check-circle text-green-400"></i> Free for students
                    </div>
                    <div class="flex items-center gap-2 text-purple-200 text-sm font-semibold">
                        <i class="fas fa-check-circle text-green-400"></i> Teacher-approved content
                    </div>
                </div>
            </div>
            <div class="flex justify-center lg:justify-end">
                <div class="relative float-anim">
                    <div class="w-64 h-64 md:w-80 md:h-80 rounded-full bg-white/10 flex items-center justify-center border-4 border-white/20 shadow-2xl" style="box-shadow:0 0 60px rgba(167,139,250,0.5);">
                        <img src="/static/steam-logo.png" alt="STEMO Robot" class="w-48 md:w-64 object-contain drop-shadow-2xl">
                    </div>
                    <div class="absolute -top-4 -right-4 bg-yellow-400 text-gray-900 rounded-2xl px-4 py-2 font-bold text-sm shadow-lg">⭐ +50 XP!</div>
                    <div class="absolute -bottom-4 -left-4 bg-green-500 text-white rounded-2xl px-4 py-2 font-bold text-sm shadow-lg">🏆 Level Up!</div>
                    <div class="absolute top-1/2 -left-8 bg-blue-500 text-white rounded-2xl px-4 py-2 font-bold text-sm shadow-lg">🧩 Block Done!</div>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- ========== STATS ========== -->
<section class="bg-purple-700 py-12">
    <div class="max-w-6xl mx-auto px-6">
        <div class="grid grid-cols-2 md:grid-cols-5 gap-4 text-center">
            <div class="stat-card rounded-2xl p-5">
                <div class="fredoka text-4xl text-white mb-1">19</div>
                <div class="text-purple-200 text-sm font-semibold">Lessons</div>
            </div>
            <div class="stat-card rounded-2xl p-5">
                <div class="fredoka text-4xl text-white mb-1">4</div>
                <div class="text-purple-200 text-sm font-semibold">Difficulty Levels</div>
            </div>
            <div class="stat-card rounded-2xl p-5">
                <div class="fredoka text-4xl text-white mb-1">50+</div>
                <div class="text-purple-200 text-sm font-semibold">Block Types</div>
            </div>
            <div class="stat-card rounded-2xl p-5">
                <div class="fredoka text-4xl text-white mb-1">4</div>
                <div class="text-purple-200 text-sm font-semibold">User Roles</div>
            </div>
            <div class="stat-card rounded-2xl p-5">
                <div class="fredoka text-4xl text-white mb-1">AI</div>
                <div class="text-purple-200 text-sm font-semibold">Powered Tutor</div>
            </div>
        </div>
    </div>
</section>

<!-- ========== HOW IT WORKS ========== -->
<section class="py-24 bg-gray-50">
    <div class="max-w-6xl mx-auto px-6">
        <div class="text-center mb-16">
            <span class="badge-pill mb-4">⚡ Simple & Powerful</span>
            <h2 class="fredoka text-4xl md:text-5xl text-gray-900 mb-4">How STEMO Coding Works</h2>
            <p class="text-gray-500 text-lg max-w-2xl mx-auto">From registration to mastering robotics — it's a smooth, guided journey for every child.</p>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div class="bg-white rounded-3xl p-8 text-center shadow-lg feature-card relative">
                <div class="w-16 h-16 rounded-2xl bg-purple-100 flex items-center justify-center text-3xl mx-auto mb-6">1️⃣</div>
                <h3 class="fredoka text-2xl text-gray-800 mb-3">Register & Join a Class</h3>
                <p class="text-gray-500 leading-relaxed">Students sign up, get approved by their teacher, and are placed in a class. Parents can also create accounts to monitor progress.</p>
            </div>
            <div class="bg-white rounded-3xl p-8 text-center shadow-lg feature-card">
                <div class="w-16 h-16 rounded-2xl bg-yellow-100 flex items-center justify-center text-3xl mx-auto mb-6">2️⃣</div>
                <h3 class="fredoka text-2xl text-gray-800 mb-3">Learn with STEMO Robot</h3>
                <p class="text-gray-500 leading-relaxed">Drag and drop colorful coding blocks to control the STEMO robot. Complete missions, earn XP, and unlock badges as you progress.</p>
            </div>
            <div class="bg-white rounded-3xl p-8 text-center shadow-lg feature-card">
                <div class="w-16 h-16 rounded-2xl bg-green-100 flex items-center justify-center text-3xl mx-auto mb-6">3️⃣</div>
                <h3 class="fredoka text-2xl text-gray-800 mb-3">Grow & Get Recognized</h3>
                <p class="text-gray-500 leading-relaxed">Climb the leaderboard, complete homework challenges, and receive certificates. Teachers track progress and assign custom lessons.</p>
            </div>
        </div>
    </div>
</section>

<!-- ========== WHAT KIDS LEARN ========== -->
<section class="py-24 bg-white">
    <div class="max-w-7xl mx-auto px-6">
        <div class="text-center mb-16">
            <span class="badge-pill mb-4">📚 Full Curriculum</span>
            <h2 class="fredoka text-4xl md:text-5xl text-gray-900 mb-4">19 Lessons. Real Skills. Real Fun.</h2>
            <p class="text-gray-500 text-lg max-w-2xl mx-auto">A complete learning journey from "what is code?" to writing reusable functions — designed for ages 7 to 16.</p>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
            <!-- Beginner -->
            <div class="rounded-3xl overflow-hidden shadow-lg border border-gray-100">
                <div class="bg-gradient-to-r from-green-400 to-emerald-500 p-5 text-white">
                    <div class="text-3xl mb-2">🟢</div>
                    <div class="fredoka text-2xl">Beginner</div>
                    <div class="text-green-100 text-sm mt-1">Lessons 1 – 5</div>
                </div>
                <div class="bg-white p-5 space-y-3">
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-green-100 flex items-center justify-center text-sm">🚶</div><div><div class="font-bold text-gray-800 text-sm">First Steps</div><div class="text-gray-500 text-xs">Move, turn, go home</div></div></div>
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-green-100 flex items-center justify-center text-sm">🎨</div><div><div class="font-bold text-gray-800 text-sm">Drawing Bot</div><div class="text-gray-500 text-xs">Pen, color, size controls</div></div></div>
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-green-100 flex items-center justify-center text-sm">🔷</div><div><div class="font-bold text-gray-800 text-sm">Shape Artist</div><div class="text-gray-500 text-xs">Squares, triangles, stars</div></div></div>
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-green-100 flex items-center justify-center text-sm">🔁</div><div><div class="font-bold text-gray-800 text-sm">Loop Lab</div><div class="text-gray-500 text-xs">Repeat blocks, efficiency</div></div></div>
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-green-100 flex items-center justify-center text-sm">🌀</div><div><div class="font-bold text-gray-800 text-sm">Spiral Master</div><div class="text-gray-500 text-xs">Complex loop patterns</div></div></div>
                </div>
            </div>
            <!-- Intermediate -->
            <div class="rounded-3xl overflow-hidden shadow-lg border border-gray-100">
                <div class="bg-gradient-to-r from-blue-400 to-cyan-500 p-5 text-white">
                    <div class="text-3xl mb-2">🔵</div>
                    <div class="fredoka text-2xl">Intermediate</div>
                    <div class="text-blue-100 text-sm mt-1">Lessons 6 – 9</div>
                </div>
                <div class="bg-white p-5 space-y-3">
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center text-sm">🔩</div><div><div class="font-bold text-gray-800 text-sm">Metal Collector</div><div class="text-gray-500 text-xs">Magnet, objects, pickup</div></div></div>
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center text-sm">🧭</div><div><div class="font-bold text-gray-800 text-sm">Smart Navigator</div><div class="text-gray-500 text-xs">Pathfinding, BFS routing</div></div></div>
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center text-sm">📡</div><div><div class="font-bold text-gray-800 text-sm">Sensor Explorer</div><div class="text-gray-500 text-xs">Ultrasonic, wall detection</div></div></div>
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center text-sm">🤔</div><div><div class="font-bold text-gray-800 text-sm">Decision Maker</div><div class="text-gray-500 text-xs">If/else logic, conditions</div></div></div>
                </div>
            </div>
            <!-- Advanced -->
            <div class="rounded-3xl overflow-hidden shadow-lg border border-gray-100">
                <div class="bg-gradient-to-r from-orange-400 to-red-500 p-5 text-white">
                    <div class="text-3xl mb-2">🔴</div>
                    <div class="fredoka text-2xl">Advanced</div>
                    <div class="text-orange-100 text-sm mt-1">Lessons 10 – 14</div>
                </div>
                <div class="bg-white p-5 space-y-3">
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-red-100 flex items-center justify-center text-sm">🧱</div><div><div class="font-bold text-gray-800 text-sm">Wall Avoider</div><div class="text-gray-500 text-xs">Maze solving, smart turns</div></div></div>
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-red-100 flex items-center justify-center text-sm">🌡️</div><div><div class="font-bold text-gray-800 text-sm">Fire Watch</div><div class="text-gray-500 text-xs">Temperature sensors, alerts</div></div></div>
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-red-100 flex items-center justify-center text-sm">🚒</div><div><div class="font-bold text-gray-800 text-sm">Firefighter Hero</div><div class="text-gray-500 text-xs">Water system, extinguish</div></div></div>
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-red-100 flex items-center justify-center text-sm">🏆</div><div><div class="font-bold text-gray-800 text-sm">Master Coder</div><div class="text-gray-500 text-xs">All skills combined, final challenge</div></div></div>
                </div>
            </div>
            <!-- Expert -->
            <div class="rounded-3xl overflow-hidden shadow-lg border border-gray-100">
                <div class="bg-gradient-to-r from-purple-500 to-violet-600 p-5 text-white">
                    <div class="text-3xl mb-2">🟣</div>
                    <div class="fredoka text-2xl">Expert</div>
                    <div class="text-purple-100 text-sm mt-1">Lessons 15 – 19</div>
                </div>
                <div class="bg-white p-5 space-y-3">
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center text-sm">🔢</div><div><div class="font-bold text-gray-800 text-sm">Variable Vault</div><div class="text-gray-500 text-xs">Named data, dynamic control</div></div></div>
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center text-sm">📍</div><div><div class="font-bold text-gray-800 text-sm">Position Memory</div><div class="text-gray-500 text-xs">GPS coordinates, navigation</div></div></div>
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center text-sm">🗺️</div><div><div class="font-bold text-gray-800 text-sm">Waypoint Trail</div><div class="text-gray-500 text-xs">Recorded paths, replay</div></div></div>
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center text-sm">🎯</div><div><div class="font-bold text-gray-800 text-sm">List Hunt</div><div class="text-gray-500 text-xs">Iteration, data lists, AI logic</div></div></div>
                    <div class="flex items-center gap-3"><div class="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center text-sm">🔧</div><div><div class="font-bold text-gray-800 text-sm">Function Factory</div><div class="text-gray-500 text-xs">Define & call reusable functions</div></div></div>
                </div>
            </div>
        </div>

        <!-- Skills kids gain -->
        <div class="bg-gradient-to-br from-purple-50 to-violet-100 rounded-3xl p-10 border border-purple-100">
            <div class="text-center mb-10">
                <h3 class="fredoka text-3xl text-gray-800 mb-2">Real Programming Skills, Taught Visually</h3>
                <p class="text-gray-500">By the end of STEMO Coding, every student understands these core concepts — the same ones professional developers use every day.</p>
            </div>
            <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 text-center">
                <div class="bg-white rounded-2xl p-4 shadow-sm"><div class="text-3xl mb-2">🔁</div><div class="text-xs font-bold text-gray-700">Loops</div></div>
                <div class="bg-white rounded-2xl p-4 shadow-sm"><div class="text-3xl mb-2">🤔</div><div class="text-xs font-bold text-gray-700">Conditions</div></div>
                <div class="bg-white rounded-2xl p-4 shadow-sm"><div class="text-3xl mb-2">🔢</div><div class="text-xs font-bold text-gray-700">Variables</div></div>
                <div class="bg-white rounded-2xl p-4 shadow-sm"><div class="text-3xl mb-2">🔧</div><div class="text-xs font-bold text-gray-700">Functions</div></div>
                <div class="bg-white rounded-2xl p-4 shadow-sm"><div class="text-3xl mb-2">📋</div><div class="text-xs font-bold text-gray-700">Lists & Data</div></div>
                <div class="bg-white rounded-2xl p-4 shadow-sm"><div class="text-3xl mb-2">📡</div><div class="text-xs font-bold text-gray-700">Sensors & I/O</div></div>
            </div>
        </div>
    </div>
</section>

<!-- ========== FEATURES ========== -->
<section class="py-24 bg-gray-50">
    <div class="max-w-7xl mx-auto px-6">
        <div class="text-center mb-16">
            <span class="badge-pill mb-4">🎯 Platform Features</span>
            <h2 class="fredoka text-4xl md:text-5xl text-gray-900 mb-4">Everything Kids Need to Thrive</h2>
            <p class="text-gray-500 text-lg max-w-2xl mx-auto">A complete ecosystem built for modern STEAM education — engaging, measurable, and fun.</p>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            <div class="feature-card rounded-3xl p-7 bg-white border border-gray-100 shadow-sm">
                <div class="text-4xl mb-4">🤖</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">AI Robot Guide (STEMO)</h3>
                <p class="text-gray-500 text-sm leading-relaxed">A friendly AI-powered tutor who explains concepts, gives hints, and encourages students in real-time — powered by Llama 3.</p>
            </div>
            <div class="feature-card rounded-3xl p-7 bg-white border border-gray-100 shadow-sm">
                <div class="text-4xl mb-4">🧩</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Visual Block Programming</h3>
                <p class="text-gray-500 text-sm leading-relaxed">50+ drag-and-drop blocks covering movement, drawing, loops, conditions, sensors, variables, lists, and functions — no typing needed.</p>
            </div>
            <div class="feature-card rounded-3xl p-7 bg-white border border-gray-100 shadow-sm">
                <div class="text-4xl mb-4">🔧</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Custom Functions</h3>
                <p class="text-gray-500 text-sm leading-relaxed">Students define their own reusable functions by name, then call them anywhere. The same concept used by every professional programmer.</p>
            </div>
            <div class="feature-card rounded-3xl p-7 bg-white border border-gray-100 shadow-sm">
                <div class="text-4xl mb-4">📡</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Command Center</h3>
                <p class="text-gray-500 text-sm leading-relaxed">A real-time satellite terminal that displays data transmissions from STEMO — kids use the "Send to CC" block like a print() function to debug their programs.</p>
            </div>
            <div class="feature-card rounded-3xl p-7 bg-white border border-gray-100 shadow-sm">
                <div class="text-4xl mb-4">🗺️</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">GPS & Waypoint System</h3>
                <p class="text-gray-500 text-sm leading-relaxed">Save positions A–D, navigate back to them like GPS, record waypoint paths, and replay them automatically. Real spatial reasoning skills.</p>
            </div>
            <div class="feature-card rounded-3xl p-7 bg-white border border-gray-100 shadow-sm">
                <div class="text-4xl mb-4">📐</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">3D Isometric View</h3>
                <p class="text-gray-500 text-sm leading-relaxed">Switch the canvas to an isometric 3D perspective — STEMO comes alive in three dimensions, making spatial programming even more visual.</p>
            </div>
            <div class="feature-card rounded-3xl p-7 bg-white border border-gray-100 shadow-sm">
                <div class="text-4xl mb-4">💾</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Project Save & Load</h3>
                <p class="text-gray-500 text-sm leading-relaxed">Save programs as .stemo files and reload them at any time. Students can build projects over multiple sessions and share them with the class.</p>
            </div>
            <div class="feature-card rounded-3xl p-7 bg-white border border-gray-100 shadow-sm">
                <div class="text-4xl mb-4">🎯</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Challenge Mode</h3>
                <p class="text-gray-500 text-sm leading-relaxed">Each lesson has a locked challenge with specific objectives that auto-check as the student runs their code. Complete all objectives to unlock the next lesson.</p>
            </div>
            <div class="feature-card rounded-3xl p-7 bg-white border border-gray-100 shadow-sm">
                <div class="text-4xl mb-4">⭐</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">XP, Levels & Badges</h3>
                <p class="text-gray-500 text-sm leading-relaxed">Earn XP for every lesson, level up, maintain daily streaks, and unlock achievement badges. A full gamification system keeps motivation high.</p>
            </div>
            <div class="feature-card rounded-3xl p-7 bg-white border border-gray-100 shadow-sm">
                <div class="text-4xl mb-4">📊</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Teacher Dashboard</h3>
                <p class="text-gray-500 text-sm leading-relaxed">Manage classes, approve students, assign specific lessons to a class, view every student's XP and level, and reset passwords with one click.</p>
            </div>
            <div class="feature-card rounded-3xl p-7 bg-white border border-gray-100 shadow-sm">
                <div class="text-4xl mb-4">👨‍👩‍👧</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Parent Monitoring Portal</h3>
                <p class="text-gray-500 text-sm leading-relaxed">Parents link to their child's account and see XP, lessons completed, badges earned, and streaks — always in the loop without interrupting learning.</p>
            </div>
            <div class="feature-card rounded-3xl p-7 bg-white border border-gray-100 shadow-sm">
                <div class="text-4xl mb-4">🏆</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Live Class Leaderboard</h3>
                <p class="text-gray-500 text-sm leading-relaxed">A real-time leaderboard ranks every student in the class by XP and level — healthy competition that drives everyone to practice more.</p>
            </div>
        </div>
    </div>
</section>

<!-- ========== FOR SCHOOLS ========== -->
<section class="py-24 bg-gradient-to-br from-purple-900 via-violet-900 to-indigo-900 relative overflow-hidden">
    <div class="absolute inset-0 opacity-5 text-9xl flex flex-wrap gap-8 p-8">
        <span>🏫</span><span>📚</span><span>🎓</span><span>🌟</span><span>💡</span><span>🏫</span><span>📚</span>
    </div>
    <div class="max-w-6xl mx-auto px-6 relative z-10">
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
            <div>
                <span class="badge-pill mb-6" style="background:rgba(255,255,255,0.1);color:#c4b5fd;border-color:rgba(255,255,255,0.2);">🏫 For Schools & Teachers</span>
                <h2 class="fredoka text-4xl md:text-5xl text-white mb-6 leading-tight">Give Your Students a<br><span class="text-yellow-400">Coding Superpower</span></h2>
                <p class="text-purple-200 text-lg mb-8 leading-relaxed">STEMO Coding integrates seamlessly into your curriculum. No special hardware needed — just a browser and curiosity.</p>
                <div class="space-y-4">
                    <div class="flex items-start gap-4">
                        <div class="w-10 h-10 rounded-xl bg-purple-700 flex items-center justify-center text-xl flex-shrink-0">✅</div>
                        <div>
                            <div class="text-white font-bold">Curriculum-aligned lessons</div>
                            <div class="text-purple-300 text-sm">Each lesson maps to real STEAM learning objectives for ages 7–16</div>
                        </div>
                    </div>
                    <div class="flex items-start gap-4">
                        <div class="w-10 h-10 rounded-xl bg-purple-700 flex items-center justify-center text-xl flex-shrink-0">✅</div>
                        <div>
                            <div class="text-white font-bold">Zero setup complexity</div>
                            <div class="text-purple-300 text-sm">Students register, teachers approve — classes are running in minutes</div>
                        </div>
                    </div>
                    <div class="flex items-start gap-4">
                        <div class="w-10 h-10 rounded-xl bg-purple-700 flex items-center justify-center text-xl flex-shrink-0">✅</div>
                        <div>
                            <div class="text-white font-bold">Full control for teachers</div>
                            <div class="text-purple-300 text-sm">Assign specific lessons, monitor every student's progress, reset passwords</div>
                        </div>
                    </div>
                    <div class="flex items-start gap-4">
                        <div class="w-10 h-10 rounded-xl bg-purple-700 flex items-center justify-center text-xl flex-shrink-0">✅</div>
                        <div>
                            <div class="text-white font-bold">Engaging for every learning style</div>
                            <div class="text-purple-300 text-sm">Visual blocks, interactive robot, AI chat, games — keeps every student involved</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="bg-white/10 backdrop-blur-sm rounded-3xl p-8 border border-white/20">
                <div class="text-center mb-6">
                    <div class="text-6xl mb-4">🎓</div>
                    <h3 class="fredoka text-2xl text-white mb-2">What Teachers Say</h3>
                </div>
                <div class="space-y-4">
                    <div class="bg-white/10 rounded-2xl p-4 border border-white/10">
                        <p class="text-purple-100 italic text-sm leading-relaxed">"My students were coding their first robot program in 15 minutes. The excitement in the classroom was unreal!"</p>
                        <div class="text-purple-300 text-xs mt-2 font-bold">— Grade 5 Teacher</div>
                    </div>
                    <div class="bg-white/10 rounded-2xl p-4 border border-white/10">
                        <p class="text-purple-100 italic text-sm leading-relaxed">"STEMO makes it easy to assign differentiated lessons. Every student works at their own pace while I track everyone from one dashboard."</p>
                        <div class="text-purple-300 text-xs mt-2 font-bold">— STEAM Coordinator</div>
                    </div>
                    <div class="bg-white/10 rounded-2xl p-4 border border-white/10">
                        <p class="text-purple-100 italic text-sm leading-relaxed">"The kids ask me 'Can we do STEMO today?' every single morning. That says everything."</p>
                        <div class="text-purple-300 text-xs mt-2 font-bold">— Primary School Teacher</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- ========== FOR PARENTS ========== -->
<section class="py-24 bg-gray-50">
    <div class="max-w-6xl mx-auto px-6">
        <div class="text-center mb-16">
            <span class="badge-pill mb-4">👨‍👩‍👧 For Parents</span>
            <h2 class="fredoka text-4xl md:text-5xl text-gray-900 mb-4">Stay Connected to Your Child's Learning</h2>
            <p class="text-gray-500 text-lg max-w-2xl mx-auto">STEMO Coding keeps parents informed and involved — because learning happens best as a family.</p>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div class="bg-white rounded-3xl p-6 text-center shadow-md feature-card">
                <div class="text-4xl mb-4">📈</div>
                <h3 class="font-extrabold text-gray-800 mb-2">Track Progress</h3>
                <p class="text-gray-500 text-sm leading-relaxed">See how many lessons completed, XP earned, and current level — updated in real-time.</p>
            </div>
            <div class="bg-white rounded-3xl p-6 text-center shadow-md feature-card">
                <div class="text-4xl mb-4">🔥</div>
                <h3 class="font-extrabold text-gray-800 mb-2">Daily Streaks</h3>
                <p class="text-gray-500 text-sm leading-relaxed">Know if your child is logging in and learning consistently with streak tracking.</p>
            </div>
            <div class="bg-white rounded-3xl p-6 text-center shadow-md feature-card">
                <div class="text-4xl mb-4">🏅</div>
                <h3 class="font-extrabold text-gray-800 mb-2">Badge Gallery</h3>
                <p class="text-gray-500 text-sm leading-relaxed">Watch your child earn badges and achievements as they complete challenges and milestones.</p>
            </div>
            <div class="bg-white rounded-3xl p-6 text-center shadow-md feature-card">
                <div class="text-4xl mb-4">🔗</div>
                <h3 class="font-extrabold text-gray-800 mb-2">Easy Linking</h3>
                <p class="text-gray-500 text-sm leading-relaxed">Link to your child's account with one step and access their full learning profile anytime.</p>
            </div>
        </div>
    </div>
</section>

<!-- ========== CTA / LOGIN+REGISTER ========== -->
<section class="hero-gradient py-24 relative overflow-hidden">
    <div class="absolute inset-0 opacity-10 text-8xl flex flex-wrap gap-10 p-10">
        <span>🚀</span><span>⭐</span><span>🤖</span><span>🏆</span><span>💡</span><span>🔬</span><span>🎮</span>
    </div>
    <div class="max-w-5xl mx-auto px-6 relative z-10 text-center">
        <h2 class="fredoka text-4xl md:text-6xl text-white mb-6">Ready to Start the<br><span class="text-yellow-400">Adventure?</span></h2>
        <p class="text-purple-200 text-xl mb-12 max-w-2xl mx-auto leading-relaxed">Join STEMO Coding today — it's free for students and takes less than 2 minutes to get started.</p>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-2xl mx-auto">
            <div class="bg-white rounded-3xl p-8 text-center shadow-2xl">
                <div class="text-5xl mb-4">🔐</div>
                <h3 class="fredoka text-2xl text-gray-800 mb-2">Already a Member?</h3>
                <p class="text-gray-500 text-sm mb-6">Students, teachers, parents and admins — log in to your dashboard.</p>
                <a href="/login" class="block w-full py-3 rounded-full bg-purple-600 text-white font-bold hover:bg-purple-700 transition-all shadow-lg">🚀 Login Now</a>
            </div>
            <div class="bg-gradient-to-br from-yellow-400 to-orange-400 rounded-3xl p-8 text-center shadow-2xl">
                <div class="text-5xl mb-4">✏️</div>
                <h3 class="fredoka text-2xl text-gray-900 mb-2">New Student?</h3>
                <p class="text-gray-800 text-sm mb-6 opacity-80">Register for free and start your coding journey with STEMO today!</p>
                <a href="/register" class="block w-full py-3 rounded-full bg-gray-900 text-white font-bold hover:bg-gray-800 transition-all shadow-lg">🎉 Register as Student</a>
            </div>
        </div>
    </div>
</section>

<!-- ========== FOOTER ========== -->
<footer class="bg-gray-900 text-gray-400 py-12">
    <div class="max-w-6xl mx-auto px-6">
        <div class="flex flex-col md:flex-row items-center justify-between gap-6">
            <div class="flex items-center gap-3">
                <img src="/static/steam-logo-white.png" alt="STEMO Coding" class="h-10 object-contain opacity-80">
                <div>
                    <div class="fredoka text-xl text-white">STEMO Coding</div>
                    <div class="text-xs text-gray-500">AI-Powered Coding & Robotics for Kids</div>
                </div>
            </div>
            <div class="flex gap-8 text-sm">
                <a href="/login" class="hover:text-white transition-colors">Login</a>
                <a href="/register" class="hover:text-white transition-colors">Register</a>
            </div>
            <div class="text-sm text-center">
                <div>© 2026 STEMO Coding · Science Games</div>
                <div class="text-xs mt-1">أكاديمية ستيم لألعاب العلوم</div>
            </div>
        </div>
    </div>
</footer>

</body>
</html>`

// ============================================
// PAGE ROUTES
// ============================================

app.get('/login', (c) => c.html(loginPage))
app.get('/register', (c) => c.html(registerPage))
app.get('/dashboard/admin', (c) => c.html(adminDashboard))
app.get('/dashboard/teacher', (c) => c.html(teacherDashboard))
app.get('/dashboard/parent', (c) => c.html(parentDashboard))

// Academy demo route — teachers and admins can view the academy without being redirected
app.get('/academy', async (c) => {
    const cookie = c.req.header('cookie') || ''
    const token = getCookieToken(cookie)
    if (!token) return c.redirect('/login')
    const payload = await verifyToken(token)
    if (!payload) return c.redirect('/login')
    // Show academy in demo mode for teachers/admins (no progress saved)
    const demoBanner = `<div style="background:#f59e0b;color:#fff;text-align:center;padding:8px 16px;font-weight:bold;font-size:14px;position:sticky;top:0;z-index:9999;">
        🎓 Demo Mode — You are viewing the academy as a teacher. Progress is not saved. <a href="/dashboard/teacher" style="color:#fff;text-decoration:underline;margin-left:12px;">← Back to Dashboard</a>
    </div>`
    const page = htmlContent.replace('<body', demoBanner + '<body')
    return c.html(page)
})

// Main app - show landing page if not logged in, else redirect to dashboard
app.get('/', async (c) => {
    const cookie = c.req.header('cookie') || ''
    const token = getCookieToken(cookie)
    if (!token) return c.html(landingPage)
    const payload = await verifyToken(token)
    if (!payload) return c.html(landingPage)
    // Redirect authenticated users to their dashboards
    if (payload.role === 'admin') return c.redirect('/dashboard/admin')
    if (payload.role === 'teacher') return c.redirect('/dashboard/teacher')
    if (payload.role === 'parent') return c.redirect('/dashboard/parent')
    // Inject user info into the main student app
    const page = htmlContent
        .replace('id="xpCounter"', `id="xpCounter" data-user='${JSON.stringify(payload)}'`)
    return c.html(page)
})

export default app
