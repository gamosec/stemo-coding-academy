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
    const { name, description, teacher_id } = body
    const finalTeacherId = me.role === 'teacher' ? me.id : (teacher_id || null)
    const result = await c.env.DB.prepare('INSERT INTO classes (name, description, teacher_id) VALUES (?, ?, ?)').bind(name, description || '', finalTeacherId).run()
    return c.json({ success: true, id: result.meta.last_row_id })
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
               COALESCE(sp.streak, 0) as streak
        FROM users u
        LEFT JOIN student_progress sp ON sp.student_id = u.id
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
                   (SELECT lesson_id FROM assigned_lessons WHERE class_id = c.id LIMIT 1) as assigned_lesson_id
            FROM class_students cs
            JOIN classes c ON cs.class_id = c.id
            LEFT JOIN users u ON c.teacher_id = u.id
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
            description: 'Discover coding blocks and understand the concept',
            difficulty: 'easy',
            xpReward: 50,
            icon: '👋',
            introduction: "Hello! I am STEMO, your robot coding buddy! 🤖 I can help you learn programming in a fun way. On the left side you will see colorful blocks - these are commands that tell me what to do. On the right is my world where I move around. Let's start with a simple command!",
            tasks: [
                { id: 't1', text: 'Click the "Forward" block on the left panel', completed: false },
                { id: 't2', text: 'Click the green "Run" button to make me move', completed: false },
                { id: 't3', text: 'Watch me move forward! 🎉', completed: false }
            ],
            hint: 'Click the Forward block on the left, then click the green Run button!',
            homework: 'Try to make me move exactly 10 steps! How many blocks do you need?',
            nextLesson: 'lesson-2'
        },
        {
            id: 'lesson-2',
            title: 'Movement Master',
            description: 'Learn all movement: Forward, Back, Left, Right',
            difficulty: 'easy',
            xpReward: 100,
            icon: '🚶',
            introduction: "Great job! Now let's learn all the ways I can move. I can go Forward, Backward, turn Left, turn Right, and even go back Home! Try clicking on the number to change it!",
            tasks: [
                { id: 't1', text: 'Add a "Forward" block and change the number to 3', completed: false },
                { id: 't2', text: 'Add a "Right" block (turn 90 degrees)', completed: false },
                { id: 't3', text: 'Add another "Forward" block with 2 steps', completed: false },
                { id: 't4', text: 'Click Run to see me walk in an L shape!', completed: false }
            ],
            hint: 'Try: Forward 3 → Right 90 → Forward 2. I will walk in an L shape!',
            homework: 'Can you make me walk in a large "Z" shape? Think about the turns!',
            nextLesson: 'lesson-3'
        },
        {
            id: 'lesson-3',
            title: 'Start Drawing!',
            description: 'Use Pen to draw lines',
            difficulty: 'easy',
            xpReward: 100,
            icon: '🖌️',
            introduction: "Now for the fun part - drawing! 🖍️ By default, my pen is UP so I don't draw when I move. To start drawing, you need to put my pen DOWN first. Then when I move, I leave a trail!",
            tasks: [
                { id: 't1', text: 'Add a "Pen" block and select "Down ✏️"', completed: false },
                { id: 't2', text: 'Add a "Forward" block with 5 steps', completed: false },
                { id: 't3', text: 'Click Run to draw a line!', completed: false }
            ],
            hint: 'First add Pen Down, then Forward. I will draw a line!',
            homework: 'Try to draw a dashed line! (Hint: Pen Down -> Forward -> Pen Up -> Forward -> Repeat)',
            nextLesson: 'lesson-4'
        },
        {
            id: 'lesson-4',
            title: 'Color Artist',
            description: 'Change colors and pen size',
            difficulty: 'easy',
            xpReward: 100,
            icon: '🎨',
            introduction: "Let's make our drawings beautiful! You can change my pen color and even how thick the line is. Colors make everything better! 🌈",
            tasks: [
                { id: 't1', text: 'Add a "Color" block and pick your favorite color', completed: false },
                { id: 't2', text: 'Add a "Size" block and set it to 10', completed: false },
                { id: 't3', text: 'Add "Pen Down" and "Forward 5"', completed: false },
                { id: 't4', text: 'Run to see a thick, colorful line!', completed: false }
            ],
            hint: 'Put Color and Size blocks BEFORE Pen Down to see the effect!',
            homework: 'Create a "Rainbow Road"! Change the color 3 times as I move!',
            nextLesson: 'lesson-5'
        }
    ],
    intermediate: [
        {
            id: 'lesson-5',
            title: 'Loop Power!',
            description: 'Use Repeat to do actions multiple times',
            difficulty: 'medium',
            xpReward: 150,
            icon: '🔁',
            introduction: "What if you want me to do the same thing many times? Instead of adding the same blocks over and over, you can use the magic REPEAT block! 🔁 This is called a LOOP!",
            tasks: [
                { id: 't1', text: 'Add a "Pen Down" block first', completed: false },
                { id: 't2', text: 'Add a "Repeat" block and set it to 4 times', completed: false },
                { id: 't3', text: 'Inside the Repeat, add "Forward 4" and "Right 90"', completed: false },
                { id: 't4', text: 'Click Run to draw a perfect square! ⬛', completed: false }
            ],
            hint: 'Repeat 4 times: Forward 4, Right 90. This draws a square!',
            homework: 'Use a loop within another loop! Draw 4 squares in a row!',
            nextLesson: 'lesson-6'
        },
        {
            id: 'lesson-6',
            title: 'Shape Artist',
            description: 'Create triangles, hexagons and more!',
            difficulty: 'medium',
            xpReward: 200,
            icon: '📐',
            introduction: "The secret to drawing any shape is knowing how much to turn. For a triangle, we turn 120° (because 360÷3=120). For a hexagon, we turn 60° (360÷6=60). Let's use math! ➗",
            tasks: [
                { id: 't1', text: 'Draw a Triangle: Repeat 3 times → Forward 5, Right 120°', completed: false },
                { id: 't2', text: 'Clear and try a Hexagon: Repeat 6 times → Forward 4, Right 60°', completed: false }
            ],
            hint: 'Formula: Turn angle = 360 ÷ number of sides.',
            homework: 'Can you draw a house? Use a square for the bottom and a triangle for the roof!',
            nextLesson: 'lesson-7'
        },
        {
            id: 'lesson-7',
            title: 'Star Power!',
            description: 'Draw a beautiful 5-pointed star',
            difficulty: 'hard',
            xpReward: 300,
            icon: '⭐',
            introduction: "Drawing a star is special because we turn MORE! For a 5-pointed star, we turn 144°. This makes the lines cross! 🌟",
            tasks: [
                { id: 't1', text: 'Add "Pen Down"', completed: false },
                { id: 't2', text: 'Add "Repeat 5 times"', completed: false },
                { id: 't3', text: 'Inside: "Forward 8" and "Right 144"', completed: false },
                { id: 't4', text: 'Add "Hide" at the end to see the star!', completed: false }
            ],
            hint: 'Star secret: Turn 144° (not 72°). Repeat 5 times!',
            homework: 'Try drawing a 6-pointed star! It\'s two triangles on top of each other!',
            nextLesson: 'lesson-8'
        },
        {
            id: 'lesson-8',
            title: 'Magnet Magic',
            description: 'Pick up metal objects with your magnet',
            difficulty: 'medium',
            xpReward: 200,
            icon: '🧲',
            introduction: "I have a powerful electromagnet! 🧲 When it's ON, I can pick up metal objects (🔩) if I'm close enough. When it's OFF, I drop them. Let's try to move some metal!",
            tasks: [
                { id: 't1', text: 'Place a Metal piece (🔩) on the board with the button above', completed: false },
                { id: 't2', text: 'Move near it and add "Magnet ON"', completed: false },
                { id: 't3', text: 'Move to a new spot and add "Magnet OFF"', completed: false },
                { id: 't4', text: 'Run to pick up and move the metal! 🎉', completed: false }
            ],
            hint: 'The magnet only works when you are very close to the metal piece.',
            homework: 'Create a "Magnetic Maze"! Put metal pieces in corners and collect them all!',
            nextLesson: 'lesson-9'
        },
        {
            id: 'lesson-9',
            title: 'Ultrasonic Sight',
            description: 'See walls using sound waves',
            difficulty: 'medium',
            xpReward: 250,
            icon: '📡',
            introduction: "I can 'see' using sound! 🦇 My ultrasonic sensor sends out waves. If they bounce back, I know there's a wall. This is how bats find their way in the dark! Let's scan for walls.",
            tasks: [
                { id: 't1', text: 'Place a Wall (🧱) ahead of me', completed: false },
                { id: 't2', text: 'Add a "Scan Ahead" block', completed: false },
                { id: 't3', text: 'Watch the sensor beam show the distance!', completed: false }
            ],
            hint: 'Click the 🧱 icon to place walls on the board.',
            homework: 'Make me stop exactly 2 steps before the wall! How many steps is that?',
            nextLesson: 'lesson-10'
        }
    ],
    advanced: [
        {
            id: 'lesson-10',
            title: 'Space Navigator',
            description: 'Reach targets automatically',
            difficulty: 'hard',
            xpReward: 300,
            icon: '🎯',
            introduction: "I can find my way to a target! 🎯 Using my smart sensors, I can calculate the path to any goal. This is how Mars Rovers explore other planets! Let's reach a target.",
            tasks: [
                { id: 't1', text: 'Place a Target (🎯) on the board', completed: false },
                { id: 't2', text: 'Add the "Go To Target" block', completed: false },
                { id: 't3', text: 'Run and watch me navigate!', completed: false }
            ],
            hint: 'The Target block combines scanning and turning to reach the goal.',
            homework: 'Place walls between me and the target! Can I still find my way?',
            nextLesson: 'lesson-11'
        },
        {
            id: 'lesson-11',
            title: 'Smart Explorer',
            description: 'Make decisions with If/Else logic',
            difficulty: 'hard',
            xpReward: 350,
            icon: '🧠',
            introduction: "The most important part of AI is making decisions. 🤖 We use 'If... Then... Else...' logic. IF there is a wall, THEN turn, ELSE move forward. This is how brains work!",
            tasks: [
                { id: 't1', text: 'Add the "If Wall Within 2 steps" block', completed: false },
                { id: 't2', text: 'Put "Turn Right" inside the THEN part', completed: false },
                { id: 't3', text: 'Put "Forward 1" inside the ELSE part', completed: false },
                { id: 't4', text: 'Put everything inside a "Repeat 10 times" loop!', completed: false }
            ],
            hint: 'If there is a wall, I will turn. If not, I will move!',
            homework: 'Create a logic gate: move forward IF the path is clear, but spray water IF there is fire!',
            nextLesson: 'lesson-12'
        },
        {
            id: 'lesson-12',
            title: 'Fire Watch',
            description: 'Detect heat with temperature sensors',
            difficulty: 'hard',
            xpReward: 400,
            icon: '🔥',
            introduction: "I have a thermal camera to detect heat! 🌡️ Fires are dangerous, so I need to find them quickly. My sensor tells me if something is hot ahead. Let's find some fires!",
            tasks: [
                { id: 't1', text: 'Place a Fire (🔥) on the board', completed: false },
                { id: 't2', text: 'Add "Check Temp" and "If Fire Within 3 steps"', completed: false },
                { id: 't3', text: 'Add a message: "I found a fire!" when detected', completed: false }
            ],
            hint: 'Fire detection works like wall detection but feels the heat instead of sound.',
            homework: 'Find the hottest spot on the board and stay there!',
            nextLesson: 'lesson-13'
        },
        {
            id: 'lesson-13',
            title: 'Firefighter Hero',
            description: 'Extinguish fires with water',
            difficulty: 'extreme',
            xpReward: 500,
            icon: '🚒',
            introduction: "It's time for action! 🦸 I carry a small water tank. If I find a fire, I can spray water to put it out. But be careful - my water level is limited! We must be efficient.",
            tasks: [
                { id: 't1', text: 'Place 3 fires on the board', completed: false },
                { id: 't2', text: 'Use "Firefighter Mode" to auto-extinguish', completed: false },
                { id: 't3', text: 'Or build your own loop with "Spray Water"!', completed: false }
            ],
            hint: 'Each spray uses 1 unit of water. I only have 5 units!',
            homework: 'Can you put out all 3 fires using only 3 sprays? Position yourself perfectly!',
            nextLesson: 'lesson-14'
        },
        {
            id: 'lesson-14',
            title: 'Master Coder',
            description: 'The final autonomous challenge',
            difficulty: 'extreme',
            xpReward: 1000,
            icon: '🏆',
            introduction: "You've reached the end of the academy! 🎓 Now, combine everything: magnets, sensors, and logic. Your mission: pick up all metal and extinguish all fires automatically!",
            tasks: [
                { id: 't1', text: 'Place walls, metal, and fire randomly', completed: false },
                { id: 't2', text: 'Build a giant autonomous program', completed: false },
                { id: 't3', text: 'Clear the board to graduate! 🎓🎉', completed: false }
            ],
            hint: 'Use loops, if/else, and all sensor blocks. You are a Master Coder now!',
            homework: 'Congratulations, Master Coder! Now, try to build a drawing robot that creates art while avoiding fires!',
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
        <div id="code-section" class="hidden">
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
            <div class="flex bg-white rounded-b-2xl card-shadow overflow-hidden" style="height: calc(100vh - 200px); min-height: 500px;">
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
                </div>
                
                <!-- Blockly Workspace - Center -->
                <div id="blocklyDiv" class="flex-1 min-w-0"></div>
                
                <!-- Robot Panel - Right Side (Bigger canvas + chat) -->
                <div id="robotPanel" class="w-[430px] bg-white border-l-2 border-gray-200 flex flex-col transition-all duration-300">
                    <div class="bg-gradient-to-r from-blue-500 to-cyan-500 text-white p-2 flex items-center justify-between">
                        <div class="flex items-center gap-2">
                            <span class="text-xl">🤖</span>
                            <span class="font-bold">STEMO's World</span>
                        </div>
                        <div class="flex gap-1">
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
                    <!-- Placement mode indicator -->
                    <div class="bg-gray-100 px-2 py-1 text-xs text-center">
                        <span id="placementModeText">Click to place: 🔩 Metal</span>
                    </div>
                    <!-- Mission HUD (shown only in Challenge Mode) -->
                    <div id="missionHUD" class="hidden bg-gradient-to-r from-orange-500 to-rose-500 text-white px-3 py-2">
                        <div class="flex items-center justify-between mb-1">
                            <span class="text-xs font-bold uppercase tracking-wide">🏆 Challenge Mission</span>
                            <button onclick="exitChallengeMode()" class="text-white/70 hover:text-white text-xs underline">Exit Challenge</button>
                        </div>
                        <div class="font-bold text-sm mb-1" id="missionTitle">Complete the mission!</div>
                        <div id="missionObjectivesList" class="flex gap-2 flex-wrap"></div>
                    </div>
                    <div class="flex-1 p-2 flex items-center justify-center overflow-hidden relative">
                        <canvas id="robotCanvas" width="400" height="400" class="rounded-xl shadow-lg cursor-crosshair relative z-10" onclick="handleCanvasClick(event)"></canvas>
                        <div id="threeCanvasContainer" class="absolute top-2 left-2 right-2 bottom-2 rounded-xl overflow-hidden hidden z-20 pointer-events-auto"></div>
                    </div>
                    
                    <!-- Chat Area - Bigger -->
                    <div class="border-t-2 border-gray-200 bg-white p-3">
                        <div id="chatMessages" class="h-24 overflow-y-auto mb-2 space-y-1 text-sm">
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
            <div class="bg-gradient-to-r from-yellow-400 to-amber-500 rounded-2xl p-4 mb-6">
                <div class="text-white font-bold text-lg">You earned</div>
                <div class="text-4xl font-bold text-white" id="xpEarned">+50 XP</div>
            </div>
            <div class="flex gap-3 justify-center">
                <button onclick="goToLessons()" class="bg-gray-200 hover:bg-gray-300 text-gray-700 px-6 py-3 rounded-full font-bold transition-all">
                    <i class="fas fa-home mr-2"></i>All Lessons
                </button>
                <button onclick="goToNextLesson()" id="nextLessonBtn" class="bg-gradient-to-r from-green-500 to-emerald-600 text-white px-6 py-3 rounded-full font-bold hover:opacity-90 transition-all">
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
            x: 200,
            y: 200,
            angle: -90,
            penDown: false,
            penColor: '#6366f1',
            penSize: 4,
            trails: [],
            visible: true,
            magnetOn: false,
            carrying: null,
            waterLevel: 5,
            spraying: false,
            lastTemp: 25
        };
        
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
        
        // Placement mode: 'none', 'wall', 'target', 'metal'
        var placementMode = 'metal';
        
        // ============================================
        // CHALLENGE MODE STATE
        // ============================================
        var challengeMode = false;
        var missionObjectives = null;
        var challengeCompleted = false;

        var MISSION_LESSON_IDS = ['lesson-8','lesson-9','lesson-10','lesson-11','lesson-12','lesson-13','lesson-14'];

        // Pre-configured challenge worlds for each mission lesson
        var LESSON_CHALLENGES = {
            'lesson-8': {
                title: 'Collect all 3 metal pieces!',
                description: 'Activate your magnet and navigate to pick up every metal object on the board.',
                setup: function() {
                    metalObjects = [
                        { id: metalIdCounter++, x: 100, y: 100, type: 'bolt',  pickedUp: false },
                        { id: metalIdCounter++, x: 330, y: 110, type: 'gear',  pickedUp: false },
                        { id: metalIdCounter++, x: 290, y: 320, type: 'screw', pickedUp: false }
                    ];
                },
                objectives: [
                    { id: 'collect3', label: '🔩 Collect 3 metals', check: function() {
                        return metalObjects.filter(function(m){ return m.pickedUp; }).length >= 3;
                    }}
                ]
            },
            'lesson-9': {
                title: 'Navigate the wall maze to the target!',
                description: 'Use your ultrasonic sensor to detect walls and steer STEMO to the target.',
                setup: function() {
                    wallObjects = [
                        { id: wallIdCounter++, x: 140, y: 80,  width: 40, height: 120 },
                        { id: wallIdCounter++, x: 240, y: 180, width: 40, height: 120 },
                        { id: wallIdCounter++, x: 80,  y: 260, width: 120, height: 40 }
                    ];
                    targetPoint = { x: 330, y: 330 };
                },
                objectives: [
                    { id: 'reach', label: '🎯 Reach the target', check: function() {
                        if (!targetPoint) return false;
                        var dx = robot.x - targetPoint.x, dy = robot.y - targetPoint.y;
                        return Math.sqrt(dx*dx + dy*dy) < 35;
                    }}
                ]
            },
            'lesson-10': {
                title: 'Reach the target point!',
                description: 'Obstacles are in your way. Program STEMO to navigate around them and reach the goal.',
                setup: function() {
                    wallObjects = [
                        { id: wallIdCounter++, x: 140, y: 120, width: 40, height: 120 },
                        { id: wallIdCounter++, x: 220, y: 220, width: 120, height: 40 }
                    ];
                    targetPoint = { x: 330, y: 330 };
                },
                objectives: [
                    { id: 'reach', label: '🎯 Reach the target', check: function() {
                        if (!targetPoint) return false;
                        var dx = robot.x - targetPoint.x, dy = robot.y - targetPoint.y;
                        return Math.sqrt(dx*dx + dy*dy) < 35;
                    }}
                ]
            },
            'lesson-11': {
                title: 'Solve the branching maze!',
                description: 'There is a wall blocking the middle. Use If/Else logic to find the correct path to the target.',
                setup: function() {
                    wallObjects = [
                        { id: wallIdCounter++, x: 180, y: 60,  width: 40, height: 130 },
                        { id: wallIdCounter++, x: 180, y: 250, width: 40, height: 110 }
                    ];
                    targetPoint = { x: 330, y: 200 };
                },
                objectives: [
                    { id: 'reach', label: '🎯 Reach the target', check: function() {
                        if (!targetPoint) return false;
                        var dx = robot.x - targetPoint.x, dy = robot.y - targetPoint.y;
                        return Math.sqrt(dx*dx + dy*dy) < 35;
                    }}
                ]
            },
            'lesson-12': {
                title: 'Detect both fires with your sensor!',
                description: 'Fires are hidden around the board. Scan with your temperature sensor to locate them.',
                setup: function() {
                    wallObjects = [
                        { id: wallIdCounter++, x: 160, y: 140, width: 40, height: 40 }
                    ];
                    fireObjects = [
                        { id: fireIdCounter++, x: 110, y: 310, health: 3 },
                        { id: fireIdCounter++, x: 320, y: 140, health: 3 }
                    ];
                },
                objectives: [
                    { id: 'detect1', label: '🌡️ Find fire 1', targetFire: 0, check: function() {
                        if (fireObjects.length < 1) return false;
                        var f = fireObjects[0];
                        var dx = robot.x - f.x, dy = robot.y - f.y;
                        return Math.sqrt(dx*dx + dy*dy) < 65;
                    }},
                    { id: 'detect2', label: '🌡️ Find fire 2', targetFire: 1, check: function() {
                        if (fireObjects.length < 2) return false;
                        var f = fireObjects[1];
                        var dx = robot.x - f.x, dy = robot.y - f.y;
                        return Math.sqrt(dx*dx + dy*dy) < 65;
                    }}
                ]
            },
            'lesson-13': {
                title: 'Extinguish all 3 fires!',
                description: 'Navigate around walls and spray water on every fire before your tank runs out!',
                setup: function() {
                    wallObjects = [
                        { id: wallIdCounter++, x: 140, y: 120, width: 100, height: 40 },
                        { id: wallIdCounter++, x: 250, y: 230, width: 40, height: 100 }
                    ];
                    fireObjects = [
                        { id: fireIdCounter++, x: 90,  y: 200, health: 3 },
                        { id: fireIdCounter++, x: 210, y: 110, health: 3 },
                        { id: fireIdCounter++, x: 320, y: 320, health: 3 }
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
                        { id: wallIdCounter++, x: 130, y: 100, width: 40, height: 100 },
                        { id: wallIdCounter++, x: 230, y: 180, width: 100, height: 40 },
                        { id: wallIdCounter++, x: 175, y: 285, width: 90, height: 40 }
                    ];
                    metalObjects = [
                        { id: metalIdCounter++, x: 90,  y: 310, type: 'bolt', pickedUp: false },
                        { id: metalIdCounter++, x: 330, y: 90,  type: 'gear', pickedUp: false }
                    ];
                    fireObjects = [
                        { id: fireIdCounter++, x: 75,  y: 150, health: 3 },
                        { id: fireIdCounter++, x: 320, y: 290, health: 3 }
                    ];
                    targetPoint = { x: 330, y: 200 };
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
                        return Math.sqrt(dx*dx + dy*dy) < 35;
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

        function updateMagneticPull() {
            if (!robot.magnetOn || robot.carrying) return;

            var pullRange = 120; // 6 steps
            var pullStrength = 1.5;

            metalObjects.forEach(function(metal) {
                if (!metal.pickedUp) {
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
            document.getElementById('missionHUD').classList.add('hidden');
            clearAll();
            addChatMessage('stemo', '🤖 Exited challenge mode. Board cleared — build freely!');
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
            metalObjects = []; wallObjects = []; fireObjects = [];
            targetPoint = null; selectedObject = null; selectedObjectType = null;
            robot.waterLevel = 5; robot.spraying = false; robot.carrying = null; robot.magnetOn = false;

            if (withChallenge) {
                var challenge = LESSON_CHALLENGES[currentLesson.id];
                if (challenge) {
                    // Set up mission objectives state
                    missionObjectives = challenge.objectives.map(function(obj) {
                        return { id: obj.id, label: obj.label, done: false, check: obj.check };
                    });
                    // Show mission HUD immediately
                    document.getElementById('missionTitle').textContent = challenge.title;
                    document.getElementById('missionHUD').classList.remove('hidden');
                    updateMissionHUD();
                    addChatMessage('stemo', '🏆 Challenge loaded! ' + challenge.description + ' Good luck! 💪');
                    // Defer world population to ensure canvas is ready after tab switch
                    var lessonId = currentLesson.id;
                    setTimeout(function() {
                        metalObjects = []; wallObjects = []; fireObjects = [];
                        targetPoint = null;
                        robot.waterLevel = 5; robot.spraying = false; robot.carrying = null; robot.magnetOn = false;
                        var ch = LESSON_CHALLENGES[lessonId];
                        if (ch) {
                            ch.setup();
                            drawRobot();
                        }
                    }, 200);
                }
            } else {
                document.getElementById('missionHUD').classList.add('hidden');
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
        }

        function checkChallengeObjectives() {
            if (!challengeMode || !missionObjectives || challengeCompleted) return;
            var allDone = true;
            var anyChanged = false;
            missionObjectives.forEach(function(obj) {
                var wasDone = obj.done;
                obj.done = obj.check();
                if (obj.done && !wasDone) anyChanged = true;
                if (!obj.done) allDone = false;
            });
            if (anyChanged) updateMissionHUD();
            if (allDone && !challengeCompleted) {
                challengeCompleted = true;
                setTimeout(function() {
                    addChatMessage('stemo', '🎉 MISSION COMPLETE! Amazing work! 🏆');
                    if (currentLesson && !stemo.completedLessons.includes(currentLesson.id)) {
                        completeLesson(currentLesson);
                    } else {
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
                this.setTooltip("Navigate to target, avoiding walls");
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

            // Reset robot before running
            robot.x = 200;
            robot.y = 200;
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
                
                // Handle go_to_target specially
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
                
                robot.x = Math.max(25, Math.min(375, newX));
                robot.y = Math.max(25, Math.min(375, newY));
                
                // Check if magnet is ON and can pick up nearby metal
                if (robot.magnetOn && !robot.carrying) {
                    var pickupRange = 35;
                    for (var m = 0; m < metalObjects.length; m++) {
                        var metal = metalObjects[m];
                        if (!metal.pickedUp) {
                            var dx = metal.x - robot.x;
                            var dy = metal.y - robot.y;
                            var dist = Math.sqrt(dx * dx + dy * dy);
                            if (dist < pickupRange) {
                                robot.carrying = metal;
                                metal.pickedUp = true;
                                addChatMessage('stemo', "🤖 🧲 Picked up " + metal.type + "! 🎉");
                                break;
                            }
                        }
                    }
                }
            } else if (cmd.action === 'turn') {
                robot.angle += cmd.value;
            } else if (cmd.action === 'home') {
                // Go home without drawing
                robot.x = 200;
                robot.y = 200;
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
                if (cmd.value) {
                    // Magnet ON - try to pick up nearby metal
                    if (!robot.carrying) {
                        var pickupRange = 35; // pixels distance to pick up
                        for (var m = 0; m < metalObjects.length; m++) {
                            var metal = metalObjects[m];
                            var dx = metal.x - robot.x;
                            var dy = metal.y - robot.y;
                            var dist = Math.sqrt(dx * dx + dy * dy);
                            if (dist < pickupRange) {
                                robot.carrying = metal;
                                metal.pickedUp = true;
                                addChatMessage('stemo', "🤖 🧲 Got it! I picked up the " + metal.type + "! 🎉");
                                break;
                            }
                        }
                        if (!robot.carrying) {
                            addChatMessage('stemo', "🤖 🧲 Magnet ON! Move closer to a metal object to pick it up.");
                        }
                    }
                } else {
                    // Magnet OFF - drop the object IN FRONT of the robot
                    if (robot.carrying) {
                        // Drop 40 pixels in front of robot's current direction
                        var dropRad = robot.angle * Math.PI / 180;
                        var dropX = robot.x + Math.cos(dropRad) * 40;
                        var dropY = robot.y + Math.sin(dropRad) * 40;
                        
                        // Keep within bounds
                        dropX = Math.max(25, Math.min(375, dropX));
                        dropY = Math.max(25, Math.min(375, dropY));
                        
                        robot.carrying.x = dropX;
                        robot.carrying.y = dropY;
                        robot.carrying.pickedUp = false;
                        addChatMessage('stemo', "🤖 🧲 Dropped the " + robot.carrying.type + " in front! 📍");
                        robot.carrying = null;
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
                    
                    robot.x = Math.max(25, Math.min(375, newX));
                    robot.y = Math.max(25, Math.min(375, newY));
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
                // Spray water to extinguish fire
                if (robot.waterLevel <= 0) {
                    addChatMessage('stemo', "💧 Water tank empty! Return to base to refill.");
                } else {
                    var fireInfo = detectFireAhead();
                    if (fireInfo.fire && fireInfo.distance < 60) { // Within 3 steps
                        robot.waterLevel--;
                        fireInfo.fire.health--;
                        robot.spraying = true;
                        
                        if (fireInfo.fire.health <= 0) {
                            // Fire extinguished!
                            fireObjects = fireObjects.filter(function(f) { return f !== fireInfo.fire; });
                            addChatMessage('stemo', "💧💥 Fire extinguished! Great job! 🎉 Water left: " + robot.waterLevel + "/5");
                        } else {
                            addChatMessage('stemo', "💧 Spraying water! Fire health: " + fireInfo.fire.health + "/3 | Water left: " + robot.waterLevel + "/5");
                        }
                        
                        // Visual effect - clear spray flag after delay
                        setTimeout(function() { robot.spraying = false; drawRobot(); }, 500);
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
            var minDist = 999;
            
            // Check all 4 boundaries
            if (dx > 0) {
                var t = (375 - rx) / dx;
                if (t > 0 && t < minDist) minDist = t;
            } else if (dx < 0) {
                var t = (25 - rx) / dx;
                if (t > 0 && t < minDist) minDist = t;
            }
            
            if (dy > 0) {
                var t = (375 - ry) / dy;
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
                temp = Math.max(baseTemp, Math.min(500, baseTemp + (200 - minDist) * 2.5));
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
                    var dx = 200 - robot.x;
                    var dy = 200 - robot.y;
                    var dist = Math.sqrt(dx * dx + dy * dy);
                    
                    if (dist < 30) {
                        robot.waterLevel = 5;
                        addChatMessage('stemo', "💧 Tank refilled! Water: 5/5");
                    } else {
                        var desiredAngle = Math.atan2(dy, dx) * 180 / Math.PI;
                        robot.angle = desiredAngle;
                        var rad = robot.angle * Math.PI / 180;
                        robot.x += Math.cos(rad) * 15;
                        robot.y += Math.sin(rad) * 15;
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
                    setTimeout(() => { robot.spraying = false; }, 1000);
                    
                    if (nearestFire.health <= 0) {
                        fireObjects = fireObjects.filter(function(f) { return f !== nearestFire; });
                        addChatMessage('stemo', "🚒💧 Fire out! " + fireObjects.length + " fires remaining. Water: " + robot.waterLevel + "/5");
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
                        var turnDir = chooseBestTurnDirection();
                        robot.angle += turnDir;
                    } else if (Math.abs(angleDiff) > 15) {
                        robot.angle += angleDiff > 0 ? 15 : -15;
                    } else {
                        var rad = robot.angle * Math.PI / 180;
                        robot.x += Math.cos(rad) * 15;
                        robot.y += Math.sin(rad) * 15;
                        
                        robot.x = Math.max(25, Math.min(375, robot.x));
                        robot.y = Math.max(25, Math.min(375, robot.y));
                    }
                }
                
                stepCount++;
                drawRobot();
                setTimeout(firefightStep, 150);
            }
            
            addChatMessage('stemo', "🚒 Firefighter mode activated! Searching for fires...");
            firefightStep();
        }
        
        function executeGoToTarget(onComplete) {
            if (!targetPoint) {
                if (onComplete) onComplete();
                return;
            }
            
            var maxSteps = 100; // Safety limit
            var stepCount = 0;
            
            function moveStep() {
                if (stepCount >= maxSteps) {
                    addChatMessage('stemo', "🎯 Gave up after 100 steps! Try clearing some walls.");
                    if (onComplete) onComplete();
                    return;
                }
                
                // Check if reached target
                var dx = targetPoint.x - robot.x;
                var dy = targetPoint.y - robot.y;
                var dist = Math.sqrt(dx * dx + dy * dy);
                
                if (dist < 25) {
                    addChatMessage('stemo', "🎯 Target reached! 🎉");
                    drawRobot();
                    if (currentLesson) {
                        checkLessonCompletion();
                    }
                    if (onComplete) onComplete();
                    return;
                }
                
                // Calculate desired angle to target
                var desiredAngle = Math.atan2(dy, dx) * 180 / Math.PI;
                var angleDiff = desiredAngle - robot.angle;
                
                // Normalize angle difference
                while (angleDiff > 180) angleDiff -= 360;
                while (angleDiff < -180) angleDiff += 360;
                
                // Check for wall ahead
                var wallDist = detectWallAhead();
                
                if (wallDist <= 30) {
                    // Wall ahead - use smart turn to choose best direction
                    var turnDir = chooseBestTurnDirection();
                    robot.angle += turnDir;
                } else if (Math.abs(angleDiff) > 15) {
                    // Need to turn toward target
                    robot.angle += angleDiff > 0 ? 15 : -15;
                } else {
                    // Move forward
                    var rad = robot.angle * Math.PI / 180;
                    robot.x += Math.cos(rad) * 20;
                    robot.y += Math.sin(rad) * 20;
                    
                    // Bounds
                    robot.x = Math.max(25, Math.min(375, robot.x));
                    robot.y = Math.max(25, Math.min(375, robot.y));
                }
                
                stepCount++;
                drawRobot();
                setTimeout(moveStep, 150);
            }
            
            addChatMessage('stemo', "🎯 Navigating to target...");
            moveStep();
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
            
            // Draw Metals with distance indicators
            // Group metals by location
            var metalGroups = groupObjects(metalObjects);
            
            Object.values(metalGroups).forEach(function(group) {
                var item = group[0];
                
                var dx = item.x - robot.x;
                var dy = item.y - robot.y;
                var dist = Math.sqrt(dx * dx + dy * dy);
                
                ctx.save();
                
                // Highlight if selected
                if (selectedObject === item) {
                    ctx.shadowColor = '#06b6d4';
                    ctx.shadowBlur = 15;
                } else {
                    ctx.shadowColor = 'rgba(0,0,0,0.2)';
                    ctx.shadowBlur = 5;
                    ctx.shadowOffsetY = 3;
                }
                
                // Draw metal shape - larger and bright in challenge mode
                var mR = challengeMode ? 16 : 10; // radius / size scale
                if (item.type === 'bolt') {
                    // Glow ring in challenge mode
                    if (challengeMode) {
                        ctx.beginPath();
                        ctx.arc(item.x, item.y, mR + 6, 0, Math.PI * 2);
                        ctx.fillStyle = 'rgba(251, 191, 36, 0.25)';
                        ctx.fill();
                    }
                    // Hexagon body
                    ctx.fillStyle = challengeMode ? '#f59e0b' : '#94a3b8';
                    ctx.beginPath();
                    for (var i = 0; i < 6; i++) {
                        ctx.lineTo(item.x + mR * Math.cos(i * Math.PI / 3 - Math.PI/6), item.y + mR * Math.sin(i * Math.PI / 3 - Math.PI/6));
                    }
                    ctx.closePath();
                    ctx.fill();
                    ctx.strokeStyle = challengeMode ? '#d97706' : '#64748b';
                    ctx.lineWidth = challengeMode ? 2.5 : 1.5;
                    ctx.stroke();
                    // Inner hex detail
                    ctx.fillStyle = challengeMode ? '#fcd34d' : '#cbd5e1';
                    ctx.beginPath();
                    for (var i = 0; i < 6; i++) {
                        ctx.lineTo(item.x + (mR*0.5) * Math.cos(i * Math.PI / 3 - Math.PI/6), item.y + (mR*0.5) * Math.sin(i * Math.PI / 3 - Math.PI/6));
                    }
                    ctx.closePath();
                    ctx.fill();
                } else if (item.type === 'gear') {
                    // Glow ring in challenge mode
                    if (challengeMode) {
                        ctx.beginPath();
                        ctx.arc(item.x, item.y, mR + 6, 0, Math.PI * 2);
                        ctx.fillStyle = 'rgba(99, 102, 241, 0.25)';
                        ctx.fill();
                    }
                    // Gear body
                    ctx.fillStyle = challengeMode ? '#6366f1' : '#78716c';
                    ctx.beginPath();
                    var outerRadius = mR;
                    var innerRadius = mR * 0.68;
                    var spikes = 8;
                    for (var i = 0; i < spikes * 2; i++) {
                        var r = (i % 2 === 0) ? outerRadius : innerRadius;
                        var a = Math.PI * i / spikes;
                        ctx.lineTo(item.x + r * Math.cos(a), item.y + r * Math.sin(a));
                    }
                    ctx.closePath();
                    ctx.fill();
                    ctx.strokeStyle = challengeMode ? '#4338ca' : '#57534e';
                    ctx.lineWidth = challengeMode ? 2 : 1;
                    ctx.stroke();
                    ctx.beginPath();
                    ctx.arc(item.x, item.y, mR * 0.28, 0, Math.PI*2);
                    ctx.fillStyle = challengeMode ? '#a5b4fc' : '#44403c';
                    ctx.fill();
                } else {
                    // Screw — circle with cross
                    if (challengeMode) {
                        ctx.beginPath();
                        ctx.arc(item.x, item.y, mR + 6, 0, Math.PI * 2);
                        ctx.fillStyle = 'rgba(16, 185, 129, 0.25)';
                        ctx.fill();
                    }
                    ctx.fillStyle = challengeMode ? '#10b981' : '#a1a1aa';
                    ctx.beginPath();
                    ctx.arc(item.x, item.y, mR, 0, Math.PI * 2);
                    ctx.fill();
                    ctx.strokeStyle = challengeMode ? '#059669' : '#52525b';
                    ctx.lineWidth = challengeMode ? 2.5 : 1.5;
                    ctx.stroke();
                    var cx = mR * 0.55;
                    ctx.beginPath();
                    ctx.moveTo(item.x - cx, item.y - cx);
                    ctx.lineTo(item.x + cx, item.y + cx);
                    ctx.moveTo(item.x + cx, item.y - cx);
                    ctx.lineTo(item.x - cx, item.y + cx);
                    ctx.strokeStyle = challengeMode ? '#d1fae5' : '#e4e4e7';
                    ctx.lineWidth = challengeMode ? 3 : 2;
                    ctx.stroke();
                }
                
                ctx.restore();
                
                // In challenge mode: always show type label above metal
                if (challengeMode && !item.pickedUp) {
                    var emoji = item.type === 'bolt' ? '🔩' : item.type === 'gear' ? '⚙️' : '🪛';
                    ctx.font = 'bold 13px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillStyle = '#1f2937';
                    ctx.fillText(emoji, item.x, item.y - mR - 4);
                }
                
                // Distance Text (only if close)
                if (dist < 100 && !item.pickedUp) {
                    ctx.fillStyle = challengeMode ? '#1d4ed8' : '#6b7280';
                    ctx.font = challengeMode ? 'bold 10px Arial' : '10px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText(Math.round(dist/20) + ' steps', item.x, item.y + mR + 14);
                    
                    // Dashed line to nearest
                    if (dist < 80) {
                        ctx.beginPath();
                        ctx.setLineDash([3, 5]);
                        ctx.strokeStyle = challengeMode ? 'rgba(99,102,241,0.4)' : 'rgba(107, 114, 128, 0.3)';
                        ctx.lineWidth = challengeMode ? 2 : 1;
                        ctx.moveTo(robot.x, robot.y);
                        ctx.lineTo(item.x, item.y);
                        ctx.stroke();
                        ctx.setLineDash([]);
                    }
                }
                
                // Draw Count Badge if stacked
                if (group.length > 1) {
                    drawCountBadge(ctx, item.x + 8, item.y - 8, group.length);
                }
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
                ctx.fillText('💧 Water: ' + robot.waterLevel + '/5', 10, canvas.height - 20);
                
                // Draw water bar
                ctx.fillStyle = '#e5e7eb';
                ctx.fillRect(10, canvas.height - 15, 50, 8);
                ctx.fillStyle = '#3b82f6';
                ctx.fillRect(10, canvas.height - 15, (robot.waterLevel / 5) * 50, 8);
                ctx.restore();
            }
            
            // Draw robot (only if visible)
            if (robot.visible) {
                ctx.save();
                ctx.translate(robot.x, robot.y);
                ctx.rotate((robot.angle + 90) * Math.PI / 180);
                
                // Body - change color if magnet is on
                ctx.fillStyle = robot.magnetOn ? '#ef4444' : '#3b82f6';
                ctx.beginPath();
                ctx.roundRect(-20, -25, 40, 50, 8);
                ctx.fill();
                
                // Magnetic field lines - Realistic arcs
                if (robot.magnetOn) {
                    ctx.save();
                    ctx.rotate(Math.PI); // Orient toward the back/around
                    
                    var time = Date.now() / 1000;
                    ctx.lineWidth = 1.5;
                    
                    for (var i = 0; i < 3; i++) {
                        var radius = 25 + (i * 15 + time * 30) % 45;
                        var opacity = 1 - (radius - 25) / 45;
                        
                        ctx.strokeStyle = 'rgba(239, 68, 68, ' + (opacity * 0.6) + ')';
                        ctx.setLineDash([5, 5]);
                        
                        ctx.beginPath();
                        // Draw two arcs representing magnetic field
                        ctx.arc(0, 0, radius, -Math.PI/3, Math.PI/3);
                        ctx.stroke();
                        
                        ctx.beginPath();
                        ctx.arc(0, 0, radius, Math.PI - Math.PI/3, Math.PI + Math.PI/3);
                        ctx.stroke();
                    }
                    ctx.restore();
                    
                    // Center glow
                    var gradient = ctx.createRadialGradient(0, 0, 10, 0, 0, 40);
                    gradient.addColorStop(0, 'rgba(239, 68, 68, 0.2)');
                    gradient.addColorStop(1, 'rgba(239, 68, 68, 0)');
                    ctx.fillStyle = gradient;
                    ctx.beginPath();
                    ctx.arc(0, 0, 40, 0, Math.PI * 2);
                    ctx.fill();
                }
            
                // Head
                ctx.fillStyle = robot.magnetOn ? '#f87171' : '#60a5fa';
                ctx.beginPath();
                ctx.arc(0, -15, 15, 0, Math.PI * 2);
                ctx.fill();
                
                // Eyes
                ctx.fillStyle = 'white';
                ctx.beginPath();
                ctx.arc(-6, -18, 5, 0, Math.PI * 2);
                ctx.arc(6, -18, 5, 0, Math.PI * 2);
                ctx.fill();
                
                // Pupils - heart eyes when carrying something
                if (robot.carrying) {
                    ctx.fillStyle = '#ef4444';
                    ctx.font = '8px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText('❤', -5, -15);
                    ctx.fillText('❤', 7, -15);
                } else {
                    ctx.fillStyle = '#1e3a5f';
                    ctx.beginPath();
                    ctx.arc(-5, -17, 2, 0, Math.PI * 2);
                    ctx.arc(7, -17, 2, 0, Math.PI * 2);
                    ctx.fill();
                }
                
                // Antenna - show magnet icon when ON
                ctx.strokeStyle = robot.magnetOn ? '#ef4444' : '#fbbf24';
                ctx.lineWidth = 3;
                ctx.beginPath();
                ctx.moveTo(0, -30);
                ctx.lineTo(0, -40);
                ctx.stroke();
                
                if (robot.magnetOn) {
                    // Magnet shape on antenna
                    ctx.fillStyle = '#ef4444';
                    ctx.beginPath();
                    ctx.arc(0, -45, 6, 0, Math.PI * 2);
                    ctx.fill();
                    ctx.fillStyle = 'white';
                    ctx.font = 'bold 8px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText('🧲', 0, -42);
                } else {
                    ctx.fillStyle = '#fbbf24';
                    ctx.beginPath();
                    ctx.arc(0, -42, 4, 0, Math.PI * 2);
                    ctx.fill();
                }
            
                // Direction arrow
                ctx.fillStyle = '#22c55e';
                ctx.beginPath();
                ctx.moveTo(0, -25);
                ctx.lineTo(-8, -10);
                ctx.lineTo(8, -10);
                ctx.closePath();
                ctx.fill();
                
                // Draw carried object attached to robot
                if (robot.carrying) {
                    ctx.save();
                    ctx.translate(0, 20); // Below robot body
                    ctx.fillStyle = '#94a3b8';
                    ctx.beginPath();
                    ctx.arc(0, 0, 8, 0, Math.PI * 2);
                    ctx.fill();
                    ctx.fillStyle = '#475569';
                    ctx.font = '10px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText('🔩', 0, 4);
                    ctx.restore();
                }
                
                ctx.restore();
            }
            
        }

        function resetRobot() {
            robot = {
                x: 200,
                y: 200,
                angle: -90,
                penDown: false,
                penColor: '#6366f1',
                penSize: 4,
                trails: [],
                visible: true,
                magnetOn: false,
                carrying: null,
                waterLevel: 5,
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
            document.getElementById('xpEarned').textContent = '+' + xp + ' XP';
            
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
                setTimeout(function() {
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
                    classHtml += '<div class="flex items-center gap-2"><span class="text-blue-500">🏫</span><span class="font-semibold text-gray-700">Class:</span><span class="text-gray-600">' + data.class.name + '</span></div>';
                    if (data.class.teacher_name) {
                        classHtml += '<div class="flex items-center gap-2"><span class="text-purple-500">👩‍🏫</span><span class="font-semibold text-gray-700">Teacher:</span><span class="text-gray-600">' + data.class.teacher_name + '</span></div>';
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

                // Top 3 podium
                var podiumHtml = '';
                var podiumOrder = [1, 0, 2]; // silver, gold, bronze display order
                podiumOrder.forEach(function(idx) {
                    var s = data[idx];
                    if (!s) return;
                    var isMe = s.id == myId;
                    var lessons = 0;
                    try { lessons = JSON.parse(s.completed_lessons || '[]').length; } catch(e) {}
                    podiumHtml += '<div class="flex flex-col items-center gap-2 ' + (idx === 0 ? 'order-2' : idx === 1 ? 'order-1' : 'order-3') + '">';
                    podiumHtml += '<div class="text-3xl">' + medals[idx] + '</div>';
                    podiumHtml += '<div class="w-14 h-14 rounded-full bg-gradient-to-br ' + podiumColors[idx] + ' flex items-center justify-center text-2xl font-bold text-white border-4 ' + (isMe ? 'border-indigo-500' : 'border-white') + '">' + (s.full_name || 'S')[0].toUpperCase() + '</div>';
                    podiumHtml += '<div class="text-center"><div class="font-bold text-sm text-gray-800 max-w-20 truncate">' + (s.full_name || s.username) + (isMe ? ' <span class="text-indigo-500">★</span>' : '') + '</div>';
                    podiumHtml += '<div class="text-yellow-500 font-bold text-sm">⭐ ' + (s.xp || 0) + '</div></div>';
                    podiumHtml += '<div class="bg-gradient-to-t ' + podiumColors[idx] + ' rounded-t-xl w-20 ' + podiumSizes[idx] + '"></div>';
                    podiumHtml += '</div>';
                });
                document.getElementById('podiumRow').innerHTML = podiumHtml;

                // Full list (skip first 3 in table, they appear in podium)
                var listHtml = data.slice(3).map(function(s, i) {
                    var rank = i + 4;
                    var isMe = s.id == myId;
                    var lessons = 0;
                    try { lessons = JSON.parse(s.completed_lessons || '[]').length; } catch(e) {}
                    return '<div class="flex items-center gap-4 p-4 rounded-2xl ' + (isMe ? 'bg-indigo-50 border-2 border-indigo-400' : 'border border-gray-100 hover:bg-gray-50') + ' transition-all">' +
                        '<div class="text-lg font-bold text-gray-400 w-8 text-center">#' + rank + '</div>' +
                        '<div class="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-400 to-purple-500 flex items-center justify-center text-lg font-bold text-white">' + (s.full_name || 'S')[0].toUpperCase() + '</div>' +
                        '<div class="flex-1 min-w-0">' +
                            '<div class="font-bold text-gray-800 truncate">' + (s.full_name || s.username) + (isMe ? ' <span class="bg-indigo-500 text-white text-xs px-2 py-0.5 rounded-full ml-1">You</span>' : '') + '</div>' +
                            '<div class="text-gray-400 text-xs">@' + s.username + ' · Level ' + (s.level || 1) + '</div>' +
                        '</div>' +
                        '<div class="text-right shrink-0">' +
                            '<div class="font-bold text-yellow-500">⭐ ' + (s.xp || 0) + '</div>' +
                            '<div class="text-gray-400 text-xs">' + lessons + '/14 lessons · ' + (s.streak || 0) + '🔥</div>' +
                        '</div>' +
                    '</div>';
                }).join('');

                // Also show top 3 in full list with highlight
                var top3Html = data.slice(0, 3).map(function(s, i) {
                    var isMe = s.id == myId;
                    var lessons = 0;
                    try { lessons = JSON.parse(s.completed_lessons || '[]').length; } catch(e) {}
                    return '<div class="flex items-center gap-4 p-4 rounded-2xl ' + (isMe ? 'bg-indigo-50 border-2 border-indigo-400' : 'bg-gradient-to-r from-yellow-50 to-amber-50 border border-yellow-200') + ' transition-all">' +
                        '<div class="text-2xl w-8 text-center">' + medals[i] + '</div>' +
                        '<div class="w-10 h-10 rounded-full bg-gradient-to-br from-yellow-400 to-amber-500 flex items-center justify-center text-lg font-bold text-white">' + (s.full_name || 'S')[0].toUpperCase() + '</div>' +
                        '<div class="flex-1 min-w-0">' +
                            '<div class="font-bold text-gray-800 truncate">' + (s.full_name || s.username) + (isMe ? ' <span class="bg-indigo-500 text-white text-xs px-2 py-0.5 rounded-full ml-1">You</span>' : '') + '</div>' +
                            '<div class="text-gray-400 text-xs">@' + s.username + ' · Level ' + (s.level || 1) + '</div>' +
                        '</div>' +
                        '<div class="text-right shrink-0">' +
                            '<div class="font-bold text-yellow-500">⭐ ' + (s.xp || 0) + '</div>' +
                            '<div class="text-gray-400 text-xs">' + lessons + '/14 lessons · ' + (s.streak || 0) + '🔥</div>' +
                        '</div>' +
                    '</div>';
                }).join('');

                document.getElementById('leaderboardList').innerHTML = '<div class="space-y-2 mb-4">' + top3Html + '</div>' + (listHtml ? '<div class="space-y-2">' + listHtml + '</div>' : '');
            } catch(e) {
                document.getElementById('leaderboardList').innerHTML = '<p class="text-center text-gray-400 py-8">Unable to load leaderboard</p>';
            }
        }
        
        // ============================================
        // PLACEMENT MODE & CANVAS CLICK HANDLER
        // ============================================
        function setPlacementMode(mode) {
            placementMode = mode;
            
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
            
            // Update indicator text
            var modeText = {
                'metal': 'Click to place: 🔩 Metal',
                'wall': 'Click & drag to place: 🧱 Wall',
                'fire': 'Click to place: 🔥 Fire',
                'target': 'Click to place: 🎯 Target'
            };
            document.getElementById('placementModeText').textContent = modeText[mode] || 'Click to place';
            
            addChatMessage('stemo', '🤖 Mode: ' + modeText[mode]);
        }
        
        var wallStartPos = null;
        
        function handleCanvasClick(event) {
            var canvas = document.getElementById('robotCanvas');
            var rect = canvas.getBoundingClientRect();
            var x = (event.clientX - rect.left) * (canvas.width / rect.width);
            var y = (event.clientY - rect.top) * (canvas.height / rect.height);
            
            // Keep within bounds
            x = Math.max(20, Math.min(380, x));
            y = Math.max(20, Math.min(380, y));
            
            // First, check if we clicked on an existing object (for selection)
            // Only select if we are NOT in placement mode (allowing stacking)
            var clickedObject = findObjectAt(x, y);
            if (clickedObject && !placementMode) {
                selectedObject = clickedObject.obj;
                selectedObjectType = clickedObject.type;
                drawRobot();
                addChatMessage('stemo', '🤖 Selected ' + clickedObject.type + '! Press Delete or click 🗑️ to remove.');
                return;
            }
            
            // Clear selection when clicking empty space for placement
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
            robot.waterLevel = 5; // Refill water
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
            camera.position.set(0, 300, 300); // Isometric angle but closer
            camera.lookAt(200, 0, 200); // Look at center of board

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
            controls.target.set(200, 0, 200);
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

            // Floor
            var floorGeometry = new THREE.PlaneGeometry(440, 440);
            var floorMaterial = new THREE.MeshStandardMaterial({ 
                color: 0xf0fdf4,
                side: THREE.DoubleSide
            });
            var floor = new THREE.Mesh(floorGeometry, floorMaterial);
            floor.rotation.x = -Math.PI / 2;
            floor.position.set(200, -1, 200);
            floor.receiveShadow = true;
            scene.add(floor);
            
            // Grid helper
            var gridHelper = new THREE.GridHelper(400, 20, 0x86efac, 0xe5e7eb);
            gridHelper.position.set(200, 0, 200);
            scene.add(gridHelper);
            
            // Robot Group (The Hover Bot)
            threeRobot = new THREE.Group();
            scene.add(threeRobot);
            
            // 1. Floating Body (Capsule-like)
            var bodyGeo = new THREE.SphereGeometry(25, 32, 32);
            bodyGeo.scale(1, 1.4, 1); // Make it an egg shape
            var bodyMat = new THREE.MeshStandardMaterial({ 
                color: 0xffffff, // White
                roughness: 0.2,  // Glossy
                metalness: 0.1
            });
            var body = new THREE.Mesh(bodyGeo, bodyMat);
            body.position.y = 40; // Hovering height
            threeRobot.add(body);
            
            // 2. Black Glass Visor
            var visorGeo = new THREE.SphereGeometry(22, 32, 32, 0, 6.3, 0, 1.2);
            visorGeo.scale(1, 1.2, 0.8);
            var visorMat = new THREE.MeshStandardMaterial({ 
                color: 0x111111, // Black
                roughness: 0.0,  // Glass styling
                metalness: 0.8
            });
            var visor = new THREE.Mesh(visorGeo, visorMat);
            visor.position.set(0, 42, 8); // Slightly forward
            visor.rotation.x = -0.2;
            threeRobot.add(visor);
            
            // 3. Glowing Eyes
            var eyeGeo = new THREE.SphereGeometry(3.5, 16, 16);
            var eyeMat = new THREE.MeshBasicMaterial({ color: 0x00ffff }); // Cyan Glow
            
            var eyeLeft = new THREE.Mesh(eyeGeo, eyeMat);
            eyeLeft.position.set(8, 44, 26);
            threeRobot.add(eyeLeft);
            
            var eyeRight = new THREE.Mesh(eyeGeo, eyeMat);
            eyeRight.position.set(-8, 44, 26);
            threeRobot.add(eyeRight);

            // 4. Shadow (Separate from robot so it stays on floor)
            var shadowGeo = new THREE.CircleGeometry(20, 32);
            var shadowMat = new THREE.MeshBasicMaterial({ 
                color: 0x000000, 
                transparent: true, 
                opacity: 0.3 
            });
            threeShadow = new THREE.Mesh(shadowGeo, shadowMat);
            threeShadow.rotation.x = -Math.PI / 2;
            threeShadow.position.set(200, 1, 200); // Slightly above floor
            scene.add(threeShadow);

            threeRobot.position.set(200, 0, 200);
        }

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
            
            // Magnet visual (Update Eyes Color instead of Body)
            // Eyes are children 2 and 3 in the group
            if (threeRobot.children.length > 2) {
                 var eyeColor = robot.magnetOn ? 0xff0000 : 0x00ffff; // Red if magnet on, Cyan default
                 if (threeRobot.children[2].material) threeRobot.children[2].material.color.setHex(eyeColor);
                 if (threeRobot.children[3].material) threeRobot.children[3].material.color.setHex(eyeColor);
            }
            
            // Sync Metals
            // Remove old metals
            threeMetals.forEach(m => scene.remove(m));
            threeMetals = [];
            
            var metalGroups = groupObjects(metalObjects);
            Object.values(metalGroups).forEach(function(group) {
                group.forEach(function(m, index) {
                    if (!m.pickedUp) {
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
                version: '1.0'
            };
            
            var jsonString = JSON.stringify(projectData, null, 2);
            var blob = new Blob([jsonString], {type: "text/plain"});
            var url = URL.createObjectURL(blob);
            
            var a = document.createElement('a');
            a.href = url;
            a.download = "stemo_project_" + new Date().getTime() + ".txt";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            // Backup: Copy to clipboard
            navigator.clipboard.writeText(jsonString).then(function() {
                addChatMessage('stemo', "💾 Project saved! (Also copied to clipboard 📋)");
            }, function() {
                addChatMessage('stemo', "💾 Project saved as .txt file!");
            });
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
                        
                        // Load world if available
                        if (projectData.world) {
                            robot = projectData.world.robot || robot;
                            wallObjects = projectData.world.walls || [];
                            metalObjects = projectData.world.metals || [];
                            fireObjects = projectData.world.fires || [];
                            targetPoint = projectData.world.target || null;
                            
                            // Reset robot visual state but keep position
                            robot.trails = [];
                            robot.carrying = null;
                            robot.magnetOn = false;
                            
                            drawRobot();
                        }
                        
                        addChatMessage('stemo', "📂 Project loaded! Let's code! 🚀");
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
                <h2 class="text-xl">Classes</h2>
                <button onclick="showCreateClass()" class="bg-indigo-600 text-white px-4 py-2 rounded-xl font-bold text-sm hover:bg-indigo-700">+ Add Class</button>
            </div>
            <div id="createClassForm" class="hidden bg-indigo-50 rounded-xl p-4 mb-4 border border-indigo-200">
                <h3 class="font-bold text-indigo-700 mb-3">Create New Class</h3>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <input id="newClassName" placeholder="Class Name" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400">
                    <input id="newClassDesc" placeholder="Description (optional)" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400">
                    <select id="newClassTeacher" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400">
                        <option value="">— Assign Teacher (optional) —</option>
                    </select>
                </div>
                <div class="flex gap-2 mt-3">
                    <button onclick="createClass()" class="bg-indigo-600 text-white px-4 py-2 rounded-lg text-sm font-bold hover:bg-indigo-700">✅ Create</button>
                    <button onclick="document.getElementById('createClassForm').classList.add('hidden')" class="bg-gray-200 px-4 py-2 rounded-lg text-sm font-bold">Cancel</button>
                </div>
                <div id="createClassMsg" class="mt-2 text-sm hidden"></div>
            </div>
            <div id="classesList" class="space-y-4"></div>
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

async function loadClasses() {
    const classes = await fetch('/api/classes').then(r=>r.json());
    document.getElementById('statClasses').textContent = classes.length;
    if (!classes.length) {
        document.getElementById('classesList').innerHTML = '<p class="text-gray-400 text-center py-8">No classes yet. Click "+ Add Class" to create one.</p>';
        return;
    }
    const container = document.getElementById('classesList');
    container.innerHTML = '';
    for (const cls of classes) {
        const students = await fetch('/api/classes/' + cls.id + '/students').then(r=>r.json());
        const available = await fetch('/api/classes/' + cls.id + '/available-students').then(r=>r.json());
        const studentRows = students.map(s => \`
            <tr class="border-b hover:bg-gray-50">
                <td class="py-2 font-semibold text-sm">\${s.full_name}<span class="text-gray-400 text-xs ml-1">@\${s.username}</span></td>
                <td class="py-2 text-xs text-yellow-500 font-bold">⭐ \${s.xp||0}</td>
                <td class="py-2 text-xs"><span class="bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded-full">Lv \${s.level||1}</span></td>
                <td class="py-2"><button onclick="removeStudentFromClass(\${cls.id},\${s.id})" class="text-red-400 hover:text-red-600 text-xs">✕ Remove</button></td>
            </tr>\`).join('');
        const availableOpts = available.map(s => \`<option value="\${s.id}">\${s.full_name} (@\${s.username})</option>\`).join('');
        const div = document.createElement('div');
        div.className = 'border rounded-xl p-5 bg-white shadow-sm';
        div.innerHTML = \`
            <div class="flex items-center justify-between mb-3">
                <div>
                    <h3 class="font-bold text-gray-800 text-lg">\${cls.name}</h3>
                    <p class="text-gray-400 text-sm">\${cls.description || ''}</p>
                </div>
                <div class="text-right">
                    <span class="bg-indigo-100 text-indigo-700 text-xs font-bold px-3 py-1 rounded-full">\${students.length} students</span>
                    <div class="text-blue-500 text-xs mt-1">📚 \${cls.teacher_name || '— Unassigned —'}</div>
                </div>
            </div>
            \${students.length ? \`<div class="overflow-x-auto mb-3"><table class="w-full text-sm"><thead><tr class="border-b text-gray-400 text-xs"><th class="pb-1 text-left">Student</th><th class="pb-1 text-left">XP</th><th class="pb-1 text-left">Level</th><th class="pb-1"></th></tr></thead><tbody>\${studentRows}</tbody></table></div>\` : '<p class="text-gray-400 text-sm mb-3">No students enrolled yet.</p>'}
            \${available.length ? \`<div class="flex gap-2 items-center mt-2"><select id="addStudentSel_\${cls.id}" class="flex-1 border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:border-indigo-400"><option value="">+ Add a student to this class...</option>\${availableOpts}</select><button onclick="addStudentToClass(\${cls.id})" class="bg-indigo-600 text-white px-4 py-1.5 rounded-lg text-sm font-bold hover:bg-indigo-700">Add</button></div>\` : '<p class="text-gray-400 text-xs mt-2">All approved students are enrolled.</p>'}
        \`;
        container.appendChild(div);
    }
}

async function removeStudentFromClass(classId, studentId) {
    await fetch('/api/classes/' + classId + '/students/' + studentId, { method: 'DELETE' });
    loadClasses();
}

async function addStudentToClass(classId) {
    const sel = document.getElementById('addStudentSel_' + classId);
    if (!sel.value) return;
    await fetch('/api/classes/' + classId + '/students', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ student_id: sel.value }) });
    loadClasses();
}

async function loadLinkDropdowns() {
    const users = allUsers.length ? allUsers : await fetch('/api/admin/users').then(r=>r.json());
    const parents = users.filter(u=>u.role==='parent');
    const students = users.filter(u=>u.role==='student');
    document.getElementById('linkParent').innerHTML = parents.map(u=>\`<option value="\${u.id}">\${u.full_name}</option>\`).join('');
    document.getElementById('linkStudent').innerHTML = students.map(u=>\`<option value="\${u.id}">\${u.full_name}</option>\`).join('');
}

function showCreateUser() { document.getElementById('createUserForm').classList.toggle('hidden'); }
async function showCreateClass() {
    document.getElementById('createClassForm').classList.toggle('hidden');
    const teachers = await fetch('/api/teachers').then(r=>r.json());
    const sel = document.getElementById('newClassTeacher');
    sel.innerHTML = '<option value="">— Assign Teacher (optional) —</option>' + teachers.map(t=>\`<option value="\${t.id}">\${t.full_name} (@\${t.username})</option>\`).join('');
}

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

async function createClass() {
    const name = document.getElementById('newClassName').value.trim();
    const msg = document.getElementById('createClassMsg');
    if (!name) { msg.className='mt-2 text-sm text-red-600'; msg.classList.remove('hidden'); msg.textContent='Class name is required.'; return; }
    const res = await fetch('/api/classes', { method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ name, description: document.getElementById('newClassDesc').value, teacher_id: document.getElementById('newClassTeacher').value || null })
    });
    const data = await res.json();
    if (data.success) {
        document.getElementById('newClassName').value = '';
        document.getElementById('newClassDesc').value = '';
        document.getElementById('createClassForm').classList.add('hidden');
        loadClasses();
    } else {
        msg.className='mt-2 text-sm text-red-600'; msg.classList.remove('hidden'); msg.textContent='❌ ' + (data.error||'Failed');
    }
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
    {id:'lesson-7',title:'Star Power!',icon:'⭐',desc:'Draw a beautiful 5-pointed star',diff:'hard',xp:300,group:'🟡 Intermediate'},
    {id:'lesson-8',title:'Magnet Magic',icon:'🧲',desc:'Pick up metal objects with your magnet',diff:'medium',xp:200,group:'🟡 Intermediate'},
    {id:'lesson-9',title:'Ultrasonic Sight',icon:'📡',desc:'See walls using sound waves',diff:'medium',xp:250,group:'🟡 Intermediate'},
    {id:'lesson-10',title:'Space Navigator',icon:'🎯',desc:'Reach targets automatically',diff:'hard',xp:300,group:'🔴 Advanced'},
    {id:'lesson-11',title:'Smart Explorer',icon:'🧠',desc:'Make decisions with If/Else logic',diff:'hard',xp:350,group:'🔴 Advanced'},
    {id:'lesson-12',title:'Fire Watch',icon:'🔥',desc:'Detect heat with temperature sensors',diff:'hard',xp:400,group:'🔴 Advanced'},
    {id:'lesson-13',title:'Firefighter Hero',icon:'🚒',desc:'Extinguish fires with water',diff:'extreme',xp:500,group:'🔴 Advanced'},
    {id:'lesson-14',title:'Master Coder',icon:'🏆',desc:'The final autonomous challenge',diff:'extreme',xp:1000,group:'🔴 Advanced'}
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
            <img src="/static/steam-logo-white.png" alt="STEMO Coding" class="h-10 object-contain" style="filter: invert(27%) sepia(90%) saturate(700%) hue-rotate(240deg) brightness(80%);">
            <span class="fredoka text-2xl text-purple-700 tracking-wide">STEMO Coding</span>
        </a>
        <div class="flex items-center gap-3">
            <a href="/login" class="px-5 py-2 rounded-full border-2 border-purple-600 text-purple-700 font-bold hover:bg-purple-50 transition-all text-sm">Login</a>
            <a href="/register" class="px-5 py-2 rounded-full bg-purple-600 text-white font-bold hover:bg-purple-700 transition-all text-sm shadow-md">Register Free</a>
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
                        <img src="/static/steam-logo-white.png" alt="STEMO Robot" class="w-48 md:w-64 object-contain drop-shadow-2xl">
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
    <div class="max-w-5xl mx-auto px-6">
        <div class="grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
            <div class="stat-card rounded-2xl p-6">
                <div class="fredoka text-4xl text-white mb-1">10+</div>
                <div class="text-purple-200 text-sm font-semibold">Interactive Lessons</div>
            </div>
            <div class="stat-card rounded-2xl p-6">
                <div class="fredoka text-4xl text-white mb-1">4</div>
                <div class="text-purple-200 text-sm font-semibold">User Roles</div>
            </div>
            <div class="stat-card rounded-2xl p-6">
                <div class="fredoka text-4xl text-white mb-1">100%</div>
                <div class="text-purple-200 text-sm font-semibold">Interactive Learning</div>
            </div>
            <div class="stat-card rounded-2xl p-6">
                <div class="fredoka text-4xl text-white mb-1">∞</div>
                <div class="text-purple-200 text-sm font-semibold">Fun Guaranteed</div>
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

<!-- ========== FEATURES ========== -->
<section class="py-24 bg-white">
    <div class="max-w-7xl mx-auto px-6">
        <div class="text-center mb-16">
            <span class="badge-pill mb-4">🎯 Platform Features</span>
            <h2 class="fredoka text-4xl md:text-5xl text-gray-900 mb-4">Everything Kids Need to Thrive</h2>
            <p class="text-gray-500 text-lg max-w-2xl mx-auto">A complete ecosystem built for modern STEAM education — engaging, measurable, and fun.</p>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-8">
            <div class="feature-card rounded-3xl p-8 bg-gradient-to-br from-purple-50 to-violet-100 border border-purple-100">
                <div class="text-4xl mb-4">🤖</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">AI Robot Guide (STEMO)</h3>
                <p class="text-gray-600 leading-relaxed">A friendly AI-powered robot character who teaches, encourages, and guides students through every lesson with personality and humor.</p>
            </div>
            <div class="feature-card rounded-3xl p-8 bg-gradient-to-br from-blue-50 to-cyan-100 border border-blue-100">
                <div class="text-4xl mb-4">🧩</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Block-Based Programming</h3>
                <p class="text-gray-600 leading-relaxed">Visual drag-and-drop coding blocks make programming intuitive — no typing required. Kids learn logic, loops, conditions, and sensors.</p>
            </div>
            <div class="feature-card rounded-3xl p-8 bg-gradient-to-br from-yellow-50 to-amber-100 border border-yellow-100">
                <div class="text-4xl mb-4">⭐</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Gamification & XP System</h3>
                <p class="text-gray-600 leading-relaxed">Earn XP points, level up, unlock badges, and maintain daily streaks. Learning feels like a game — kids come back every day.</p>
            </div>
            <div class="feature-card rounded-3xl p-8 bg-gradient-to-br from-green-50 to-emerald-100 border border-green-100">
                <div class="text-4xl mb-4">📊</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Teacher Dashboard</h3>
                <p class="text-gray-600 leading-relaxed">Teachers manage classes, approve students, assign specific lessons, monitor progress in real-time, and reset passwords easily.</p>
            </div>
            <div class="feature-card rounded-3xl p-8 bg-gradient-to-br from-pink-50 to-rose-100 border border-pink-100">
                <div class="text-4xl mb-4">👨‍👩‍👧</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Parent Monitoring Portal</h3>
                <p class="text-gray-600 leading-relaxed">Parents stay connected with a dedicated portal to view their child's XP, completed lessons, badges earned, and daily streaks.</p>
            </div>
            <div class="feature-card rounded-3xl p-8 bg-gradient-to-br from-orange-50 to-red-100 border border-orange-100">
                <div class="text-4xl mb-4">🏆</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Live Leaderboard</h3>
                <p class="text-gray-600 leading-relaxed">A class-wide leaderboard ranks students by XP and level, creating healthy competition and motivating every learner to push further.</p>
            </div>
            <div class="feature-card rounded-3xl p-8 bg-gradient-to-br from-teal-50 to-cyan-100 border border-teal-100">
                <div class="text-4xl mb-4">📡</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Robotics Simulation</h3>
                <p class="text-gray-600 leading-relaxed">Students program a virtual robot with sensors, magnets, ultrasonic sight, and movement commands — real robotics concepts made accessible.</p>
            </div>
            <div class="feature-card rounded-3xl p-8 bg-gradient-to-br from-indigo-50 to-blue-100 border border-indigo-100">
                <div class="text-4xl mb-4">💬</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">AI Chat Assistant</h3>
                <p class="text-gray-600 leading-relaxed">Students can ask STEMO questions anytime. The AI assistant explains concepts in kid-friendly language, keeping learning fun and self-directed.</p>
            </div>
            <div class="feature-card rounded-3xl p-8 bg-gradient-to-br from-violet-50 to-purple-100 border border-violet-100">
                <div class="text-4xl mb-4">🎯</div>
                <h3 class="text-xl font-extrabold text-gray-800 mb-2">Structured Curriculum</h3>
                <p class="text-gray-600 leading-relaxed">10+ carefully designed lessons covering movement, drawing, loops, sensors, magnets, and advanced challenges — progressive and comprehensive.</p>
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
                <a href="/register" class="block w-full py-3 rounded-full bg-gray-900 text-white font-bold hover:bg-gray-800 transition-all shadow-lg">🎉 Register Free</a>
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
