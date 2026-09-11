import { Hono } from 'hono'
import { cors } from 'hono/cors'

type Bindings = {
    AI: any
    DB: D1Database
    JWT_SECRET: string
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
// INPUT VALIDATION HELPERS
// ============================================

// Reject strings containing HTML-special characters (prevents stored XSS)
function hasHtmlChars(str: string): boolean {
    return /[<>"'`]/.test(str)
}

// Only allow http:// and https:// URLs — blocks javascript: data: etc.
function isSafeUrl(url: string): boolean {
    try {
        const u = new URL(url)
        return u.protocol === 'http:' || u.protocol === 'https:'
    } catch { return false }
}

const VALID_ROLES = ['admin', 'teacher', 'student', 'parent']

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

// JWT secret — reads from env var when available, falls back to default for dev
// In production set JWT_SECRET via: wrangler pages secret put JWT_SECRET
function getJwtSecret(env?: any): string {
    return env?.JWT_SECRET || 'stemo-secret-key-2024'
}

async function createToken(payload: any, env?: any): Promise<string> {
    const header = b64url(btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })))
    const body = b64url(btoa(unescape(encodeURIComponent(JSON.stringify({ ...payload, exp: Date.now() + 86400000 * 7 })))))
    const encoder = new TextEncoder()
    const key = await crypto.subtle.importKey('raw', encoder.encode(getJwtSecret(env)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(`${header}.${body}`))
    const sigB64 = b64url(btoa(String.fromCharCode(...new Uint8Array(sig))))
    return `${header}.${body}.${sigB64}`
}

function b64urlDecode(str: string): string {
    str = str.replace(/-/g, '+').replace(/_/g, '/')
    while (str.length % 4) str += '='
    return decodeURIComponent(escape(atob(str)))
}

async function verifyToken(token: string, env?: any): Promise<any> {
    try {
        const parts = token.split('.')
        if (parts.length !== 3) return null

        // 1. Verify HMAC signature before trusting any payload data
        const encoder = new TextEncoder()
        const key = await crypto.subtle.importKey(
            'raw', encoder.encode(getJwtSecret(env)),
            { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
        )
        const sigBytes = Uint8Array.from(
            atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')),
            (c) => c.charCodeAt(0)
        )
        const valid = await crypto.subtle.verify(
            'HMAC', key, sigBytes,
            encoder.encode(`${parts[0]}.${parts[1]}`)
        )
        if (!valid) return null

        // 2. Only decode payload after signature is confirmed valid
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
    const payload = await verifyToken(token, c.env)
    if (!payload) return c.json({ error: 'Invalid token' }, 401)
    c.set('user', payload)
    await next()
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Global error handler — log internally, never expose stack traces to clients
app.onError((err, c) => {
    console.error('[ERROR]', err.message, err.stack)
    return c.json({ error: 'Internal server error' }, 500)
})


// Enable CORS — restrict to known production origins only
app.use('/api/*', cors({
    origin: (origin) => {
        const allowed = [
            'https://stemo-coding.pages.dev',
            'https://8f1b3afd.stemo-coding.pages.dev',
        ]
        // Allow same-origin requests (no Origin header) and known origins
        if (!origin || allowed.some(o => origin === o || origin.endsWith('.stemo-coding.pages.dev'))) {
            return origin || '*'
        }
        return null
    },
    credentials: true,
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type'],
}))

// Security headers — applied to every response
app.use('*', async (c, next) => {
    await next()
    c.res.headers.set('X-Content-Type-Options', 'nosniff')
    c.res.headers.set('X-Frame-Options', 'DENY')
    c.res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
    // Interactive lesson pages are trusted viewer shells. Untrusted HTML is placed
    // inside an opaque-origin sandboxed iframe; CSP blocks API/fetch connections.
    if (c.req.path.startsWith('/interactive-lessons/')) {
        c.res.headers.set('Content-Security-Policy',
            "default-src 'none'; " +
            "script-src 'unsafe-inline' https:; " +
            "style-src 'unsafe-inline' https:; " +
            "img-src data: https:; " +
            "font-src data: https:; " +
            "media-src data: https:; " +
            "frame-src data:; " +
            "connect-src 'none'; " +
            "form-action 'none'; " +
            "base-uri 'none'; " +
            "frame-ancestors 'none'"
        )
        c.res.headers.set('Cache-Control', 'no-store')
        return
    }
    // CSP: allow inline scripts/styles (needed for server-rendered pages) but lock down
    // connect-src to self (blocks XSS data-exfiltration), frame-src to YouTube only
    c.res.headers.set('Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com https://blockly-demo.appspot.com; " +
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
        "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.gstatic.com; " +
        "img-src 'self' data: https://img.youtube.com https://i.ytimg.com; " +
        "frame-src https://www.youtube.com https://youtube.com; " +
        "connect-src 'self'; " +
        "object-src 'none'; " +
        "base-uri 'self'"
    )
})

// Auto-migrate: create any missing tables on first request
app.use('*', async (c, next) => {
    if (c.env?.DB) {
        try {
            await c.env.DB.prepare(`CREATE TABLE IF NOT EXISTS lesson_videos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lesson_name TEXT NOT NULL,
                youtube_url TEXT NOT NULL,
                sort_order INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`).run()
            await c.env.DB.prepare(`CREATE TABLE IF NOT EXISTS interactive_lessons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                html_content TEXT NOT NULL,
                lesson_number INTEGER,
                is_published INTEGER NOT NULL DEFAULT 1,
                sort_order INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`).run()
            try {
                await c.env.DB.prepare('ALTER TABLE interactive_lessons ADD COLUMN lesson_number INTEGER').run()
            } catch(_) {}
            await c.env.DB.prepare(`
                UPDATE interactive_lessons AS target
                SET lesson_number = target.sort_order
                WHERE target.lesson_number IS NULL
                  AND target.sort_order > 0
                  AND (SELECT COUNT(*) FROM interactive_lessons AS matching WHERE matching.sort_order = target.sort_order) = 1
            `).run()
            try {
                await c.env.DB.prepare(
                    'CREATE UNIQUE INDEX IF NOT EXISTS idx_interactive_lessons_lesson_number ON interactive_lessons(lesson_number) WHERE lesson_number IS NOT NULL'
                ).run()
            } catch(_) {}
        } catch(_) {}
    }
    return next()
})

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
        const token = await createToken({ id: user.id, username: user.username, role: user.role, full_name: user.full_name }, c.env)
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
        if (username.length > 50) return c.json({ error: 'Username must be 50 characters or less' }, 400)
        if (full_name.length > 100) return c.json({ error: 'Name must be 100 characters or less' }, 400)
        if (password.length < 6) return c.json({ error: 'Password must be at least 6 characters' }, 400)
        if (password.length > 200) return c.json({ error: 'Password too long' }, 400)
        if (hasHtmlChars(username)) return c.json({ error: 'Username contains invalid characters' }, 400)
        if (hasHtmlChars(full_name)) return c.json({ error: 'Name contains invalid characters (< > " \' ` not allowed)' }, 400)
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
                const parent = await c.env.DB.prepare("SELECT id FROM users WHERE username = ? AND role = 'parent' AND (status = 'approved' OR status IS NULL)").bind(parent_username).first() as any
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
    // Teachers can only approve/reject students — not other teachers or admins
    if (me.role === 'teacher') {
        const target = await c.env.DB.prepare("SELECT role FROM users WHERE id = ?").bind(id).first() as any
        if (!target || target.role !== 'student') return c.json({ error: 'Teachers can only approve student accounts' }, 403)
    }
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
    res.headers.set('Set-Cookie', 'stemo_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0')
    return res
})

// Self-service password change — requires current password (anti-abuse)
app.post('/api/auth/change-password', authMiddleware, async (c) => {
    const me = c.get('user')
    const body = await c.req.json()
    const current_password = body.current_password || ''
    const new_password = body.new_password || ''
    if (!current_password || !new_password) return c.json({ error: 'Both fields are required' }, 400)
    if (new_password.length < 6) return c.json({ error: 'New password must be at least 6 characters' }, 400)
    if (new_password.length > 200) return c.json({ error: 'Password too long' }, 400)
    if (current_password === new_password) return c.json({ error: 'New password must differ from current password' }, 400)
    const currentHash = await hashPassword(current_password)
    const user = await c.env.DB.prepare('SELECT id FROM users WHERE id = ? AND password_hash = ?').bind(me.id, currentHash).first()
    if (!user) return c.json({ error: 'Current password is incorrect' }, 400)
    const newHash = await hashPassword(new_password)
    await c.env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(newHash, me.id).run()
    return c.json({ success: true })
})

// Get current user
app.get('/api/auth/me', async (c) => {
    const cookie = c.req.header('cookie') || ''
    const token = getCookieToken(cookie)
    if (!token) return c.json({ user: null })
    const payload = await verifyToken(token, c.env)
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
    if (!VALID_ROLES.includes(role)) return c.json({ error: 'Invalid role' }, 400)
    if (username.length > 50) return c.json({ error: 'Username must be 50 characters or less' }, 400)
    if (full_name.length > 100) return c.json({ error: 'Name must be 100 characters or less' }, 400)
    if (password.length > 200) return c.json({ error: 'Password too long' }, 400)
    if (hasHtmlChars(username)) return c.json({ error: 'Username contains invalid characters' }, 400)
    if (hasHtmlChars(full_name)) return c.json({ error: 'Name contains invalid characters' }, 400)
    const hash = await hashPassword(password)
    try {
        const result = await c.env.DB.prepare('INSERT INTO users (username, password_hash, role, full_name, status) VALUES (?, ?, ?, ?, ?)').bind(username, hash, role, full_name, 'approved').run()
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

// Change user role (admin only)
app.put('/api/admin/users/:id/role', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const id = c.req.param('id')
    if (String(id) === String(me.id)) return c.json({ error: 'Cannot change your own role' }, 400)
    const { role } = await c.req.json()
    const allowed = ['student', 'teacher', 'parent', 'admin']
    if (!allowed.includes(role)) return c.json({ error: 'Invalid role' }, 400)
    await c.env.DB.prepare('UPDATE users SET status = ? WHERE id = ?').bind('approved', id).run()
    await c.env.DB.prepare('UPDATE users SET role = ? WHERE id = ?').bind(role, id).run()
    // Any non-student role: remove from class_students and wipe student_progress
    if (role !== 'student') {
        await c.env.DB.prepare('DELETE FROM class_students WHERE student_id = ?').bind(id).run()
        await c.env.DB.prepare('DELETE FROM student_progress WHERE student_id = ?').bind(id).run()
    }
    return c.json({ success: true, role })
})

// Delete user
app.delete('/api/admin/users/:id', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const id = c.req.param('id')
    if (String(id) === String(me.id)) return c.json({ error: 'Cannot delete your own account' }, 400)
    try {
        // Cascade: remove from all related tables before deleting the user
        await c.env.DB.prepare('DELETE FROM parent_students WHERE parent_id = ? OR student_id = ?').bind(id, id).run()
        await c.env.DB.prepare('DELETE FROM class_students WHERE student_id = ?').bind(id).run()
        await c.env.DB.prepare('DELETE FROM student_progress WHERE student_id = ?').bind(id).run()
        await c.env.DB.prepare('DELETE FROM chat_history WHERE student_id = ?').bind(id).run()
        await c.env.DB.prepare('DELETE FROM assigned_lessons WHERE assigned_by = ?').bind(id).run()
        // Remove as teacher from classes (nullify rather than delete the class)
        await c.env.DB.prepare('UPDATE classes SET teacher_id = NULL WHERE teacher_id = ?').bind(id).run()
        await c.env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run()
        return c.json({ success: true })
    } catch (err: any) {
        return c.json({ error: 'Delete failed: ' + (err?.message || String(err)) }, 500)
    }
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
        const { results } = await c.env.DB.prepare('SELECT c.*, u.full_name as teacher_name, s.name as school_name FROM classes c LEFT JOIN users u ON c.teacher_id = u.id LEFT JOIN schools s ON s.id = c.school_id ORDER BY c.created_at DESC').all()
        rows = results
    } else if (me.role === 'teacher') {
        const { results } = await c.env.DB.prepare('SELECT c.*, u.full_name as teacher_name, s.name as school_name FROM classes c LEFT JOIN users u ON c.teacher_id = u.id LEFT JOIN schools s ON s.id = c.school_id WHERE c.teacher_id = ? ORDER BY c.created_at DESC').bind(me.id).all()
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
        SELECT u.id, u.username, u.full_name, sp.xp, sp.level, sp.completed_lessons, sp.streak,
               s.name as school_name
        FROM class_students cs JOIN users u ON cs.student_id = u.id
        LEFT JOIN student_progress sp ON sp.student_id = u.id
        LEFT JOIN classes cl ON cl.id = cs.class_id
        LEFT JOIN schools s ON s.id = cl.school_id
        WHERE cs.class_id = ?
    `).bind(classId).all()
    return c.json(results)
})

// Add student to class
app.post('/api/classes/:id/students', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin' && me.role !== 'teacher') return c.json({ error: 'Forbidden' }, 403)
    const classId = c.req.param('id')
    // Teachers can only add students to their own classes
    if (me.role === 'teacher') {
        const cls = await c.env.DB.prepare('SELECT id FROM classes WHERE id = ? AND teacher_id = ?').bind(classId, me.id).first()
        if (!cls) return c.json({ error: 'Forbidden: not your class' }, 403)
    }
    const { student_id } = await c.req.json()
    await c.env.DB.prepare('INSERT OR IGNORE INTO class_students (class_id, student_id) VALUES (?, ?)').bind(classId, student_id).run()
    return c.json({ success: true })
})

// Remove student from class
app.delete('/api/classes/:id/students/:studentId', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin' && me.role !== 'teacher') return c.json({ error: 'Forbidden' }, 403)
    const classId = c.req.param('id')
    // Teachers can only remove students from their own classes
    if (me.role === 'teacher') {
        const cls = await c.env.DB.prepare('SELECT id FROM classes WHERE id = ? AND teacher_id = ?').bind(classId, me.id).first()
        if (!cls) return c.json({ error: 'Forbidden: not your class' }, 403)
    }
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
            WHERE role = 'student' AND (status = 'approved' OR status IS NULL)
            AND id NOT IN (SELECT DISTINCT student_id FROM class_students)
            ORDER BY full_name`
        args = []
    } else {
        query = `SELECT id, full_name, username FROM users
            WHERE role = 'student' AND (status = 'approved' OR status IS NULL)
            AND id NOT IN (SELECT DISTINCT student_id FROM class_students)
            ORDER BY full_name`
        args = []
    }
    const stmt = c.env.DB.prepare(query)
    const { results } = await (args.length ? stmt.bind(...args) : stmt).all()
    return c.json(results)
})

// Get students available to enrol into a specific class.
// Admin: all approved students not already in THIS class (supports transfer UI).
// Teacher: only students not assigned to ANY class (strict — no poaching from other teachers).
app.get('/api/classes/:id/available-students', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin' && me.role !== 'teacher') return c.json({ error: 'Forbidden' }, 403)
    const classId = c.req.param('id')
    if (me.role === 'admin') {
        const { results } = await c.env.DB.prepare(`
            SELECT id, full_name, username FROM users
            WHERE role = 'student' AND (status = 'approved' OR status IS NULL)
            AND id NOT IN (SELECT student_id FROM class_students WHERE class_id = ?)
            ORDER BY full_name
        `).bind(classId).all()
        return c.json(results)
    } else {
        // Teacher: only truly unassigned students (not in any class at all)
        const { results } = await c.env.DB.prepare(`
            SELECT id, full_name, username FROM users
            WHERE role = 'student' AND (status = 'approved' OR status IS NULL)
            AND id NOT IN (SELECT DISTINCT student_id FROM class_students)
            ORDER BY full_name
        `).all()
        return c.json(results)
    }
})

// Get all students with their current class assignment (admin only — for search/transfer UI)
app.get('/api/admin/students-with-class', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const { results } = await c.env.DB.prepare(`
        SELECT u.id, u.full_name, u.username, cs.class_id, c.name as class_name,
               s.name as school_name
        FROM users u
        LEFT JOIN class_students cs ON cs.student_id = u.id
        LEFT JOIN classes c ON c.id = cs.class_id
        LEFT JOIN schools s ON s.id = c.school_id
        WHERE u.role = 'student' AND (u.status = 'approved' OR u.status IS NULL)
        ORDER BY u.full_name
    `).all()
    return c.json(results)
})

// Get teachers list (admin only)
app.get('/api/teachers', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const { results } = await c.env.DB.prepare("SELECT id, full_name, username FROM users WHERE role = 'teacher' AND (status = 'approved' OR status IS NULL) ORDER BY full_name").all()
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

function progressPayload(progress: any, studentId: string | number) {
    const completedLessons = JSON.parse(progress?.completed_lessons || '[]')
    const earnedBadges = JSON.parse(progress?.earned_badges || '[]')
    return {
        student_id: studentId,
        xp: Number(progress?.xp || 0),
        level: Number(progress?.level || 1),
        completed_lessons: completedLessons,
        earned_badges: earnedBadges,
        streak: Number(progress?.streak || 0),
        progress_revision: String(progress?.updated_at || ''),
    }
}

function newProgressRevision(): string {
    return `${new Date().toISOString()}|${crypto.randomUUID()}`
}

// Get student progress
app.get('/api/progress/:studentId', authMiddleware, async (c) => {
    const me = c.get('user')
    const studentId = c.req.param('studentId')
    // Students can only view their own progress
    if (me.role === 'student' && String(me.id) !== studentId) return c.json({ error: 'Forbidden' }, 403)
    // Parents can only view progress of their linked children
    if (me.role === 'parent') {
        const link = await c.env.DB.prepare('SELECT 1 FROM parent_students WHERE parent_id = ? AND student_id = ?').bind(me.id, studentId).first()
        if (!link) return c.json({ error: 'Forbidden' }, 403)
    }
    const progress = await c.env.DB.prepare('SELECT * FROM student_progress WHERE student_id = ?').bind(studentId).first()
    return c.json(progressPayload(progress, studentId))
})

// Save student progress — server-authoritative validation
app.post('/api/progress', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'student') return c.json({ error: 'Only students can save progress' }, 403)

    const body = await c.req.json()

    // ── Build lookup maps from server-side curriculum ──────────────────────
    const allLessons = [...curriculum.basic, ...curriculum.intermediate, ...curriculum.advanced, ...curriculum.creative, ...curriculum.challenges] as any[]
    const validLessonIds = new Set(allLessons.map((l: any) => l.id))
    const lessonXpMap: Record<string, number> = {}
    allLessons.forEach((l: any) => { lessonXpMap[l.id] = l.xpReward || 0 })
    const validBadgeIds = new Set((badges as any[]).map((b: any) => b.id))

    // ── Load current stored progress (prevents rollback attacks) ───────────
    const stored = await c.env.DB.prepare(
        'SELECT xp, level, completed_lessons, earned_badges, streak, updated_at FROM student_progress WHERE student_id = ?'
    ).bind(me.id).first() as any
    const storedRevision = String(stored?.updated_at || '')
    const clientRevision = typeof body.progress_revision === 'string' ? body.progress_revision : ''
    if (clientRevision !== storedRevision) {
        return c.json({
            success: false,
            error: 'stale_progress',
            ...progressPayload(stored, me.id),
        }, 409)
    }
    const storedLessons: string[] = JSON.parse(stored?.completed_lessons || '[]')
    const storedBadges: string[]  = JSON.parse(stored?.earned_badges   || '[]')

    // ── Sanitize completed_lessons ─────────────────────────────────────────
    // Merge with stored (completions can never shrink). NEW completions are
    // gated: max 3 per save, and each must be UNLOCKED (previous lesson in the
    // main path completed; creative lessons always unlocked; a -challenge ID
    // requires its base lesson in the set). Prevents claiming many lessons in
    // one forged request.
    const incomingLessons = Array.isArray(body.completed_lessons)
        ? body.completed_lessons
        : []
    const currentSet = new Set(storedLessons.filter((id: string) => validLessonIds.has(id)))
    const mainPath: string[] = [...curriculum.basic, ...curriculum.intermediate, ...curriculum.advanced].map((l: any) => l.id)
    const creativeIds = new Set(curriculum.creative.map((l: any) => l.id))
    // Teacher-assigned lessons are playable even ahead of normal progression
    const assignedRows = await c.env.DB.prepare(`
        SELECT al.lesson_id FROM assigned_lessons al
        JOIN class_students cs ON cs.class_id = al.class_id
        WHERE cs.student_id = ?
    `).bind(me.id).all() as any
    const assignedIds = new Set((assignedRows?.results || []).map((r: any) => r.lesson_id))
    const isUnlocked = (id: string): boolean => {
        if (creativeIds.has(id)) return true
        if (assignedIds.has(id)) return true
        const idx = mainPath.indexOf(id)
        if (idx !== -1) return idx === 0 || currentSet.has(mainPath[idx - 1])
        if (id.endsWith('-challenge')) return currentSet.has(id.slice(0, -'-challenge'.length))
        return false
    }
    const newIds: string[] = [...new Set(incomingLessons.filter((id: any) =>
        typeof id === 'string' && validLessonIds.has(id) && !currentSet.has(id)))] as string[]
    // Base lessons before their challenges so a same-save lesson+challenge pair works
    newIds.sort((a, b) => (a.endsWith('-challenge') ? 1 : 0) - (b.endsWith('-challenge') ? 1 : 0))
    // Cooldown: if the last save was < 20s ago, accept at most 1 new completion
    // (slows down scripted rapid-fire requests without blocking real students)
    const storedTimestamp = stored?.updated_at ? String(stored.updated_at).split('|')[0] : ''
    const lastSaveMs = storedTimestamp
        ? Date.parse(storedTimestamp.includes('T') ? storedTimestamp : storedTimestamp.replace(' ', 'T') + 'Z')
        : 0
    const maxNew = (lastSaveMs && Date.now() - lastSaveMs < 20000) ? 1 : 3
    let added = 0
    for (const id of newIds) {
        if (added >= maxNew) break
        if (isUnlocked(id)) { currentSet.add(id); added++ }
    }
    const safeLessons = [...currentSet]

    // ── Compute XP server-side from completed lessons ──────────────────────
    // Client-supplied XP is completely ignored — prevents any XP injection
    const xp = safeLessons.reduce((sum: number, id: string) => sum + (lessonXpMap[id] || 0), 0)

    // ── Compute level server-side ──────────────────────────────────────────
    const level = Math.floor(xp / 500) + 1

    // ── Compute streak server-side ─────────────────────────────────────────
    // Derived from the date of the last save (UTC): same day keeps it,
    // consecutive day +1, a gap resets to 1. Client streak value is ignored.
    const storedStreak = Number(stored?.streak || 0)
    const today = new Date().toISOString().slice(0, 10)
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10)
    const lastDate = stored?.updated_at ? String(stored.updated_at).slice(0, 10) : null
    let safeStreak: number
    if (!lastDate) safeStreak = 1
    else if (lastDate === today) safeStreak = Math.max(1, Math.min(365, storedStreak))
    else if (lastDate === yesterday) safeStreak = Math.min(365, storedStreak + 1)
    else safeStreak = 1

    // ── Compute earned_badges server-side ──────────────────────────────────
    // Client badge claims are ignored; badges are recomputed from the
    // server-authoritative XP / level / lesson count / streak (stored badges kept)
    const isBadgeEarnedServer = (b: any): boolean => {
        if (b.type === 'lessons') return safeLessons.length >= b.threshold
        if (b.type === 'streak')  return safeStreak >= b.threshold
        if (b.type === 'level')   return level >= b.threshold
        return xp >= b.threshold // xp (default)
    }
    const earnedNow = (badges as any[]).filter(isBadgeEarnedServer).map((b: any) => b.id)
    const safeBadges = [...new Set([
        ...storedBadges.filter((id: string) => validBadgeIds.has(id)),
        ...earnedNow
    ])]

    const nextRevision = newProgressRevision()
    const saveResult = stored
        ? await c.env.DB.prepare(`
            UPDATE student_progress
            SET xp=?, level=?, completed_lessons=?, earned_badges=?, streak=?,
                updated_at=?
            WHERE student_id=? AND updated_at=?
        `).bind(
            xp, level, JSON.stringify(safeLessons), JSON.stringify(safeBadges),
            safeStreak, nextRevision, me.id, storedRevision
        ).run()
        : await c.env.DB.prepare(`
            INSERT OR IGNORE INTO student_progress
                (student_id, xp, level, completed_lessons, earned_badges, streak, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(
            me.id, xp, level, JSON.stringify(safeLessons),
            JSON.stringify(safeBadges), safeStreak, nextRevision
        ).run()

    if (!saveResult.meta.changes) {
        const fresh = await c.env.DB.prepare(
            'SELECT * FROM student_progress WHERE student_id = ?'
        ).bind(me.id).first()
        return c.json({
            success: false,
            error: 'stale_progress',
            ...progressPayload(fresh, me.id),
        }, 409)
    }

    return c.json({
        success: true,
        xp,
        level,
        streak: safeStreak,
        completed_lessons: safeLessons,
        earned_badges: safeBadges,
        progress_revision: nextRevision,
    })
})

// Admin: sanitize a student's stored progress to match server-computed values
app.post('/api/admin/sanitize-progress/:studentId', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)

    const allLessons = [...curriculum.basic, ...curriculum.intermediate, ...curriculum.advanced, ...curriculum.creative, ...curriculum.challenges] as any[]
    const validLessonIds = new Set(allLessons.map((l: any) => l.id))
    const lessonXpMap: Record<string, number> = {}
    allLessons.forEach((l: any) => { lessonXpMap[l.id] = l.xpReward || 0 })
    const validBadgeIds = new Set((badges as any[]).map((b: any) => b.id))

    const studentId = c.req.param('studentId')
    const stored = await c.env.DB.prepare(
        'SELECT * FROM student_progress WHERE student_id = ?'
    ).bind(studentId).first() as any

    if (!stored) return c.json({ error: 'No progress record found' }, 404)

    const cleanLessons = JSON.parse(stored.completed_lessons || '[]')
        .filter((id: string) => validLessonIds.has(id))
    const cleanBadges = JSON.parse(stored.earned_badges || '[]')
        .filter((id: string) => validBadgeIds.has(id))
    const xp    = cleanLessons.reduce((s: number, id: string) => s + (lessonXpMap[id] || 0), 0)
    const level = Math.floor(xp / 500) + 1
    const streak = Math.min(365, Math.max(0, stored.streak || 0))

    await c.env.DB.prepare(
        'UPDATE student_progress SET xp=?, level=?, completed_lessons=?, earned_badges=?, streak=? WHERE student_id=?'
    ).bind(xp, level, JSON.stringify(cleanLessons), JSON.stringify(cleanBadges), streak, studentId).run()

    return c.json({ ok: true, xp, level, lessons: cleanLessons.length })
})

// Teacher/admin reset of one student's progress. A lesson reset removes the
// base lesson and its optional challenge completion, then recalculates rewards.
// "all" clears every completion and reward so the student starts from zero.
app.post('/api/teacher/students/:id/reset-progress', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'teacher' && me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)

    const studentId = c.req.param('id')
    const body = await c.req.json().catch(() => ({}))
    const requestedLesson = typeof body.lesson_id === 'string' ? body.lesson_id.trim() : 'all'
    const allLessons = [...curriculum.basic, ...curriculum.intermediate, ...curriculum.advanced, ...curriculum.creative, ...curriculum.challenges] as any[]
    const validLessonIds = new Set(allLessons.map((lesson: any) => lesson.id))
    const baseLessonId = requestedLesson.endsWith('-challenge')
        ? requestedLesson.slice(0, -'-challenge'.length)
        : requestedLesson

    const student = await c.env.DB.prepare(
        "SELECT id FROM users WHERE id = ? AND role = 'student'"
    ).bind(studentId).first()
    if (!student) return c.json({ error: 'Student not found' }, 404)

    if (me.role === 'teacher') {
        const inClass = await c.env.DB.prepare(`
            SELECT cs.student_id FROM class_students cs
            JOIN classes cl ON cs.class_id = cl.id
            WHERE cs.student_id = ? AND cl.teacher_id = ?
            LIMIT 1
        `).bind(studentId, me.id).first()
        if (!inClass) return c.json({ error: 'Student not in your class' }, 403)
    }

    if (requestedLesson !== 'all' && !validLessonIds.has(baseLessonId)) {
        return c.json({ error: 'Unknown lesson' }, 400)
    }

    const lessonXpMap: Record<string, number> = {}
    allLessons.forEach((lesson: any) => { lessonXpMap[lesson.id] = lesson.xpReward || 0 })
    const validBadgeIds = new Set((badges as any[]).map((badge: any) => badge.id))

    // Compare-and-swap prevents a student save and a reset from overwriting
    // one another. If another request wins, recalculate from the fresh row.
    for (let attempt = 0; attempt < 5; attempt++) {
        const stored = await c.env.DB.prepare(
            'SELECT completed_lessons, streak, updated_at FROM student_progress WHERE student_id = ?'
        ).bind(studentId).first() as any
        const storedRevision = String(stored?.updated_at || '')
        const storedLessons: string[] = JSON.parse(stored?.completed_lessons || '[]')
        const currentStreak = Math.min(365, Math.max(0, Number(stored?.streak || 0)))
        const remainingLessons = requestedLesson === 'all'
            ? []
            : storedLessons.filter((id: string) =>
                id !== baseLessonId && id !== `${baseLessonId}-challenge`
            )
        const resetScope = requestedLesson === 'all' ? 'all' : baseLessonId
        const xp = remainingLessons.reduce((sum: number, id: string) => sum + (lessonXpMap[id] || 0), 0)
        const level = Math.floor(xp / 500) + 1
        const streak = requestedLesson === 'all' ? 0 : currentStreak
        const safeBadges = requestedLesson === 'all' ? [] : (badges as any[])
            .filter((badge: any) => {
                if (badge.type === 'lessons') return remainingLessons.length >= badge.threshold
                if (badge.type === 'streak') return streak >= badge.threshold
                if (badge.type === 'level') return level >= badge.threshold
                return xp >= badge.threshold
            })
            .map((badge: any) => badge.id)
            .filter((id: string) => validBadgeIds.has(id))
        const nextRevision = newProgressRevision()
        const resetResult = stored
            ? await c.env.DB.prepare(`
                UPDATE student_progress
                SET xp=?, level=?, completed_lessons=?, earned_badges=?, streak=?,
                    updated_at=?
                WHERE student_id=? AND updated_at=?
            `).bind(
                xp, level, JSON.stringify(remainingLessons), JSON.stringify(safeBadges),
                streak, nextRevision, studentId, storedRevision
            ).run()
            : await c.env.DB.prepare(`
                INSERT OR IGNORE INTO student_progress
                    (student_id, xp, level, completed_lessons, earned_badges, streak, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `).bind(
                studentId, xp, level, JSON.stringify(remainingLessons),
                JSON.stringify(safeBadges), streak, nextRevision
            ).run()

        if (resetResult.meta.changes) {
            return c.json({
                success: true,
                lesson_id: resetScope,
                xp,
                level,
                streak,
                completed_lessons: remainingLessons,
                earned_badges: safeBadges,
                progress_revision: nextRevision,
            })
        }
    }

    return c.json({ error: 'Progress changed during reset. Please try again.' }, 409)
})

// Admin resets any user's password (no current password needed — admin authority)
app.post('/api/admin/users/:id/reset-password', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const id = c.req.param('id')
    const body = await c.req.json()
    const password = body.password || ''
    if (password.length < 6) return c.json({ error: 'Password must be at least 6 characters' }, 400)
    if (password.length > 200) return c.json({ error: 'Password too long' }, 400)
    const user = await c.env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(id).first()
    if (!user) return c.json({ error: 'User not found' }, 404)
    const hash = await hashPassword(password)
    await c.env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(hash, id).run()
    return c.json({ success: true })
})

// Wipe orphaned student_progress for a non-student user (teacher/admin/parent)
app.post('/api/admin/clean-progress/:userId', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const userId = c.req.param('userId')
    const user = await c.env.DB.prepare('SELECT role FROM users WHERE id = ?').bind(userId).first() as any
    if (!user) return c.json({ error: 'User not found' }, 404)
    if (user.role === 'student') return c.json({ error: 'Use Sanitize for students' }, 400)
    await c.env.DB.prepare('DELETE FROM class_students WHERE student_id = ?').bind(userId).run()
    await c.env.DB.prepare('DELETE FROM student_progress WHERE student_id = ?').bind(userId).run()
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

// ── Video Lessons ──────────────────────────────────────────────────────────
app.get('/api/videos', authMiddleware, async (c) => {
    const { results } = await c.env.DB.prepare(
        'SELECT * FROM lesson_videos ORDER BY sort_order, id'
    ).all()
    return c.json(results)
})

app.post('/api/admin/videos', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const { lesson_name, youtube_url, sort_order } = await c.req.json()
    if (!lesson_name || !youtube_url) return c.json({ error: 'lesson_name and youtube_url are required' }, 400)
    if (!isSafeUrl(youtube_url.trim())) return c.json({ error: 'URL must start with http:// or https://' }, 400)
    await c.env.DB.prepare(
        'INSERT INTO lesson_videos (lesson_name, youtube_url, sort_order) VALUES (?, ?, ?)'
    ).bind(lesson_name.trim(), youtube_url.trim(), sort_order || 0).run()
    return c.json({ ok: true })
})

app.put('/api/admin/videos/:id', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const { lesson_name, youtube_url, sort_order } = await c.req.json()
    if (!lesson_name || !youtube_url) return c.json({ error: 'lesson_name and youtube_url are required' }, 400)
    if (!isSafeUrl(youtube_url.trim())) return c.json({ error: 'URL must start with http:// or https://' }, 400)
    await c.env.DB.prepare(
        'UPDATE lesson_videos SET lesson_name=?, youtube_url=?, sort_order=? WHERE id=?'
    ).bind(lesson_name.trim(), youtube_url.trim(), sort_order || 0, c.req.param('id')).run()
    return c.json({ ok: true })
})

app.delete('/api/admin/videos/:id', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    await c.env.DB.prepare('DELETE FROM lesson_videos WHERE id=?').bind(c.req.param('id')).run()
    return c.json({ ok: true })
})
// ──────────────────────────────────────────────────────────────────────────

// ── Interactive HTML Lessons ──────────────────────────────────────────────
const MAX_INTERACTIVE_HTML_BYTES = 256 * 1024

function validInteractiveLessonId(value: string): boolean {
    return /^[1-9]\d*$/.test(value)
}

function validInteractiveHtml(content: string): boolean {
    const normalized = content.trim().toLowerCase()
    return normalized.length > 0 && (normalized.startsWith('<!doctype html') || normalized.includes('<html'))
}

function escapeHtmlAttribute(value: string): string {
    return value.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

const BUILTIN_LESSON_LOGO_NAMES = new Set([
    'logo.png', 'logo.jpg', 'logo.jpeg', 'logo.svg',
    'steam-logo.png', 'steam-logo.jpg', 'steam-logo.jpeg', 'steam-logo.svg',
    'steam-logo-white.png', 'steam-logo-white.svg',
    'steam-logo-color.png', 'steam-logo-color.svg',
    'steamlogo.png', 'steamlogo.jpg', 'steamlogo.svg'
])

function builtinLessonLogoFallback(reference: string): string {
    const cleanReference = reference.trim().split(/[?#]/)[0].replace(/\\/g, '/')
    if (/^(?:[a-z][a-z0-9+.-]*:|\/\/|\/|#)/i.test(cleanReference)) return reference
    const fileName = cleanReference.split('/').pop()?.toLowerCase() || ''
    return BUILTIN_LESSON_LOGO_NAMES.has(fileName) ? '/static/steam-logo.png' : reference
}

function restoreBuiltinLessonLogos(content: string): string {
    let restored = content.replace(
        /(\b(?:src|href|poster)\s*=\s*)(["'])([^"']+)\2/gi,
        (_match, prefix, quote, reference) => prefix + quote + builtinLessonLogoFallback(reference) + quote
    )
    restored = restored.replace(
        /(\bsrcset\s*=\s*)(["'])([^"']+)\2/gi,
        (_match, prefix, quote, srcset) => {
            const rewritten = srcset.split(',').map((candidate: string) => {
                const parts = candidate.trim().split(/\s+/)
                if (parts.length) parts[0] = builtinLessonLogoFallback(parts[0])
                return parts.join(' ')
            }).join(', ')
            return prefix + quote + rewritten + quote
        }
    )
    return restored.replace(
        /(url\(\s*["']?)([^"')]+)(["']?\s*\))/gi,
        (_match, prefix, reference, suffix) => prefix + builtinLessonLogoFallback(reference) + suffix
    )
}

function interactiveLessonMetadataQuery(publishedOnly = false): string {
    return `SELECT id, title, lesson_number, is_published, sort_order, created_at, updated_at
        FROM interactive_lessons ${publishedOnly ? 'WHERE is_published = 1' : ''}
        ORDER BY sort_order, id`
}

async function interactiveLessonNumberExists(db: any, lessonNumber: number): Promise<boolean> {
    const statement = db.prepare('SELECT id FROM interactive_lessons WHERE lesson_number=? LIMIT 1').bind(lessonNumber)
    return Boolean(await statement.first())
}

app.get('/api/interactive-lessons', authMiddleware, async (c) => {
    const me = c.get('user')
    if (!['student', 'teacher', 'admin'].includes(me.role)) return c.json({ error: 'Forbidden' }, 403)
    const { results } = await c.env.DB.prepare(interactiveLessonMetadataQuery(true)).all()
    return c.json(results)
})

app.get('/api/admin/interactive-lessons', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const { results } = await c.env.DB.prepare(interactiveLessonMetadataQuery()).all()
    return c.json(results)
})

app.post('/api/admin/interactive-lessons', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const { title, html_content, file_name, lesson_number, sort_order, is_published } = await c.req.json()
    const cleanTitle = typeof title === 'string' ? title.trim() : ''
    const content = typeof html_content === 'string' ? html_content : ''
    const validFileName = typeof file_name === 'string' && /^[^/\\]+\.(html?|HTML?)$/.test(file_name)
    if (!cleanTitle || cleanTitle.length > 120 || hasHtmlChars(cleanTitle)) {
        return c.json({ error: 'Lesson title must be 1–120 plain-text characters' }, 400)
    }
    if (!validFileName) return c.json({ error: 'Upload a .html or .htm file' }, 400)
    if (new TextEncoder().encode(content).byteLength > MAX_INTERACTIVE_HTML_BYTES) {
        return c.json({ error: 'The complete lesson package must be 256 KB or smaller' }, 400)
    }
    if (!validInteractiveHtml(content)) return c.json({ error: 'Upload a complete HTML document' }, 400)
    const lessonNumber = Number(lesson_number)
    if (!Number.isInteger(lessonNumber) || lessonNumber < 1) {
        return c.json({ error: 'Choose a positive lesson number' }, 400)
    }
    const suppliedOrder = sort_order === null || sort_order === undefined || sort_order === '' ? NaN : Number(sort_order)
    const order = Number.isFinite(suppliedOrder) ? Math.max(0, Math.floor(suppliedOrder)) : lessonNumber
    const published = is_published === false || is_published === 0 ? 0 : 1
    if (await interactiveLessonNumberExists(c.env.DB, lessonNumber)) {
        return c.json({ error: `Lesson number ${lessonNumber} is already in use. Choose a different number.` }, 409)
    }
    const result = await c.env.DB.prepare(
        'INSERT INTO interactive_lessons (title, html_content, lesson_number, is_published, sort_order) VALUES (?, ?, ?, ?, ?)'
    ).bind(cleanTitle, content, lessonNumber, published, order).run()
    return c.json({ ok: true, id: result.meta.last_row_id })
})

app.put('/api/admin/interactive-lessons/:id', authMiddleware, async (c) => {
    const me = c.get('user')
    const id = c.req.param('id')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    if (!validInteractiveLessonId(id)) return c.json({ error: 'Invalid lesson' }, 400)
    const { title, sort_order, is_published } = await c.req.json()
    const cleanTitle = typeof title === 'string' ? title.trim() : ''
    if (!cleanTitle || cleanTitle.length > 120 || hasHtmlChars(cleanTitle)) {
        return c.json({ error: 'Lesson title must be 1–120 plain-text characters' }, 400)
    }
    const order = Number.isFinite(Number(sort_order)) ? Math.max(0, Math.floor(Number(sort_order))) : 0
    const published = is_published === false || is_published === 0 ? 0 : 1
    const result = await c.env.DB.prepare(
        "UPDATE interactive_lessons SET title=?, sort_order=?, is_published=?, updated_at=CURRENT_TIMESTAMP WHERE id=?"
    ).bind(cleanTitle, order, published, id).run()
    if (!result.meta.changes) return c.json({ error: 'Lesson not found' }, 404)
    return c.json({ ok: true })
})

app.delete('/api/admin/interactive-lessons/:id', authMiddleware, async (c) => {
    const me = c.get('user')
    const id = c.req.param('id')
    if (me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    if (!validInteractiveLessonId(id)) return c.json({ error: 'Invalid lesson' }, 400)
    await c.env.DB.prepare('DELETE FROM interactive_lessons WHERE id=?').bind(id).run()
    return c.json({ ok: true })
})

function renderInteractiveLesson(c: any, lesson: any) {
    const title = escapeHtmlAttribute(lesson.title || 'Interactive Lesson')
    const srcdoc = escapeHtmlAttribute(restoreBuiltinLessonLogos(lesson.html_content))
    return c.html(`<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title} | STEMO Interactive Lesson</title>
    <style>html,body{width:100%;height:100%;margin:0;background:#f8fafc}iframe{display:block;width:100%;height:100%;border:0;background:#fff}</style>
</head>
<body>
    <iframe title="${title}" sandbox="allow-scripts allow-forms allow-modals allow-downloads" referrerpolicy="no-referrer" srcdoc="${srcdoc}"></iframe>
</body>
</html>`)
}

// Public lesson numbers are immutable and separate from display ordering. The
// database ID route below remains available for old bookmarks and admin tools.
app.get('/interactive-lessons/lesson/:number', authMiddleware, async (c) => {
    const me = c.get('user')
    const number = c.req.param('number')
    if (!['student', 'teacher', 'admin'].includes(me.role)) return c.text('Forbidden', 403)
    if (!/^[1-9]\d*$/.test(number)) return c.text('Lesson not found', 404)
    const lesson = await c.env.DB.prepare(
        me.role === 'admin'
            ? 'SELECT title, html_content, is_published FROM interactive_lessons WHERE lesson_number=? LIMIT 1'
            : 'SELECT title, html_content, is_published FROM interactive_lessons WHERE lesson_number=? AND is_published=1 LIMIT 1'
    ).bind(Number(number)).first() as any
    if (!lesson) return c.text('Lesson not found', 404)
    return renderInteractiveLesson(c, lesson)
})

// The uploaded document is embedded in an opaque-origin iframe instead of being
// rendered as the platform page itself. It cannot read platform cookies or parent
// DOM, call APIs (connect-src none), open popups, or navigate the academy.
app.get('/interactive-lessons/:id', authMiddleware, async (c) => {
    const me = c.get('user')
    const id = c.req.param('id')
    if (!['student', 'teacher', 'admin'].includes(me.role)) return c.text('Forbidden', 403)
    if (!validInteractiveLessonId(id)) return c.text('Lesson not found', 404)
    const lesson = await c.env.DB.prepare(
        'SELECT title, html_content, is_published FROM interactive_lessons WHERE id=?'
    ).bind(id).first() as any
    if (!lesson || (!lesson.is_published && me.role !== 'admin')) return c.text('Lesson not found', 404)
    return renderInteractiveLesson(c, lesson)
})
// ──────────────────────────────────────────────────────────────────────────

// Get all students (for admin/teacher dropdowns)
app.get('/api/admin/students', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'admin' && me.role !== 'teacher') return c.json({ error: 'Forbidden' }, 403)
    const { results } = await c.env.DB.prepare("SELECT id, username, full_name FROM users WHERE role = 'student' ORDER BY full_name").all()
    return c.json(results)
})

const LEADERBOARD_DEFAULT_PAGE_SIZE = 30
const LEADERBOARD_MAX_PAGE_SIZE = 50

function getLeaderboardPagination(c: any) {
    const requestedPage = Number.parseInt(c.req.query('page') || '1', 10)
    const requestedSize = Number.parseInt(c.req.query('page_size') || String(LEADERBOARD_DEFAULT_PAGE_SIZE), 10)
    const pageSize = Number.isFinite(requestedSize)
        ? Math.min(LEADERBOARD_MAX_PAGE_SIZE, Math.max(10, requestedSize))
        : LEADERBOARD_DEFAULT_PAGE_SIZE
    const page = Number.isFinite(requestedPage) ? Math.max(1, requestedPage) : 1
    return { page, pageSize, offset: (page - 1) * pageSize }
}

function leaderboardPageResponse(results: any[], page: number, pageSize: number, total: number) {
    const totalPages = Math.max(1, Math.ceil(total / pageSize))
    return {
        results,
        page,
        pageSize,
        total,
        totalPages,
        hasPreviousPage: page > 1,
        hasNextPage: page < totalPages
    }
}

// Leaderboard — top students ranked by XP (accessible to students and teachers)
app.get('/api/leaderboard', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'student' && me.role !== 'teacher' && me.role !== 'admin') return c.json({ error: 'Forbidden' }, 403)
    const { page, pageSize, offset } = getLeaderboardPagination(c)
    const totalRow = await c.env.DB.prepare(`
        SELECT COUNT(DISTINCT u.id) as total
        FROM users u
        WHERE u.role = 'student' AND (u.status = 'approved' OR u.status IS NULL)
    `).first() as any
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
        WHERE u.role = 'student' AND (u.status = 'approved' OR u.status IS NULL)
        ORDER BY COALESCE(sp.xp, 0) DESC, u.id ASC
        LIMIT ? OFFSET ?
    `).bind(pageSize, offset).all()
    return c.json(leaderboardPageResponse(results, page, pageSize, Number(totalRow?.total || 0)))
})

// Public landing-page leaderboard. Only approved students' display names,
// XP, and level are exposed; usernames, classes, and schools stay private.
app.get('/api/public/leaderboard', async (c) => {
    try {
        // The Vite preview does not provide Cloudflare bindings; keep the
        // public landing page usable there while production uses D1.
        if (!c.env.DB) return c.json({ results: [], total: 0 })
        const totalRow = await c.env.DB.prepare(`
            SELECT COUNT(*) as total
            FROM users
            WHERE role = 'student' AND (status = 'approved' OR status IS NULL)
        `).first() as any
        const { results } = await c.env.DB.prepare(`
            SELECT u.full_name,
                   COALESCE(sp.xp, 0) as xp,
                   COALESCE(sp.level, 1) as level
            FROM users u
            LEFT JOIN student_progress sp ON sp.student_id = u.id
            WHERE u.role = 'student' AND (u.status = 'approved' OR u.status IS NULL)
            ORDER BY COALESCE(sp.xp, 0) DESC, u.id ASC
            LIMIT 8
        `).all()
        const safeResults = (results || []).map((student: any, index: number) => {
            const parts = String(student.full_name || 'STEMO Student').trim().split(/\s+/).filter(Boolean)
            const firstName = parts[0] || 'STEMO Student'
            const lastInitial = parts.length > 1 ? ` ${parts[parts.length - 1].charAt(0)}.` : ''
            return {
                rank: index + 1,
                display_name: firstName + lastInitial,
                xp: Number(student.xp || 0),
                level: Number(student.level || 1)
            }
        })
        return c.json({ results: safeResults, total: Number(totalRow?.total || 0) })
    } catch (e) {
        console.error('Public leaderboard error:', e)
        return c.json({ error: 'Unable to load leaderboard' }, 500)
    }
})

// Leaderboard — student's own class
app.get('/api/leaderboard/class', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'student') return c.json({ error: 'Forbidden' }, 403)
    try {
        const { page, pageSize, offset } = getLeaderboardPagination(c)
        const totalRow = await c.env.DB.prepare(`
            SELECT COUNT(*) as total FROM (
                SELECT u.id
                FROM class_students cs2
                JOIN class_students cs ON cs.class_id = cs2.class_id
                JOIN users u ON u.id = cs.student_id
                WHERE cs2.student_id = ? AND u.role = 'student' AND (u.status = 'approved' OR u.status IS NULL)
                GROUP BY u.id
            ) class_students
        `).bind(me.id).first() as any
        const { results } = await c.env.DB.prepare(`
            SELECT u.id, u.full_name, u.username,
                   COALESCE(sp.xp, 0) as xp,
                   COALESCE(sp.level, 1) as level,
                   COALESCE(sp.completed_lessons, '[]') as completed_lessons,
                   COALESCE(sp.streak, 0) as streak,
                   c.name as class_name,
                   s.name as school_name
            FROM class_students cs2
            JOIN class_students cs ON cs.class_id = cs2.class_id
            JOIN users u ON u.id = cs.student_id
            LEFT JOIN student_progress sp ON sp.student_id = u.id
            LEFT JOIN classes c ON c.id = cs.class_id
            LEFT JOIN schools s ON s.id = c.school_id
            WHERE cs2.student_id = ? AND u.role = 'student' AND (u.status = 'approved' OR u.status IS NULL)
            GROUP BY u.id
            ORDER BY COALESCE(sp.xp, 0) DESC, u.id ASC
            LIMIT ? OFFSET ?
        `).bind(me.id, pageSize, offset).all()
        return c.json(leaderboardPageResponse(results, page, pageSize, Number(totalRow?.total || 0)))
    } catch (e: any) { console.error('Leaderboard class error:', e); return c.json({ error: 'Internal server error' }, 500) }
})

// Leaderboard — student's own school
app.get('/api/leaderboard/school', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'student') return c.json({ error: 'Forbidden' }, 403)
    try {
        const { page, pageSize, offset } = getLeaderboardPagination(c)
        const totalRow = await c.env.DB.prepare(`
            SELECT COUNT(*) as total FROM (
                SELECT DISTINCT u.id
                FROM class_students mycs
                JOIN classes myc ON myc.id = mycs.class_id
                JOIN schools mys ON mys.id = myc.school_id
                JOIN classes c ON c.school_id = mys.id
                JOIN class_students cs ON cs.class_id = c.id
                JOIN users u ON u.id = cs.student_id
                WHERE mycs.student_id = ? AND u.role = 'student' AND (u.status = 'approved' OR u.status IS NULL)
            ) school_students
        `).bind(me.id).first() as any
        const { results } = await c.env.DB.prepare(`
            SELECT u.id, u.full_name, u.username,
                   COALESCE(sp.xp, 0) as xp,
                   COALESCE(sp.level, 1) as level,
                   COALESCE(sp.completed_lessons, '[]') as completed_lessons,
                   COALESCE(sp.streak, 0) as streak,
                   c.name as class_name,
                   s.name as school_name
            FROM class_students mycs
            JOIN classes myc ON myc.id = mycs.class_id
            JOIN schools mys ON mys.id = myc.school_id
            JOIN classes c ON c.school_id = mys.id
            JOIN class_students cs ON cs.class_id = c.id
            JOIN users u ON u.id = cs.student_id
            LEFT JOIN student_progress sp ON sp.student_id = u.id
            LEFT JOIN schools s ON s.id = c.school_id
            WHERE mycs.student_id = ? AND u.role = 'student' AND (u.status = 'approved' OR u.status IS NULL)
            GROUP BY u.id
            ORDER BY COALESCE(sp.xp, 0) DESC, u.id ASC
            LIMIT ? OFFSET ?
        `).bind(me.id, pageSize, offset).all()
        return c.json(leaderboardPageResponse(results, page, pageSize, Number(totalRow?.total || 0)))
    } catch (e: any) { console.error('Leaderboard school error:', e); return c.json({ error: 'Internal server error' }, 500) }
})

// Student's ranks — platform, class, school
app.get('/api/student/rank', authMiddleware, async (c) => {
    const me = c.get('user')
    if (me.role !== 'student') return c.json({ error: 'Forbidden' }, 403)
    try {
        const myProg = await c.env.DB.prepare('SELECT xp FROM student_progress WHERE student_id = ?').bind(me.id).first() as any
        const myXp = myProg?.xp || 0

        // Platform rank
        const pr = await c.env.DB.prepare(`SELECT COUNT(*) + 1 as rank FROM student_progress sp JOIN users u ON sp.student_id = u.id WHERE u.role = 'student' AND (u.status = 'approved' OR u.status IS NULL) AND sp.xp > ?`).bind(myXp).first() as any
        const pt = await c.env.DB.prepare(`SELECT COUNT(*) as total FROM users WHERE role = 'student' AND (status = 'approved' OR status IS NULL)`).first() as any

        // Class rank
        const myClass = await c.env.DB.prepare('SELECT class_id FROM class_students WHERE student_id = ? LIMIT 1').bind(me.id).first() as any
        let classRank = null, classTotal = null
        if (myClass) {
            const cr = await c.env.DB.prepare(`SELECT COUNT(*) + 1 as rank FROM student_progress sp JOIN class_students cs ON cs.student_id = sp.student_id WHERE cs.class_id = ? AND sp.xp > ?`).bind(myClass.class_id, myXp).first() as any
            const ct = await c.env.DB.prepare(`SELECT COUNT(*) as total FROM class_students WHERE class_id = ?`).bind(myClass.class_id).first() as any
            classRank = cr?.rank || 1; classTotal = ct?.total || 1
        }

        // School rank
        const mySchool = await c.env.DB.prepare(`SELECT s.id as school_id, s.name as school_name FROM class_students cs JOIN classes c ON c.id = cs.class_id JOIN schools s ON s.id = c.school_id WHERE cs.student_id = ? LIMIT 1`).bind(me.id).first() as any
        let schoolRank = null, schoolTotal = null
        if (mySchool) {
            const sr = await c.env.DB.prepare(`SELECT COUNT(*) + 1 as rank FROM student_progress sp JOIN class_students cs ON cs.student_id = sp.student_id JOIN classes c ON c.id = cs.class_id WHERE c.school_id = ? AND sp.xp > ?`).bind(mySchool.school_id, myXp).first() as any
            const st = await c.env.DB.prepare(`SELECT COUNT(DISTINCT cs.student_id) as total FROM class_students cs JOIN classes c ON c.id = cs.class_id WHERE c.school_id = ?`).bind(mySchool.school_id).first() as any
            schoolRank = sr?.rank || 1; schoolTotal = st?.total || 1
        }

        return c.json({
            platform: { rank: pr?.rank || 1, total: pt?.total || 1 },
            class: myClass ? { rank: classRank, total: classTotal } : null,
            school: mySchool ? { rank: schoolRank, total: schoolTotal, name: mySchool.school_name } : null
        })
    } catch (e: any) { console.error('Student rank error:', e); return c.json({ error: 'Internal server error' }, 500) }
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
            homework: 'Can you make me walk in a "Z" shape? Try: Forward → Right turn → Forward → Left turn → Forward. Notice how turns change the direction of the next move!',
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
                { id: 't5', text: 'Challenge: draw a staircase! Add this sequence three times: Pen Down → Forward 2 → Right 90 → Forward 2 → Left 90.', completed: false }
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
                { id: 't5', text: 'Try drawing a thick red square: Color red → Size 8 → Pen Down, then add Forward 4 → Right 90 four times.', completed: false }
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
                { id: 't4', text: 'Place 2 metal pieces. Pick up the first, move it to a new spot, and turn Magnet OFF to drop it. Then collect the second one.', completed: false },
                { id: 't5', text: 'Challenge: place 3 metals in a line. Collect them one at a time: Magnet ON near a metal → move it → Magnet OFF. Can you sort all 3?', completed: false }
            ],
            hint: 'Turn Magnet ON only when you are close to one metal piece. Move it to its new spot, turn Magnet OFF to drop it, then go back for the next piece.',
            homework: 'Design a "Metal Sorting Station"! Place 4 metal pieces scattered on the board. Move each piece, one at a time, to the top-right corner. Use loops to make your program shorter!',
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
            homework: 'Build a "Safety Scan" program: Scan Ahead → move Forward 1 → Scan Ahead again. Watch the distance after every move and end the program when you are safely close to the wall. This is how parking sensors help drivers!',
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
            introduction: "NASA's Mars Rovers (Curiosity and Perseverance) drive themselves to target locations using exactly the same idea you are about to learn! 🚀 They calculate the direction to a target, rotate until they face it, then drive forward. My 'Go To Target' block turns me toward the current target and drives in that direction. The cool part: even if I am facing the wrong way, I spin around until I am pointing at the goal before moving. It works best when the path is clear; later, Smart Navigate can find a route around a complex maze. This technique is used in GPS navigation, drone delivery, and self-driving cars.",
            tasks: [
                { id: 't1', text: 'Click the 🎯 Target button and place a target anywhere on the board', completed: false },
                { id: 't2', text: 'Add the "Go To Target 🎯" block and Run — watch me calculate and navigate!', completed: false },
                { id: 't3', text: 'Move the target to a new, far-away place. Clear the program, then use "Go To Target" again to see me navigate to the new location!', completed: false },
                { id: 't4', text: 'Now add a 🧱 wall between me and the target. Does my navigation avoid it, or do I need to help?', completed: false },
                { id: 't5', text: 'Advanced: place the target in a corner with walls nearby. Use Scan Ahead, then move manually with Forward and Turn blocks to follow a clear route. Save Go To Target for open paths.', completed: false }
            ],
            hint: 'The "Go To Target" block turns me toward the current target and moves forward. It works best with a clear path. Scan Ahead first when walls are nearby, or use Smart Navigate in a maze.',
            homework: 'Create a "Delivery Practice" mission! Place one metal piece and one target. Turn Magnet ON near the metal, move it toward the target, then turn Magnet OFF to drop it at the destination.',
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
                { id: 't4', text: 'Now add a SECOND If Wall block after the first one. Give each block a different turn, then run the program and see how changing one decision changes my route.', completed: false },
                { id: 't5', text: 'Challenge: place walls on two parts of your route. Use two If Wall blocks inside one Repeat loop so I keep exploring instead of bumping into a wall!', completed: false }
            ],
            hint: 'If/Else always checks a condition (True/False). THEN = what to do if TRUE. ELSE = what to do if FALSE. You can chain multiple If blocks — check one condition, then another! Real AI is just millions of these simple decisions.',
            homework: 'Build a "Smart Explorer"! Use a Repeat loop with If Wall Within 2: THEN turn right, ELSE move forward 1. Add walls and watch STEMO react on its own!',
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
            homework: 'Build a "Fire Mapping" mission: place 3 fires. Write a program that sweeps the board in a zigzag pattern, checking temperature at each position. Use the temperature messages to note where the heat is strongest. Real wildfire drones do exactly this!',
            nextLesson: 'lesson-13'
        },
        {
            id: 'lesson-13',
            title: 'Firefighter Hero',
            description: 'Extinguish fires efficiently — every water drop counts!',
            difficulty: 'extreme',
            xpReward: 500,
            icon: '🚒',
            introduction: "Now it is time for ACTION! 🦸 I carry a small water tank with limited supply — just like a real aerial firefighting drone that can only carry so much water before it must refuel. In this challenge I start with 9 units. Each unit removes one point of fire health, and every challenge fire has 3 points of health. This means you CANNOT spray randomly — you must position carefully and only spray when you are close enough. This is the engineering concept of EFFICIENCY: achieving the maximum result (all fires out) with the minimum resource (least water). Aerospace engineers obsess over this — a Mars mission that wastes fuel means the rover cannot reach its goals. Let's think strategically!",
            tasks: [
                { id: 't1', text: 'Place ONE fire. Move to within 3 steps of it and add "Spray Water 💧". Run — watch the fire go out and the water meter decrease! 🎯', completed: false },
                { id: 't2', text: 'Place TWO fires far apart. Plan the SHORTEST path to visit both. Each fire needs 3 water units, so reach each one before using Spray Water.', completed: false },
                { id: 't3', text: 'Open the 3-fire challenge. The tank starts with 9 units — exactly enough for the three challenge fires when you reach them safely.', completed: false },
                { id: 't4', text: 'Watch the water meter on the board before and after each fire. Notice how putting out one full fire uses 3 water units.', completed: false },
                { id: 't5', text: 'Advanced: plan your route before you run it. Only use Spray Water when STEMO is close enough to a fire, so no water is wasted.', completed: false },
                { id: 't6', text: 'Speed challenge: replay the 3-fire challenge and count your movement blocks. Can you reach all three fires using a shorter route? ⏱️', completed: false }
            ],
            hint: 'Plan your route BEFORE coding: which fire is closest? Go there first. Then which is next closest? This "nearest neighbour" strategy is used in real delivery route planning! Get within 3 steps of a fire before using Spray Water. Each challenge fire needs 3 water units.',
            homework: 'Put out all 3 fires by reaching each one before using Spray Water. One Spray Water block fully extinguishes a nearby challenge fire and uses 3 water units, so plan your route before you run it!',
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
                { id: 't4', text: 'Press Reset, then Clear Waypoints. Move STEMO near two of the challenge fires and add a waypoint at each one. Run For Each → Spray Water to use your own smaller fire list!', completed: false },
                { id: 't5', text: 'MASTER challenge: after a reset, Clear Waypoints and record all three challenge fire locations with Add Waypoint. Run For Each Waypoint → Check Temp → Spray Water to handle your own list!', completed: false }
            ],
            hint: 'The waypoint list is pre-loaded with all 3 fire locations. "For Each Waypoint → Spray Water" is the ENTIRE solution — one compound block handles navigation + action for every item in the list. The challenge starts with 10 water units, enough for all three fires.',
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
                { id: 't1', text: 'Drag a "🔧 Define Function" block. Name it "drawSquare". Inside, add: Pen Down → Repeat 4 times (Move 3 steps, Turn Right 90°). Below the definition add ▶ Call Function: drawSquare, then press Run — a square appears!', completed: false },
                { id: 't2', text: 'Drag another "🔧 Define Function" block. Name it "bigSquare". Inside, add: Repeat 4 times → (▶ Call Function: drawSquare, Turn Right 90°). Definitions save a recipe; they run only when called.', completed: false },
                { id: 't3', text: 'Replace the Call Function: drawSquare below the definitions with: ▶ Call Function: bigSquare → Turn Right 45° → ▶ Call Function: bigSquare. Press Run — the star appears!', completed: false },
                { id: 't4', text: 'Change the step size inside drawSquare from 3 to 5. Press Run — the whole star grows. That is the power of functions: change one number, everything updates!', completed: false },
                { id: 't5', text: 'Create a third function called "starBurst". Inside: Call bigSquare → Turn Right 30° → Call bigSquare → Turn Right 30° → Call bigSquare. What shape do you get?', completed: false }
            ],
            hint: 'Define functions first (at the top or side), then call them below. The name in "Define Function" must exactly match the name in "Call Function" — spelling counts! drawSquare ≠ DrawSquare.',
            homework: 'Design your own geometric artwork: create at least 3 functions (e.g. drawTriangle, drawStar, drawSpiral). Combine them with different rotation angles to create a unique pattern. Save it and share with the class!',
            nextLesson: 'lesson-14'
        },
        {
            id: 'lesson-14',
            title: 'Master Coder',
            description: 'The ultimate autonomous mission — graduate as a Master Coder! 🎓',
            difficulty: 'extreme',
            xpReward: 1000,
            icon: '🏆',
            introduction: "🎓 CONGRATULATIONS — you have reached the FINAL lesson of the STEMO Academy! Across your whole journey you have learned: sequencing, loops, geometry, sensors (ultrasonic + thermal), decision-making (If/Else), electromagnets, efficient resource use, variables, saved positions, lists, and functions. These are the EXACT skills that real robotics engineers use every day. Your final mission is the ultimate test: the challenge board is ready with walls, metal pieces, fires, and a target. Write ONE program that navigates around obstacles, collects at least one metal, extinguishes every fire, and reaches the target. You are the engineer. STEMO is your robot. Let's graduate!",
            tasks: [
                { id: 't1', text: 'Open the Final Mission challenge. The board is already set up with walls, metal pieces, fires, and a target.', completed: false },
                { id: 't2', text: 'Phase 1 — Scan: add Scan Ahead in all 4 directions at the start so I know where the obstacles are', completed: false },
                { id: 't3', text: 'Phase 2 — Collect: navigate to the metal pieces with Magnet ON. Collect at least one metal to complete the collection objective.', completed: false },
                { id: 't4', text: 'Phase 3 — Extinguish: navigate to both fires and spray water on each one. Watch the tank meter as you work.', completed: false },
                { id: 't5', text: 'Phase 4 — Finish: navigate to the target after collecting metal and extinguishing the fires.', completed: false },
                { id: 't6', text: 'Combine all 4 phases into ONE program and Run it start to finish — complete the metal, fire, and target objectives! 🏆🎉', completed: false },
                { id: 't7', text: 'BONUS: count your total blocks used. Can you reduce it by 20% using loops and smarter routing? The best engineers optimise! ✨', completed: false }
            ],
            hint: 'Break the mission into phases (Scan → Collect → Extinguish → Target) and build each phase separately first, then connect them. Use loops wherever actions repeat and watch the tank meter while you extinguish fires. This top-down design approach is how real software is built!',
            homework: 'You are now a Master Coder! 🎓 Your challenge: design a completely NEW mission scenario and write the autonomous program for it. Ideas: delivery robot (pick up packages, avoid fires, drop at destination), rescue robot (find stranded people behind walls), or artist robot (draw a shape while collecting metals). Share your creation!',
            nextLesson: null
        }
    ],
    creative: [
        {
            id: 'lesson-art-1',
            title: 'Rainbow Spiral',
            description: 'Draw a hypnotic spiral that grows as it spins',
            difficulty: 'easy',
            xpReward: 150,
            icon: '🌀',
            par: 6,
            introduction: "Welcome to the ART STUDIO! 🎨 Here there are no wrong answers — only beautiful creations. Today we draw a SPIRAL, the same shape you see in snail shells, galaxies, and sunflowers! The secret of a spiral is simple: move a little, turn a little, then move a bit MORE, turn again — over and over. A Repeat block does the spinning for you. Add a Color block and even an Emotion block to give STEMO some personality while it paints. Ready, artist?",
            tasks: [
                { id: 't1', text: 'Add "Pen Down ✏️" so STEMO leaves a trail', completed: false },
                { id: 't2', text: 'Add a "🎨 Color" block and pick your favourite colour', completed: false },
                { id: 't3', text: 'Add "🔁 Repeat" set to a big number (try 30). Inside it put: Forward 1 and Right 25', completed: false },
                { id: 't4', text: 'Press ▶ Run and watch your spiral appear!', completed: false },
                { id: 't5', text: 'Add a "😊 Emotion → Excited" and a "🕺 Dance" block at the end to celebrate!', completed: false }
            ],
            hint: 'A spiral = Repeat many times → Forward a little + Turn a little. Change the turn angle (try 20, 25, 30) to make tighter or wider spirals!',
            homework: 'Make a DOUBLE spiral: draw one spiral, then change the colour and draw another turning the OTHER way (use Left instead of Right).',
            nextLesson: 'lesson-art-2'
        },
        {
            id: 'lesson-art-2',
            title: 'Rainbow Maker',
            description: 'Paint a bright rainbow with every colour of the spectrum',
            difficulty: 'easy',
            xpReward: 150,
            icon: '🌈',
            par: 14,
            introduction: "Did you know a real rainbow always has its colours in the same order — Red, Orange, Yellow, Green, Blue, Purple? ☀️🌧️ Today YOU are the rain and the sun! We'll draw curved arcs, one for each colour, stacked on top of each other. To make a curve, we move forward a tiny bit and turn a tiny bit, again and again — just like the spiral, but only a half-turn. Change the colour for each band and watch a rainbow grow!",
            tasks: [
                { id: 't1', text: 'Add "Pen Down ✏️" and a "🖌️ Size" block set to 6 for fat, juicy bands', completed: false },
                { id: 't2', text: 'Add "🎨 Color" → red. Then "🔁 Repeat 18" → (Forward 1, Right 10) to draw an arc', completed: false },
                { id: 't3', text: 'Change colour to orange and draw another arc just outside the first', completed: false },
                { id: 't4', text: 'Keep going — yellow, green, blue, purple. One arc per colour!', completed: false },
                { id: 't5', text: 'Finish with "💬 Say → I made a rainbow!" so STEMO shows off your art', completed: false }
            ],
            hint: 'Each colour band is the same arc (Repeat → Forward + Turn), just a different Color block before it. Move STEMO Forward a few steps between bands so they do not overlap.',
            homework: 'Add a sun ☀️ next to your rainbow: change colour to yellow and draw a small circle (Repeat 36 → Forward 1, Right 10).',
            nextLesson: 'lesson-art-3'
        },
        {
            id: 'lesson-art-3',
            title: 'Write Your Name',
            description: 'Turn STEMO into a pen and sign your masterpiece',
            difficulty: 'medium',
            xpReward: 200,
            icon: '✍️',
            par: 16,
            introduction: "Every great artist signs their work! ✍️ Today you'll guide STEMO like a pen to write the first letter of YOUR name. Letters are made of lines and turns — exactly the blocks you already know! Use Pen Up to jump (lift the pen) between strokes, and Pen Down to draw. Take it slow, one stroke at a time. This is how plotter robots and signing machines work in the real world!",
            tasks: [
                { id: 't1', text: 'Pick the first letter of your name. Imagine drawing it with straight lines', completed: false },
                { id: 't2', text: 'Add "Pen Down ✏️" then build the first stroke with Forward and Turn blocks', completed: false },
                { id: 't3', text: 'Use "Pen Up 🖊️" to move to the next stroke without drawing, then "Pen Down" again', completed: false },
                { id: 't4', text: 'Finish all the strokes of your letter and press ▶ Run', completed: false },
                { id: 't5', text: 'Add "😎 Emotion → Cool" and "🔊 Sound → Fanfare" to celebrate your signature!', completed: false }
            ],
            hint: 'Letters with straight lines (L, T, E, H, I, F, A) are easiest. Plan each stroke: Pen Down → draw → Pen Up → reposition → Pen Down → draw next stroke.',
            homework: 'Write all the letters of your first name! Use Pen Up to leave a gap between each letter.',
            nextLesson: 'lesson-art-4'
        },
        {
            id: 'lesson-art-4',
            title: 'Magic Mandala',
            description: 'Create a symmetrical mandala using loops inside loops',
            difficulty: 'medium',
            xpReward: 250,
            icon: '❄️',
            par: 8,
            introduction: "A MANDALA is a beautiful, perfectly symmetrical pattern — you'll find them in flowers, snowflakes ❄️, and art from around the world. The trick that makes them magical is a LOOP INSIDE A LOOP: the inner loop draws one shape (like a square), and the outer loop spins STEMO a little and draws it again, all the way around the circle. With just a few blocks you can make a pattern that looks incredibly complex. Let's create some magic!",
            tasks: [
                { id: 't1', text: 'Add "Pen Down ✏️" and a "🎨 Color" you love', completed: false },
                { id: 't2', text: 'Add an OUTER "🔁 Repeat 12" block', completed: false },
                { id: 't3', text: 'Inside it, add an INNER "🔁 Repeat 4" → (Forward 3, Right 90) to draw a square', completed: false },
                { id: 't4', text: 'Still inside the OUTER loop but after the inner one, add "Right 30" to spin the square around', completed: false },
                { id: 't5', text: 'Press ▶ Run — a stunning mandala! Add "🕺 Dance" to celebrate your art', completed: false }
            ],
            hint: 'Loop inside a loop! Outer Repeat = how many copies around the circle (12). Inner Repeat = the shape (square = 4 × Forward+Right 90). The extra turn (360 ÷ 12 = 30°) spins each copy.',
            homework: 'Change the inner shape to a triangle (Repeat 3 → Forward 4, Right 120) and the outer turn to match. Try different colours for a kaleidoscope!',
            nextLesson: null
        }
    ],
    // Challenge bonus entries — awarded when a student completes challenge mode for a mission lesson.
    // ID pattern: "<lessonId>-challenge". XP = 2× the base lesson reward.
    // These IDs are stored in completed_lessons and are validated server-side exactly like normal lesson IDs.
    challenges: [
        { id: 'lesson-4-challenge',  xpReward: 200  },
        { id: 'lesson-5-challenge',  xpReward: 300  },
        { id: 'lesson-6-challenge',  xpReward: 400  },
        { id: 'lesson-7-challenge',  xpReward: 600  },
        { id: 'lesson-8-challenge',  xpReward: 400  },
        { id: 'lesson-9-challenge',  xpReward: 500  },
        { id: 'lesson-10-challenge', xpReward: 600  },
        { id: 'lesson-11-challenge', xpReward: 700  },
        { id: 'lesson-12-challenge', xpReward: 800  },
        { id: 'lesson-13-challenge', xpReward: 1000 },
        { id: 'lesson-14-challenge', xpReward: 2000 },
        { id: 'lesson-15-challenge', xpReward: 800  },
        { id: 'lesson-16-challenge', xpReward: 900  },
        { id: 'lesson-17-challenge', xpReward: 1000 },
        { id: 'lesson-18-challenge', xpReward: 1200 },
        { id: 'lesson-19-challenge', xpReward: 1400 },
        { id: 'lesson-art-1-challenge', xpReward: 300 },
        { id: 'lesson-art-2-challenge', xpReward: 300 },
        { id: 'lesson-art-3-challenge', xpReward: 400 },
        { id: 'lesson-art-4-challenge', xpReward: 500 }
    ]
}

// Badges data  (type: 'xp'|'lessons'|'streak'|'level', threshold: number used for non-xp checks)
const badges = [
    // ── XP milestones ──────────────────────────────────────────────
    { id: 'first-steps',   name: 'First Steps',      description: 'Complete your first lesson',  icon: '🎯', type: 'xp',      threshold: 50,   xpRequired: 50,   req: '50 XP' },
    { id: 'fast-starter',  name: 'Fast Starter',     description: 'Earn 100 XP',                  icon: '⚡', type: 'xp',      threshold: 100,  xpRequired: 100,  req: '100 XP' },
    { id: 'mover',         name: 'Robot Mover',      description: 'Move STEMO 100 times',         icon: '🚀', type: 'xp',      threshold: 200,  xpRequired: 200,  req: '200 XP' },
    { id: 'bronze-coder',  name: 'Bronze Coder',     description: 'Earn 250 XP',                  icon: '🥉', type: 'xp',      threshold: 250,  xpRequired: 250,  req: '250 XP' },
    { id: 'artist',        name: 'Code Artist',      description: 'Draw 10 shapes',               icon: '🎨', type: 'xp',      threshold: 500,  xpRequired: 500,  req: '500 XP' },
    { id: 'loop-master',   name: 'Loop Master',      description: 'Use loops 20 times',           icon: '🔁', type: 'xp',      threshold: 750,  xpRequired: 750,  req: '750 XP' },
    { id: 'star-coder',    name: 'Star Coder',       description: 'Earn 1000 XP',                 icon: '⭐', type: 'xp',      threshold: 1000, xpRequired: 1000, req: '1000 XP' },
    { id: 'robot-friend',  name: "Robot's Best Friend", description: 'Chat with STEMO 50 times',  icon: '🤖', type: 'xp',      threshold: 1500, xpRequired: 1500, req: '1500 XP' },
    { id: 'silver-coder',  name: 'Silver Coder',     description: 'Earn 2000 XP',                 icon: '🥈', type: 'xp',      threshold: 2000, xpRequired: 2000, req: '2000 XP' },
    { id: 'gold-coder',    name: 'Gold Coder',       description: 'Earn 3500 XP',                 icon: '🥇', type: 'xp',      threshold: 3500, xpRequired: 3500, req: '3500 XP' },
    { id: 'diamond-coder', name: 'Diamond Coder',    description: 'Earn 5000 XP',                 icon: '💎', type: 'xp',      threshold: 5000, xpRequired: 5000, req: '5000 XP' },
    // ── Lesson milestones ──────────────────────────────────────────
    { id: 'quick-learner', name: 'Quick Learner',    description: 'Complete 3 lessons',           icon: '📚', type: 'lessons', threshold: 3,    xpRequired: 150,  req: '3 lessons' },
    { id: 'halfway-hero',  name: 'Halfway Hero',     description: 'Complete 10 lessons',          icon: '🎯', type: 'lessons', threshold: 10,   xpRequired: 500,  req: '10 lessons' },
    { id: 'completionist', name: 'Completionist',    description: 'Complete all 19 lessons',      icon: '🏅', type: 'lessons', threshold: 19,   xpRequired: 9999, req: '19 lessons' },
    // ── Streak badges ─────────────────────────────────────────────
    { id: 'on-fire',       name: 'On Fire',          description: '3-day coding streak',          icon: '🔥', type: 'streak',  threshold: 3,    xpRequired: 150,  req: '3-day streak' },
    { id: 'unstoppable',   name: 'Unstoppable',      description: '7-day coding streak',          icon: '🌪️', type: 'streak',  threshold: 7,    xpRequired: 350,  req: '7-day streak' },
    // ── Level badges ──────────────────────────────────────────────
    { id: 'rising-star',   name: 'Rising Star',      description: 'Reach Level 3',                icon: '🌟', type: 'level',   threshold: 3,    xpRequired: 1000, req: 'Level 3' },
    { id: 'coding-hero',   name: 'Coding Hero',      description: 'Reach Level 5',                icon: '🦸', type: 'level',   threshold: 5,    xpRequired: 2000, req: 'Level 5' },
    { id: 'legend',        name: 'Legend',           description: 'Reach Level 10',               icon: '👑', type: 'level',   threshold: 10,   xpRequired: 4500, req: 'Level 10' },
    { id: 'grandmaster',   name: 'Grandmaster',      description: 'Reach Level 13',               icon: '🏆', type: 'level',   threshold: 13,   xpRequired: 6000, req: 'Level 13' },
]

// ============================================
// API ROUTES
// ============================================

// Get curriculum — requires authentication
app.get('/api/curriculum', authMiddleware, (c) => {
    return c.json(curriculum)
})

// Get lesson by ID — requires authentication
app.get('/api/lesson/:id', authMiddleware, (c) => {
    const id = c.req.param('id')
    const allLessons = [
        ...curriculum.basic,
        ...curriculum.intermediate,
        ...curriculum.advanced,
        ...curriculum.creative
    ]
    const lesson = allLessons.find((l: any) => l.id === id)
    if (!lesson) {
        return c.json({ error: 'Lesson not found' }, 404)
    }
    return c.json(lesson)
})

// Get all badges — requires authentication
app.get('/api/badges', authMiddleware, (c) => {
    return c.json(badges)
})

// AI Chat endpoint — requires authentication
app.post('/api/chat', authMiddleware, async (c) => {
    try {
        const { message, context } = await c.req.json()
        if (!message || typeof message !== 'string') return c.json({ error: 'Message required' }, 400)
        if (message.length > 1000) return c.json({ error: 'Message too long (max 1000 characters)' }, 400)
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
            display: block;
            width: 100%;
            height: 100%;
        }
        #robotWorldViewport { min-width: 0; min-height: 0; }
        #robotWorldStage {
            position: relative;
            flex: 0 0 auto;
            width: 550px;
            height: 550px;
            max-width: 100%;
            max-height: 100%;
        }
        /* Keep the lower controls usable without letting them shrink the world. */
        #panelChat { padding: 8px; }
        #chatMessages { height: 38px; margin-bottom: 4px; }
        #chatInput { padding-top: 4px; padding-bottom: 4px; }
        #panelChat button { width: 32px; height: 32px; }
        #panelCC #ccMessages { height: 64px !important; }
        #panelCC > div:first-child { padding-top: 5px !important; padding-bottom: 5px !important; }
        #panelCC > div:last-child { padding-top: 4px !important; padding-bottom: 4px !important; }
        
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

        /* ============ TABLET / TOUCH SUPPORT ============ */
        .block-item { touch-action: manipulation; }
        .block-item:active { transform: scale(0.95); }
        @media (hover: none) {
            .lesson-card:hover { transform: none; box-shadow: none; }
            .block-item:hover { transform: none; }
        }
        @media (pointer: coarse) {
            .block-item { padding-top: 10px; padding-bottom: 10px; font-size: 13px; }
            #blockPalette::-webkit-scrollbar { display: none; }
        }
        /* Desktop keeps the full-height side-by-side layout */
        @media (min-width: 1024px) {
            #codeLayout { height: calc(100vh - 153px); min-height: 560px; }
            #robotPanel {
                width: clamp(590px, 48vw, 700px);
                flex: 0 0 auto;
            }
        }
        /* Mid-size tablets (landscape): keep the world large without starving Blockly */
        @media (min-width: 1024px) and (max-width: 1279px) {
            #robotPanel { width: min(52vw, 590px); }
        }
        /* Tablets portrait & small screens: stack the workspace vertically */
        @media (max-width: 1023px) {
            #codeLayout { flex-direction: column; }
            #blockPalette {
                display: flex; flex-direction: row; align-items: center;
                width: 100%; overflow-x: auto; overflow-y: hidden;
                white-space: nowrap; gap: 6px; padding: 8px;
                border-right: 0; border-bottom: 2px solid #e5e7eb;
            }
            #blockPalette > div { flex-shrink: 0; margin-bottom: 0 !important; }
            #blocklyDiv { flex: none; width: 100%; height: 46vh; min-height: 300px; }
            #robotPanel { width: 100%; border-left: 0; border-top: 2px solid #e5e7eb; }
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
        /* Hide all Blockly built-in UI widgets — zoom buttons, trashcan, minimap */
        .blocklyZoom, .blocklyTrash, .blocklyFlyoutButton,
        .blocklyZoomReset, .blocklyZoomIn, .blocklyZoomOut { display: none !important; }
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
                <i class="fas fa-graduation-cap mr-1"></i><span data-i18n="tab_learn">Learn</span>
            </button>
            <button onclick="switchTab('code')" id="tab-code" class="tab-inactive px-5 py-2 rounded-full font-bold transition-all text-sm">
                <i class="fas fa-code mr-1"></i><span data-i18n="tab_code">Code</span>
            </button>
            <button onclick="switchTab('achievements')" id="tab-achievements" class="tab-inactive px-5 py-2 rounded-full font-bold transition-all text-sm">
                <i class="fas fa-trophy mr-1"></i><span data-i18n="tab_achievements">Achievements</span>
            </button>
            <button onclick="switchTab('profile')" id="tab-profile" class="tab-inactive px-5 py-2 rounded-full font-bold transition-all text-sm">
                <i class="fas fa-user mr-1"></i><span data-i18n="tab_profile">My Profile</span>
            </button>
            <button onclick="switchTab('leaderboard')" id="tab-leaderboard" class="tab-inactive px-5 py-2 rounded-full font-bold transition-all text-sm">
                <i class="fas fa-ranking-star mr-1"></i><span data-i18n="tab_leaderboard">Leaderboard</span>
            </button>
            <button onclick="switchTab('videos')" id="tab-videos" class="tab-inactive px-5 py-2 rounded-full font-bold transition-all text-sm">
                <i class="fas fa-video mr-1"></i><span data-i18n="tab_videos">Video Training</span>
            </button>
            <button onclick="switchTab('interactive')" id="tab-interactive" class="tab-inactive px-5 py-2 rounded-full font-bold transition-all text-sm">
                <i class="fas fa-laptop-code mr-1"></i><span data-i18n="tab_interactive">Interactive Lessons</span>
            </button>
            <select id="langSelect" onchange="setLanguage(this.value)" class="ml-auto px-3 py-2 rounded-full font-bold text-sm bg-white border-2 border-indigo-200 text-indigo-600 cursor-pointer" title="Language / اللغة">
                <option value="en">🇬🇧 English</option>
                <option value="ar">🇸🇦 العربية</option>
                <option value="es">🇪🇸 Español</option>
                <option value="fr">🇫🇷 Français</option>
            </select>
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
                        <h2 class="text-3xl font-bold mb-2" data-i18n="welcome_title">Welcome to STEMO Academy!</h2>
                        <p class="text-lg text-purple-100 mb-4" data-i18n="welcome_sub">Learn to code by programming your robot friend. Ready for an adventure?</p>
                        <button onclick="startFirstLesson()" class="bg-white text-indigo-600 px-6 py-3 rounded-full font-bold hover:bg-yellow-300 hover:text-indigo-700 transition-all transform hover:scale-105 shadow-lg">
                            <i class="fas fa-play mr-2"></i><span data-i18n="btn_start_learning">Start Learning!</span>
                        </button>
                    </div>
                </div>
            </div>

            <!-- Teacher Assigned Lesson Banner -->
            <div id="assignedLessonBanner" class="hidden bg-gradient-to-r from-amber-400 to-orange-500 rounded-2xl p-5 mb-6 text-white shadow-lg">
                <div class="flex items-center gap-4 flex-wrap">
                    <span class="text-4xl" id="assignedLessonBannerIcon">📖</span>
                    <div class="flex-1">
                        <div class="text-xs font-bold text-amber-100 uppercase tracking-wide mb-1" data-i18n="assigned_label">📌 Your teacher assigned this lesson</div>
                        <div class="text-xl font-bold" id="assignedLessonBannerTitle">-</div>
                        <div class="text-amber-100 text-sm" id="assignedLessonBannerDesc"></div>
                    </div>
                    <button id="assignedLessonBannerBtn" onclick="" class="bg-white text-orange-600 px-5 py-2 rounded-full font-bold text-sm hover:bg-yellow-300 transition-all shadow" data-i18n="btn_start_now">🚀 Start Now</button>
                </div>
            </div>

            <h3 class="text-2xl font-bold text-gray-800 mb-4">
                <i class="fas fa-book-open text-indigo-500 mr-2"></i><span data-i18n="curriculum_path">Curriculum Path</span>
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
                                <i class="fas fa-tasks text-indigo-500 mr-2"></i><span data-i18n="your_tasks">Your Tasks:</span>
                            </h3>
                            <div id="lessonTasks" class="space-y-3">
                                <!-- Tasks will be inserted here -->
                            </div>
                        </div>
                        
                        <!-- Homework/Challenge -->
                        <div>
                            <h3 class="text-lg font-bold text-orange-600 mb-4">
                                <i class="fas fa-book-reader mr-2"></i><span data-i18n="homework_title">Homework Challenge:</span>
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
                                <span class="font-bold text-amber-800" data-i18n="hint_title">Hint</span>
                            </div>
                            <p class="text-amber-700 text-sm" id="lessonHintText">Hint text...</p>
                        </div>
                    </div>
                    
                    <!-- Action Buttons -->
                    <div class="p-6 bg-gray-50 flex gap-4">
                        <button onclick="hideLessonDetail()" class="flex-1 bg-gray-200 hover:bg-gray-300 text-gray-700 py-3 rounded-full font-bold transition-all">
                            <i class="fas fa-arrow-left mr-2"></i><span data-i18n="btn_back_lessons">Back to Lessons</span>
                        </button>
                        <button onclick="startLessonFromDetail()" class="flex-1 bg-gradient-to-r from-green-500 to-emerald-600 hover:opacity-90 text-white py-3 rounded-full font-bold transition-all">
                            <i class="fas fa-play mr-2"></i><span data-i18n="btn_start_coding">Start Coding!</span>
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
                        <p class="text-xs text-purple-200" id="currentLessonDesc">Click blocks to add • Right-click a block to delete it or a whole group</p>
                    </div>
                </div>
                <div class="flex flex-wrap gap-2 items-center justify-end">
                    <!-- Toggle Robot Panel Button -->
                    <button onclick="toggleRobotPanel()" id="toggleRobotBtn" class="bg-cyan-500 hover:bg-cyan-600 text-white px-3 py-1.5 rounded-full font-bold transition-all flex items-center gap-1 text-sm">
                        <span id="robotPanelIcon">🤖</span>
                        <span id="robotPanelText" class="hidden sm:inline">Hide Robot</span>
                    </button>
                    <button onclick="runCode()" class="bg-green-500 hover:bg-green-600 text-white px-5 py-1.5 rounded-full font-bold transition-all transform hover:scale-105 flex items-center gap-2 text-base">
                        <i class="fas fa-play"></i> <span data-i18n="btn_run">Run</span>
                    </button>
                    <button onclick="stopAndResetRobot()" class="bg-yellow-500 hover:bg-yellow-600 text-white px-3 py-1.5 rounded-full font-bold transition-all flex items-center gap-1 text-sm" title="Stop the program and return STEMO to the starting point">
                        <i class="fas fa-stop"></i> <span data-i18n="btn_stop_reset">Stop &amp; Reset</span>
                    </button>
                    <div class="flex items-center gap-0.5 bg-gray-100 rounded-full px-1 py-0.5" title="Where STEMO starts">
                        <button onclick="setStartPoint('center')" id="startCenterBtn" class="bg-teal-500 hover:bg-teal-600 text-white px-2 py-1 rounded-full font-bold transition-all text-xs" title="Start from center (home)">🏠</button>
                        <button onclick="setStartPoint('left')" id="startLeftBtn" class="bg-gray-300 hover:bg-gray-400 text-gray-700 px-2 py-1 rounded-full font-bold transition-all text-xs" title="Start from the left edge (more room to write)" data-i18n="btn_left_start">⬅️ Left</button>
                    </div>
                    <button onclick="undoCode()" class="bg-gray-500 hover:bg-gray-600 text-white px-3 py-1.5 rounded-full font-bold transition-all flex items-center gap-1 text-sm" title="Undo last block change (Ctrl+Z)" data-i18n="btn_undo">
                        ↩️ Undo
                    </button>
                    <button id="groupSelectBtn" onclick="toggleGroupSelect()" class="bg-purple-500 hover:bg-purple-600 text-white px-3 py-1.5 rounded-full font-bold transition-all flex items-center gap-1 text-sm" title="Select multiple blocks then delete them as a group" data-i18n="btn_select_group">
                        🔲 Select Group
                    </button>
                    <button id="deleteGroupBtn" onclick="deleteGroupSelected()" class="bg-red-500 hover:bg-red-600 text-white px-3 py-1.5 rounded-full font-bold transition-all flex items-center gap-1 text-sm" title="Delete all selected blocks" style="display:none">
                        🗑️ Delete (<span id="groupCountSpan">0</span>)
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
            <div id="codeLayout" class="flex bg-white rounded-b-2xl card-shadow overflow-hidden">
                <!-- Block Palette - Left Side -->
                <div id="blockPalette" class="w-32 bg-gradient-to-b from-gray-50 to-gray-100 p-2 overflow-y-auto border-r-2 border-gray-200 flex-shrink-0">
                    <div class="text-xs font-bold text-gray-500 mb-1 uppercase" data-i18n="cat_move">🚶 Move</div>
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
                    <div class="block-item bg-yellow-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-yellow-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('go_left_start')">
                        ⬅️ Left Start
                    </div>
                    <div class="block-item bg-gray-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-gray-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('hide_stemo')">
                        👻 Hide
                    </div>
                    
                    <div class="text-xs font-bold text-gray-500 mb-1 mt-2 uppercase" data-i18n="cat_draw">🎨 Draw</div>
                    <div class="block-item bg-pink-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-pink-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('pen_control')">
                        🖍️ Pen
                    </div>
                    <div class="block-item bg-pink-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-pink-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('set_color')">
                        🎨 Color
                    </div>
                    <div class="block-item bg-pink-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-pink-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('set_pen_size')">
                        🖌️ Size
                    </div>

                    <div class="text-xs font-bold text-gray-500 mb-1 mt-2 uppercase" data-i18n="cat_fun">🎉 Fun</div>
                    <div class="block-item bg-fuchsia-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-fuchsia-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('stemo_say')">
                        💬 Say
                    </div>
                    <div class="block-item bg-fuchsia-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-fuchsia-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('stemo_emotion')">
                        😊 Emotion
                    </div>
                    <div class="block-item bg-fuchsia-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-fuchsia-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('stemo_dance')">
                        🕺 Dance
                    </div>
                    <div class="block-item bg-fuchsia-500 text-white px-2 py-1.5 rounded-lg mb-1 cursor-pointer hover:bg-fuchsia-600 hover:scale-105 transition-all text-xs font-bold shadow" onclick="addBlock('play_fun_sound')">
                        🔊 Sound
                    </div>
                    
                    <div class="text-xs font-bold text-gray-500 mb-1 mt-2 uppercase" data-i18n="cat_loop">🔁 Loop</div>
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
                <div id="robotPanel" class="lg:w-[590px] bg-white border-l-2 border-gray-200 flex flex-col transition-all duration-300">
                    <div class="bg-gradient-to-r from-blue-500 to-cyan-500 text-white p-2 flex items-center justify-between">
                        <div class="flex items-center gap-2 flex-shrink-0">
                            <span class="text-xl">🤖</span>
                            <span class="font-bold">STEMO's World</span>
                            <div id="ccSignalDot" title="Command Center signal" style="width:8px;height:8px;border-radius:50%;background:#4ade80;box-shadow:0 0 6px #4ade80;transition:all 0.3s;flex-shrink:0;"></div>
                        </div>
                        <div class="flex flex-wrap gap-1 justify-end flex-1 min-w-0">
                            <button onclick="toggleSound()" id="soundToggleBtn" class="bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Toggle sound effects">
                                🔊
                            </button>
                            <button onclick="openStemoColor()" id="stemoColorBtn" class="bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Customize STEMO's color">
                                🎨
                            </button>
                            <input type="color" id="stemoColorInput" value="#3b82f6" onchange="setStemoColor(this.value)" style="position:absolute;width:1px;height:1px;opacity:0;pointer-events:none;" />
                            <button onclick="setStemoColor('#3b82f6')" id="stemoColorResetBtn" class="bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Reset STEMO's color">
                                ♻️
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
                        <div id="wallAngleControls" class="hidden items-center gap-1 whitespace-nowrap">
                            <button onclick="setWallAngle(0)" class="bg-amber-700 hover:bg-amber-800 text-white rounded px-2 py-0.5 font-bold" title="Horizontal wall">H</button>
                            <button onclick="setWallAngle(90)" class="bg-amber-700 hover:bg-amber-800 text-white rounded px-2 py-0.5 font-bold" title="Vertical wall">V</button>
                            <label class="font-bold text-gray-600">Angle</label>
                            <input id="wallAngleInput" type="number" min="0" max="359" step="1" value="0" onchange="setWallAngle(this.value)" class="w-14 border border-gray-300 rounded px-1 py-0.5 text-center" title="Wall angle in degrees" />
                            <span class="font-bold text-gray-600">°</span>
                        </div>
                        <!-- Right: exit button (shown during challenge) -->
                        <div id="missionExitBtn" class="hidden">
                            <button onclick="exitChallengeMode()" class="bg-rose-500 hover:bg-rose-600 text-white rounded-full shadow px-3 py-0.5 text-xs font-bold transition-colors">✕ Exit Challenge</button>
                        </div>
                    </div>
                    <div id="robotWorldViewport" class="flex-1 p-2 flex items-center justify-center overflow-hidden relative">
                        <div id="robotWorldStage">
                            <canvas id="robotCanvas" width="550" height="550" class="rounded-xl shadow-lg cursor-crosshair relative z-10" onclick="handleCanvasClick(event)"></canvas>
                            <div id="threeCanvasContainer" class="absolute inset-0 rounded-xl overflow-hidden hidden z-20 pointer-events-auto"></div>
                            <!-- Mission Toast -->
                            <div id="missionHUD" class="hidden absolute top-2 left-2 right-2 z-30 pointer-events-none">
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
                            <span id="roleBadge" class="bg-indigo-100 text-indigo-700 text-sm font-bold px-3 py-1 rounded-full mt-1 inline-block">🎓 Student</span>
                        </div>
                    </div>
                    <div id="profileClassInfo" class="bg-gray-50 rounded-2xl p-4 mb-4 space-y-2"></div>
                    <div class="text-gray-400 text-xs" id="profileJoined"></div>
                </div>
                <!-- Change Password Card -->
                <div class="bg-white rounded-3xl card-shadow p-6">
                    <h3 class="text-lg font-bold text-gray-800 mb-4">🔒 Change Password</h3>
                    <div class="space-y-3">
                        <input id="pwCurrent" type="password" placeholder="Current password" class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-gray-800 focus:outline-none focus:border-indigo-400 text-sm">
                        <input id="pwNew" type="password" placeholder="New password (min 6 characters)" class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-gray-800 focus:outline-none focus:border-indigo-400 text-sm">
                        <input id="pwConfirm" type="password" placeholder="Confirm new password" class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-gray-800 focus:outline-none focus:border-indigo-400 text-sm">
                        <div id="pwMsg" class="text-sm hidden"></div>
                        <button onclick="changeStudentPassword()" class="w-full bg-indigo-600 hover:bg-indigo-700 text-white py-3 rounded-xl font-bold transition-all">Update Password</button>
                    </div>
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
                <!-- Rankings -->
                <div class="bg-white rounded-3xl card-shadow p-6">
                    <h3 class="text-lg font-bold text-gray-700 mb-4"><i class="fas fa-ranking-star text-yellow-500 mr-2"></i>My Rankings</h3>
                    <div class="grid grid-cols-3 gap-3">
                        <div class="text-center p-4 rounded-2xl bg-blue-50 border border-blue-100">
                            <div class="text-xs text-blue-500 font-bold mb-2">🎒 My Class</div>
                            <div class="text-3xl font-bold text-blue-700" id="rankClass">—</div>
                            <div class="text-xs text-gray-400 mt-1" id="rankClassOf"></div>
                        </div>
                        <div class="text-center p-4 rounded-2xl bg-purple-50 border border-purple-100">
                            <div class="text-xs text-purple-600 font-bold mb-2">🏫 School</div>
                            <div class="text-3xl font-bold text-purple-700" id="rankSchool">—</div>
                            <div class="text-xs text-gray-400 mt-1" id="rankSchoolOf"></div>
                        </div>
                        <div class="text-center p-4 rounded-2xl bg-yellow-50 border border-yellow-100">
                            <div class="text-xs text-yellow-600 font-bold mb-2">🌍 Platform</div>
                            <div class="text-3xl font-bold text-yellow-600" id="rankPlatform">—</div>
                            <div class="text-xs text-gray-400 mt-1" id="rankPlatformOf"></div>
                        </div>
                    </div>
                </div>
                <!-- Earned Badges showcase -->
                <div class="bg-white rounded-3xl card-shadow p-6">
                    <h3 class="text-lg font-bold text-gray-700 mb-4"><i class="fas fa-medal text-yellow-500 mr-2"></i>My Badges</h3>
                    <div class="flex flex-wrap gap-3" id="profileBadgesList">
                        <p class="text-gray-400 text-sm italic">Loading badges...</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Leaderboard Tab -->
        <div id="leaderboard-section" class="hidden">
            <div class="bg-white rounded-3xl card-shadow p-6">
                <!-- 3-tab switcher -->
                <div class="flex gap-2 mb-6 bg-gray-100 p-1 rounded-2xl w-fit">
                    <button onclick="switchLbTab('class')" id="lb-tab-class"
                        class="px-4 py-2 rounded-xl font-bold text-sm transition-all bg-white shadow text-indigo-700">🎒 My Class</button>
                    <button onclick="switchLbTab('school')" id="lb-tab-school"
                        class="px-4 py-2 rounded-xl font-bold text-sm transition-all text-gray-500 hover:text-gray-700">🏫 School</button>
                    <button onclick="switchLbTab('platform')" id="lb-tab-platform"
                        class="px-4 py-2 rounded-xl font-bold text-sm transition-all text-gray-500 hover:text-gray-700">🌍 Platform</button>
                </div>
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-xl font-bold text-gray-800" id="lbTitle">
                        <i class="fas fa-trophy text-yellow-500 mr-2"></i><span id="lbTitleText">Class Leaderboard</span>
                    </h3>
                    <button onclick="loadLeaderboard()" class="bg-indigo-100 hover:bg-indigo-200 text-indigo-700 px-4 py-2 rounded-full text-sm font-bold transition-all">🔄 Refresh</button>
                </div>
                <!-- Top 3 podium -->
                <div class="flex justify-center gap-4 mb-8" id="podiumRow"></div>
                <!-- Full ranking table -->
                <div id="leaderboardList" class="space-y-2"></div>
                <div id="leaderboardPagination" class="hidden mt-6 flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-gray-100 pt-4">
                    <div class="text-sm text-gray-500" id="leaderboardPageSummary"></div>
                    <div class="flex items-center gap-2">
                        <label for="leaderboardPageSize" class="text-xs text-gray-500">Per page</label>
                        <select id="leaderboardPageSize" onchange="changeLeaderboardPageSize(this.value)" class="border border-gray-200 rounded-lg px-2 py-1.5 text-sm text-gray-700 focus:outline-none focus:border-indigo-400">
                            <option value="30" selected>30</option>
                            <option value="50">50</option>
                        </select>
                        <button id="leaderboardPrev" onclick="changeLeaderboardPage(-1)" class="px-3 py-1.5 rounded-lg text-sm font-bold bg-gray-100 text-gray-400 disabled:opacity-50" disabled>← Previous</button>
                        <button id="leaderboardNext" onclick="changeLeaderboardPage(1)" class="px-3 py-1.5 rounded-lg text-sm font-bold bg-indigo-100 text-indigo-700 disabled:opacity-50" disabled>Next →</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Video Training Tab -->
        <div id="videos-section" class="hidden">
            <div class="bg-white rounded-3xl card-shadow p-6">
                <div class="flex items-center justify-between mb-6">
                    <h3 class="text-2xl font-bold text-gray-800">
                        <i class="fas fa-video text-red-500 mr-2"></i>Video Training
                    </h3>
                    <button onclick="loadStudentVideos()" class="bg-indigo-100 hover:bg-indigo-200 text-indigo-700 px-4 py-2 rounded-full text-sm font-bold transition-all">🔄 Refresh</button>
                </div>
                <p class="text-gray-500 mb-6 text-sm">Watch video guides for each lesson. Click a lesson to play the video!</p>
                <!-- Video player embed -->
                <div id="videoPlayer" class="hidden mb-6">
                    <div class="bg-black rounded-2xl overflow-hidden" style="aspect-ratio:16/9;max-width:720px;margin:0 auto;">
                        <iframe id="videoFrame" width="100%" height="100%" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen style="display:block;"></iframe>
                    </div>
                    <div class="text-center mt-3">
                        <button onclick="document.getElementById('videoPlayer').classList.add('hidden');document.getElementById('videoFrame').src=''" class="text-gray-500 hover:text-gray-700 text-sm font-bold">✕ Close Player</button>
                    </div>
                </div>
                <!-- Video list -->
                <div id="videoList" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <div class="text-gray-400 text-center py-12 col-span-3">
                        <i class="fas fa-video text-4xl mb-3 block"></i>Loading videos...
                    </div>
                </div>
            </div>
        </div>

        <!-- Interactive HTML Lessons Tab -->
        <div id="interactive-section" class="hidden">
            <div class="bg-white rounded-3xl card-shadow p-6">
                <div class="flex items-center justify-between mb-4 gap-4">
                    <h3 class="text-2xl font-bold text-gray-800">
                        <i class="fas fa-laptop-code text-purple-500 mr-2"></i><span data-i18n="interactive_title">Interactive Lessons</span>
                    </h3>
                    <button onclick="loadInteractiveLessons()" class="bg-purple-100 hover:bg-purple-200 text-purple-700 px-4 py-2 rounded-full text-sm font-bold transition-all">🔄 <span data-i18n="btn_refresh">Refresh</span></button>
                </div>
                <p class="text-gray-500 mb-6 text-sm" data-i18n="interactive_subtitle">Explore interactive activities prepared by your academy.</p>
                <div id="interactiveLessonList" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <div class="text-gray-400 text-center py-12 col-span-3">
                        <i class="fas fa-laptop-code text-4xl mb-3 block"></i><span data-i18n="interactive_loading">Loading interactive lessons...</span>
                    </div>
                </div>
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
                    <div id="challengeModeDescription" class="text-gray-500 text-xs text-center">A pre-set mission loads. Complete the objective to win XP!</div>
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
            <div id="starRating" class="mb-4 hidden">
                <div id="starRow" class="text-5xl tracking-widest mb-1">⭐⭐⭐</div>
                <div class="text-gray-500 text-sm font-bold" id="starLabel">Perfect — 3 stars!</div>
            </div>
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

        var WORLD_VIEW_SCALE = 0.86;
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
            lastTemp: 25,
            emotion: 'normal',
            sayText: '',
            dancing: false
        };

        // STEMO start points — center (home) is default; left gives room to write long words
        var STEMO_START_POINTS = {
            center: { x: 275, y: 275, angle: -90 },
            left:   { x: 70,  y: 275, angle: -90 }
        };
        var stemoStartName = safeStorageGetEarly('stemoStartPoint') || 'center';
        function getStemoStart() {
            return STEMO_START_POINTS[stemoStartName] || STEMO_START_POINTS.center;
        }

        // STEMO customization — persisted body color chosen by the kid
        var stemoBodyColor = safeStorageGetEarly('stemoBodyColor') || '#3b82f6';
        function safeStorageGetEarly(k) {
            try { return window.localStorage && localStorage.getItem(k); } catch (e) { return null; }
        }
        // Lighten a hex color by a percent (0-1) — used for STEMO's head shade
        function lightenColor(hex, percent) {
            try {
                var h = hex.replace('#', '');
                if (h.length === 3) h = h[0]+h[0]+h[1]+h[1]+h[2]+h[2];
                var r = parseInt(h.substring(0,2),16), g = parseInt(h.substring(2,4),16), b = parseInt(h.substring(4,6),16);
                r = Math.round(r + (255 - r) * percent);
                g = Math.round(g + (255 - g) * percent);
                b = Math.round(b + (255 - b) * percent);
                return 'rgb(' + r + ',' + g + ',' + b + ')';
            } catch (e) { return hex; }
        }

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
        var SOUND_COOLDOWN = { move: 80, turn: 80, spray: 120, click: 30, safety_alert: 900, fire_alarm: 700 };
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
                    case 'safety_alert': tone(880, 0.12, 'square', 0.12);
                                         setTimeout(function(){ tone(660, 0.14, 'square', 0.12); }, 140); break;
                    case 'fire_alarm':  tone(1040, 0.13, 'square', 0.13);
                                         setTimeout(function(){ tone(1040, 0.13, 'square', 0.13); }, 190); break;
                    case 'success':    tone(523, 0.10, 'triangle', 0.13);
                                       setTimeout(function(){ tone(659, 0.10, 'triangle', 0.13); }, 100);
                                       setTimeout(function(){ tone(784, 0.10, 'triangle', 0.13); }, 200);
                                       setTimeout(function(){ tone(1047, 0.18, 'triangle', 0.14); }, 300); break;
                    case 'beep':       tone(880, 0.06, 'square', 0.07); break;
                    case 'pop':        tone(420, 0.07, 'sine', 0.14, 180); break;
                    case 'cheer':      tone(659, 0.10, 'triangle', 0.13);
                                       setTimeout(function(){ tone(784, 0.10, 'triangle', 0.13); }, 90);
                                       setTimeout(function(){ tone(988, 0.10, 'triangle', 0.13); }, 180);
                                       setTimeout(function(){ tone(1319, 0.20, 'triangle', 0.14); }, 270); break;
                    case 'fanfare':    tone(523, 0.12, 'sawtooth', 0.10);
                                       setTimeout(function(){ tone(523, 0.10, 'sawtooth', 0.10); }, 130);
                                       setTimeout(function(){ tone(784, 0.10, 'sawtooth', 0.11); }, 250);
                                       setTimeout(function(){ tone(1047, 0.24, 'sawtooth', 0.12); }, 360); break;
                    case 'magic':      tone(784, 0.08, 'sine', 0.10, 1568);
                                       setTimeout(function(){ tone(1047, 0.08, 'sine', 0.10, 2093); }, 80);
                                       setTimeout(function(){ tone(1319, 0.14, 'sine', 0.11, 2637); }, 160); break;
                    case 'meow':       tone(620, 0.18, 'sawtooth', 0.10, 420);
                                       setTimeout(function(){ tone(420, 0.16, 'sawtooth', 0.09, 300); }, 160); break;
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
        var lastSelectedBlock = null;
        var groupSelectMode = false;
        var groupSelectedBlocks = []; // block IDs in current group selection
        
        // Metal objects on the board
        var metalObjects = [];
        var metalIdCounter = 0;
        
        // Wall objects for ultrasonic sensor
        var wallObjects = [];
        var wallIdCounter = 0;
        
        // Fire objects for temperature sensor
        var fireObjects = [];
        var fireIdCounter = 0;
        var activeSafetyHazard = null;
        var safetyAlertUntil = 0;
        var safetyAlertTimer = null;
        
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
        var wallPlacementAngle = 0;
        
        // ============================================
        // CHALLENGE MODE STATE
        // ============================================
        var challengeMode = false;
        var challengeActiveLessonId = null; // locked at launch; never changes when "Next Lesson" is clicked
        var missionObjectives = null;
        var challengeCompleted = false;
        var challengeSensorScanCount = 0;
        var challengeWallConditionCount = 0;
        var challengeWallConditionTrueCount = 0;
        // True while executeCommands is running; used to suppress premature objective checks on drawing lessons
        var robotExecuting = false;
        // Incrementing this invalidates every delayed callback from an older run.
        var executionGeneration = 0;
        // Drawing lessons whose objectives should only be evaluated after execution finishes
        var DRAWING_LESSON_IDS = ['lesson-4','lesson-5','lesson-6','lesson-7'];

        var MISSION_LESSON_IDS = ['lesson-4','lesson-5','lesson-6','lesson-7','lesson-8','lesson-9','lesson-10','lesson-11','lesson-12','lesson-13','lesson-14','lesson-15','lesson-16','lesson-17','lesson-18','lesson-19','lesson-art-1','lesson-art-2','lesson-art-3','lesson-art-4'];

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
                    { id: 'colors', label: '🎨 Use 2+ different colours', check: function() {
                        var seen = {};
                        robot.trails.forEach(function(t) { seen[t.color] = true; });
                        return Object.keys(seen).length >= 2;
                    }},
                    { id: 'size', label: '🖌️ Use a Color or Size block', check: function() {
                        if (!workspace) return false;
                        return workspace.getAllBlocks().some(function(b) {
                            return b.type === 'set_color' || b.type === 'set_pen_size';
                        });
                    }},
                    { id: 'shape', label: '⬜ Draw 4+ line segments', check: function() {
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
                title: 'Draw the Spinning Boxes! 🟦',
                description: 'Copy the full pattern of 8 rotated boxes shown in ghost lines. Choose one pen colour and use that same colour for the entire drawing!',
                setup: function() {
                    // Simulate the target pattern and store as ghost trails for canvas reference.
                    // Pattern: Color blue → Repeat 8 → (Repeat 4 → Move 6, Right 90°) → Right 45°.
                    // Each box has 4 × 120 px sides and returns to the center before rotating.
                    var simX = 275, simY = 275, simAngle = 0;
                    targetTrails = [];
                    var step = 120;
                    for (var i = 0; i < 8; i++) {
                        for (var j = 0; j < 4; j++) {
                            var rad = simAngle * Math.PI / 180;
                            var nx = simX + Math.cos(rad) * step;
                            var ny = simY + Math.sin(rad) * step;
                            targetTrails.push({ x1: simX, y1: simY, x2: nx, y2: ny, color: '#6366f1' });
                            simX = nx; simY = ny;
                            simAngle += 90;
                        }
                        simAngle += 45;
                    }
                },
                objectives: [
                    { id: 'nested', label: '🔁 Use 2 Repeat blocks for boxes and rotation', check: function() {
                        if (!workspace) return false;
                        return workspace.getAllBlocks().filter(function(b) { return b.type === 'repeat_times'; }).length >= 2;
                    }},
                    { id: 'boxes', label: '🟦 Draw all 8 boxes (32 sides)', check: function() {
                        return robot.trails.length >= 32;
                    }},
                    { id: 'same-color', label: '🎨 Use the same pen colour for the full drawing', check: function() {
                        var seen = {};
                        robot.trails.forEach(function(t) { seen[t.color] = true; });
                        return robot.trails.length >= 32 && Object.keys(seen).length === 1;
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
                    { id: 'angle', label: '↪️ Use a large turn (90°+)', check: function() {
                        if (!workspace) return false;
                        return workspace.getAllBlocks().some(function(b) {
                            return (b.type === 'turn_right' || b.type === 'turn_left') && Number(b.getFieldValue('DEGREES')) >= 90;
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
                title: 'Ultrasonic corridor — sense, decide, and turn!',
                description: 'Use a Repeat loop containing "If Wall Within 1 step" and react when STEMO senses both walls. Scan Ahead is a valid extra sensor tool, but equivalent programs using the wall condition are also accepted. Smart Navigate, Go to Target, and Auto Move are not allowed shortcuts.',
                setup: function() {
                    wallObjects = [
                        // Top-left horizontal wall — STEMO hits this going north
                        // Bottom face at y=195 → STEMO at y=215 is exactly 1 step away → Turn Right (faces east)
                        { id: wallIdCounter++, x: 115, y: 155, width: 180, height: 40 },
                        // Right vertical wall — STEMO hits this going east
                        // Left face at x=415 → STEMO at x=395 is exactly 1 step away → Turn Right (faces south)
                        { id: wallIdCounter++, x: 415, y: 155, width: 40, height: 300 },
                        // Bottom horizontal — completes the L-shape visually (below the target)
                        { id: wallIdCounter++, x: 295, y: 455, width: 160, height: 40 }
                    ];
                    // Target is directly south after the two one-step sensor turns.
                    targetPoint = { x: 395, y: 395 };
                },
                objectives: [
                    { id: 'sensor-logic', label: '📡 Use If Wall twice inside a Repeat loop', check: function() {
                        if (!workspace) return false;
                        var blocks = workspace.getAllBlocks(false);
                        var hasShortcut = blocks.some(function(b) {
                            return b.type === 'smart_navigate' || b.type === 'go_to_target' || b.type === 'auto_move';
                        });
                        var hasValidLoopedCondition = blocks.some(function(b) {
                            if (b.type !== 'if_wall_ahead') return false;
                            var parent = b.getParent();
                            var insideRepeat = false;
                            while (parent) {
                                if (parent.type === 'repeat_times') insideRepeat = true;
                                parent = parent.getParent();
                            }
                            var thenBlock = b.getInputTargetBlock('DO');
                            var validTurn = thenBlock && (thenBlock.type === 'smart_turn' || thenBlock.type === 'turn_right' || thenBlock.type === 'turn_left');
                            return insideRepeat && validTurn;
                        });
                        return !hasShortcut && hasValidLoopedCondition &&
                            challengeWallConditionCount >= 2 && challengeWallConditionTrueCount >= 2;
                    }},
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
                        return fireObjects.length === 0;
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
                        return fireObjects.length === 0;
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
                        robot.trails.forEach(function(t){ total += Math.sqrt((t.x2-t.x1)*(t.x2-t.x1)+(t.y2-t.y1)*(t.y2-t.y1)); });
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
                        var sp = getStemoStart();
                        var dx = robot.x - sp.x, dy = robot.y - sp.y;
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
            },
            'lesson-art-1': {
                title: 'Spin a Rainbow Spiral! 🌀',
                description: 'Match the faded spiral on the canvas. Use a Color block + a Repeat loop (try Repeat 30 → Forward 1, Right 25). Add an Emotion or Dance block to celebrate!',
                setup: function() {
                    targetTrails = [];
                    var cols = ['#ef4444','#f97316','#eab308','#22c55e','#3b82f6','#a855f7'];
                    var px = null, py = null, idx = 0;
                    for (var a = 0; a <= 1080; a += 12) {
                        var r = (a / 1080) * 180;
                        var rad = a * Math.PI / 180;
                        var nx = 275 + Math.cos(rad) * r;
                        var ny = 275 + Math.sin(rad) * r;
                        if (px !== null) { targetTrails.push({ x1: px, y1: py, x2: nx, y2: ny, color: cols[idx % cols.length] }); idx++; }
                        px = nx; py = ny;
                    }
                },
                objectives: [
                    { id: 'loop', label: '🔁 Use a Repeat block', check: function() {
                        if (!workspace) return false;
                        return workspace.getAllBlocks().some(function(b) { return b.type === 'repeat_times'; });
                    }},
                    { id: 'color', label: '🎨 Use a Color block', check: function() {
                        if (!workspace) return false;
                        return workspace.getAllBlocks().some(function(b) { return b.type === 'set_color'; });
                    }},
                    { id: 'spiral', label: '🌀 Draw 15+ line segments', check: function() {
                        return robot.trails.length >= 15;
                    }}
                ]
            },
            'lesson-art-2': {
                title: 'Paint a Rainbow! 🌈',
                description: 'Match the faded rainbow arcs. Use 3+ different Color blocks and a Repeat loop to bend each band (try Repeat 18 → Forward 1, Right 10).',
                setup: function() {
                    targetTrails = [];
                    var cols = ['#ef4444','#f97316','#eab308','#22c55e','#3b82f6','#a855f7'];
                    for (var c = 0; c < cols.length; c++) {
                        var r = 60 + c * 16;
                        var prevx = null, prevy = null;
                        for (var a = 200; a <= 340; a += 8) {
                            var rad = a * Math.PI / 180;
                            var x = 275 + Math.cos(rad) * r;
                            var y = 360 + Math.sin(rad) * r;
                            if (prevx !== null) targetTrails.push({ x1: prevx, y1: prevy, x2: x, y2: y, color: cols[c] });
                            prevx = x; prevy = y;
                        }
                    }
                },
                objectives: [
                    { id: 'colors', label: '🎨 Use 3+ different colours', check: function() {
                        var seen = {};
                        robot.trails.forEach(function(t) { seen[t.color] = true; });
                        return Object.keys(seen).length >= 3;
                    }},
                    { id: 'loop', label: '🔁 Use a Repeat block', check: function() {
                        if (!workspace) return false;
                        return workspace.getAllBlocks().some(function(b) { return b.type === 'repeat_times'; });
                    }},
                    { id: 'bands', label: '🌈 Draw 18+ line segments', check: function() {
                        return robot.trails.length >= 18;
                    }}
                ]
            },
            'lesson-art-3': {
                title: 'Sign Your Name! ✍️',
                description: 'Guide STEMO like a pen to draw the first letter of your name. Use Pen Down to draw and Pen Up to jump between strokes. Finish with an Emotion, Say or Sound block!',
                setup: function() {
                    targetTrails = [
                        { x1: 230, y1: 360, x2: 275, y2: 200, color: '#94a3b8' },
                        { x1: 275, y1: 200, x2: 320, y2: 360, color: '#94a3b8' },
                        { x1: 248, y1: 290, x2: 302, y2: 290, color: '#94a3b8' }
                    ];
                },
                objectives: [
                    { id: 'penup', label: '✏️ Use Pen Up to lift between strokes', check: function() {
                        if (!workspace) return false;
                        return workspace.getAllBlocks().some(function(b) {
                            return b.type === 'pen_control' && b.getFieldValue('STATE') === 'UP';
                        });
                    }},
                    { id: 'strokes', label: '✍️ Draw 3+ line segments', check: function() {
                        return robot.trails.length >= 3;
                    }},
                    { id: 'flair', label: '😎 Add an Emotion, Say or Sound block', check: function() {
                        if (!workspace) return false;
                        return workspace.getAllBlocks().some(function(b) {
                            return b.type === 'stemo_emotion' || b.type === 'stemo_say' || b.type === 'play_fun_sound';
                        });
                    }}
                ]
            },
            'lesson-art-4': {
                title: 'Create a Magic Mandala! ❄️',
                description: 'Match the faded mandala. Put a Repeat loop INSIDE another Repeat loop: the inner one draws a shape, the outer one spins it around (try outer Repeat 12 → inner Repeat 4 → Forward 3, Right 90 → then Right 30).',
                setup: function() {
                    targetTrails = [];
                    var sx = 275, sy = 275, sa = 0;
                    function sm(steps, color) {
                        var d = steps * 20;
                        var nx = sx + Math.cos(sa * Math.PI / 180) * d;
                        var ny = sy + Math.sin(sa * Math.PI / 180) * d;
                        targetTrails.push({ x1: sx, y1: sy, x2: nx, y2: ny, color: color });
                        sx = nx; sy = ny;
                    }
                    function st(deg) { sa += deg; }
                    for (var i = 0; i < 12; i++) {
                        for (var j = 0; j < 4; j++) { sm(3, '#a855f7'); st(90); }
                        st(30);
                    }
                },
                objectives: [
                    { id: 'nested', label: '🔁 Use 2 Repeat blocks (a loop inside a loop)', check: function() {
                        if (!workspace) return false;
                        var n = workspace.getAllBlocks().filter(function(b) { return b.type === 'repeat_times'; }).length;
                        return n >= 2;
                    }},
                    { id: 'color', label: '🎨 Use a Color block', check: function() {
                        if (!workspace) return false;
                        return workspace.getAllBlocks().some(function(b) { return b.type === 'set_color'; });
                    }},
                    { id: 'mandala', label: '❄️ Draw 16+ line segments', check: function() {
                        return robot.trails.length >= 16;
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
        var progressRevision = null;

        // true when a teacher/admin visits /academy — suppresses all XP, progress, and saves
        var isTeacherDemo = false;
        var teacherPreviewCompletedLessons = [];

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
            isTeacherDemo = xpEl.getAttribute('data-demo') === 'teacher';
            var userData = null;
            try { userData = JSON.parse(xpEl.getAttribute('data-user') || 'null'); } catch(e) {}
            if (isTeacherDemo) {
                // Teacher/admin preview mode — reset any stale localStorage data so it shows clean
                stemo.xp = 0; stemo.level = 1; stemo.completedLessons = []; stemo.badges = []; stemo.streak = 1;
                teacherPreviewCompletedLessons = [];
                // Teacher preview has no reward system: hide the XP counter entirely.
                if (xpEl.parentElement) xpEl.parentElement.classList.add('hidden');
                var challengeDesc = document.getElementById('challengeModeDescription');
                if (challengeDesc) challengeDesc.textContent = 'Load the pre-set mission and preview its objective.';
                // Show the teacher/admin's actual name and role
                if (userData) {
                    var displayName = userData.full_name || userData.username || 'Teacher';
                    document.getElementById('studentName').textContent = displayName;
                    var roleLabel = userData.role ? (userData.role.charAt(0).toUpperCase() + userData.role.slice(1)) : 'Teacher';
                    // Update the role badge in the profile tab
                    var roleBadgeEl = document.getElementById('roleBadge');
                    if (roleBadgeEl) roleBadgeEl.textContent = '🎓 ' + roleLabel;
                }
                xpEl.title = 'Preview Mode — XP not tracked for ' + (userData && userData.role ? userData.role + 's' : 'teachers');
                updateUI();
                loadLessons();
                loadBadges();
            } else if (userData) {
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

        function applyAuthoritativeProgress(data) {
            if (!data || data.xp === undefined) return false;
            var serverLessons = Array.isArray(data.completed_lessons)
                ? data.completed_lessons
                : JSON.parse(data.completed_lessons || '[]');
            var serverBadges = Array.isArray(data.earned_badges)
                ? data.earned_badges
                : JSON.parse(data.earned_badges || '[]');
            var changed = data.xp !== stemo.xp ||
                data.level !== stemo.level ||
                Number(data.streak || 0) !== stemo.streak ||
                JSON.stringify(serverLessons) !== JSON.stringify(stemo.completedLessons) ||
                JSON.stringify(serverBadges) !== JSON.stringify(stemo.badges);
            stemo.xp = Number(data.xp || 0);
            stemo.level = Number(data.level || 1);
            stemo.completedLessons = serverLessons;
            stemo.badges = serverBadges;
            stemo.streak = Number(data.streak || 0);
            progressRevision = String(data.progress_revision || '');
            localStorage.setItem('stemo_xp', stemo.xp);
            localStorage.setItem('stemo_level', stemo.level);
            localStorage.setItem('stemo_completed', JSON.stringify(stemo.completedLessons));
            localStorage.setItem('stemo_badges', JSON.stringify(stemo.badges));
            localStorage.setItem('stemo_streak', stemo.streak);
            if (changed) updateUI();
            return changed;
        }

        // Save progress to D1 (and localStorage as fallback)
        async function saveProgress() {
            if (isTeacherDemo) return; // Teachers never earn or save XP
            if (progressRevision === null) return;
            localStorage.setItem('stemo_xp', stemo.xp);
            localStorage.setItem('stemo_level', stemo.level);
            localStorage.setItem('stemo_completed', JSON.stringify(stemo.completedLessons));
            localStorage.setItem('stemo_badges', JSON.stringify(stemo.badges));
            localStorage.setItem('stemo_streak', stemo.streak);
            try {
                const res = await fetch('/api/progress', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        xp: stemo.xp,
                        level: stemo.level,
                        completed_lessons: stemo.completedLessons,
                        earned_badges: stemo.badges,
                        streak: stemo.streak,
                        progress_revision: progressRevision
                    })
                });
                // Sync with server-authoritative values (server recomputes XP/level/streak/badges)
                const saved = await res.json();
                if (saved && saved.xp !== undefined && (saved.success || res.status === 409)) {
                    var changed = applyAuthoritativeProgress(saved);
                    if (res.status === 409) {
                        loadLessons();
                        loadBadges();
                        updateProfileStats();
                    } else if (changed) {
                        updateProfileStats();
                    }
                }
            } catch(e) { console.log('Progress saved locally only'); }
        }

        // Load progress from D1
        async function loadProgressFromDB(userId) {
            try {
                const res = await fetch('/api/progress/' + userId);
                const data = await res.json();
                if (data && data.xp !== undefined) {
                    applyAuthoritativeProgress(data);
                    loadLessons();
                    loadBadges();
                    updateProfileStats();
                }
            } catch(e) { console.log('Using local progress'); }
        }

        // Change password (student self-service)
        async function changeStudentPassword() {
            var cur = document.getElementById('pwCurrent').value.trim();
            var nw  = document.getElementById('pwNew').value;
            var cf  = document.getElementById('pwConfirm').value;
            var msg = document.getElementById('pwMsg');
            msg.className = 'text-sm'; msg.classList.remove('hidden');
            if (!cur || !nw || !cf) { msg.classList.add('text-red-600'); msg.textContent = '❌ All fields are required.'; return; }
            if (nw.length < 6)      { msg.classList.add('text-red-600'); msg.textContent = '❌ New password must be at least 6 characters.'; return; }
            if (nw !== cf)          { msg.classList.add('text-red-600'); msg.textContent = '❌ Passwords do not match.'; return; }
            msg.classList.remove('text-red-600'); msg.classList.add('text-gray-500'); msg.textContent = 'Saving…';
            try {
                const res = await fetch('/api/auth/change-password', {
                    method: 'POST', headers: {'Content-Type':'application/json'},
                    body: JSON.stringify({ current_password: cur, new_password: nw })
                }).then(r => r.json());
                if (res.success) {
                    msg.classList.remove('text-gray-500'); msg.classList.add('text-green-600');
                    msg.textContent = '✅ Password updated successfully!';
                    document.getElementById('pwCurrent').value = '';
                    document.getElementById('pwNew').value = '';
                    document.getElementById('pwConfirm').value = '';
                } else {
                    msg.classList.remove('text-gray-500'); msg.classList.add('text-red-600');
                    msg.textContent = '❌ ' + (res.error || 'Failed to update password.');
                }
            } catch(e) { msg.classList.add('text-red-600'); msg.textContent = '❌ Network error. Try again.'; }
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
                        { name: 'Advanced 🏆', key: 'advanced' },
                        { name: 'Art Studio 🎨', key: 'creative' }
                    ];

                    levels.forEach(function(level) {
                        html += '<div class="col-span-full mt-6 mb-2"><h4 class="text-xl font-bold text-indigo-600 border-l-4 border-indigo-500 pl-3">' + level.name + '</h4></div>';
                        
                        data[level.key].forEach(function(lesson, index) {
                            var isCompleted = stemo.completedLessons.includes(lesson.id);
                            
                            // Teacher/admin academy mode previews every lesson without prerequisites.
                            // Students still unlock lessons in curriculum order.
                            var isLocked = false;
                            if (!isTeacherDemo) {
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
                            }

                            var lessonIcon = lesson.icon || '📚';
                            var icon = isCompleted ? '✅' : (isLocked ? '🔒' : lessonIcon);
                            
                            var diffGradient = lesson.difficulty === 'easy' ? 'from-green-400 to-emerald-500' : 
                                              (lesson.difficulty === 'medium' ? 'from-yellow-400 to-orange-500' : 'from-red-400 to-pink-500');
                            var diffClass = lesson.difficulty === 'easy' ? 'bg-green-100 text-green-700' :
                                           (lesson.difficulty === 'medium' ? 'bg-yellow-100 text-yellow-700' : 
                                           (lesson.difficulty === 'hard' ? 'bg-red-100 text-red-700' : 'bg-purple-100 text-purple-700'));
                            
                            var lessonStars = isCompleted ? getStars(lesson.id) : 0;
                            var starsBadge = lessonStars > 0 ? '<span class="text-sm" title="' + lessonStars + ' of 3 stars">' + starString(lessonStars) + '</span>' : '';
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
                                    '<h4 class="font-bold text-lg text-gray-800 mb-1">' + trL(lesson, 'title') + '</h4>' +
                                    '<p class="text-gray-500 text-sm mb-3">' + trL(lesson, 'description') + '</p>' +
                                    '<div class="flex items-center gap-2 flex-wrap">' +
                                    '<span class="text-xs px-2 py-1 rounded-full ' + diffClass + '">' + trDiff(lesson.difficulty) + '</span>' +
                                    (isCompleted ? '<span class="text-xs text-green-600 font-bold">' + ((I18N[currentLang] || I18N.en).completed_label || 'Completed!') + '</span>' : '') +
                                    starsBadge +
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
            document.getElementById('lessonDetailTitle').textContent = trL(lesson, 'title');
            document.getElementById('lessonDetailDesc').textContent = trL(lesson, 'description');
            document.getElementById('lessonXP').textContent = '+' + lesson.xpReward + ' XP';
            document.getElementById('lessonIntro').textContent = trL(lesson, 'introduction') || trL(lesson, 'hint');
            document.getElementById('lessonHintText').textContent = trL(lesson, 'hint');
            document.getElementById('lessonHomeworkText').textContent = trL(lesson, 'homework') || (currentLang === 'ar' ? 'جرّب شيئاً إبداعياً باستخدام اللبنات التي تعلمتها للتو!' : "Try something creative with the blocks you just learned!");
            
            // Render tasks
            var tasksContainer = document.getElementById('lessonTasks');
            var tasksHtml = '';
            
            if (lesson.tasks && lesson.tasks.length > 0) {
                lesson.tasks.forEach(function(task, index) {
                    tasksHtml += '<div class="flex items-center gap-3 p-3 bg-gray-50 rounded-xl">' +
                        '<div class="w-8 h-8 rounded-full bg-indigo-100 text-indigo-600 flex items-center justify-center font-bold text-sm">' + (index + 1) + '</div>' +
                        '<span class="text-gray-700">' + trTask(lesson, index, task.text) + '</span>' +
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
                document.getElementById('modePickerTitle').textContent = trL(currentLesson, 'title');
                document.getElementById('modePickerDesc').textContent = trL(currentLesson, 'description');
                document.getElementById('modePickerXP').textContent = isTeacherDemo
                    ? (currentLang === 'ar' ? 'معاينة التحدي' : 'Challenge Preview')
                    : '+' + currentLesson.xpReward + ' XP · ' + (currentLang === 'ar' ? 'تحدٍّ' : 'Challenge');
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
            challengeSensorScanCount = 0;
            challengeWallConditionCount = 0;
            challengeWallConditionTrueCount = 0;

            // Set up the code view header
            document.getElementById('currentLessonTitle').textContent = trL(currentLesson, 'title');
            document.getElementById('currentLessonDesc').textContent = trL(currentLesson, 'description');
            document.getElementById('hintText').textContent = trL(currentLesson, 'hint');
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
                        return { id: obj.id, label: trObj(currentLesson.id, obj.id, obj.label), done: false, check: obj.check };
                    });
                    // Prime the toast content
                    document.getElementById('missionTitle').textContent = trChTitle(currentLesson.id, challenge.title);
                    var descEl = document.getElementById('missionDesc');
                    var chDesc = trChDesc(currentLesson.id, challenge.description);
                    if (descEl && chDesc) { descEl.textContent = chDesc; descEl.style.display = 'block'; }
                    updateMissionHUD();
                    addChatMessage('stemo', currentLang === 'ar' ? ('🏆 تم تحميل التحدي! ' + chDesc + ' حظاً موفقاً! 💪') : ('🏆 Challenge loaded! ' + challenge.description + ' Good luck! 💪'));
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
                badgeEl.textContent = remaining === 0 ? (currentLang === 'ar' ? '✅ تم!' : '✅ Done!') : (currentLang === 'ar' ? ('متبقٍ ' + remaining) : (remaining + ' left'));
            }
            var badge = document.getElementById('missionBadge');
            if (badge) {
                badge.querySelector('div').style.background = remaining === 0 ? '#22c55e' : '';
            }
        }

        function checkChallengeObjectives() {
            if (!challengeMode || !missionObjectives || challengeCompleted) return;
            // Drawing lessons: suppress objective checks while the robot is still executing.
            // Workspace-block checks (repeat, turn) are instantly true, causing premature completion.
            // Wait until execution finishes so all objectives are evaluated together.
            if (robotExecuting && DRAWING_LESSON_IDS.indexOf(challengeActiveLessonId) !== -1) return;
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
                    if (currentLesson) {
                        completeChallengeLesson(currentLesson);
                    } else {
                        showSuccessModal(0, true);
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
        function isBadgeEarned(badge) {
            if (stemo.badges.includes(badge.id)) return true;
            if (badge.type === 'lessons') return stemo.completedLessons.length >= badge.threshold;
            if (badge.type === 'streak')  return stemo.streak >= badge.threshold;
            if (badge.type === 'level')   return stemo.level >= badge.threshold;
            return stemo.xp >= badge.threshold; // xp (default)
        }

        function loadBadges() {
            fetch('/api/badges')
                .then(function(r) { return r.json(); })
                .then(function(allBadges) {
                    var grid = document.getElementById('badgesGrid');
                    var needSave = false;
                    var html = '';
                    var earned = 0;

                    allBadges.forEach(function(badge) {
                        var isEarned = isBadgeEarned(badge);
                        if (isEarned && !stemo.badges.includes(badge.id)) {
                            stemo.badges.push(badge.id);
                            needSave = true;
                        }
                        if (isEarned) earned++;
                        var typeLabel = badge.req || (badge.xpRequired + ' XP');
                        html += '<div class="rounded-2xl card-shadow p-4 text-center border-2 transition-all ' +
                                (isEarned ? 'bg-white border-indigo-200 shadow-indigo-100' : 'bg-gray-50 border-transparent opacity-50 grayscale') + '">' +
                            '<div class="text-4xl mb-2">' + badge.icon + '</div>' +
                            '<h4 class="font-bold text-xs text-gray-800">' + trBadge(badge, 'name') + '</h4>' +
                            '<p class="text-xs text-gray-400 mt-1">' + trBadge(badge, 'description') + '</p>' +
                            '<div class="text-xs font-semibold mt-2 ' + (isEarned ? 'text-indigo-600' : 'text-gray-400') + '">' + typeLabel + '</div>' +
                            (isEarned ? '<div class="text-xs text-green-500 font-bold mt-1">' + (currentLang === 'ar' ? '✓ مُكتسبة' : '✓ Earned') + '</div>' : '') +
                            '</div>';
                    });

                    grid.innerHTML = html;
                    document.getElementById('badgesEarned').textContent = earned;
                    document.getElementById('profileBadges').textContent = earned;
                    if (needSave) saveProgress();
                    renderProfileBadges(allBadges);
                });
        }

        function renderProfileBadges(allBadges) {
            var container = document.getElementById('profileBadgesList');
            if (!container) return;
            var earned = (allBadges || []).filter(function(b) { return isBadgeEarned(b); });
            if (earned.length === 0) {
                container.innerHTML = '<p class="text-gray-400 text-sm italic">' + (currentLang === 'ar' ? 'لا شارات بعد — أكمل الدروس لتكسب شارتك الأولى! 🎯' : 'No badges yet — complete lessons to earn your first badge! 🎯') + '</p>';
                return;
            }
            container.innerHTML = earned.map(function(b) {
                return '<div class="flex items-center gap-2 bg-indigo-50 border border-indigo-100 rounded-2xl px-3 py-2">' +
                    '<span class="text-2xl">' + b.icon + '</span>' +
                    '<div><div class="text-xs font-bold text-indigo-800">' + trBadge(b, 'name') + '</div>' +
                    '<div class="text-xs text-gray-400">' + trBadge(b, 'description') + '</div></div></div>';
            }).join('');
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

        Blockly.Blocks['stemo_say'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("💬 Say")
                    .appendField(new Blockly.FieldTextInput("Hello!"), "TEXT");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(300);
            }
        };

        Blockly.Blocks['stemo_emotion'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("😊 Feel")
                    .appendField(new Blockly.FieldDropdown([
                        ["😀 Happy", "happy"],
                        ["😢 Sad", "sad"],
                        ["😎 Cool", "cool"],
                        ["🤩 Excited", "excited"],
                        ["😐 Normal", "normal"]
                    ]), "EMOTION");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(300);
            }
        };

        Blockly.Blocks['stemo_dance'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🕺 Dance");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(300);
            }
        };

        Blockly.Blocks['play_fun_sound'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("🔊 Play")
                    .appendField(new Blockly.FieldDropdown([
                        ["🎉 Cheer", "cheer"],
                        ["🎺 Fanfare", "fanfare"],
                        ["✨ Magic", "magic"],
                        ["🐱 Meow", "meow"],
                        ["🤖 Beep", "beep"],
                        ["💥 Pop", "pop"]
                    ]), "SOUND");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(300);
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

        Blockly.Blocks['go_left_start'] = {
            init: function() {
                this.appendDummyInput()
                    .appendField("⬅️ Go to Left Start");
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
                    .appendField("1 step");
                this.appendStatementInput("DO")
                    .appendField("then");
                this.appendStatementInput("ELSE")
                    .appendField("else");
                this.setPreviousStatement(true, null);
                this.setNextStatement(true, null);
                this.setColour(45);
                this.setTooltip("Check if a wall is within 1 step, then do something");
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
            // Wrap every block definition so labels/dropdowns render in the current language
            (function() {
                function arabizeBlock(block) {
                    if (currentLang !== 'ar') return;
                    block.inputList.forEach(function(input) {
                        input.fieldRow.forEach(function(f) {
                            try {
                                if (f instanceof Blockly.FieldDropdown) {
                                    if (Array.isArray(f.menuGenerator_)) {
                                        f.menuGenerator_ = f.menuGenerator_.map(function(opt) {
                                            return [BLOCK_AR[opt[0]] || opt[0], opt[1]];
                                        });
                                        if (f.forceRerender) f.forceRerender();
                                    }
                                } else if (f instanceof Blockly.FieldLabel) {
                                    var t = BLOCK_AR[f.getValue()];
                                    if (t) f.setValue(t);
                                }
                            } catch(e) {}
                        });
                    });
                }
                Object.keys(Blockly.Blocks).forEach(function(id) {
                    var def = Blockly.Blocks[id];
                    if (!def || typeof def.init !== 'function' || def.__i18n) return;
                    var orig = def.init;
                    def.init = function() { orig.call(this); arabizeBlock(this); };
                    def.__i18n = true;
                });
            })();
            workspace = Blockly.inject('blocklyDiv', {
                scrollbars: true,
                trashcan: false,
                zoom: {
                    controls: false,
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
            
            // Track selected block via Blockly events
            workspace.addChangeListener(function(event) {
                if (event.type === Blockly.Events.SELECTED || event.type === 'selected') {
                    var newId = event.newElementId || event.newValue;
                    var block = newId ? workspace.getBlockById(newId) : null;
                    lastSelectedBlock = block;
                    // Group select mode: each click toggles a block in/out of the group
                    if (groupSelectMode && block) {
                        var idx = groupSelectedBlocks.indexOf(block.id);
                        if (idx >= 0) {
                            groupSelectedBlocks.splice(idx, 1);
                        } else {
                            groupSelectedBlocks.push(block.id);
                        }
                        highlightGroupBlocks();
                        updateGroupDeleteBtn();
                    }
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

            // Start a fresh execution and invalidate callbacks from any older run.
            executionGeneration++;
            robotExecuting = true;
            if (challengeMode && challengeActiveLessonId === 'lesson-9') {
                challengeSensorScanCount = 0;
                challengeWallConditionCount = 0;
            }
            var sp = getStemoStart();
            robot.x = sp.x;
            robot.y = sp.y;
            robot.angle = sp.angle;
            robot.penDown = false;
            robot.penSize = 4;
            robot.visible = true;
            robot.magnetOn = false;
            robot.carrying = null;
            robot.trails = [];
            robot.emotion = 'normal';
            robot.sayText = '';
            robot.dancing = false;
            drawRobot();
            
            // Parse and execute blocks
            var commands = [];
            parseBlocks(blocks[0], commands);
            console.log('Commands to execute:', commands);
            
            if (commands.length === 0) {
                robotExecuting = false;
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
                } else if (type === 'go_left_start') {
                    commands.push({ action: 'home_left' });
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
                } else if (type === 'stemo_say') {
                    commands.push({ action: 'say', value: block.getFieldValue('TEXT') });
                } else if (type === 'stemo_emotion') {
                    commands.push({ action: 'emotion', value: block.getFieldValue('EMOTION') });
                } else if (type === 'stemo_dance') {
                    commands.push({ action: 'dance' });
                } else if (type === 'play_fun_sound') {
                    commands.push({ action: 'fun_sound', value: block.getFieldValue('SOUND') });
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
                    var doBlock = block.getInputTargetBlock('DO');
                    var elseBlock = block.getInputTargetBlock('ELSE');
                    commands.push({ 
                        action: 'if_wall', 
                        distance: 1,
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

        function executeCommands(commands, onComplete, runGeneration) {
            var index = 0;
            var isTopLevel = !onComplete; // Track if this is the main execution
            if (runGeneration === undefined) runGeneration = executionGeneration;
            
            function executeNext() {
                if (!robotExecuting || runGeneration !== executionGeneration) return;
                if (index >= commands.length) {
                    console.log('Execution batch complete!');
                    if (isTopLevel) {
                        robotExecuting = false;
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
                    if (challengeMode && challengeActiveLessonId === 'lesson-9') {
                        challengeWallConditionCount++;
                    }
                    var wallDist = detectWallAhead();
                    var wallSteps = wallDist / 20;
                    if (challengeMode && challengeActiveLessonId === 'lesson-9' && wallSteps <= cmd.distance) {
                        challengeWallConditionTrueCount++;
                    }
                    var nestedCommands = wallSteps <= cmd.distance ? cmd.doCommands : cmd.elseCommands;
                    
                    if (nestedCommands && nestedCommands.length > 0) {
                        // Execute nested commands, then continue
                        executeCommands(nestedCommands, function() {
                            drawRobot();
                            setTimeout(executeNext, 200);
                        }, runGeneration);
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
                        }, runGeneration);
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
                        }, runGeneration);
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
                    }, runGeneration);
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
                    }, runGeneration);
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
                        }, runGeneration);
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
                        }, runGeneration);
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
                        }, runGeneration);
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
                    }, runGeneration);
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
                        }, runGeneration);
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
                        }, runGeneration);
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
                    var wDist = rayWallIntersection(robot.x, robot.y, moveDx, moveDy, wobj);
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
                // Go home without drawing — uses the chosen start point
                var sp = getStemoStart();
                robot.x = sp.x;
                robot.y = sp.y;
                robot.angle = sp.angle;
            } else if (cmd.action === 'home_left') {
                // Jump to the left start point (room to write long words)
                var lp = STEMO_START_POINTS.left;
                robot.x = lp.x;
                robot.y = lp.y;
                robot.angle = lp.angle;
            } else if (cmd.action === 'pen') {
                robot.penDown = cmd.value;
            } else if (cmd.action === 'color') {
                robot.penColor = cmd.value;
            } else if (cmd.action === 'size') {
                robot.penSize = cmd.value;
            } else if (cmd.action === 'say') {
                robot.sayText = cmd.value || '';
                playSound('beep');
                drawRobot();
            } else if (cmd.action === 'emotion') {
                robot.emotion = cmd.value || 'normal';
                drawRobot();
            } else if (cmd.action === 'dance') {
                robot.emotion = 'happy';
                playSound('cheer');
                startDanceAnimation(1400);
            } else if (cmd.action === 'fun_sound') {
                playSound(cmd.value);
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
                if (challengeMode && challengeActiveLessonId === 'lesson-9') {
                    challengeSensorScanCount++;
                }
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
                var dist = rayWallIntersection(robot.x, robot.y, Math.cos(rad), Math.sin(rad), wall);
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
                var dist = rayWallIntersection(robot.x, robot.y, Math.cos(rad), Math.sin(rad), wall);
                
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

        function rayWallIntersection(rx, ry, dx, dy, wall) {
            var angle = wall.angle || 0;
            if (angle === 0) {
                return rayBoxIntersection(rx, ry, dx, dy, wall.x, wall.y, wall.width, wall.height);
            }

            // Transform the ray into the wall's unrotated local coordinate system.
            var cx = wall.x + wall.width / 2;
            var cy = wall.y + wall.height / 2;
            var rad = -angle * Math.PI / 180;
            var cos = Math.cos(rad);
            var sin = Math.sin(rad);
            var localRx = (rx - cx) * cos - (ry - cy) * sin;
            var localRy = (rx - cx) * sin + (ry - cy) * cos;
            var localDx = dx * cos - dy * sin;
            var localDy = dx * sin + dy * cos;
            return rayBoxIntersection(
                localRx, localRy, localDx, localDy,
                -wall.width / 2, -wall.height / 2, wall.width, wall.height
            );
        }

        function distanceToWall(px, py, wall) {
            var cx = wall.x + wall.width / 2;
            var cy = wall.y + wall.height / 2;
            var rad = -(wall.angle || 0) * Math.PI / 180;
            var cos = Math.cos(rad);
            var sin = Math.sin(rad);
            var localX = (px - cx) * cos - (py - cy) * sin;
            var localY = (px - cx) * sin + (py - cy) * cos;
            var dx = Math.max(Math.abs(localX) - wall.width / 2, 0);
            var dy = Math.max(Math.abs(localY) - wall.height / 2, 0);
            return Math.sqrt(dx * dx + dy * dy);
        }

        function getAutomaticSafetyAlert() {
            var threshold = 40; // Two movement steps
            var headingRad = robot.angle * Math.PI / 180;
            var headingDx = Math.cos(headingRad);
            var headingDy = Math.sin(headingRad);
            var nearestWall = 999;
            var nearestWallIndex = -1;
            for (var i = 0; i < wallObjects.length; i++) {
                var wallDistance = rayWallIntersection(
                    robot.x, robot.y, headingDx, headingDy, wallObjects[i]
                );
                if (wallDistance > 0 && wallDistance < nearestWall) {
                    nearestWall = wallDistance;
                    nearestWallIndex = i;
                }
            }

            var nearestFire = 999;
            var nearestFireIndex = -1;
            for (var f = 0; f < fireObjects.length; f++) {
                var fdx = fireObjects[f].x - robot.x;
                var fdy = fireObjects[f].y - robot.y;
                var fireDistance = Math.sqrt(fdx * fdx + fdy * fdy);
                if (fireDistance < nearestFire) {
                    nearestFire = fireDistance;
                    nearestFireIndex = f;
                }
            }

            var hazardType = nearestFire <= threshold ? 'fire' : (nearestWall <= threshold ? 'wall' : null);
            var normalizedHeading = ((Math.round(robot.angle) % 360) + 360) % 360;
            var hazardKey = hazardType === 'fire'
                ? 'fire:' + nearestFireIndex
                : (hazardType === 'wall' ? 'wall:' + nearestWallIndex + ':heading:' + normalizedHeading : null);

            if (!hazardType) {
                activeSafetyHazard = null;
                safetyAlertUntil = 0;
                return { active: false, type: null, label: '' };
            }

            // Trigger once when STEMO enters a danger zone. The visual warning lasts
            // only 650ms and does not repeat until STEMO first leaves the zone.
            if (hazardKey !== activeSafetyHazard) {
                activeSafetyHazard = hazardKey;
                safetyAlertUntil = Date.now() + 650;
                playSound(hazardType === 'fire' ? 'fire_alarm' : 'safety_alert');
                if (safetyAlertTimer) clearTimeout(safetyAlertTimer);
                safetyAlertTimer = setTimeout(function() {
                    safetyAlertTimer = null;
                    drawRobot();
                }, 675);
            }

            var visible = Date.now() < safetyAlertUntil;
            return {
                active: visible,
                type: hazardType,
                label: hazardType === 'fire' ? '🔥 FIRE ALERT' : '⚠️ WALL ALERT'
            };
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
        function executeFirefighterMode(onComplete, runGeneration) {
            if (runGeneration === undefined) runGeneration = executionGeneration;
            var maxSteps = 200; // Safety limit
            var stepCount = 0;
            
            function firefightStep() {
                if (!robotExecuting || runGeneration !== executionGeneration) return;
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
        function executeGoToTarget(onComplete, runGeneration) {
            if (runGeneration === undefined) runGeneration = executionGeneration;
            if (!targetPoint) { if (onComplete) onComplete(); return; }
            var maxSteps = 300;
            var stepCount = 0;
            function moveStep() {
                if (!robotExecuting || runGeneration !== executionGeneration) return;
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
        function executeSmartNavigate(onComplete, runGeneration) {
            if (runGeneration === undefined) runGeneration = executionGeneration;
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
                if (!robotExecuting || runGeneration !== executionGeneration) return;
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
        function executeNavigateToPoint(tx, ty, msg, onComplete, runGeneration) {
            if (runGeneration === undefined) runGeneration = executionGeneration;
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
                if (!robotExecuting || runGeneration !== executionGeneration) return;
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
        function executeReplayWaypoints(pts, idx, onComplete, runGeneration) {
            if (runGeneration === undefined) runGeneration = executionGeneration;
            if (!robotExecuting || runGeneration !== executionGeneration) return;
            if (idx >= pts.length) {
                addChatMessage('stemo', "✅ Replayed all " + pts.length + " waypoints!");
                if (onComplete) onComplete();
                return;
            }
            var pt = pts[idx];
            executeNavigateToPoint(pt.x, pt.y, null, function() {
                if (challengeMode) checkChallengeObjectives();
                setTimeout(function() { executeReplayWaypoints(pts, idx + 1, onComplete, runGeneration); }, 200);
            }, runGeneration);
        }

        // For each waypoint: navigate there, then run doCommands
        function executeForeachWaypoint(pts, idx, doCommands, onComplete, runGeneration) {
            if (runGeneration === undefined) runGeneration = executionGeneration;
            if (!robotExecuting || runGeneration !== executionGeneration) return;
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
                        setTimeout(function() { executeForeachWaypoint(pts, idx + 1, doCommands, onComplete, runGeneration); }, 200);
                    }, runGeneration);
                } else {
                    setTimeout(function() { executeForeachWaypoint(pts, idx + 1, doCommands, onComplete, runGeneration); }, 200);
                }
            }, runGeneration);
        }

        // ============================================
        // ROBOT DRAWING
        // ============================================
        function drawRobot() {
            var canvas = document.getElementById('robotCanvas');
            var ctx = canvas.getContext('2d');
            var safetyAlert = getAutomaticSafetyAlert();
            
            // Clear at native canvas size, then zoom the logical 550×550 world
            // out slightly so complex drawings stay comfortably inside view.
            // Simulation coordinates remain unchanged.
            ctx.setTransform(1, 0, 0, 1, 0, 0);
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            var worldViewScale = WORLD_VIEW_SCALE;
            var worldViewOffsetX = (canvas.width - canvas.width * worldViewScale) / 2;
            var worldViewOffsetY = (canvas.height - canvas.height * worldViewScale) / 2;
            ctx.setTransform(worldViewScale, 0, 0, worldViewScale, worldViewOffsetX, worldViewOffsetY);
            
            // One 20px grid square equals one STEMO movement step.
            // Anchor the grid at STEMO's center home (275,275), not the canvas edge.
            var gridOriginX = 275;
            var gridOriginY = 275;
            var firstGridX = gridOriginX % 20;
            var firstGridY = gridOriginY % 20;
            for (var i = firstGridX; i < canvas.width; i += 20) {
                var xStep = (i - gridOriginX) / 20;
                var xMajor = xStep % 5 === 0;
                ctx.strokeStyle = '#e5e7eb';
                ctx.lineWidth = 1;
                ctx.beginPath();
                ctx.moveTo(i, 0);
                ctx.lineTo(i, canvas.height);
                ctx.stroke();
                
                // Label five-step landmarks only, keeping the one-step grid uncluttered.
                if (xMajor && i > 0 && i < canvas.width) {
                    ctx.fillStyle = '#9ca3af';
                    ctx.font = '9px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText(xStep.toString(), i, 11);
                }
            }
            for (var j = firstGridY; j < canvas.height; j += 20) {
                var yStep = (gridOriginY - j) / 20;
                var yMajor = yStep % 5 === 0;
                ctx.strokeStyle = '#e5e7eb';
                ctx.lineWidth = 1;
                ctx.beginPath();
                ctx.moveTo(0, j);
                ctx.lineTo(canvas.width, j);
                ctx.stroke();
                
                // Positive Y is upward, matching the coordinate readout.
                if (yMajor && j > 0 && j < canvas.height) {
                    ctx.fillStyle = '#9ca3af';
                    ctx.font = '9px Arial';
                    ctx.textAlign = 'left';
                    ctx.fillText(yStep.toString(), 3, j + 3);
                }
            }
            
            // Keep the scale visible for learners.
            ctx.fillStyle = '#6b7280';
            ctx.font = '9px Arial';
            ctx.textAlign = 'right';
            ctx.fillText('1 square = 1 step', canvas.width - 5, canvas.height - 5);
            
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
                var wallCenterX = wall.x + wall.width / 2;
                var wallCenterY = wall.y + wall.height / 2;
                ctx.translate(wallCenterX, wallCenterY);
                ctx.rotate((wall.angle || 0) * Math.PI / 180);
                ctx.translate(-wallCenterX, -wallCenterY);
                
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
                var safetyPulse = safetyAlert.active ? 0.65 + Math.sin(Date.now() / 90) * 0.35 : 0;
                
                // Body - change color if magnet is on; otherwise use kid's chosen color
                // Dance wiggle — gentle rock so STEMO looks alive when celebrating
                if (robot.dancing) {
                    ctx.rotate(Math.sin(Date.now() / 120) * 0.25);
                }
                ctx.fillStyle = robot.magnetOn ? '#ef4444' : stemoBodyColor;
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
                ctx.fillStyle = robot.magnetOn ? '#f87171' : lightenColor(stemoBodyColor, 0.3);
                ctx.beginPath();
                ctx.arc(0, -11, 11, 0, Math.PI * 2);
                ctx.fill();
                
                // Eyes
                ctx.fillStyle = 'white';
                ctx.beginPath();
                ctx.arc(-4, -13, 3.5, 0, Math.PI * 2);
                ctx.arc(4, -13, 3.5, 0, Math.PI * 2);
                ctx.fill();
                
                // Pupils & mouth — react to emotion / carrying state
                var emo = robot.emotion || 'normal';
                if (robot.carrying) {
                    ctx.fillStyle = '#ef4444';
                    ctx.font = '6px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText('❤', -4, -11);
                    ctx.fillText('❤', 4, -11);
                } else if (emo === 'happy' || emo === 'excited') {
                    // Curved happy eyes (^ ^) + big smile
                    ctx.strokeStyle = '#1e3a5f';
                    ctx.lineWidth = 1.5;
                    ctx.beginPath();
                    ctx.arc(-4, -12.5, 2.2, Math.PI * 1.1, Math.PI * 1.9);
                    ctx.arc(4, -12.5, 2.2, Math.PI * 1.1, Math.PI * 1.9);
                    ctx.stroke();
                    ctx.beginPath();
                    ctx.arc(0, -8, 4, 0.1 * Math.PI, 0.9 * Math.PI);
                    ctx.stroke();
                } else if (emo === 'sad') {
                    ctx.fillStyle = '#1e3a5f';
                    ctx.beginPath();
                    ctx.arc(-3.5, -12.5, 1.5, 0, Math.PI * 2);
                    ctx.arc(4.5, -12.5, 1.5, 0, Math.PI * 2);
                    ctx.fill();
                    // Frown
                    ctx.strokeStyle = '#1e3a5f';
                    ctx.lineWidth = 1.5;
                    ctx.beginPath();
                    ctx.arc(0, -5, 4, 1.1 * Math.PI, 1.9 * Math.PI);
                    ctx.stroke();
                } else if (emo === 'cool') {
                    // Sunglasses
                    ctx.fillStyle = '#1e293b';
                    ctx.fillRect(-7, -14, 6, 4);
                    ctx.fillRect(1, -14, 6, 4);
                    ctx.fillRect(-1, -13, 2, 1.5);
                    ctx.strokeStyle = '#1e3a5f';
                    ctx.lineWidth = 1.5;
                    ctx.beginPath();
                    ctx.arc(0, -8, 3.5, 0.15 * Math.PI, 0.85 * Math.PI);
                    ctx.stroke();
                } else {
                    ctx.fillStyle = '#1e3a5f';
                    ctx.beginPath();
                    ctx.arc(-3.5, -12.5, 1.5, 0, Math.PI * 2);
                    ctx.arc(4.5, -12.5, 1.5, 0, Math.PI * 2);
                    ctx.fill();
                }
                
                // Antenna
                ctx.strokeStyle = safetyAlert.active ? '#ef4444' : (robot.magnetOn ? '#ef4444' : '#fbbf24');
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.moveTo(0, -21);
                ctx.lineTo(0, -29);
                ctx.stroke();
                
                if (safetyAlert.active) {
                    ctx.shadowColor = '#ef4444';
                    ctx.shadowBlur = 12 + safetyPulse * 12;
                    ctx.fillStyle = safetyPulse > 0.65 ? '#ef4444' : '#fecaca';
                    ctx.beginPath();
                    ctx.arc(0, -33, 5, 0, Math.PI * 2);
                    ctx.fill();
                    ctx.shadowBlur = 0;
                } else if (robot.magnetOn) {
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

                if (safetyAlert.active) {
                    ctx.save();
                    ctx.fillStyle = 'rgba(220,38,38,0.92)';
                    ctx.strokeStyle = '#ffffff';
                    ctx.lineWidth = 2;
                    ctx.font = 'bold 11px Arial';
                    ctx.textAlign = 'center';
                    var labelWidth = ctx.measureText(safetyAlert.label).width + 16;
                    ctx.beginPath();
                    ctx.roundRect(robot.x - labelWidth / 2, robot.y - 58, labelWidth, 22, 8);
                    ctx.fill();
                    ctx.stroke();
                    ctx.fillStyle = '#ffffff';
                    ctx.fillText(safetyAlert.label, robot.x, robot.y - 43);
                    ctx.restore();
                }

                // Speech bubble — drawn in screen space (not rotated) above STEMO
                if (robot.sayText) {
                    ctx.save();
                    ctx.font = 'bold 13px Nunito, Arial';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    var txt = robot.sayText.length > 30 ? robot.sayText.substring(0, 29) + '…' : robot.sayText;
                    var tw = ctx.measureText(txt).width;
                    var bw = tw + 22, bh = 26;
                    var bx = robot.x, by = robot.y - 48;
                    // Keep bubble inside the canvas
                    bx = Math.max(bw/2 + 4, Math.min(canvas.width - bw/2 - 4, bx));
                    by = Math.max(bh/2 + 4, by);
                    ctx.fillStyle = 'rgba(255,255,255,0.97)';
                    ctx.strokeStyle = stemoBodyColor;
                    ctx.lineWidth = 2.5;
                    ctx.beginPath();
                    ctx.roundRect(bx - bw/2, by - bh/2, bw, bh, 9);
                    ctx.fill();
                    ctx.stroke();
                    // Tail
                    ctx.beginPath();
                    ctx.moveTo(robot.x - 5, by + bh/2 - 1);
                    ctx.lineTo(robot.x, by + bh/2 + 8);
                    ctx.lineTo(robot.x + 5, by + bh/2 - 1);
                    ctx.closePath();
                    ctx.fillStyle = 'rgba(255,255,255,0.97)';
                    ctx.fill();
                    ctx.fillStyle = '#1e293b';
                    ctx.fillText(txt, bx, by);
                    ctx.restore();
                }
            }
            
        }

        function stopAndResetRobot() {
            resetRobot("🛑 Program stopped. I am back at the starting point and your code is still here!");
        }

        function resetRobot(message) {
            executionGeneration++;
            robotExecuting = false;
            if (danceRAF) {
                cancelAnimationFrame(danceRAF);
                danceRAF = null;
            }
            var sp = getStemoStart();
            robot = {
                x: sp.x,
                y: sp.y,
                angle: sp.angle,
                penDown: false,
                penColor: '#6366f1',
                penSize: 4,
                trails: [],
                visible: true,
                magnetOn: false,
                carrying: null,
                waterLevel: 10,
                spraying: false,
                lastTemp: 25,
                emotion: 'normal',
                sayText: '',
                dancing: false
            };
            drawRobot();
            addChatMessage('stemo', message || "🤖 Ready! Use Pen Down to start drawing!");
        }

        // Animate STEMO's dance wiggle for a short duration, then settle
        var danceRAF = null;
        function startDanceAnimation(durationMs) {
            robot.dancing = true;
            var start = Date.now();
            if (danceRAF) cancelAnimationFrame(danceRAF);
            function step() {
                if (Date.now() - start < durationMs) {
                    drawRobot();
                    danceRAF = requestAnimationFrame(step);
                } else {
                    robot.dancing = false;
                    danceRAF = null;
                    drawRobot();
                }
            }
            step();
        }

        // ============================================
        // STAR RATINGS — 1-3 stars per lesson by efficiency (block count vs par)
        // ============================================
        function getStarsMap() {
            try { return JSON.parse(safeStorageGet('stemoStars') || '{}'); } catch (e) { return {}; }
        }
        function getStars(lessonId) {
            return getStarsMap()[lessonId] || 0;
        }
        function setStars(lessonId, n) {
            var map = getStarsMap();
            if (n > (map[lessonId] || 0)) {
                map[lessonId] = n;
                safeStorageSet('stemoStars', JSON.stringify(map));
            }
        }
        // Compute stars from how many blocks were used vs the lesson's "par"
        function computeStars(lesson) {
            var used = 0;
            try { used = workspace ? workspace.getAllBlocks(false).length : 0; } catch (e) { used = 0; }
            var par = (lesson && lesson.par) ? lesson.par : 0;
            if (!par || used <= 0) return 3; // no par defined → reward completion fully
            if (used <= par) return 3;
            if (used <= Math.ceil(par * 1.6)) return 2;
            return 1;
        }
        function starString(n) {
            return '⭐⭐⭐'.substring(0, n) + '☆☆☆'.substring(0, 3 - n);
        }

        // ============================================
        // MULTI-LANGUAGE (i18n) — English, Arabic, Spanish, French
        // ============================================
        var I18N = {
            en: {
                tab_learn: 'Learn', tab_code: 'Code', tab_achievements: 'Achievements',
                tab_profile: 'My Profile', tab_leaderboard: 'Leaderboard', tab_videos: 'Video Training', tab_interactive: 'Interactive Lessons',
                interactive_title: 'Interactive Lessons', interactive_subtitle: 'Explore interactive activities prepared by your academy.',
                interactive_loading: 'Loading interactive lessons...', interactive_empty: 'No interactive lessons available yet.', interactive_open: 'Open Lesson', btn_refresh: 'Refresh',
                btn_run: 'Run', btn_stop_reset: 'Stop & Reset',
                cat_move: '🚶 Move', cat_draw: '🎨 Draw', cat_fun: '🎉 Fun', cat_loop: '🔁 Loop',
                welcome_title: 'Welcome to STEMO Academy!',
                welcome_sub: 'Learn to code by programming your robot friend. Ready for an adventure?',
                btn_start_learning: 'Start Learning!',
                curriculum_path: 'Curriculum Path',
                your_tasks: 'Your Tasks:', homework_title: 'Homework Challenge:', hint_title: 'Hint',
                btn_back_lessons: 'Back to Lessons', btn_start_coding: 'Start Coding!',
                assigned_label: '📌 Your teacher assigned this lesson', btn_start_now: '🚀 Start Now',
                code_subtitle: 'Click blocks to add • Right-click a block to delete it or a whole group',
                btn_undo: '↩️ Undo', btn_select_group: '🔲 Select Group', btn_left_start: '⬅️ Left Start',
                hide_robot: 'Hide Robot', show_robot: 'Show Robot',
                completed_label: 'Completed!', locked_hint: 'Locked'
            },
            ar: {
                tab_learn: 'تعلّم', tab_code: 'برمجة', tab_achievements: 'الإنجازات',
                tab_profile: 'ملفي', tab_leaderboard: 'المتصدّرون', tab_videos: 'دروس فيديو', tab_interactive: 'دروس تفاعلية',
                interactive_title: 'دروس تفاعلية', interactive_subtitle: 'اكتشف أنشطة تفاعلية أعدّتها أكاديميتك.',
                interactive_loading: 'جارٍ تحميل الدروس التفاعلية...', interactive_empty: 'لا توجد دروس تفاعلية متاحة بعد.', interactive_open: 'فتح الدرس', btn_refresh: 'تحديث',
                btn_run: 'تشغيل', btn_stop_reset: 'إيقاف وإعادة',
                cat_move: '🚶 حركة', cat_draw: '🎨 رسم', cat_fun: '🎉 مرح', cat_loop: '🔁 تكرار',
                welcome_title: 'أهلاً بك في أكاديمية ستيمو!',
                welcome_sub: 'تعلّم البرمجة عن طريق برمجة صديقك الروبوت. هل أنت مستعد للمغامرة؟',
                btn_start_learning: 'ابدأ التعلّم!',
                curriculum_path: 'مسار الدروس',
                your_tasks: 'مهامك:', homework_title: 'تحدّي الواجب المنزلي:', hint_title: 'تلميح',
                btn_back_lessons: 'العودة إلى الدروس', btn_start_coding: 'ابدأ البرمجة!',
                assigned_label: '📌 معلّمك حدّد لك هذا الدرس', btn_start_now: '🚀 ابدأ الآن',
                code_subtitle: 'اضغط على اللبنات لإضافتها • اضغط بالزر الأيمن على لبنة لحذفها أو حذف مجموعة كاملة',
                btn_undo: '↩️ تراجع', btn_select_group: '🔲 تحديد مجموعة', btn_left_start: '⬅️ بداية يسار',
                hide_robot: 'إخفاء الروبوت', show_robot: 'إظهار الروبوت',
                completed_label: 'مكتمل!', locked_hint: 'مقفل'
            },
            es: {
                tab_learn: 'Aprender', tab_code: 'Código', tab_achievements: 'Logros',
                tab_profile: 'Mi Perfil', tab_leaderboard: 'Clasificación', tab_videos: 'Videos', tab_interactive: 'Lecciones interactivas',
                interactive_title: 'Lecciones interactivas', interactive_subtitle: 'Explora actividades preparadas por tu academia.',
                interactive_loading: 'Cargando lecciones interactivas...', interactive_empty: 'Aún no hay lecciones interactivas.', interactive_open: 'Abrir lección', btn_refresh: 'Actualizar',
                btn_run: 'Ejecutar', btn_stop_reset: 'Detener y reiniciar',
                cat_move: '🚶 Mover', cat_draw: '🎨 Dibujar', cat_fun: '🎉 Diversión', cat_loop: '🔁 Repetir'
            },
            fr: {
                tab_learn: 'Apprendre', tab_code: 'Code', tab_achievements: 'Succès',
                tab_profile: 'Mon Profil', tab_leaderboard: 'Classement', tab_videos: 'Vidéos', tab_interactive: 'Leçons interactives',
                interactive_title: 'Leçons interactives', interactive_subtitle: 'Découvrez les activités préparées par votre académie.',
                interactive_loading: 'Chargement des leçons interactives...', interactive_empty: 'Aucune leçon interactive disponible.', interactive_open: 'Ouvrir la leçon', btn_refresh: 'Actualiser',
                btn_run: 'Lancer', btn_stop_reset: 'Arrêter et réinitialiser',
                cat_move: '🚶 Bouger', cat_draw: '🎨 Dessiner', cat_fun: '🎉 Amusant', cat_loop: '🔁 Répéter'
            }
        };
        var currentLang = safeStorageGet('stemoLang') || 'en';

        // Arabic labels for the block palette (left panel) and category headers.
        // Keyed by the original English text of each element.
        var PALETTE_AR = {
            '🚶 Forward': '🚶 للأمام', '🔙 Back': '🔙 للخلف', '↩️ Left': '↩️ يسار', '↪️ Right': '↪️ يمين',
            '🏠 Home': '🏠 المنزل', '⬅️ Left Start': '⬅️ بداية يسار', '👻 Hide': '👻 إخفاء',
            '🖍️ Pen': '🖍️ القلم', '🎨 Color': '🎨 اللون', '🖌️ Size': '🖌️ الحجم',
            '💬 Say': '💬 قُل', '😊 Emotion': '😊 المشاعر', '🕺 Dance': '🕺 رقص', '🔊 Sound': '🔊 صوت',
            '🔁 Repeat': '🔁 كرّر', '🧲 Magnet ON': '🧲 مغناطيس يعمل', '🧲 Magnet OFF': '🧲 مغناطيس متوقف',
            '📡 Scan': '📡 مسح', '🚗 Auto Move': '🚗 حركة تلقائية', '🎯 Go Target': '🎯 اذهب للهدف',
            '🧭 Smart Navigate': '🧭 ملاحة ذكية', '🧱 If Wall': '🧱 إذا جدار', '🧠 Smart Turn': '🧠 دوران ذكي',
            '🌡️ Check Temp': '🌡️ فحص الحرارة', '🔥 If Hot': '🔥 إذا حرارة', '💧 Spray Water': '💧 رشّ الماء',
            '🚒 Firefighter': '🚒 وضع الإطفاء', '📦 Set Var': '📦 عيّن متغيّر', '➕ Change Var': '➕ غيّر متغيّر',
            '🚀 Move [Var]': '🚀 تحرك [متغيّر]', '🔄 Turn [Var]': '🔄 دُر [متغيّر]', '🔁 Repeat [Var]': '🔁 كرّر [متغيّر]',
            '📍 Show Coords': '📍 أظهر موقعي', '📡 Send to Command Center': '📡 أرسل لمركز القيادة',
            '💾 Save Position': '💾 احفظ الموقع', '🔙 Go to Position': '🔙 اذهب للموقع المحفوظ',
            '📌 Add Waypoint': '📌 أضف نقطة مسار', '▶️ Replay Path': '▶️ أعد تشغيل المسار',
            '🔂 For Each Waypoint': '🔂 لكل نقطة مسار', '🗑️ Clear List': '🗑️ امسح القائمة',
            '🔧 Define Function': '🔧 عرّف دالة', '▶ Call Function': '▶ استدعِ دالة',
            '🧲 Robot': '🧲 الروبوت', '📡 Sensor': '📡 الحساسات', '🔥 Fire': '🔥 الحريق',
            '🔢 Variables': '🔢 المتغيّرات', '📍 Position & Lists': '📍 المواقع والقوائم', '🔧 Functions': '🔧 الدوال'
        };

        // Arabic labels for Blockly block text and dropdown options (keyed by English)
        var BLOCK_AR = {
            '🚶 Move': '🚶 تحرك', '🔙 Back': '🔙 ارجع', 'steps': 'خطوات', '°': '°', 'px': 'بكسل',
            '↩️ Left': '↩️ دُر يساراً', '↪️ Right': '↪️ دُر يميناً',
            '🖍️ Pen': '🖍️ القلم', '🎨 Color': '🎨 اللون', '🖌️ Size': '🖌️ الحجم',
            '💬 Say': '💬 قُل', '😊 Feel': '😊 اشعر', '🕺 Dance': '🕺 ارقص', '🔊 Play': '🔊 شغّل',
            '🏠 Go Home': '🏠 اذهب للمنزل', '⬅️ Go to Left Start': '⬅️ اذهب لبداية اليسار',
            '👻 Hide': '👻 إخفاء', '🧲 Magnet ON': '🧲 شغّل المغناطيس', '🧲 Magnet OFF': '🧲 أطفئ المغناطيس',
            '🔁 Repeat': '🔁 كرّر', 'times': 'مرات', 'do': 'نفّذ', 'then': 'إذن', 'else': 'وإلا',
            '📡 Scan Ahead': '📡 امسح للأمام', '🚗 Auto Move': '🚗 حركة تلقائية',
            '🎯 Go To Target': '🎯 اذهب إلى الهدف', '🧭 Smart Navigate': '🧭 ملاحة ذكية',
            '🧱 If Wall Within': '🧱 إذا جدار خلال', '🧠 Smart Turn': '🧠 دوران ذكي',
            '🌡️ Check Temp': '🌡️ افحص الحرارة', '🔥 If Fire Within': '🔥 إذا حريق خلال',
            '💧 Spray Water': '💧 رشّ الماء', '🚒 Firefighter Mode': '🚒 وضع الإطفاء',
            '📦 Set': '📦 عيّن', '➕ Change': '➕ غيّر', 'to': 'إلى', 'by': 'بمقدار',
            '🚀 Move': '🚀 تحرك', '🔄 Turn': '🔄 دُر', 'degrees right': 'درجة لليمين',
            '📍 Show My Position': '📍 أظهر موقعي', '📡 Send to Command Center:': '📡 أرسل لمركز القيادة:',
            '💾 Save Position as': '💾 احفظ الموقع باسم', '🔙 Go to Position': '🔙 اذهب للموقع',
            '📌 Add Waypoint to List': '📌 أضف نقطة مسار للقائمة', '▶️ Replay Path': '▶️ أعد تشغيل المسار',
            '🔂 For Each Waypoint:': '🔂 لكل نقطة مسار:', '🗑️ Clear Waypoint List': '🗑️ امسح قائمة المسار',
            '🔧 Define Function:': '🔧 عرّف دالة:', '▶ Call Function:': '▶ استدعِ دالة:',
            'Down ✏️': 'أسفل ✏️', 'Up ✋': 'أعلى ✋', 'Hide 🙈': 'إخفاء 🙈', 'Show 👀': 'إظهار 👀',
            '😀 Happy': '😀 سعيد', '😢 Sad': '😢 حزين', '😎 Cool': '😎 رائع', '🤩 Excited': '🤩 متحمس', '😐 Normal': '😐 عادي',
            '🎉 Cheer': '🎉 هتاف', '🎺 Fanfare': '🎺 أبواق', '✨ Magic': '✨ سحر', '🐱 Meow': '🐱 مواء', '🤖 Beep': '🤖 صفير', '💥 Pop': '💥 فرقعة'
        };
        function blockText(en) {
            if (currentLang === 'ar' && BLOCK_AR[en]) return BLOCK_AR[en];
            return en;
        }

        // ===== Arabic content dictionaries (lessons, badges, challenges) =====
        // AR_L: lesson id -> { t, d, i, hint, hw, tasks: [..] }
        var AR_L = {
            'lesson-1': {
                t: 'تعرّف على ستيمو!',
                d: 'اكتشف ما هي البرمجة وأعطِ أول أمر لك',
                i: 'مرحبا! أنا ستيمو — صديقك الروبوت في البرمجة! 🤖 برنامج الحاسوب هو ببساطة قائمة من التعليمات التي تخبر الروبوت (أو الحاسوب) بما يجب فعله بالضبط، خطوة بخطوة. تخيله مثل وصفة طبخ: إذا قالت الوصفة اضف بيضتين، فإن الطاهي يفعل ذلك بالضبط — لا أكثر ولا أقل! على الجهة اليسرى سترى مكعبات ملونة — كل مكعب هو تعليمة واحدة. وعلى اليمين عالمي الذي أتحرك فيه. توضع المكعبات في منطقة البرنامج في الوسط. عندما تضغط زر التشغيل الأخضر، أقرأ مكعباتك من الأعلى إلى الأسفل وأنفذ كل تعليمة. لنكتب أول برنامج لك على الإطلاق!',
                hint: 'تُضاف المكعبات بالنقر عليها في اللوحة اليسرى. الرقم داخل المكعب هو عدد الخطوات التي أخطوها. مكعبات أكثر = خطوات أكثر!',
                hw: 'حاول أن تجعلني أتحرك 10 خطوات بالضبط! يمكنك استخدام مكعب واحد بقيمة 10، أو مكعبين كل واحد بقيمة 5 — كلاهما يعمل! أيهما تفضل؟',
                tasks: [
                    'انظر إلى اللوحة اليسرى — ابحث عن مكعب للأمام الأزرق. انقر عليه مرة واحدة لإضافته إلى برنامجك!',
                    'هل ترى الرقم داخل مكعب للأمام؟ انقر عليه وغيّره إلى 3 خطوات',
                    'انقر زر التشغيل ▶ الأخضر الكبير وشاهدني أتحرك!',
                    'الآن أضف مكعب للأمام ثانيًا — يجب أن أتحرك أبعد هذه المرة',
                    'انقر زر المسح 🗑️ لمسح كل المكعبات والبدء من جديد',
                    'ابنِ برنامجك الخاص بأربعة مكعبات للأمام بالضبط. كم أبتعد؟ 🎉'
                ]
            },
            'lesson-2': {
                t: 'سيّد الحركة',
                d: 'تعلّم كل الاتجاهات الأربعة وتنقّل باحتراف',
                i: 'عمل رائع في برنامجك الأول! 🎉 الآن لنستكشف كل الطرق التي أستطيع التحرك بها. أستطيع الذهاب للأمام ⬆️، وللخلف ⬇️، والدوران يسارًا ⬅️، والدوران يمينًا ➡️. يُقاس الدوران بالدرجات — فكّر في وجه الساعة: 90° هي ربع دورة (مثل الانعطاف عند زاوية)، و180° هي نصف دورة (مواجهة الاتجاه المعاكس)، و360° هي دورة كاملة! الروبوتات الحقيقية مثل المكانس الكهربائية تستخدم هذه الدورات نفسها لتنظيف بيتك كله دون أن تفوّت أي بقعة. أستطيع أيضًا القفز عائدًا إلى البيت 🏠 فورًا. لنتقن كل الحركات!',
                hint: 'فكّر في البوصلة: للأمام = شمال، يمين = شرق، للخلف = جنوب، يسار = غرب. دورة 90° هي دائمًا زاوية مثالية — تمامًا مثل زوايا غرفة مربعة!',
                hw: 'هل تستطيع أن تجعلني أمشي على شكل حرف Z؟ جرّب: للأمام ← دوران يمين ← للأمام ← دوران يسار ← للأمام. لاحظ كيف تغيّر الدورانات اتجاه الحركة التالية!',
                tasks: [
                    'أضف للأمام 4 — أتحرك 4 خطوات لأعلى',
                    'أضف يمين 90 — أدور لأواجه اليمين (ربع دورة)',
                    'أضف للأمام 3 — أتحرك 3 خطوات لليمين. شغّله! أمشي على شكل حرف L! ↱',
                    'امسح وجرّب: للأمام 3 ← يسار 90 ← للأمام 3 ← يسار 90 ← للأمام 3. أي شكل أصنع؟',
                    'أضف للخلف 2 في النهاية — شاهدني أرجع للوراء!',
                    'أضف البيت كآخر مكعب على الإطلاق — أنتقل فورًا عائدًا إلى البداية! 🏠'
                ]
            },
            'lesson-3': {
                t: 'ابدأ الرسم!',
                d: 'ارفع القلم وأنزله لرسم الخطوط والأنماط',
                i: 'والآن الجزء الممتع حقًا — الرسم! 🖍️ تخيّل أنني أحمل قلمًا ملوّنًا على الأرض. عندما يكون القلم مرفوعًا (🖊️ لأعلى)، أتحرك دون أن أترك أثرًا — مثل رفع قلمك عن الورقة. وعندما يكون القلم منخفضًا (✏️ يلمس الأرض)، كل خطوة أخطوها تترك أثرًا! هكذا تمامًا يعمل روبوت الراسمة — الآلات التي ترسم اللافتات الضخمة والخرائط! القاعدة الأساسية: أضف دائمًا انزال القلم قبل التحرك، وإلا لن يظهر شيء. لنرسم!',
                hint: 'تذكّر الترتيب: انزال القلم أولًا، ثم التحرك. رفع القلم = لا أثر. انزال القلم = أثر. فكّر بها مثل ختم على الورق!',
                hw: 'ارسم الأحرف الأولى من اسمك! فكّر في أي الخطوط تحتاج انزال القلم وأي الفراغات تحتاج رفع القلم. مثلًا حرف L = للأمام 4، يمين 90، للأمام 2.',
                tasks: [
                    'أضف مكعب انزال القلم ✏️ — قلمي الآن يلمس الأرض',
                    'أضف للأمام 5 وانقر تشغيل — لقد رسمت خطًا! 📏',
                    'الآن أضف رفع القلم 🖊️ ← للأمام 3 ← انزال القلم ✏️ ← للأمام 3. شغّله — أترى الفجوة في الخط؟ إنه خط متقطّع!',
                    'امسح وارسم شكل حرف L: انزال القلم ← للأمام 5 ← يمين 90 ← للأمام 5',
                    'تحدٍ: ارسم درجًا! أضف هذا التسلسل ثلاث مرات: انزال القلم ← للأمام 2 ← يمين 90 ← للأمام 2 ← يسار 90.'
                ]
            },
            'lesson-4': {
                t: 'فنان الألوان',
                d: 'ارسم بالألوان وتحكّم في سماكة الخط',
                i: 'لنجعل رسوماتنا جميلة وملوّنة! 🎨 يستطيع قلمي أن يرسم بأي لون تختاره. كما يمكنك التحكم في سماكة أو رفع الخط باستخدام مكعب الحجم. الحجم 1 هو خط رفيع جدًا؛ والحجم 20 هو قلم سميك! برامج التصميم الحقيقية (مثل شعارات ألعابك المفضلة) تستخدم هذه الأفكار نفسها — اللون والحجم والموضع. تلميح احترافي: اضبط اللون والحجم دائمًا قبل إنزال القلم، لتكون أول ضربة مثالية تمامًا!',
                hint: 'ضع مكعبات اللون والحجم قبل انزال القلم للحصول على أنظف نتيجة. يمكنك أيضًا تغيير اللون أثناء الرسم — أضف مكعب لون جديدًا بين مكعبات للأمام!',
                hw: 'أنشئ طريقًا ملوّنًا! ارسم 6 خطوط متتالية، كل واحد بلون مختلف (أحمر، برتقالي، أصفر، أخضر، أزرق، بنفسجي). استخدم رفع القلم بين الخطوط لترك فجوات صغيرة!',
                tasks: [
                    'أضف مكعب لون واختر الأحمر — ثم انزال القلم ← للأمام 5 ← تشغيل. خط أحمر! 🔴',
                    'أضف مكعب حجم 10 قبل انزال القلم — شغّل مجددًا. الخط الآن سميك!',
                    'غيّر مكعب اللون إلى الأزرق والحجم إلى 3. شغّل — خط أزرق رفيع! 🔵',
                    'الآن ابنِ هذا: لون أحمر ← انزال القلم ← للأمام 3 ← لون أزرق ← للأمام 3 ← لون أخضر ← للأمام 3. خط بثلاثة ألوان! 🎨',
                    'جرّب رسم مربع أحمر سميك: لون أحمر ← حجم 8 ← انزال القلم، ثم أضف للأمام 4 ← يمين 90 أربع مرات.'
                ]
            },
            'lesson-5': {
                t: 'قوة الحلقات!',
                d: 'استخدم التكرار لتستبدل المكعبات المكررة المملة',
                i: 'ماذا لو احتجت أن تتحرك للأمام 100 مرة؟ يمكنك إضافة 100 مكعب للأمام... لكن ذلك سيستغرق وقتًا طويلًا! 😅 المبرمجون يكرهون تكرار أنفسهم — لذلك اخترعوا الحلقة. تقول الحلقة نفّذ هذه المجموعة من التعليمات N مرة. في الحياة الواقعية، تنفّذ حلقة الغسالة: املأ الماء ← دوّر ← صرّف الماء — وتكرر هذه الدورة حتى تنظف الملابس! مكعب التكرار في البرمجة يفعل الشيء نفسه. معلومة ممتعة: بدون الحلقات، ألعاب هاتفك ستحتاج ملايين الأسطر من الكود. مع الحلقات، النتيجة نفسها تحتاج أسطرًا قليلة! لنرَ السحر:',
                hint: 'قاعدة المربع: تكرار 4 ← للأمام N ← يمين 90. الرقم في للأمام يحدد الحجم. للأمام أكبر = مربع أكبر!',
                hw: 'هل تستطيع رسم درج باستخدام حلقة؟ جرّب: تكرار 5 مرات ← للأمام 2 ← يمين 90 ← للأمام 2 ← يسار 90. كيف يبدو؟',
                tasks: [
                    'أولًا، بدون حلقة: أضف للأمام 4 أربع مرات منفصلة + أربعة مكعبات يمين 90 (8 مكعبات إجمالًا). شغّل — لقد رسمت مربعًا! 🟦',
                    'الآن امسح واستخدم حلقة: أضف تكرار 4 ← بداخله أضف للأمام 4 ويمين 90. شغّل — المربع نفسه بثلاثة مكعبات فقط! ✨',
                    'غيّر رقم التكرار إلى 8 واليمين إلى 45°. شغّل — أرسم مثمّنًا منتظمًا! ⬡',
                    'أضف انزال القلم قبل التكرار حتى ترى الشكل مرسومًا',
                    'تحدٍ: اصنع مستطيلًا طويلًا — كرّر مرتين: للأمام 6، يمين 90، للأمام 3، يمين 90'
                ]
            },
            'lesson-6': {
                t: 'فنان الأشكال',
                d: 'استخدم الرياضيات لرسم أي مضلّع تتخيله',
                i: 'إليك صيغة رياضية سحرية يستخدمها المعماريون ومصممو الألعاب والمهندسون: زاوية الدوران = 360 ÷ عدد الأضلاع. المثلث له 3 أضلاع ← 360÷3 = 120°. المربع له 4 أضلاع ← 360÷4 = 90°. المسدس له 6 أضلاع ← 360÷6 = 60°. الدائرة لها عدد لا نهائي من الأضلاع الصغيرة! هذه الصيغة تعمل مع أي شكل. قرص العسل في خلية النحل مصنوع من مسدسات مثالية — يستخدم النحل هذا الشكل لأنه لا يهدر أي مساحة ويستهلك أقل قدر من الشمع. لنستخدم الرياضيات نفسها التي يستخدمها النحل:',
                hint: 'الصيغة: زاوية الدوران = 360 ÷ عدد الأضلاع. دائمًا! مثلث=120، مربع=90، خماسي=72، مسدس=60، مثمّن=45، دائرة≈1 (بخطوات كثيرة).',
                hw: 'هل تستطيع رسم بيت؟ البيت = مربع (4 أضلاع، 90°) للجدران + مثلث (3 أضلاع، 120°) للسقف. بعد المربع، ضع القلم بعناية قبل رسم المثلث فوقه!',
                tasks: [
                    'مثلث (3 أضلاع): انزال القلم ← تكرار 3 ← للأمام 5، يمين 120°. شغّل! 🔺',
                    'خماسي (5 أضلاع): 360÷5 = 72°. تكرار 5 ← للأمام 5، يمين 72°. شغّل! ⬠',
                    'مسدس (6 أضلاع): 360÷6 = 60°. تكرار 6 ← للأمام 4، يمين 60°. شغّل! ⬡ (مثل قرص العسل!)',
                    'مثمّن (8 أضلاع، مثل إشارة التوقف!): 360÷8 = 45°. تكرار 8 ← للأمام 3، يمين 45°. شغّل! 🛑',
                    'الآن جرّب شكلك الخاص — اختر أي عدد من الأضلاع (جرّب 12 أو 20) واحسب زاوية الدوران!'
                ]
            },
            'lesson-7': {
                t: 'قوة النجوم!',
                d: 'ارسم نجومًا جميلة بثماني رؤوس باستخدام خدعة زاوية سرية',
                i: 'النجوم مميزة لأن خطوطها تتقاطع فوق بعضها! النجمة الثمانية هي واحدة من أجمل الأنماط الهندسية في العالم — تجدها في الفن الإسلامي والعمارة حول المساجد والمباني. الزاوية السرية للنجمة الثمانية هي 135°. لماذا؟ الدائرة فيها 360°. اقسم على 8 رؤوس = 45°. ثم اضرب في 3 (لتخطي رأسين وصنع خطوط متقاطعة) = 135°! بمجرد تكرار 8 + للأمام + يمين 135°، يرسم ستيمو نجمة ثمانية مثالية في كل مرة. لنصنع بعض النجوم!',
                hint: 'النجمة الثمانية: تكرار 8 ← للأمام N، يمين 135°. الرقم السحري هو 135! الصيغة: 3 × (360 ÷ 8) = 135°.',
                hw: 'ارسم ثلاث نجوم ثمانية بأحجام وألوان مختلفة. استخدم رفع القلم للتنقل بينها. هل تستطيع أن تجعلها تبدو كسماء ليلية؟',
                tasks: [
                    'ارسم نجمة ثمانية: انزال القلم ← تكرار 8 ← للأمام 6، يمين 135°. شغّل! ✨',
                    'اجعلها أكبر: غيّر للأمام إلى 10. النجمة تكبر لكنها تبقى مثالية!',
                    'أضف لونًا ذهبيًا (أصفر) وحجم 4 قبل انزال القلم — نجمة ذهبية جريئة! 🌟',
                    'غيّر اللون إلى الأخضر وارسم نجمة أخرى في مكان مختلف — استخدم رفع القلم للتنقل! 💚',
                    'جرّب نجمة ثمانية بحجم 2 (خطوط رفيعة) وحجم 8 (خطوط سميكة) — أيهما أجمل؟ 🎨'
                ]
            },
            'lesson-8': {
                t: 'سحر المغناطيس',
                d: 'التقط الأجسام المعدنية وحرّكها بمغناطيس كهربائي',
                i: 'لديّ مغناطيس كهربائي قوي مدمج في مقدمتي! 🧲 المغناطيس الكهربائي يعمل فقط عندما يمرّ التيار الكهربائي خلاله — شغّله وتلتصق الأجسام المعدنية بي، وأطفئه فتسقط. الروبوتات الحقيقية في ساحات الخردة ومراكز إعادة التدوير تستخدم هذه التقنية بالضبط لفرز المعدن عن البلاستيك والورق تلقائيًا. الروبوتات ذاتية القيادة في مستودعات أمازون تستخدم المغناطيس لتحريك الرفوف! مغناطيسي قوي بما يكفي لحمل قطع البراغي 🔩 التي تضعها على اللوح. القاعدة: يجب أن أكون قريبًا جدًا من القطعة المعدنية لتلتصق. لنحرّك بعض المعدن!',
                hint: 'شغّل المغناطيس فقط عندما تكون قريبًا من قطعة معدنية واحدة. حرّكها إلى موقعها الجديد، وأطفئ المغناطيس لإسقاطها، ثم عد للقطعة التالية.',
                hw: 'صمّم محطة فرز معادن! ضع 4 قطع معدنية متناثرة على اللوح. حرّك كل قطعة، واحدة تلو الأخرى، إلى الزاوية العلوية اليمنى. استخدم الحلقات لجعل برنامجك أقصر!',
                tasks: [
                    'انقر زر 🔩 فوق اللوح لوضع قطعة معدنية قريبة مني',
                    'ابنِ: للأمام (للاقتراب) ← تشغيل المغناطيس ← تشغيل. هل يلتصق البرغي؟ 🧲',
                    'الآن أضف: للأمام 3 ← إطفاء المغناطيس. تسقط القطعة المعدنية في الموقع الجديد!',
                    'ضع قطعتين معدنيتين. التقط الأولى، حرّكها إلى موقع جديد، وأطفئ المغناطيس لإسقاطها. ثم اجمع القطعة الثانية.',
                    'تحدٍ: ضع 3 قطع معدنية في صف. اجمعها واحدة تلو الأخرى: تشغيل المغناطيس قرب معدن ← حرّكه ← إطفاء المغناطيس. هل تستطيع فرز الثلاث؟'
                ]
            },
            'lesson-9': {
                t: 'الرؤية بالموجات فوق الصوتية',
                d: 'شاهد العوائق باستخدام الموجات الصوتية مثل الخفاش',
                i: 'أستطيع الرؤية بلا عيون! 🦇 يعمل مستشعري فوق الصوتي تمامًا مثل تحديد الموقع بالصدى عند الخفافيش: أرسل موجة صوتية عالية النبرة (أعلى من أن يسمعها البشر)، وأقيس الوقت الذي تستغرقه لترتد. كلما استغرقت وقتًا أطول، كان العائق أبعد! تسمى هذه التقنية سونار (الملاحة وتحديد المدى بالصوت). تستخدمها الغواصات لرسم قاع المحيط. وتستخدمها السيارات في مستشعرات الركن التي تصدر صافرة عند الاقتراب من الجدار. أشهر مستشعر للهواة يسمى HC-SR04 وهو موجود في ملايين روبوتات الطلاب حول العالم! لنمسح عالمنا:',
                hint: 'يظهر شعاع المسح الأمامي باللون الأصفر — كلما كان الشعاع أقصر، كان الجدار أقرب. إذا وصل الشعاع إلى حافة اللوح دون جدار، تكون القراءة واضح. امسح دائمًا قبل التحرك إلى منطقة مجهولة!',
                hw: 'ابنِ برنامج مسح آمن: مسح للأمام ← تقدّم خطوة واحدة ← امسح للأمام مجددًا. راقب المسافة بعد كل حركة وأنهِ البرنامج عندما تكون قريبًا من الجدار بأمان. هكذا تساعد حساسات الركن السائقين!',
                tasks: [
                    'انقر زر الجدار 🧱 لوضع جدار على بعد 4 خطوات أمامي',
                    'أضف مكعب مسح أمامي 📡 وشغّل — شاهد الشعاع الأصفر يُظهر المسافة!',
                    'الآن أضف: للأمام 2 ← مسح أمامي ← للأمام 1 ← مسح أمامي. راقب قراءة المسافة تتغير كلما اقتربت!',
                    'ضع جدرانًا على اليسار واليمين أيضًا. أضف مسح أمامي في البداية، ثم يمين 90 ← مسح أمامي ← يسار 180 ← مسح أمامي لقياس كل الجهات!',
                    'تحدٍ: باستخدام ما يخبرك به المستشعر، ابنِ برنامجًا ينقلني إلى خطوة واحدة بالضبط من الجدار دون أن ألمسه!'
                ]
            },
            'lesson-10': {
                t: 'ملّاح الفضاء',
                d: 'وجّه الروبوت إلى الأهداف مثل مركبة المريخ الجوّالة',
                i: 'مركبات ناسا الجوّالة على المريخ (كيوريوسيتي وبيرسيفيرانس) تقود نفسها إلى المواقع المستهدفة باستخدام الفكرة نفسها التي أنت على وشك تعلّمها! 🚀 تحسب الاتجاه إلى الهدف، وتدور حتى تواجهه، ثم تتقدم للأمام. مكعب اذهب إلى الهدف يدوّرني نحو الهدف الحالي ويقودني في اتجاهه. الجزء الرائع: حتى لو كنت أواجه الاتجاه الخاطئ، أدور حتى أشير نحو الهدف قبل التحرك. يعمل أفضل عندما يكون الطريق واضحًا؛ لاحقًا، تستطيع الملاحة الذكية إيجاد طريق حول متاهة معقدة. تُستخدم هذه الفكرة في ملاحة GPS وتوصيل الطائرات المسيّرة والسيارات ذاتية القيادة.',
                hint: 'مكعب اذهب إلى الهدف يدوّرني نحو الهدف الحالي ثم يحرّكني للأمام. يعمل أفضل في طريق واضح. امسح للأمام أولًا عند وجود جدران، أو استخدم الملاحة الذكية في المتاهة.',
                hw: 'أنشئ مهمة تدريب توصيل! ضع قطعة معدن واحدة وهدفًا واحدًا. شغّل المغناطيس قرب المعدن، حرّكه نحو الهدف، ثم أطفئ المغناطيس لإسقاطه عند الوجهة.',
                tasks: [
                    'انقر زر الهدف 🎯 وضع هدفًا في أي مكان على اللوح',
                    'أضف مكعب اذهب إلى الهدف 🎯 وشغّل — شاهدني أحسب وأتنقّل!',
                    'حرّك الهدف إلى مكان جديد وبعيد. امسح البرنامج، ثم استخدم اذهب إلى الهدف مجددًا لأتنقّل إلى الموقع الجديد!',
                    'الآن أضف جدارًا 🧱 بيني وبين الهدف. هل تتجنّبه ملاحتي، أم أحتاج مساعدتك؟',
                    'متقدم: ضع الهدف في زاوية قرب جدران. امسح للأمام، ثم تحرّك يدويًا بمكعبات للأمام ودُر لاتباع طريق واضح. احتفظ بمكعب اذهب إلى الهدف للطرق المفتوحة.'
                ]
            },
            'lesson-11': {
                t: 'المستكشف الذكي',
                d: 'اتخذ القرارات بإذا/وإلا — قلب الذكاء الاصطناعي',
                i: 'أنت الآن تدخل عالم الذكاء الاصطناعي! 🤖 كل نظام ذكي — من حواسيب الشطرنج إلى السيارات ذاتية القيادة — مبني على فكرة بسيطة واحدة: إذا (كان الشرط صحيحًا) عندها افعل هذا، وإلا افعل ذاك. إشارة المرور تستخدم هذا: إذا ضغط أحد المشاة الزر عندها اجعلها حمراء للسيارات، وإلا ابقَها خضراء. فتح هاتفك بالوجه يستخدم هذا: إذا تطابق الوجه عندها افتح، وإلا ابقَ مقفلًا. الشرط دائمًا إما صحيح أو خاطئ — لا يوجد ربما في الكود! في هذا الدرس، نمنحني القدرة على التفاعل مع بيئتي دون أن تتحكم بكل حركة. هذا سلوك ذاتي!',
                hint: 'إذا/وإلا تفحص دائمًا شرطًا (صحيح/خاطئ). عندها = ماذا تفعل إذا كان صحيحًا. وإلا = ماذا تفعل إذا كان خاطئًا. يمكنك ربط عدة مكعبات إذا — تفحص شرطًا ثم آخر! الذكاء الاصطناعي الحقيقي ما هو إلا ملايين من هذه القرارات البسيطة.',
                hw: 'ابنِ مستكشفًا ذكيًا! استخدم حلقة تكرار مع إذا جدار خلال خطوتين: إذن دُر يمينًا، وإلا تقدّم خطوة واحدة. أضف جدرانًا وشاهد ستيمو يتفاعل وحده!',
                tasks: [
                    'ضع جدارًا 3 خطوات أمامي. أضف: إذا جدار ضمن 2 ← عندها: يمين 90 ← وإلا: للأمام 1. شغّل — أتفادى الجدار! 🛡️',
                    'ضع إذا/وإلا داخل حلقة كرّر 8 مرات — الآن أستكشف، وأدور تلقائيًا كلما رأيت جدارًا!',
                    'أضف جدرانًا أكثر وزِد التكرار إلى 15. شاهدني أتنقّل في متاهة صغيرة!',
                    'الآن أضف مكعب إذا جدار ثانيًا بعد الأول. أعطِ كل مكعب دورانًا مختلفًا، ثم شغّل البرنامج وشاهد كيف يغيّر قرار واحد مساري.',
                    'تحدٍ: ضع جدرانًا في جزأين من مسارك. استخدم مكعبي إذا جدار داخل حلقة تكرار واحدة لأستمر في الاستكشاف بدل الاصطدام بجدار!'
                ]
            },
            'lesson-12': {
                t: 'مراقبة الحرائق',
                d: 'اكتشف مصادر الحرارة بمستشعر كاميرا حرارية',
                i: 'أحمل كاميرا حرارية بالأشعة تحت الحمراء — التقنية نفسها المستخدمة في طائرات إطفاء الحرائق ونظارات الرؤية الليلية العسكرية! 🌡️ الكاميرا العادية ترى الضوء. أما الكاميرا الحرارية فترى الحرارة — كل جسم يصدر قدرًا ضئيلًا من الحرارة، والحرائق تصدر الكثير. يقيس مستشعري درجة الحرارة أثناء تحركي. عندما ترتفع قراءة الحرارة فجأة، يعني ذلك أن النار قريبة! روبوتات إطفاء الحرائق الحقيقية تُنشَر بالفعل في المستودعات والغابات والمناطق العسكرية للعثور على الحرائق قبل دخول البشر إلى المناطق الخطرة. لندرّب مهارات كشف الحرارة لديّ:',
                hint: 'ترتفع درجة الحرارة كلما اقتربت من النار. افحص الحرارة ← اقترب ← افحص الحرارة مجددًا. إذا كانت القراءة الثانية أعلى، فأنت متجه نحو النار! اجمعه مع مكعبات إذا للتفاعل تلقائيًا.',
                hw: 'ابنِ مهمة رسم خريطة الحرائق: ضع 3 حرائق. اكتب برنامجًا يمسح اللوح بنمط متعرّج، فاحصًا درجة الحرارة عند كل موضع. استخدم رسائل الحرارة لتلاحظ أين تكون الحرارة الأقوى. طائرات حرائق الغابات تفعل هذا بالضبط!',
                tasks: [
                    'انقر زر النار 🔥 لوضع نار واحدة على اللوح',
                    'أضف مكعب افحص درجة الحرارة 🌡️ وشغّل — شاهد قراءة الحرارة تظهر!',
                    'اقترب أكثر: للأمام 2 ← افحص الحرارة ← للأمام 2 ← افحص الحرارة. لاحظ أن الحرارة ترتفع كلما اقتربت! 🌡️📈',
                    'أضف: إذا نار ضمن 3 خطوات ← عندها: اعرض رسالة 🚨 اكتُشفت نار! أطلب المساعدة!',
                    'ضع نارين في مكانين مختلفين. استخدم حلقة تكرار مع افحص الحرارة + الحركة للعثور على كلتا النارين تلقائيًا!'
                ]
            },
            'lesson-13': {
                t: 'بطل الإطفاء',
                d: 'أطفئ الحرائق بكفاءة — كل قطرة ماء مهمة!',
                i: 'الآن حان وقت العمل! 🦸 أحمل خزان ماء صغيرًا بكمية محدودة — تمامًا مثل طائرة إطفاء جوية حقيقية لا تحمل إلا قدرًا معينًا من الماء قبل أن تحتاج للتعبئة. في هذا التحدي أبدأ بـ 9 وحدات. كل وحدة تقلّل صحة النار نقطة واحدة، وكل نار في التحدي لها 3 نقاط صحة. هذا يعني أنك لا تستطيع الرش عشوائيًا — يجب أن تحدد الموقع بدقة وترش فقط عندما تكون قريبًا بما يكفي. هذا مفهوم هندسي يسمى الكفاءة: تحقيق أقصى نتيجة (إطفاء كل الحرائق) بأقل مورد (أقل ماء). مهندسو الفضاء يهتمون بهذا بشدة — مهمة إلى المريخ تهدر الوقود تعني أن المركبة لن تصل إلى أهدافها. لنفكّر باستراتيجية!',
                hint: 'خطّط لمسارك قبل البرمجة: أي نار أقرب؟ اذهب إليها أولًا. ثم أيها التالية الأقرب؟ تُستخدم استراتيجية أقرب جار هذه في تخطيط مسارات التوصيل الحقيقية! اقترب إلى ضمن 3 خطوات من النار قبل استخدام رش الماء. كل نار في التحدي تحتاج 3 وحدات ماء.',
                hw: 'أطفئ الحرائق الثلاث بالوصول إلى كل واحدة قبل استخدام رش الماء. مكعب رش ماء واحد يطفئ نار تحدٍ قريبة بالكامل ويستهلك 3 وحدات ماء، لذا خطّط لمسارك قبل تشغيله!',
                tasks: [
                    'ضع نارًا واحدة. تحرّك إلى ضمن 3 خطوات منها وأضف رُش الماء 💧. شغّل — شاهد النار تنطفئ ومؤشر الماء ينخفض! 🎯',
                    'ضع نارين متباعدتين. خطّط لأقصر مسار لزيارتهما. كل نار تحتاج 3 وحدات ماء، لذا صِل إلى كل واحدة قبل استخدام رش الماء.',
                    'افتح تحدي الحرائق الثلاث. يبدأ الخزان بـ 9 وحدات — تكفي تمامًا لحرائق التحدي الثلاث عند الوصول إليها بأمان.',
                    'راقب مؤشر الماء على اللوح قبل وبعد كل نار. لاحظ أن إطفاء نار كاملة يستهلك 3 وحدات ماء.',
                    'متقدم: خطّط لمسارك قبل تشغيله. استخدم رش الماء فقط عندما يكون ستيمو قريبًا بما يكفي من نار، حتى لا يُهدر الماء.',
                    'تحدي السرعة: أعد تحدي الحرائق الثلاث وعدّ مكعبات الحركة. هل تصل إلى الحرائق الثلاثة بمسار أقصر؟ ⏱️'
                ]
            },
            'lesson-15': {
                t: 'خزنة المتغيّرات',
                d: 'خزّن الأرقام في متغيّرات واستخدمها للتحكّم في ستيمو — غيّر رقمًا واحدًا يتغيّر كل شيء!',
                i: 'البرامج الحقيقية تستخدم المتغيّرات — صناديق مسمّاة تخزّن قيمًا يمكنك إعادة استخدامها. بدل كتابة للأمام 4، للأمام 4، للأمام 4، للأمام 4 أربع مرات، تكتب: اضبط السرعة=4، ثم تحرّك بمقدار السرعة خطوات — وإذا غيّرت السرعة إلى 6، تتحدّث كل حركة فورًا! هكذا تعمل كل البرامج: من محرّكات فيزياء ألعاب الفيديو (السرعة، الجاذبية، قوة القفز كلها متغيّرات) إلى حاسبات مسارات ناسا (السرعة، الزاوية، قوة الدفع). المتغيّرات تجعل كودك مرنًا وقويًا وقابلًا لإعادة الاستخدام.',
                hint: 'المتغيّرات مثل جِرار مسمّاة — تضع رقمًا فيها مرة، ثم تستخدم الاسم في أي مكان. أنزل القلم قبل التحرك، وإلا لن يُرسم الأثر. للمربع: كرّر بمقدار العدد ← تحرّك بمقدار السرعة خطوات ← دُر بمقدار الزاوية درجات يمينًا.',
                hw: 'ابنِ حلزون التكبير: اضبط السرعة=1. كرّر 20 مرة: تحرّك بمقدار السرعة خطوات ← دُر 90 يمينًا ← غيّر السرعة بمقدار 1. المتغيّر يكبر كل حلقة — يتّجه ستيمو حلزونيًا للخارج! يسمى هذا متغيّر التجميع.',
                tasks: [
                    'اسحب 📦 اضبط متغيّرًا ← اضبط السرعة إلى 4. أضف 🚀 تحرّك [السرعة] خطوات. شغّل — يتحرك ستيمو 4 خطوات للأمام!',
                    'غيّر السرعة إلى 7 وأعد التشغيل — لا مكعبات أخرى لتغييرها! تستخدم الحركة القيمة الجديدة تلقائيًا.',
                    'أضف 📦 اضبط متغيّرًا العدد=4، الزاوية=90. ابنِ: انزال القلم ← كرّر [العدد] مرة ← تحرّك [السرعة] خطوات + دُر [الزاوية] درجات. ارسم مربعًا!',
                    'غيّر السرعة إلى 8 — أعد التشغيل. مربعك الآن أكبر، بلا أي تغييرات أخرى. تلك هي قوة المتغيّرات!',
                    'مهمة: اضبط العدد=8، الزاوية=45. ارسم نجمة ثمانية باستخدام المتغيّرات. غيّر السرعة من 3 إلى 6. شاهد النجمة تكبر!'
                ]
            },
            'lesson-16': {
                t: 'ذاكرة الموقع',
                d: 'احفظ إحداثيات X وY وتنقّل عائدًا — تمامًا مثل تقنية نقطة البيت في GPS!',
                i: 'كل طائرة مسيّرة لها نقطة بيت — إحداثية GPS للمكان الذي أقلعت منه، تُحفظ تلقائيًا. عندما تنخفض البطارية، تتنقّل عائدة إلى تلك النقطة بالضبط وتهبط. ستيمو لديه الميزة نفسها! يمكنك حفظ حتى 4 مواقع مسمّاة (A، B، C، D)، ثم تستكشف بحرية، ثم تأمر ستيمو بالعودة إلى أي موقع محفوظ باستخدام باحث المسار BFS الكامل — لا يضيع أبدًا. طائرات البحث والإنقاذ الحقيقية تستخدم هذا لإسقاط عُدد الإنقاذ والعودة إلى القاعدة للتزوّد.',
                hint: 'يجب أن يأتي احفظ الموقع A قبل أي حركة، وإلا سيخزّن A الموقع الخاطئ! أظهر موقعي يعرض الإحداثيات كخطوات من المركز (0,0). استخدم اذهب إلى الموقع للعودة — يستخدم باحث المسار BFS لتجنّب كل الجدران.',
                hw: 'ابنِ مسار دورية: احفظ A (البداية)، تحرّك شرقًا 5، احفظ B، تحرّك جنوبًا 5، احفظ C. ثم كرّر: اذهب إلى A ← اذهب إلى B ← اذهب إلى C ← اذهب إلى A. هكذا تقوم روبوتات الأمن بدورياتها في المباني!',
                tasks: [
                    'أضف مكعب 📍 أظهر موقعي وشغّل. شاهد إحداثيات بداية ستيمو (0، 0 = المركز) مطبوعة في المحادثة!',
                    'أضف 💾 احفظ الموقع A كأول مكعب لك — هذا يسجّل نقطة البداية. حرّك ستيمو 5 خطوات للأمام. ثم 🔙 اذهب إلى الموقع A — شاهده يعود إلى البيت!',
                    'احفظ الموقع A (البداية)، تحرّك إلى مكان معقّد (دورانات + حركات)، ثم اذهب إلى الموقع A. يجد BFS أقصر طريق للعودة!',
                    'جرّب حفظ موقعين: احفظ A في البداية، تحرّك شرقًا، احفظ B في المكان الحالي. ثم اذهب إلى الموقع A، ثم اذهب إلى الموقع B — يتنقّل ستيمو بينهما!',
                    'تحدي المهمة: احفظ الموقع A. تنقّل بذكاء إلى الهدف. ثم اذهب إلى الموقع A للعودة إلى البيت. يجب تحقيق الهدفين معًا!'
                ]
            },
            'lesson-17': {
                t: 'مسار نقاط الطريق',
                d: 'قائمة من المواقع محمّلة مسبقًا — أعد تشغيل المسار لجمع كل المعادن!',
                i: 'طائرات التوصيل تخزّن نقاط الطريق — قائمة من إحداثيات GPS لكل محطة في مسارها. تتنقّل من نقطة إلى نقطة تلقائيًا، تلتقط أو تُسقط الحمولة عند كل محطة. يمكن أن تحتوي القائمة على 3 عناصر أو 300 — الكود نفسه يتعامل مع الاثنين! هذا الدرس يحمّل قائمة نقاط الطريق مسبقًا بثلاثة مواقع معادن. مهمتك: شغّل المغناطيس وأمر ستيمو بإعادة تشغيل القائمة. مكعب واحد يجمع كل شيء!',
                hint: 'قائمة نقاط الطريق محمّلة مسبقًا عند بدء التحدي — فقط أضف تشغيل المغناطيس قبل أعد تشغيل المسار. تتم زيارة كل نقطة طريق باستخدام باحث المسار BFS حتى لا يعلق ستيمو. تُلتقط المعادن تلقائيًا عندما يصل ستيمو ضمن المدى والمغناطيس مشغّل.',
                hw: 'أنشئ روبوت تسجيل: ضع 4 معادن بنفسك، ثم اكتب برنامجًا يزور كل واحد ويسجّل موقعه باستخدام أضف نقطة طريق. امسح اللوح، أعد الضبط، ثم أعد تشغيل المسار — يقود مسارك المسجّل ستيمو إلى المواقع الأربعة مجددًا!',
                tasks: [
                    'شغّل ▶️ أعد تشغيل المسار بمفرده — يزور ستيمو المواقع الثلاثة المحمّلة مسبقًا بالترتيب. بلا مغناطيس بعد، فقط راقب المسار!',
                    'أضف تشغيل المغناطيس قبل أعد تشغيل المسار. شغّل — يتبع ستيمو المسار نفسه لكنه الآن يلتقط المعادن على طول الطريق!',
                    'أضف 📍 أظهر موقعي داخل الاستكشاف: حرّك ستيمو، أضف نقطة طريق، تحرّك مجددًا، أضف نقطة طريق — قائمتك المخصصة!',
                    'امسح القائمة (🗑️ امسح نقاط الطريق)، حرّك ستيمو يدويًا إلى مكانين مضيفًا نقاط طريق، ثم أعد تشغيل المسار لتتبّع مسارك المخصص.',
                    'مهمة: تشغيل المغناطيس ← أعد تشغيل المسار ← إطفاء المغناطيس. اجمع كل المعادن الثلاثة في برنامج واحد!'
                ]
            },
            'lesson-18': {
                t: 'صيد القوائم',
                d: 'كرّر عبر قائمة من أهداف الحرائق ونفّذ عند كل واحد — جوهر معالجة بيانات الذكاء الاصطناعي!',
                i: 'أنظمة الذكاء الاصطناعي تعمل بتخزين البيانات في قوائم والدوران خلالها لاتخاذ القرارات. نظام كشف الحرائق يخزّن إحداثيات الحرائق المكتشفة في قائمة، ثم يكرّر خلالها: لكل موقع نار ← تنقّل إليه ← رُش الماء. النمط نفسه يعالج نتائج الفحوص الطبية، ويتحكم في روبوتات المستودعات، ويقود طائرات التوصيل. هذا الدرس يعلّم أهم مفهوم في علوم الحاسوب: التكرار — تكرار عمل لكل عنصر في قائمة. مكعب واحد. ثلاث نيران. لنبدأ!',
                hint: 'قائمة نقاط الطريق محمّلة مسبقًا بمواقع الحرائق الثلاثة كلها. لكل نقطة طريق ← رُش الماء هو الحل بأكمله — مكعب مركّب واحد يتولّى التنقّل + الفعل لكل عنصر في القائمة. يبدأ التحدي بـ 10 وحدات ماء، وهي تكفي للحرائق الثلاثة كلها.',
                hw: 'صمّم برنامج القوائم الأمثل: ضع عناصر من اختيارك (معادن، نيران، أهداف). ابنِ قائمة نقاط طريق يدويًا باستخدام أضف نقطة طريق. ثم اكتب برنامج لكل يتعامل مع كل عنصر بشكل مناسب. اعرض برنامجك على الصف!',
                tasks: [
                    'اسحب مكعب 🔂 لكل نقطة طريق. داخل قسم نفّذ، أضف 💧 رُش الماء. شغّل — يتنقّل ستيمو إلى النار 1، يرش، النار 2، يرش، النار 3، يرش. تمّ كل شيء!',
                    'أضف 📍 أظهر موقعي داخل لكل — يعلن ستيمو موقعه عند كل نار. يسمى هذا التسجيل، والأنظمة الحقيقية تفعله لتصحيح الأخطاء!',
                    'عدّل: أضف 🌡️ افحص الحرارة داخل لكل قبل رُش الماء — شاهد ارتفاع الحرارة عند كل نار قبل الإطفاء مباشرة!',
                    'اضغط إعادة الضبط، ثم امسح نقاط الطريق. حرّك ستيمو قرب نارين من حرائق التحدي وأضف نقطة طريق عند كل واحدة. شغّل لكل ← رُش الماء لاستخدام قائمة حرائقك الصغيرة الخاصة!',
                    'تحدي الخبراء: بعد إعادة الضبط، امسح نقاط الطريق وسجّل مواقع حرائق التحدي الثلاث كلها بمكعب أضف نقطة طريق. شغّل لكل نقطة طريق ← افحص الحرارة ← رُش الماء للتعامل مع قائمتك الخاصة!'
                ]
            },
            'lesson-19': {
                t: 'مصنع الدوال',
                d: 'علّم ستيمو الحِيَل مرة واحدة — استدعِها إلى الأبد! الدوال هي القوة الخارقة السرية لكل مبرمج.',
                i: 'كل مبرمج محترف يستخدم الدوال — مكعبات كود مسمّاة قابلة لإعادة الاستخدام. بدل نسخ ولصق المكعبات العشرة نفسها مرارًا وتكرارًا، تكتبها مرة واحدة، وتسمّيها، وتستدعي الاسم. مهندسو ناسا يستخدمون الدوال للتحكم في مركبات المريخ الجوّالة. مطوّرو الألعاب يستخدمون الدوال لكل حركة شخصية. في هذا الدرس ستنشئ دالتين — drawSquare وbigSquare — وتجمعهما لإنتاج نمط نجمة هندسي مذهل بمكعبات قليلة. هذه هندسة برمجيات حقيقية!',
                hint: 'عرّف الدوال أولًا (في الأعلى أو الجانب)، ثم استدعِها بالأسفل. يجب أن يطابق الاسم في عرّف دالة الاسم في استدعِ دالة بالضبط — الإملاء مهم! drawSquare ليست DrawSquare.',
                hw: 'صمّم عملك الفني الهندسي الخاص: أنشئ 3 دوال على الأقل (مثل drawTriangle، drawStar، drawSpiral). اجمعها بزوايا دوران مختلفة لإنشاء نمط فريد. احفظه وشاركه مع الصف!',
                tasks: [
                    'اسحب مكعب 🔧 عرّف دالة. سمّه drawSquare. بداخله، أضف: انزال القلم ← كرّر 4 مرات (تحرّك 3 خطوات، دُر يمينًا 90°). تحت التعريف أضف ▶ استدعِ دالة: drawSquare، ثم اضغط تشغيل — يظهر مربع!',
                    'اسحب مكعب 🔧 عرّف دالة آخر. سمّه bigSquare. بداخله، أضف: كرّر 4 مرات ← (▶ استدعِ دالة: drawSquare، دُر يمينًا 90°). التعريفات تحفظ وصفة؛ لا تعمل إلا عند استدعائها.',
                    'استبدل استدعِ دالة: drawSquare تحت التعريفات بهذا: ▶ استدعِ دالة: bigSquare ← دُر يمينًا 45° ← ▶ استدعِ دالة: bigSquare. اضغط تشغيل — تظهر النجمة!',
                    'غيّر حجم الخطوة داخل drawSquare من 3 إلى 5. اضغط تشغيل — تكبر النجمة كلها. تلك قوة الدوال: غيّر رقمًا واحدًا يتحدّث كل شيء!',
                    'أنشئ دالة ثالثة اسمها starBurst. بداخلها: استدعِ bigSquare ← دُر يمينًا 30° ← استدعِ bigSquare ← دُر يمينًا 30° ← استدعِ bigSquare. أي شكل تحصل عليه؟'
                ]
            },
            'lesson-14': {
                t: 'المبرمج الخبير',
                d: 'المهمة الذاتية النهائية — تخرّج كمبرمج خبير! 🎓',
                i: '🎓 تهانينا — وصلت إلى الدرس الأخير في أكاديمية ستيمو! عبر رحلتك كلها تعلّمت: التسلسل، الحلقات، الهندسة، المستشعرات (فوق الصوتي + الحراري)، اتخاذ القرار (إذا/وإلا)، المغناطيس الكهربائي، الاستخدام الفعّال للموارد، المتغيّرات، المواقع المحفوظة، القوائم، والدوال. هذه هي المهارات نفسها بالضبط التي يستخدمها مهندسو الروبوتات الحقيقيون كل يوم. مهمتك الأخيرة هي الاختبار النهائي: لوح التحدي مجهّز بجدران وقطع معدنية وحرائق وهدف. اكتب برنامجًا واحدًا يتنقّل حول العوائق، ويجمع معدنًا واحدًا على الأقل، ويطفئ كل الحرائق، ويصل إلى الهدف. أنت المهندس. ستيمو روبوتك. لنتخرّج!',
                hint: 'قسّم المهمة إلى مراحل (مسح ← جمع ← إطفاء ← هدف) وابنِ كل مرحلة على حدة أولًا، ثم اربطها. استخدم الحلقات حيثما تتكرر الأفعال وراقب مؤشر الخزان أثناء إطفاء الحرائق. نهج التصميم من الأعلى للأسفل هذا هو طريقة بناء البرمجيات الحقيقية!',
                hw: 'أنت الآن مبرمج خبير! 🎓 تحدّيك: صمّم سيناريو مهمة جديدًا تمامًا واكتب البرنامج الذاتي له. أفكار: روبوت توصيل (يلتقط الطرود، يتجنّب النيران، يُسقط في الوجهة)، روبوت إنقاذ (يجد أشخاصًا عالقين خلف جدران)، أو روبوت فنان (يرسم شكلًا أثناء جمع المعادن). شارك إبداعك!',
                tasks: [
                    'افتح تحدي المهمة النهائية. اللوح مجهّز بالفعل بجدران وقطع معدنية وحرائق وهدف.',
                    'المرحلة 1 — المسح: أضف مسح أمامي في الاتجاهات الأربعة كلها في البداية لأعرف أين العوائق',
                    'المرحلة 2 — الجمع: تنقّل إلى القطع المعدنية مع تشغيل المغناطيس. اجمع معدنًا واحدًا على الأقل لإكمال هدف الجمع.',
                    'المرحلة 3 — الإطفاء: تنقّل إلى النارين ورُش الماء على كل واحدة. راقب مؤشر الخزان أثناء العمل.',
                    'المرحلة 4 — الإنهاء: تنقّل إلى الهدف بعد جمع المعدن وإطفاء الحرائق.',
                    'اجمع المراحل الأربع كلها في برنامج واحد وشغّله من البداية للنهاية — أكمل أهداف المعدن والحريق والهدف! 🏆🎉',
                    'مكافأة: عُدّ إجمالي مكعباتك المستخدمة. هل تستطيع تقليلها بنسبة 20% باستخدام الحلقات والتوجيه الأذكى؟ أفضل المهندسين يحسّنون! ✨'
                ]
            },
            'lesson-art-1': {
                t: 'حلزون قوس قزح',
                d: 'ارسم حلزونًا ساحرًا يكبر بينما يدور',
                i: 'مرحبًا بك في استوديو الفن! 🎨 هنا لا توجد إجابات خاطئة — فقط إبداعات جميلة. اليوم نرسم حلزونًا، الشكل نفسه الذي تراه في أصداف الحلزون والمجرّات وعبّاد الشمس! سرّ الحلزون بسيط: تحرّك قليلًا، دُر قليلًا، ثم تحرّك أكثر بقليل، دُر مجددًا — مرارًا وتكرارًا. مكعب التكرار يقوم بالدوران عنك. أضف مكعب لون وحتى مكعب مشاعر لتمنح ستيمو بعض الشخصية أثناء الرسم. مستعد أيها الفنان؟',
                hint: 'الحلزون = كرّر مرات كثيرة ← للأمام قليلًا + دُر قليلًا. غيّر زاوية الدوران (جرّب 20، 25، 30) لتصنع حلزونات أضيق أو أوسع!',
                hw: 'اصنع حلزونًا مزدوجًا: ارسم حلزونًا، ثم غيّر اللون وارسم آخر يدور بالاتجاه الآخر (استخدم يسار بدل يمين).',
                tasks: [
                    'أضف انزال القلم ✏️ ليترك ستيمو أثرًا',
                    'أضف مكعب 🎨 لون واختر لونك المفضّل',
                    'أضف 🔁 تكرار مضبوطًا على رقم كبير (جرّب 30). بداخله ضع: للأمام 1 ويمين 25',
                    'اضغط ▶ تشغيل وشاهد حلزونك يظهر!',
                    'أضف 😊 مشاعر ← متحمس ومكعب 🕺 رقص في النهاية للاحتفال!'
                ]
            },
            'lesson-art-2': {
                t: 'صانع قوس قزح',
                d: 'ارسم قوس قزح مشرقًا بكل ألوان الطيف',
                i: 'هل تعلم أن قوس قزح الحقيقي تكون ألوانه دائمًا بالترتيب نفسه — أحمر، برتقالي، أصفر، أخضر، أزرق، بنفسجي؟ ☀️🌧️ اليوم أنت المطر والشمس! سنرسم أقواسًا منحنية، واحدًا لكل لون، مكدّسة فوق بعضها. لصنع منحنى، نتحرك للأمام قليلًا وندور قليلًا، مرارًا وتكرارًا — تمامًا مثل الحلزون، لكن نصف دورة فقط. غيّر اللون لكل شريط وشاهد قوس قزح ينمو!',
                hint: 'كل شريط لوني هو القوس نفسه (كرّر ← للأمام + دُر)، فقط بمكعب لون مختلف قبله. حرّك ستيمو للأمام بضع خطوات بين الأشرطة كي لا تتداخل.',
                hw: 'أضف شمسًا ☀️ بجانب قوس قزحك: غيّر اللون إلى الأصفر وارسم دائرة صغيرة (كرّر 36 ← للأمام 1، يمين 10).',
                tasks: [
                    'أضف انزال القلم ✏️ ومكعب 🖌️ حجم مضبوطًا على 6 لأشرطة سميكة عصيرية',
                    'أضف 🎨 لون ← أحمر. ثم 🔁 كرّر 18 ← (للأمام 1، يمين 10) لرسم قوس',
                    'غيّر اللون إلى البرتقالي وارسم قوسًا آخر خارج الأول مباشرة',
                    'استمر — أصفر، أخضر، أزرق، بنفسجي. قوس لكل لون!',
                    'أنهِ بـ 💬 قُل ← صنعت قوس قزح! ليتباهى ستيمو بفنك'
                ]
            },
            'lesson-art-3': {
                t: 'اكتب اسمك',
                d: 'حوّل ستيمو إلى قلم ووقّع تحفتك الفنية',
                i: 'كل فنان عظيم يوقّع عمله! ✍️ اليوم ستوجّه ستيمو مثل قلم لكتابة الحرف الأول من اسمك. الأحرف مصنوعة من خطوط ودورانات — تمامًا المكعبات التي تعرفها بالفعل! استخدم رفع القلم للقفز (رفع القلم) بين الضربات، وانزال القلم للرسم. خذ وقتك، ضربة واحدة في كل مرة. هكذا تعمل روبوتات الراسمات وآلات التوقيع في العالم الحقيقي!',
                hint: 'الأحرف ذات الخطوط المستقيمة (L، T، E، H، I، F، A) هي الأسهل. خطّط لكل ضربة: انزال القلم ← ارسم ← رفع القلم ← أعد التموضع ← انزال القلم ← ارسم الضربة التالية.',
                hw: 'اكتب كل أحرف اسمك الأول! استخدم رفع القلم لترك فجوة بين كل حرف.',
                tasks: [
                    'اختر الحرف الأول من اسمك. تخيّل رسمه بخطوط مستقيمة',
                    'أضف انزال القلم ✏️ ثم ابنِ الضربة الأولى بمكعبات للأمام ودُر',
                    'استخدم رفع القلم 🖊️ للانتقال إلى الضربة التالية دون رسم، ثم انزال القلم مجددًا',
                    'أنهِ كل ضربات حرفك واضغط ▶ تشغيل',
                    'أضف 😎 مشاعر ← رائع و🔊 صوت ← أبواق للاحتفال بتوقيعك!'
                ]
            },
            'lesson-art-4': {
                t: 'ماندالا سحرية',
                d: 'أنشئ ماندالا متناظرة باستخدام حلقات داخل حلقات',
                i: 'الماندالا هي نمط جميل ومتناظر تمامًا — تجدها في الزهور وندف الثلج ❄️ والفن من حول العالم. الخدعة التي تجعلها سحرية هي حلقة داخل حلقة: الحلقة الداخلية ترسم شكلًا واحدًا (مثل مربع)، والحلقة الخارجية تدوّر ستيمو قليلًا وترسمه مجددًا، حول الدائرة كلها. بمكعبات قليلة يمكنك صنع نمط يبدو معقّدًا للغاية. لنصنع بعض السحر!',
                hint: 'حلقة داخل حلقة! التكرار الخارجي = كم نسخة حول الدائرة (12). التكرار الداخلي = الشكل (مربع = 4 × للأمام+يمين 90). الدوران الإضافي (360 ÷ 12 = 30°) يدوّر كل نسخة.',
                hw: 'غيّر الشكل الداخلي إلى مثلث (كرّر 3 ← للأمام 4، يمين 120) والدوران الخارجي ليطابقه. جرّب ألوانًا مختلفة لصنع منظار ملوّن!',
                tasks: [
                    'أضف انزال القلم ✏️ ومكعب 🎨 لون تحبّه',
                    'أضف 🔁 تكرار 12 خارجيًا',
                    'بداخله، أضف 🔁 تكرار 4 داخليًا ← (للأمام 3، يمين 90) لرسم مربع',
                    'ما زلت داخل الحلقة الخارجية لكن بعد الداخلية، أضف يمين 30 لتدوير المربع حولها',
                    'اضغط ▶ تشغيل — ماندالا مذهلة! أضف 🕺 رقص للاحتفال بفنك'
                ]
            }
        };
        // AR_CH: lesson id -> { title, desc, obj: { objectiveId: label } }
        var AR_CH = {
            'lesson-4': {
                title: 'ارسم المربع الملوّن! 🟥🟦🟩🟪',
                desc: 'ارسم مربعًا كل ضلع فيه بلون مختلف. استخدم مكعبات اللون + الحجم ودُر 90° بين كل ضلع!',
                obj: {
                    'colors': '🎨 استخدم لونين مختلفين أو أكثر',
                    'size': '🖌️ استخدم مكعب لون أو حجم',
                    'shape': '⬜ ارسم 4 مقاطع خطية أو أكثر'
                }
            },
            'lesson-5': {
                title: 'ابنِ الدرج! 🪜',
                desc: 'ارسم درجًا يصعد ويميل يمينًا باستخدام حلقة تكرار. الكود: كرّر 4 ← للأمام 2، يمين 90، للأمام 2، يسار 90',
                obj: {
                    'loop': '🔁 استخدم مكعب تكرار',
                    'segments': '🪜 ارسم 8 مقاطع (4 درجات)',
                    'pen': '✏️ استخدم انزال القلم للرسم'
                }
            },
            'lesson-6': {
                title: 'ارسم نجمة الدوران! ⭐',
                desc: 'انسخ نمط النجمة المعروض بخطوط شبحية على اللوح. استخدم 3 ألوان، وارسم أشكالًا رباعية الأضلاع بالحلقات، ودوّرها!',
                obj: {
                    'loop': '🔁 استخدم مكعب تكرار',
                    'segments': '✏️ ارسم 12 مقطعًا خطيًا أو أكثر',
                    'turns': '📐 استخدم دورانات يمين أو يسار'
                }
            },
            'lesson-7': {
                title: 'ارسم نجمة ثمانية! ✨',
                desc: 'استخدم حلقة تكرار 8 وزاوية النجمة السرية (135°) لرسم نجمة ثمانية جميلة!',
                obj: {
                    'loop': '🔁 استخدم مكعب تكرار',
                    'angle': '↪️ استخدم دورانًا كبيرًا (90° أو أكثر)',
                    'segments': '✨ ارسم 8 خطوط نجمة'
                }
            },
            'lesson-8': {
                title: 'اجمع كل القطع المعدنية الثلاث!',
                desc: 'فعّل مغناطيسك وتنقّل لالتقاط كل جسم معدني على اللوح.',
                obj: {
                    'metal-1': '🔩 الخطوة 1: التقط المعدن رقم 1',
                    'metal-2': '🔩 الخطوة 2: التقط المعدن رقم 2',
                    'metal-3': '🔩 الخطوة 3: التقط المعدن رقم 3',
                    'go-home': '🏠 الخطوة 4: عُد إلى البيت وأطفئ المغناطيس'
                }
            },
            'lesson-9': {
                title: 'ممر الموجات فوق الصوتية — استشعر وقرّر ودُر!',
                desc: 'استخدم حلقة تكرار تحتوي على شرط: إذا كان الجدار ضمن خطوة واحدة، فاستجب له بالدوران. يجب أن يستشعر ستيمو الجدارين ويتفاعل معهما قبل الوصول إلى الهدف. المسح للأمام أداة صحيحة إضافية، لكن تُقبل أيضًا البرامج المكافئة التي تستخدم شرط الجدار. لا تُقبل اختصارات التنقل الذكي أو الذهاب إلى الهدف أو الحركة التلقائية.',
                obj: {
                    'sensor-logic': '📡 استخدم شرط الجدار مرتين داخل حلقة تكرار',
                    'reach': '🎯 تنقّل عبر الجدارين وصِل إلى الهدف!'
                }
            },
            'lesson-10': {
                title: 'صِل إلى نقطة الهدف!',
                desc: 'العوائق في طريقك. برمِج ستيمو للتنقّل حولها والوصول إلى الهدف.',
                obj: {
                    'reach': '🎯 صِل إلى الهدف'
                }
            },
            'lesson-11': {
                title: 'اهرب من المتاهة — 3 طرق للفوز!',
                desc: 'متاهة شبكية 3×3 بممرات واسعة ونهايات مسدودة. يمكنك حلّها بثلاث طرق: (1) يدوي: دُر يمينًا، كرّر 7 تحرّك، دُر يسارًا، كرّر 7 تحرّك. (2) إذا جدار: كرّر 25 ← إذا جدار ضمن 2 ← دُر يمينًا، وإلا تحرّك 1. (3) التنقّل الذكي: ضع المكعب ودع الذكاء الاصطناعي يجد أقصر مسار!',
                obj: {
                    'reach': '🎯 تنقّل عبر المتاهة وصِل إلى الهدف!'
                }
            },
            'lesson-12': {
                title: 'اكتشف كلتا النارين بمستشعرك!',
                desc: 'الحرائق مخفية حول اللوح. امسح بمستشعر درجة الحرارة لتحديد موقع كلتيهما.',
                obj: {
                    'detect1': '🌡️ اعثر على النار 1',
                    'detect2': '🌡️ اعثر على النار 2'
                }
            },
            'lesson-13': {
                title: 'أطفئ كل النيران الثلاث!',
                desc: 'تنقّل حول الجدران ورُش الماء على كل نار قبل أن ينفد خزانك!',
                obj: {
                    'extinguish': '💧 أطفئ كل النيران'
                }
            },
            'lesson-14': {
                title: 'التحدي النهائي!',
                desc: 'اجمع المعادن، وأطفئ النيران، وصِل إلى الهدف. استخدم كل ما تعلّمته!',
                obj: {
                    'metal': '🔩 اجمع معدنًا واحدًا أو أكثر',
                    'fire': '💧 أطفئ النيران',
                    'reach': '🎯 صِل إلى الهدف'
                }
            },
            'lesson-15': {
                title: 'خزنة المتغيّرات — غيّر رقمًا واحدًا يتغيّر كل شيء!',
                desc: '1️⃣ انزال القلم  2️⃣ كرّر [متغيّر: العدد] مرة ← تحرّك [متغيّر: السرعة] خطوات + دُر [متغيّر: الزاوية] درجات  3️⃣ شغّل! المتغيّرات السرعة=4، العدد=4، الزاوية=90 مضبوطة لك مسبقًا.',
                obj: {
                    'moved': '📦 استخدم متغيّرًا لتحريك ستيمو (طول الأثر أكبر من 200 بكسل)',
                    'closed': '🔁 ارسم شكلًا مغلقًا (عُد إلى ضمن 80 بكسل من البداية)'
                }
            },
            'lesson-16': {
                title: 'ذاكرة الموقع — احفظ مكانك وعُد إلى البيت!',
                desc: 'استخدم احفظ الموقع A في البداية. تنقّل إلى الهدف. ثم اذهب إلى الموقع A للعودة. مثل ضبط نقطة بيت في GPS!',
                obj: {
                    'target': '🎯 صِل إلى الهدف',
                    'home': '🏠 عُد إلى البداية (ضمن 60 بكسل)'
                }
            },
            'lesson-17': {
                title: 'مسار نقاط الطريق — سجّل مسارًا، أعد تشغيله تلقائيًا!',
                desc: 'ثلاث قطع معدنية تنتظر. قائمة نقاط الطريق محمّلة مسبقًا بمواقعها. شغّل المغناطيس، ثم أعد تشغيل المسار لزيارة الثلاث وجمعها كلها!',
                obj: {
                    'metals': '🔩 اجمع كل القطع المعدنية الثلاث باستخدام أعد تشغيل المسار'
                }
            },
            'lesson-18': {
                title: 'صيد القوائم — كرّر عبر قائمة ونفّذ على كل عنصر!',
                desc: '3 نيران محمّلة مسبقًا في قائمة نقاط الطريق. استخدم لكل نقطة طريق مع رُش الماء فقط داخل مكعب النفّذ — المكعب يتنقّل إلى كل نار تلقائيًا. لا تضف مكعبات اذهب إلى الموقع داخل الحلقة!',
                obj: {
                    'fires': '💧 أطفئ كل النيران الثلاث باستخدام لكل نقطة طريق'
                }
            },
            'lesson-19': {
                title: 'مصنع الدوال — اكتب مرة، استدعِ إلى الأبد!',
                desc: 'طابق النجمة الباهتة على اللوح!  1️⃣ عرّف drawSquare: انزال القلم ← كرّر 4× (تحرّك 3 خطوات، دُر يمينًا 90°)  2️⃣ عرّف bigSquare: كرّر 4× (استدعِ drawSquare، دُر يمينًا 90°)  3️⃣ استدعِ bigSquare ← دُر يمينًا 45° ← استدعِ bigSquare',
                obj: {
                    'funcs': '🔧 عرّف دالتين على الأقل',
                    'pattern': '🌟 ارسم نمط النجمة (طابق الدليل الشبحي)'
                }
            },
            'lesson-art-1': {
                title: 'أدِر حلزون قوس قزح! 🌀',
                desc: 'طابق الحلزون الباهت على اللوح. استخدم مكعب لون + حلقة تكرار (جرّب كرّر 30 ← للأمام 1، يمين 25). أضف مكعب مشاعر أو رقص للاحتفال!',
                obj: {
                    'loop': '🔁 استخدم مكعب تكرار',
                    'color': '🎨 استخدم مكعب لون',
                    'spiral': '🌀 ارسم 15 مقطعًا خطيًا أو أكثر'
                }
            },
            'lesson-art-2': {
                title: 'ارسم قوس قزح! 🌈',
                desc: 'طابق أقواس قوس قزح الباهتة. استخدم 3 مكعبات لون مختلفة أو أكثر وحلقة تكرار لثني كل شريط (جرّب كرّر 18 ← للأمام 1، يمين 10).',
                obj: {
                    'colors': '🎨 استخدم 3 ألوان مختلفة أو أكثر',
                    'loop': '🔁 استخدم مكعب تكرار',
                    'bands': '🌈 ارسم 18 مقطعًا خطيًا أو أكثر'
                }
            },
            'lesson-art-3': {
                title: 'وقّع باسمك! ✍️',
                desc: 'وجّه ستيمو مثل قلم لرسم الحرف الأول من اسمك. استخدم انزال القلم للرسم ورفع القلم للقفز بين الضربات. أنهِ بمكعب مشاعر أو قُل أو صوت!',
                obj: {
                    'penup': '✏️ استخدم رفع القلم للرفع بين الضربات',
                    'strokes': '✍️ ارسم 3 مقاطع خطية أو أكثر',
                    'flair': '😎 أضف مكعب مشاعر أو قُل أو صوت'
                }
            },
            'lesson-art-4': {
                title: 'أنشئ ماندالا سحرية! ❄️',
                desc: 'طابق الماندالا الباهتة. ضع حلقة تكرار داخل حلقة تكرار أخرى: الداخلية ترسم شكلًا، والخارجية تدوّره حولها (جرّب خارجية كرّر 12 ← داخلية كرّر 4 ← للأمام 3، يمين 90 ← ثم يمين 30).',
                obj: {
                    'nested': '🔁 استخدم مكعبَي تكرار (حلقة داخل حلقة)',
                    'color': '🎨 استخدم مكعب لون',
                    'mandala': '❄️ ارسم 16 مقطعًا خطيًا أو أكثر'
                }
            }
        };
        // AR_BADGES: badge id -> { n, d }
        var AR_BADGES = {
            'first-steps':   { n: 'الخطوات الأولى',        d: 'أكمل درسك الأول' },
            'fast-starter':  { n: 'بداية سريعة',           d: 'اكسب 100 نقطة خبرة' },
            'mover':         { n: 'محرّك الروبوت',         d: 'حرّك ستيمو 100 مرة' },
            'bronze-coder':  { n: 'مبرمج برونزي',          d: 'اكسب 250 نقطة خبرة' },
            'artist':        { n: 'فنان البرمجة',          d: 'ارسم 10 أشكال' },
            'loop-master':   { n: 'سيّد الحلقات',          d: 'استخدم الحلقات 20 مرة' },
            'star-coder':    { n: 'مبرمج النجوم',          d: 'اكسب 1000 نقطة خبرة' },
            'robot-friend':  { n: 'أعز أصدقاء الروبوت',    d: 'تحدّث مع ستيمو 50 مرة' },
            'silver-coder':  { n: 'مبرمج فضي',             d: 'اكسب 2000 نقطة خبرة' },
            'gold-coder':    { n: 'مبرمج ذهبي',            d: 'اكسب 3500 نقطة خبرة' },
            'diamond-coder': { n: 'مبرمج ماسي',            d: 'اكسب 5000 نقطة خبرة' },
            'quick-learner': { n: 'متعلّم سريع',           d: 'أكمل 3 دروس' },
            'halfway-hero':  { n: 'بطل منتصف الطريق',      d: 'أكمل 10 دروس' },
            'completionist': { n: 'مُنجِز الكل',           d: 'أكمل كل الدروس الـ19' },
            'on-fire':       { n: 'مشتعل',                 d: 'سلسلة برمجة 3 أيام' },
            'unstoppable':   { n: 'لا يُوقَف',             d: 'سلسلة برمجة 7 أيام' },
            'rising-star':   { n: 'نجم صاعد',              d: 'اوصل إلى المستوى 3' },
            'coding-hero':   { n: 'بطل البرمجة',           d: 'اوصل إلى المستوى 5' },
            'legend':        { n: 'أسطورة',               d: 'اوصل إلى المستوى 10' },
            'grandmaster':   { n: 'المعلّم الأكبر',        d: 'اوصل إلى المستوى 13' }
        };
        var DIFF_AR = { easy: 'سهل', medium: 'متوسط', hard: 'صعب', extreme: 'خبير', creative: 'إبداعي' };
        function trL(lesson, field) {
            if (currentLang === 'ar' && lesson && AR_L[lesson.id]) {
                var a = AR_L[lesson.id];
                var map = { title: 't', description: 'd', introduction: 'i', hint: 'hint', homework: 'hw' };
                var v = a[map[field] || field];
                if (v) return v;
            }
            return lesson ? lesson[field] : '';
        }
        function trTask(lesson, index, text) {
            if (currentLang === 'ar' && lesson && AR_L[lesson.id] && AR_L[lesson.id].tasks && AR_L[lesson.id].tasks[index]) {
                return AR_L[lesson.id].tasks[index];
            }
            return text;
        }
        function trDiff(d) {
            if (currentLang === 'ar' && DIFF_AR[d]) return DIFF_AR[d];
            return d;
        }
        function trBadge(badge, field) {
            if (currentLang === 'ar' && badge && AR_BADGES[badge.id]) {
                var v = AR_BADGES[badge.id][field === 'name' ? 'n' : 'd'];
                if (v) return v;
            }
            return badge ? badge[field] : '';
        }
        function trChTitle(lessonId, fallback) {
            if (currentLang === 'ar' && AR_CH[lessonId] && AR_CH[lessonId].title) return AR_CH[lessonId].title;
            return fallback;
        }
        function trChDesc(lessonId, fallback) {
            if (currentLang === 'ar' && AR_CH[lessonId] && AR_CH[lessonId].desc) return AR_CH[lessonId].desc;
            return fallback;
        }
        function trObj(lessonId, objId, fallback) {
            if (currentLang === 'ar' && AR_CH[lessonId] && AR_CH[lessonId].obj && AR_CH[lessonId].obj[objId]) return AR_CH[lessonId].obj[objId];
            return fallback;
        }

        function applyLanguage(lang) {
            var dict = I18N[lang] || I18N.en;
            var nodes = document.querySelectorAll('[data-i18n]');
            for (var i = 0; i < nodes.length; i++) {
                var key = nodes[i].getAttribute('data-i18n');
                if (dict[key] !== undefined) nodes[i].textContent = dict[key];
                else if (I18N.en[key] !== undefined) nodes[i].textContent = I18N.en[key];
            }
            // Translate block palette items and category headers (Arabic <-> English)
            var pal = document.getElementById('blockPalette');
            if (pal) {
                var els = pal.querySelectorAll('.block-item, div.uppercase');
                for (var j = 0; j < els.length; j++) {
                    var el = els[j];
                    if (el.hasAttribute('data-i18n')) continue;
                    if (!el.getAttribute('data-en')) el.setAttribute('data-en', el.textContent.trim());
                    var en = el.getAttribute('data-en');
                    el.textContent = (lang === 'ar' && PALETTE_AR[en]) ? PALETTE_AR[en] : en;
                }
            }
            document.documentElement.setAttribute('dir', lang === 'ar' ? 'rtl' : 'ltr');
            document.documentElement.setAttribute('lang', lang);
            var sel = document.getElementById('langSelect');
            if (sel) sel.value = lang;
        }
        function refreshWorkspaceBlocks() {
            // Re-render existing Blockly blocks so their labels use the new language
            try {
                if (typeof workspace !== 'undefined' && workspace) {
                    var xml = Blockly.Xml.workspaceToDom(workspace);
                    workspace.clear();
                    Blockly.Xml.domToWorkspace(xml, workspace);
                }
            } catch(e) { console.log('block refresh skipped', e); }
        }
        function setLanguage(lang) {
            currentLang = lang;
            safeStorageSet('stemoLang', lang);
            applyLanguage(lang);
            // Re-render dynamic content in the new language
            try { loadLessons(); } catch(e) {}
            try { loadBadges(); } catch(e) {}
            try { if (typeof currentLesson !== 'undefined' && currentLesson && document.getElementById('lessonDetailPanel') && !document.getElementById('lessonDetailPanel').classList.contains('hidden')) { showLessonDetail(currentLesson); } } catch(e) {}
            refreshWorkspaceBlocks();
            playSound('click');
        }
        document.addEventListener('DOMContentLoaded', function() {
            applyLanguage(currentLang);
            updateStartPointUI();
        });

        // STEMO start point — choose center (home) or left edge; moves STEMO there and persists
        function setStartPoint(name) {
            stemoStartName = (name === 'left') ? 'left' : 'center';
            safeStorageSet('stemoStartPoint', stemoStartName);
            updateStartPointUI();
            resetRobot();
            playSound('click');
        }
        function updateStartPointUI() {
            var c = document.getElementById('startCenterBtn');
            var l = document.getElementById('startLeftBtn');
            if (!c || !l) return;
            var active = 'bg-teal-500 hover:bg-teal-600 text-white px-2 py-1 rounded-full font-bold transition-all text-xs';
            var idle = 'bg-gray-300 hover:bg-gray-400 text-gray-700 px-2 py-1 rounded-full font-bold transition-all text-xs';
            if (stemoStartName === 'left') { l.className = active; c.className = idle; }
            else { c.className = active; l.className = idle; }
        }

        // STEMO body color customization (persisted)
        function openStemoColor() {
            var inp = document.getElementById('stemoColorInput');
            if (inp) { inp.value = stemoBodyColor; inp.click(); }
        }
        function setStemoColor(color) {
            stemoBodyColor = color || '#3b82f6';
            safeStorageSet('stemoBodyColor', stemoBodyColor);
            var inp = document.getElementById('stemoColorInput');
            if (inp) inp.value = stemoBodyColor;
            drawRobot();
            playSound('pop');
            addChatMessage('stemo', "🤖 New look! Thanks for the makeover! 🎨");
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

        function undoCode() {
            if (workspace) {
                workspace.undo(false);
            }
        }

        function toggleGroupSelect() {
            groupSelectMode = !groupSelectMode;
            var btn = document.getElementById('groupSelectBtn');
            if (groupSelectMode) {
                btn.textContent = '✖ Exit Select';
                btn.classList.remove('bg-purple-500','hover:bg-purple-600');
                btn.classList.add('bg-amber-500','hover:bg-amber-600');
                addChatMessage('stemo', '🤖 Group Select ON! Click blocks to add them to your group, then press 🗑️ Delete to remove them all.');
            } else {
                btn.textContent = '🔲 Select Group';
                btn.classList.add('bg-purple-500','hover:bg-purple-600');
                btn.classList.remove('bg-amber-500','hover:bg-amber-600');
                groupSelectedBlocks = [];
                highlightGroupBlocks();
                updateGroupDeleteBtn();
            }
        }

        function highlightGroupBlocks() {
            if (!workspace) return;
            workspace.getAllBlocks(false).forEach(function(block) {
                var svg = block.getSvgRoot ? block.getSvgRoot() : null;
                if (!svg) return;
                if (groupSelectedBlocks.indexOf(block.id) >= 0) {
                    svg.style.filter = 'drop-shadow(0 0 6px #f59e0b) drop-shadow(0 0 3px #f59e0b)';
                    svg.style.opacity = '1';
                } else {
                    svg.style.filter = groupSelectMode ? 'opacity(0.5)' : '';
                    svg.style.opacity = '';
                }
            });
        }

        function updateGroupDeleteBtn() {
            var btn = document.getElementById('deleteGroupBtn');
            var span = document.getElementById('groupCountSpan');
            if (!btn || !span) return;
            if (groupSelectedBlocks.length > 0) {
                btn.style.display = '';
                span.textContent = groupSelectedBlocks.length;
            } else {
                btn.style.display = 'none';
            }
        }

        function deleteGroupSelected() {
            if (!workspace || groupSelectedBlocks.length === 0) return;
            var count = groupSelectedBlocks.length;
            groupSelectedBlocks.forEach(function(id) {
                var block = workspace.getBlockById(id);
                if (block && !block.disposed) block.dispose(true);
            });
            groupSelectedBlocks = [];
            groupSelectMode = false;
            highlightGroupBlocks();
            updateGroupDeleteBtn();
            var btn = document.getElementById('groupSelectBtn');
            if (btn) {
                btn.textContent = '🔲 Select Group';
                btn.classList.add('bg-purple-500','hover:bg-purple-600');
                btn.classList.remove('bg-amber-500','hover:bg-amber-600');
            }
            addChatMessage('stemo', '🤖 Deleted ' + count + ' block(s)! ');
        }

        function deleteSelectedBlock() {
            if (!workspace) return;
            // Use event-tracked selection (most reliable), fall back to Blockly APIs
            var selected = lastSelectedBlock;
            if (!selected || selected.disposed) {
                selected = (Blockly.getSelected ? Blockly.getSelected() : null) || Blockly.selected || null;
            }
            if (!selected || selected.disposed) {
                addChatMessage('stemo', '🤖 Click a block first to select it (it will highlight), then press Delete Block!');
                return;
            }
            selected.dispose(true);
            lastSelectedBlock = null;
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
            
            // Free build: award base XP as soon as the robot moves or draws anything
            var robotMoved = robot.x !== 200 || robot.y !== 200 || robot.angle !== -90;
            var robotDrew = robot.trails.length > 0;
            
            if (robotMoved || robotDrew) {
                var alreadyComplete = isTeacherDemo
                    ? teacherPreviewCompletedLessons.indexOf(currentLesson.id) !== -1
                    : stemo.completedLessons.includes(currentLesson.id);
                if (!alreadyComplete) {
                    completeLesson(currentLesson);
                    // Encourage challenge mode for mission lessons
                    if (!isTeacherDemo && MISSION_LESSON_IDS.indexOf(currentLesson.id) !== -1) {
                        setTimeout(function() {
                            addChatMessage('stemo', '🏆 Nice work! You earned base XP. Want to earn <b>2× bonus XP</b>? Try <b>Challenge Mode</b> to complete the real mission!');
                        }, 2000);
                    }
                }
            }
        }

        function completeLesson(lesson) {
            if (isTeacherDemo) {
                teacherPreviewCompletedLessons.push(lesson.id);
                showSuccessModal(0, false, computeStars(lesson));
                return;
            }
            stemo.completedLessons.push(lesson.id);
            stemo.xp += lesson.xpReward;
            
            var newLevel = Math.floor(stemo.xp / 500) + 1;
            if (newLevel > stemo.level) {
                stemo.level = newLevel;
            }
            
            var stars = computeStars(lesson);
            setStars(lesson.id, stars);

            saveProgress();
            updateUI();
            loadLessons();
            loadBadges();
            
            showSuccessModal(lesson.xpReward, false, stars);
        }

        // Completes a lesson via challenge mode: awards base XP (if not yet earned) + 2× challenge bonus
        function completeChallengeLesson(lesson) {
            if (isTeacherDemo) {
                showSuccessModal(0, true, 3);
                return;
            }
            var totalXp = 0;
            // Award base lesson XP if the student hasn't done free build yet
            if (!stemo.completedLessons.includes(lesson.id)) {
                stemo.completedLessons.push(lesson.id);
                stemo.xp += lesson.xpReward;
                totalXp += lesson.xpReward;
            }
            // Award challenge bonus (2× base) if not already earned
            var challengeId = lesson.id + '-challenge';
            var bonusXp = lesson.xpReward * 2;
            if (!stemo.completedLessons.includes(challengeId)) {
                stemo.completedLessons.push(challengeId);
                stemo.xp += bonusXp;
                totalXp += bonusXp;
            }

            var newLevel = Math.floor(stemo.xp / 500) + 1;
            if (newLevel > stemo.level) {
                stemo.level = newLevel;
            }

            setStars(lesson.id, 3);

            saveProgress();
            updateUI();
            loadLessons();
            loadBadges();

            showSuccessModal(totalXp, true, 3);
        }

        function showSuccessModal(xp, isChallenge, stars) {
            var modal = document.getElementById('successModal');
            var content = document.getElementById('successModalContent');
            // Star rating display
            var starWrap = document.getElementById('starRating');
            if (starWrap) {
                if (stars && stars > 0) {
                    document.getElementById('starRow').textContent = starString(stars);
                    var labels = { 1: 'Nice — 1 star! Try using fewer blocks ✨', 2: 'Great — 2 stars! Almost perfect 🌟', 3: 'Perfect — 3 stars! 🏆' };
                    document.getElementById('starLabel').textContent = labels[stars] || '';
                    starWrap.classList.remove('hidden');
                } else {
                    starWrap.classList.add('hidden');
                }
            }
            var nextBtn = document.getElementById('nextLessonBtn');

            var xpBanner = document.getElementById('xpBanner');
            // Teacher preview has no XP panel or reward message.
            if (isTeacherDemo) {
                xpBanner.classList.add('hidden');
            // XP banner: show points for first completion, "Already completed" for replays
            } else if (xp > 0) {
                xpBanner.classList.remove('hidden');
                document.getElementById('xpBannerLabel').textContent = isChallenge ? '🏆 Challenge Bonus!' : 'You earned';
                document.getElementById('xpEarned').textContent = '+' + xp + ' XP';
                xpBanner.className = isChallenge
                    ? 'bg-gradient-to-r from-purple-500 to-indigo-600 rounded-2xl p-4 mb-6'
                    : 'bg-gradient-to-r from-yellow-400 to-amber-500 rounded-2xl p-4 mb-6';
            } else {
                xpBanner.classList.remove('hidden');
                document.getElementById('xpBannerLabel').textContent = isChallenge ? 'Challenge Complete! 🏆' : 'Great practice!';
                document.getElementById('xpEarned').textContent = 'Already completed ✓';
                xpBanner.className = 'bg-gradient-to-r from-gray-400 to-gray-500 rounded-2xl p-4 mb-6';
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
        // ============================================
        // HTML ESCAPE HELPER — prevents XSS in innerHTML
        // ============================================
        function escHtml(str) {
            if (str === null || str === undefined) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

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
            // Escape before injecting into innerHTML
            var safeCmd = escHtml(cmd);
            // Log the outgoing order in the CC terminal
            addCommandCenterMessage(['<span style="color:#38bdf8">⬆ ORDER SENT:</span> <span style="color:#fbbf24">"' + safeCmd + '"</span>']);
            // Mirror to STEMO chat for acknowledgement
            setTimeout(function() {
                addChatMessage('stemo', '📡 Command Center: "' + safeCmd + '" — message received! Direct command execution is coming soon.');
            }, 300);
        }

        function addChatMessage(sender, message) {
            var container = document.getElementById('chatMessages');
            var div = document.createElement('div');
            div.className = 'flex items-start gap-2';
            // User messages are plain text — escape to prevent XSS
            // AI/stemo responses are trusted structured text — also escaped for safety
            var safeMsg = escHtml(message);
            if (sender === 'stemo') {
                div.innerHTML = '<span class="text-2xl">🤖</span><div class="chat-bubble bg-blue-100 text-sm">' + safeMsg + '</div>';
            } else {
                div.innerHTML = '<div class="chat-bubble bg-indigo-100 text-sm ml-auto">' + safeMsg + '</div><span class="text-2xl">👦</span>';
            }
            
            container.appendChild(div);
            container.scrollTop = container.scrollHeight;
        }

        // ============================================
        // TAB NAVIGATION
        // ============================================
        function switchTab(tab) {
            ['learn','code','achievements','profile','leaderboard','videos','interactive'].forEach(function(t) {
                document.getElementById(t + '-section').classList.add('hidden');
                document.getElementById('tab-' + t).className = 'tab-inactive px-5 py-2 rounded-full font-bold transition-all text-sm';
            });
            document.getElementById(tab + '-section').classList.remove('hidden');
            document.getElementById('tab-' + tab).className = 'tab-active px-5 py-2 rounded-full font-bold transition-all text-sm';
            if (tab === 'code' && workspace) {
                setTimeout(function() { Blockly.svgResize(workspace); }, 100);
            }
            if (tab === 'leaderboard') switchLbTab('class');
            if (tab === 'videos') loadStudentVideos();
            if (tab === 'interactive') loadInteractiveLessons();
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
                            document.getElementById('profileLessonTitle').textContent = trL(lessonData, 'title');
                            document.getElementById('profileLessonBanner').classList.remove('hidden');
                            // Learn tab banner
                            document.getElementById('assignedLessonBannerIcon').textContent = lessonData.icon || '📖';
                            document.getElementById('assignedLessonBannerTitle').textContent = trL(lessonData, 'title');
                            document.getElementById('assignedLessonBannerDesc').textContent = trL(lessonData, 'description') || '';
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
                // Ranks
                loadProfileRanks();
                // Badges showcase
                fetch('/api/badges').then(r => r.json()).then(renderProfileBadges).catch(function(){});
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

        async function loadProfileRanks() {
            try {
                const r = await fetch('/api/student/rank').then(res => res.json());
                if (r.error) return;
                // Class rank
                if (r.class) {
                    document.getElementById('rankClass').textContent = '#' + r.class.rank;
                    document.getElementById('rankClassOf').textContent = 'of ' + r.class.total + ' students';
                } else {
                    document.getElementById('rankClass').textContent = 'N/A';
                    document.getElementById('rankClassOf').textContent = 'Not in a class';
                }
                // School rank
                if (r.school) {
                    document.getElementById('rankSchool').textContent = '#' + r.school.rank;
                    document.getElementById('rankSchoolOf').textContent = 'of ' + r.school.total + ' students';
                } else {
                    document.getElementById('rankSchool').textContent = 'N/A';
                    document.getElementById('rankSchoolOf').textContent = 'No school assigned';
                }
                // Platform rank
                document.getElementById('rankPlatform').textContent = '#' + r.platform.rank;
                document.getElementById('rankPlatformOf').textContent = 'of ' + r.platform.total + ' students';
            } catch(e) {}
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
        // ── Student Video Training ───────────────────────────────────────────────
        function ytEmbedUrl(url) {
            try {
                var u = new URL(url);
                var vid = u.hostname === 'youtu.be' ? u.pathname.slice(1) : (u.searchParams.get('v') || '');
                return vid ? 'https://www.youtube.com/embed/' + vid : url;
            } catch(e) { return url; }
        }

        function ytThumb(url) {
            try {
                var u = new URL(url);
                var vid = u.hostname === 'youtu.be' ? u.pathname.slice(1) : (u.searchParams.get('v') || '');
                return vid ? 'https://img.youtube.com/vi/' + vid + '/mqdefault.jpg' : '';
            } catch(e) { return ''; }
        }

        function playStudentVideo(embedUrl, title) {
            document.getElementById('videoFrame').src = embedUrl + '?autoplay=1';
            document.getElementById('videoPlayer').classList.remove('hidden');
            document.getElementById('videoPlayer').scrollIntoView({behavior:'smooth'});
        }

        async function loadStudentVideos() {
            const list = document.getElementById('videoList');
            list.innerHTML = '<div class="text-gray-400 text-center py-12 col-span-3"><i class="fas fa-spinner fa-spin text-3xl mb-2 block"></i>Loading videos...</div>';
            try {
                const videos = await fetch('/api/videos').then(r => r.json());
                if (!Array.isArray(videos) || !videos.length) {
                    list.innerHTML = '<div class="text-gray-400 text-center py-12 col-span-3"><i class="fas fa-video text-5xl mb-3 block opacity-40"></i><p class="font-semibold">No videos available yet.</p><p class="text-sm mt-1">Check back soon — your teacher is preparing great content!</p></div>';
                    return;
                }
                list.innerHTML = videos.map(v => {
                    var thumb = ytThumb(v.youtube_url);
                    var embed = ytEmbedUrl(v.youtube_url);
                    var thumbHtml = thumb
                        ? '<img src="' + thumb + '" class="w-full object-cover rounded-xl mb-3" style="aspect-ratio:16/9;" onerror="this.remove()">'
                        : '<div class="w-full bg-gradient-to-br from-red-400 to-red-600 rounded-xl mb-3 flex items-center justify-center text-white text-4xl" style="aspect-ratio:16/9;"><i class="fas fa-play-circle"></i></div>';
                    return \`<div class="bg-gray-50 border border-gray-200 rounded-2xl p-4 hover:shadow-md transition-all cursor-pointer group" onclick="playStudentVideo('\${embed}')">
                        \${thumbHtml}
                        <div class="flex items-start gap-2">
                            <div class="bg-red-500 text-white rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0 mt-0.5 group-hover:scale-110 transition-transform">
                                <i class="fas fa-play text-xs"></i>
                            </div>
                            <div>
                                <p class="font-bold text-gray-800 text-sm leading-tight">\${v.lesson_name}</p>
                                <p class="text-gray-400 text-xs mt-1">Click to watch</p>
                            </div>
                        </div>
                    </div>\`;
                }).join('');
            } catch(e) {
                list.innerHTML = '<div class="text-red-400 text-center py-8 col-span-3">⚠️ Could not load videos. Please try again.</div>';
            }
        }
        // ────────────────────────────────────────────────────────────────────────

        // ── Student Interactive HTML Lessons ────────────────────────────────────
        function interactiveText(key) {
            var dict = I18N[currentLang] || I18N.en;
            return dict[key] || I18N.en[key] || key;
        }

        function escapeInteractiveTitle(value) {
            return String(value || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        function openInteractiveLesson(id, lessonNumber) {
            var target = Number(lessonNumber) > 0 ? '/interactive-lessons/lesson/' + Number(lessonNumber) : '/interactive-lessons/' + id;
            window.open(target, '_blank', 'noopener');
        }

        async function loadInteractiveLessons() {
            var list = document.getElementById('interactiveLessonList');
            list.innerHTML = '<div class="text-gray-400 text-center py-12 col-span-3"><i class="fas fa-spinner fa-spin text-3xl mb-2 block"></i>' + interactiveText('interactive_loading') + '</div>';
            try {
                var lessons = await fetch('/api/interactive-lessons').then(function(r) { return r.json(); });
                if (!Array.isArray(lessons) || !lessons.length) {
                    list.innerHTML = '<div class="text-gray-400 text-center py-12 col-span-3"><i class="fas fa-laptop-code text-5xl mb-3 block opacity-40"></i><p class="font-semibold">' + interactiveText('interactive_empty') + '</p></div>';
                    return;
                }
                list.innerHTML = lessons.map(function(lesson) {
                    var id = Number(lesson.id);
                    var lessonNumber = Number(lesson.lesson_number);
                    return '<div class="bg-gradient-to-br from-purple-50 to-indigo-50 border border-purple-100 rounded-2xl p-5 hover:shadow-md transition-all">' +
                        '<div class="w-12 h-12 bg-purple-500 text-white rounded-xl flex items-center justify-center text-xl mb-4"><i class="fas fa-laptop-code"></i></div>' +
                        '<h4 class="font-bold text-gray-800">' + escapeInteractiveTitle(lesson.title) + '</h4>' +
                        '<p class="text-gray-500 text-sm mt-1 mb-1">HTML interactive activity</p>' +
                        (lessonNumber > 0 ? '<p class="text-purple-600 text-xs font-bold mb-3">Lesson ' + lessonNumber + '</p>' : '<div class="mb-3"></div>') +
                        '<button onclick="openInteractiveLesson(' + id + ',' + lessonNumber + ')" class="w-full bg-purple-600 hover:bg-purple-700 text-white py-2.5 rounded-xl font-bold text-sm transition-all"><i class="fas fa-play mr-1"></i> ' + interactiveText('interactive_open') + '</button>' +
                    '</div>';
                }).join('');
            } catch(e) {
                list.innerHTML = '<div class="text-red-400 text-center py-8 col-span-3">⚠️ Could not load interactive lessons. Please try again.</div>';
            }
        }
        // ────────────────────────────────────────────────────────────────────────

        var currentLbTab = 'class';
        var currentLbPage = 1;
        var currentLbPageSize = 30;

        function hideLeaderboardPagination() {
            var pagination = document.getElementById('leaderboardPagination');
            if (pagination) pagination.classList.add('hidden');
        }

        function changeLeaderboardPage(direction) {
            currentLbPage = Math.max(1, currentLbPage + direction);
            loadLeaderboard();
        }

        function changeLeaderboardPageSize(value) {
            var size = parseInt(value, 10);
            currentLbPageSize = size === 50 ? 50 : 30;
            currentLbPage = 1;
            loadLeaderboard();
        }

        function switchLbTab(tab) {
            currentLbTab = tab;
            currentLbPage = 1;
            ['class','school','platform'].forEach(function(t) {
                var btn = document.getElementById('lb-tab-' + t);
                if (!btn) return;
                if (t === tab) {
                    btn.className = 'px-4 py-2 rounded-xl font-bold text-sm transition-all bg-white shadow text-indigo-700';
                } else {
                    btn.className = 'px-4 py-2 rounded-xl font-bold text-sm transition-all text-gray-500 hover:text-gray-700';
                }
            });
            var titles = { class: 'Class Leaderboard', school: 'School Leaderboard', platform: 'Platform Leaderboard' };
            var titleEl = document.getElementById('lbTitleText');
            if (titleEl) titleEl.textContent = titles[tab] || 'Leaderboard';
            loadLeaderboard();
        }

        async function loadLeaderboard() {
            document.getElementById('leaderboardList').innerHTML = '<p class="text-center text-gray-400 py-6">Loading...</p>';
            document.getElementById('podiumRow').innerHTML = '';
            hideLeaderboardPagination();
            var tab = currentLbTab || 'class';
            var url = tab === 'class' ? '/api/leaderboard/class'
                    : tab === 'school' ? '/api/leaderboard/school'
                    : '/api/leaderboard';
            url += '?page=' + currentLbPage + '&page_size=' + currentLbPageSize;
            try {
                const data = await fetch(url).then(r => r.json());
                if (data && data.error) {
                    var msg = tab === 'class' ? 'Join a class to see your classmates here! 🎒'
                            : tab === 'school' ? 'No school assigned to your class yet. 🏫'
                            : 'Unable to load leaderboard.';
                    document.getElementById('leaderboardList').innerHTML = '<p class="text-center text-gray-400 py-8">' + msg + '</p>';
                    return;
                }
                var rows = Array.isArray(data) ? data : (Array.isArray(data.results) ? data.results : []);
                var page = Number(data.page) || currentLbPage;
                var pageSize = Number(data.pageSize) || currentLbPageSize;
                var total = Number(data.total) || rows.length;
                var totalPages = Number(data.totalPages) || Math.max(1, Math.ceil(total / pageSize));
                if (page > totalPages && totalPages > 0) {
                    currentLbPage = totalPages;
                    loadLeaderboard();
                    return;
                }
                if (rows.length === 0) {
                    var empty = tab === 'class' ? 'No classmates yet — ask your teacher to add students! 🎒'
                              : tab === 'school' ? 'No school leaderboard yet — your school may not be set up yet. 🏫'
                              : 'No students yet. Be the first! 🚀';
                    document.getElementById('leaderboardList').innerHTML = '<p class="text-center text-gray-400 py-8">' + empty + '</p>';
                    return;
                }
                currentLbPage = page;
                currentLbPageSize = pageSize;
                var pagination = document.getElementById('leaderboardPagination');
                var pageSummary = document.getElementById('leaderboardPageSummary');
                var prevButton = document.getElementById('leaderboardPrev');
                var nextButton = document.getElementById('leaderboardNext');
                var pageSizeSelect = document.getElementById('leaderboardPageSize');
                var firstShown = (page - 1) * pageSize + 1;
                var lastShown = Math.min(page * pageSize, total);
                if (pagination) pagination.classList.remove('hidden');
                if (pageSummary) pageSummary.textContent = 'Showing ' + firstShown + '–' + lastShown + ' of ' + total + ' students · Page ' + page + ' of ' + totalPages;
                if (prevButton) prevButton.disabled = page <= 1;
                if (nextButton) nextButton.disabled = page >= totalPages;
                if (pageSizeSelect) pageSizeSelect.value = String(pageSize);
                const myId = currentUser ? currentUser.id : null;
                const medals = ['🥇','🥈','🥉'];
                const podiumColors = ['from-yellow-400 to-amber-500','from-gray-300 to-gray-400','from-orange-400 to-amber-600'];
                const podiumSizes = ['h-28','h-20','h-16'];

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
                    var safeName = escHtml(s.full_name || s.username);
                    var safeUser = escHtml(s.username);
                    var schoolBit = s.school_name
                        ? '<span class="inline-flex items-center gap-1 bg-purple-100 text-purple-700 text-xs font-semibold px-2 py-0.5 rounded-full">🏫 ' + escHtml(s.school_name) + '</span>'
                        : '';
                    var classBit = s.class_name
                        ? '<span class="inline-flex items-center gap-1 bg-blue-100 text-blue-700 text-xs font-semibold px-2 py-0.5 rounded-full">🎒 ' + escHtml(s.class_name) + '</span>'
                        : '';
                    return '<div class="flex items-center gap-3 p-3 rounded-2xl ' + rowBg + ' transition-all">' +
                        rankBadge +
                        '<div class="w-10 h-10 rounded-full bg-gradient-to-br ' + avatarGrad + ' flex items-center justify-center text-lg font-bold text-white shrink-0">' + escHtml((s.full_name || 'S')[0].toUpperCase()) + '</div>' +
                        '<div class="flex-1 min-w-0">' +
                            '<div class="font-bold text-gray-800 truncate">' + safeName + (isMe ? ' <span class="bg-indigo-500 text-white text-xs px-2 py-0.5 rounded-full ml-1">You</span>' : '') + '</div>' +
                            '<div class="text-gray-400 text-xs mb-1">@' + safeUser + ' · Level ' + (s.level || 1) + '</div>' +
                            '<div class="flex flex-wrap gap-1">' + schoolBit + classBit + '</div>' +
                        '</div>' +
                        '<div class="text-right shrink-0">' +
                            '<div class="font-bold text-yellow-500 text-base">⭐ ' + (s.xp || 0).toLocaleString() + '</div>' +
                            '<div class="text-gray-400 text-xs">' + lessons + '/19 lessons</div>' +
                            '<div class="text-gray-400 text-xs">' + (s.streak || 0) + ' 🔥 streak</div>' +
                        '</div>' +
                    '</div>';
                }

                // Top 3 podium
                var podiumHtml = '';
                var podium = document.getElementById('podiumRow');
                if (page === 1) {
                    [1, 0, 2].forEach(function(idx) {
                        var s = rows[idx];
                        if (!s) return;
                        var isMe = s.id == myId;
                        podiumHtml += '<div class="flex flex-col items-center gap-1 ' + (idx === 0 ? 'order-2' : idx === 1 ? 'order-1' : 'order-3') + '">';
                        podiumHtml += '<div class="text-3xl">' + medals[idx] + '</div>';
                        podiumHtml += '<div class="w-14 h-14 rounded-full bg-gradient-to-br ' + podiumColors[idx] + ' flex items-center justify-center text-2xl font-bold text-white border-4 ' + (isMe ? 'border-indigo-500' : 'border-white') + '">' + escHtml((s.full_name || 'S')[0].toUpperCase()) + '</div>';
                        podiumHtml += '<div class="text-center" style="max-width:6rem">';
                        podiumHtml += '<div class="font-bold text-xs text-gray-800 truncate">' + escHtml(s.full_name || s.username) + (isMe ? ' ★' : '') + '</div>';
                        podiumHtml += '<div class="text-yellow-500 font-bold text-sm">⭐ ' + (s.xp || 0).toLocaleString() + '</div>';
                        if (s.school_name) podiumHtml += '<div class="text-purple-600 text-xs truncate">🏫 ' + escHtml(s.school_name) + '</div>';
                        if (s.class_name)  podiumHtml += '<div class="text-blue-500 text-xs truncate">🎒 ' + escHtml(s.class_name) + '</div>';
                        podiumHtml += '</div>';
                        podiumHtml += '<div class="bg-gradient-to-t ' + podiumColors[idx] + ' rounded-t-xl w-20 ' + podiumSizes[idx] + '"></div>';
                        podiumHtml += '</div>';
                    });
                }
                if (podium) {
                    podium.innerHTML = podiumHtml;
                    podium.classList.toggle('hidden', page !== 1);
                }

                var allRows = rows.map(function(s, i) {
                    var rank = (page - 1) * pageSize + i + 1;
                    return lbRow(s, rank, page === 1 && i < 3);
                }).join('');
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
            var wallAngleControls = document.getElementById('wallAngleControls');
            if (wallAngleControls) {
                wallAngleControls.className = mode === 'wall'
                    ? 'flex items-center gap-1 whitespace-nowrap'
                    : 'hidden items-center gap-1 whitespace-nowrap';
            }

            // Update indicator text
            var posSlot = (document.getElementById('posSlotSelect') || {}).value || 'A';
            var modeText = {
                'metal':    'Click to place: 🔩 Metal  (click again to stop)',
                'wall':     '🧱 Choose H, V, or any angle, then click to place  (click 🧱 again to stop)',
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

        function setWallAngle(value) {
            var parsed = Number(value);
            if (!isFinite(parsed)) parsed = 0;
            wallPlacementAngle = ((parsed % 360) + 360) % 360;
            var input = document.getElementById('wallAngleInput');
            if (input) input.value = String(Math.round(wallPlacementAngle * 100) / 100);
            if (placementMode !== 'wall') setPlacementMode('wall');
            document.getElementById('placementModeText').textContent =
                '🧱 Wall angle: ' + wallPlacementAngle + '° — click the board to place it';
        }
        
        var wallStartPos = null;
        
        function handleCanvasClick(event) {
            var canvas = document.getElementById('robotCanvas');
            var rect = canvas.getBoundingClientRect();
            var x = (event.clientX - rect.left) * (canvas.width / rect.width);
            var y = (event.clientY - rect.top) * (canvas.height / rect.height);
            // Reverse the display-only fit transform used by drawRobot so
            // placement, selection, and saved coordinates remain unchanged.
            var worldViewScale = WORLD_VIEW_SCALE;
            var worldViewOffsetX = (canvas.width - canvas.width * worldViewScale) / 2;
            var worldViewOffsetY = (canvas.height - canvas.height * worldViewScale) / 2;
            x = (x - worldViewOffsetX) / worldViewScale;
            y = (y - worldViewOffsetY) / worldViewScale;
            if (x < 0 || x > canvas.width || y < 0 || y > canvas.height) return;
            
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
                var wcx = w.x + w.width / 2;
                var wcy = w.y + w.height / 2;
                var wrad = -(w.angle || 0) * Math.PI / 180;
                var wcos = Math.cos(wrad);
                var wsin = Math.sin(wrad);
                var localX = (x - wcx) * wcos - (y - wcy) * wsin;
                var localY = (x - wcx) * wsin + (y - wcy) * wcos;
                if (Math.abs(localX) <= w.width / 2 && Math.abs(localY) <= w.height / 2) {
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
            // Manual walls span 6 steps and snap to the one-step grid so adjacent
            // pieces meet cleanly without small gaps.
            var wallWidth = 120;
            var wallHeight = 40;
            var snappedCenterX = 275 + Math.round((x - 275) / 20) * 20;
            var snappedCenterY = 275 + Math.round((y - 275) / 20) * 20;
            var wallRad = wallPlacementAngle * Math.PI / 180;
            var halfBoundsWidth = Math.abs(Math.cos(wallRad)) * wallWidth / 2 + Math.abs(Math.sin(wallRad)) * wallHeight / 2;
            var halfBoundsHeight = Math.abs(Math.sin(wallRad)) * wallWidth / 2 + Math.abs(Math.cos(wallRad)) * wallHeight / 2;
            snappedCenterX = Math.max(15 + halfBoundsWidth, Math.min(535 - halfBoundsWidth, snappedCenterX));
            snappedCenterY = Math.max(15 + halfBoundsHeight, Math.min(535 - halfBoundsHeight, snappedCenterY));
            wallObjects.push({
                id: wallIdCounter++,
                x: snappedCenterX - wallWidth / 2,
                y: snappedCenterY - wallHeight / 2,
                width: wallWidth,
                height: wallHeight,
                angle: wallPlacementAngle
            });
            
            drawRobot();
            addChatMessage('stemo', "🤖 🧱 Long wall placed at " + wallPlacementAngle + "° and snapped to the grid.");
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
            var warningLight = new THREE.PointLight(0xef4444, 0, 90, 2);
            warningLight.position.set(0, 80, 0);
            threeRobot.add(warningLight);

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
                sparkles: sparkles,
                warningLight: warningLight
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
                    var safetyLightActive = Date.now() < safetyAlertUntil;
                    if (safetyLightActive) {
                        ud.antennaBall.material.color.setHex(0xef4444);
                        ud.antennaBall.material.emissive.setHex(0xef4444);
                        ud.antennaBall.material.emissiveIntensity = 1.8 + (Math.sin(time * 12) + 1) * 0.8;
                    } else {
                        ud.antennaBall.material.color.setHex(0xfde047);
                        ud.antennaBall.material.emissive.setHex(0xfacc15);
                        ud.antennaBall.material.emissiveIntensity = 0.6 + (Math.sin(time * 4) + 1) * 0.3;
                    }
                    if (ud.warningLight) {
                        ud.warningLight.position.y = ud.antennaBall.position.y;
                        ud.warningLight.intensity = safetyLightActive
                            ? 2.2 + (Math.sin(time * 12) + 1) * 1.2
                            : 0;
                    }
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
                      // 2D uses clockwise-positive angles because canvas Y points
                      // downward. Negate that angle around Three.js's Y axis so the
                      // 3D wall has exactly the same horizontal/vertical direction.
                      mesh.rotation.y = -(w.angle || 0) * Math.PI / 180;
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
                requestAnimationFrame(resizeRobotWorldStage);
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
            'lesson-13': { id: 'lesson-13', title: 'Firefighter Hero',  description: 'Extinguish all fires before your water runs out!',    hint: 'Spray water only when close to a fire. Watch the tank meter and reset the challenge to try a new route.',           icon: '🚒', xpReward: 500, nextLesson: 'lesson-15' },
            'lesson-14': { id: 'lesson-14', title: 'Master Coder',      description: 'The final challenge — use everything you have learned!', hint: 'Collect metals, extinguish fires, and reach the target. Plan your route carefully!',      icon: '🏆', xpReward: 1000, nextLesson: null },
            'lesson-15': { id: 'lesson-15', title: 'Variable Vault',    description: 'Store values in variables and use them to control STEMO.',  hint: 'Set speed=4, count=4, angle=90. Then: Pen Down → Repeat count → Move speed steps, Turn angle degrees. One number controls everything!', icon: '🔢', xpReward: 400, nextLesson: 'lesson-16' },
            'lesson-16': { id: 'lesson-16', title: 'Position Memory',   description: 'Save your coordinates and navigate back home like GPS.',     hint: 'First block: Save Position A (records start). Navigate to target. Last block: Go to Position A (returns home via shortest path)!',            icon: '📍', xpReward: 450, nextLesson: 'lesson-17' },
            'lesson-17': { id: 'lesson-17', title: 'Waypoint Trail',    description: 'Follow a pre-loaded list of locations to collect metals.',   hint: 'The list is already loaded! Add Magnet ON, then Replay Path — STEMO visits every waypoint in order and picks up metals along the way.',       icon: '🗺️', xpReward: 500, nextLesson: 'lesson-18' },
            'lesson-18': { id: 'lesson-18', title: 'List Hunt',         description: 'Loop through a list of fire targets — AI iteration in action!', hint: 'Use For Each Waypoint → Spray Water. STEMO navigates to each fire location and sprays automatically. This is how AI processes data lists!', icon: '🎯', xpReward: 600, nextLesson: 'lesson-19' },
            'lesson-19': { id: 'lesson-19', title: 'Function Factory', description: 'Write a function once, call it forever — the superpower of every programmer.', hint: 'Define "drawSquare": Pen Down + Repeat 4× (Move 3, Turn Right 90°). Define "bigSquare": Repeat 4× (Call drawSquare + Turn Right 90°). Then: Call bigSquare → Turn Right 45° → Call bigSquare. Star pattern complete!', icon: '🔧', xpReward: 700, nextLesson: 'lesson-14' },
            'lesson-art-1': { id: 'lesson-art-1', title: 'Rainbow Spiral', description: 'Draw a hypnotic spiral that grows as it spins', hint: 'A spiral = Repeat many times → Forward a little + Turn a little. Change the turn angle for tighter or wider spirals!', icon: '🌀', xpReward: 150, nextLesson: 'lesson-art-2' },
            'lesson-art-2': { id: 'lesson-art-2', title: 'Rainbow Maker', description: 'Paint a bright rainbow with every colour of the spectrum', hint: 'Each colour band is the same arc (Repeat → Forward + Turn), just a different Color block before it.', icon: '🌈', xpReward: 150, nextLesson: 'lesson-art-3' },
            'lesson-art-3': { id: 'lesson-art-3', title: 'Write Your Name', description: 'Turn STEMO into a pen and sign your masterpiece', hint: 'Pen Down to draw a stroke, Pen Up to jump to the next stroke. Letters with straight lines (L, T, E, H, I, A) are easiest.', icon: '✍️', xpReward: 200, nextLesson: 'lesson-art-4' },
            'lesson-art-4': { id: 'lesson-art-4', title: 'Magic Mandala', description: 'Create a symmetrical mandala using loops inside loops', hint: 'Loop inside a loop! Outer Repeat = copies around the circle. Inner Repeat = the shape. Extra turn (360 ÷ copies) spins each one.', icon: '❄️', xpReward: 250, nextLesson: null }
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
                            document.getElementById('currentLessonTitle').textContent = trL(lesson, 'title');
                            document.getElementById('currentLessonDesc').textContent = trL(lesson, 'description');
                            var hintEl = document.getElementById('hintText');
                            if (hintEl) hintEl.textContent = trL(lesson, 'hint') || '';
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
                                return { id: obj.id, label: trObj(savedLessonId, obj.id, obj.label), done: false, check: obj.check };
                            });

                            document.getElementById('missionTitle').textContent = trChTitle(savedLessonId, ch.title);
                            var descEl2 = document.getElementById('missionDesc');
                            var chDesc2 = trChDesc(savedLessonId, ch.description);
                            if (descEl2 && chDesc2) { descEl2.textContent = chDesc2; descEl2.style.display = 'block'; }
                            updateMissionHUD();
                            showMissionToast();
                            document.getElementById('missionBadge').classList.remove('hidden');
                            document.getElementById('missionExitBtn').classList.remove('hidden');

                            drawRobot();
                            addChatMessage('stemo', currentLang === 'ar' ? ('📂 تم تحميل التحدي! ' + chDesc2 + ' حظاً موفقاً! 💪') : ('📂 Challenge loaded! ' + ch.description + ' Good luck! 💪'));

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
                if (typeof obj.angle === 'number') key += ',angle:' + obj.angle;
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
            
            var stacked = window.innerWidth < 1024; // tablet/portrait layout stacks panels vertically
            if (robotPanelVisible) {
                panel.style.display = '';
                // Clear inline width so CSS breakpoints control sizing.
                panel.style.width = '';
                panel.classList.remove('overflow-hidden', 'border-l-0');
                panel.classList.add('border-l-2');
                icon.textContent = '🤖';
                text.textContent = 'Hide Robot';
                btn.classList.remove('bg-gray-500');
                btn.classList.add('bg-cyan-500', 'hover:bg-cyan-600');
            } else {
                if (stacked) { panel.style.display = 'none'; } else { panel.style.width = '0'; }
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
                    resizeRobotWorldStage();
                }, 350);
            }
        }

        function resizeRobotWorldStage() {
            var viewport = document.getElementById('robotWorldViewport');
            var stage = document.getElementById('robotWorldStage');
            if (!viewport || !stage || viewport.clientWidth <= 0 || viewport.clientHeight <= 0) return;
            var availableWidth = Math.max(0, viewport.clientWidth - 16);
            var availableHeight = Math.max(0, viewport.clientHeight - 16);
            var size = Math.min(660, availableWidth, availableHeight);
            if (size <= 0) return;
            stage.style.width = size + 'px';
            stage.style.height = size + 'px';

            var threeContainer = document.getElementById('threeCanvasContainer');
            if (renderer && camera && threeContainer && !threeContainer.classList.contains('hidden')) {
                var w = threeContainer.clientWidth;
                var h = threeContainer.clientHeight;
                if (w > 0 && h > 0) {
                    renderer.setSize(w, h);
                    camera.aspect = w / h;
                    camera.updateProjectionMatrix();
                }
            }
        }

        if (typeof ResizeObserver !== 'undefined') {
            var robotWorldResizeObserver = new ResizeObserver(function() {
                resizeRobotWorldStage();
            });
            var robotWorldViewport = document.getElementById('robotWorldViewport');
            if (robotWorldViewport) robotWorldResizeObserver.observe(robotWorldViewport);
        }
        setTimeout(resizeRobotWorldStage, 0);

        // Keep Blockly + robot panel in sync on orientation change / window resize (tablet support)
        var _stemoResizeTimer = null;
        window.addEventListener('resize', function() {
            clearTimeout(_stemoResizeTimer);
            _stemoResizeTimer = setTimeout(function() {
                if (workspace) Blockly.svgResize(workspace);
                var panel = document.getElementById('robotPanel');
                if (panel && robotPanelVisible) {
                    // Clear stale inline sizing when crossing the stacked/side-by-side breakpoint
                    panel.style.display = '';
                    panel.style.width = '';
                }
                resizeRobotWorldStage();
            }, 200);
        });
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
        <button onclick="showTab('videos')" id="tab-videos" class="tab-btn bg-gray-200 text-gray-600 px-5 py-2 rounded-full font-bold text-sm">🎬 Videos</button>
        <button onclick="showTab('interactive')" id="tab-interactive" class="tab-btn bg-gray-200 text-gray-600 px-5 py-2 rounded-full font-bold text-sm">💻 Interactive Lessons</button>
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
    <!-- Videos Tab -->
    <div id="section-videos" class="hidden">
        <div class="bg-white rounded-2xl shadow p-6">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-xl">🎬 Video Training</h2>
                <button onclick="showAddVideoForm()" class="bg-red-500 text-white px-4 py-2 rounded-xl font-bold text-sm hover:bg-red-600">+ Add Video</button>
            </div>
            <!-- Add / Edit Video Form -->
            <div id="videoForm" class="hidden bg-red-50 rounded-xl p-4 mb-4 border border-red-200">
                <h3 class="font-bold text-red-700 mb-3" id="videoFormTitle">Add New Video</h3>
                <input type="hidden" id="editVideoId">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <input id="videoLessonName" placeholder="Lesson name (e.g. Lesson 1: Introduction)" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-400">
                    <input id="videoYoutubeUrl" placeholder="YouTube URL" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-400">
                    <input id="videoSortOrder" type="number" placeholder="Order (1, 2, 3…)" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-400">
                </div>
                <div class="flex gap-2 mt-3">
                    <button onclick="saveVideo()" class="bg-red-600 text-white px-4 py-2 rounded-lg text-sm font-bold hover:bg-red-700">✅ Save</button>
                    <button onclick="document.getElementById('videoForm').classList.add('hidden')" class="bg-gray-200 px-4 py-2 rounded-lg text-sm font-bold">Cancel</button>
                </div>
                <div id="videoFormMsg" class="mt-2 text-sm hidden"></div>
            </div>
            <!-- Video list table -->
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead><tr class="border-b text-gray-500 text-left"><th class="pb-2">Order</th><th class="pb-2">Lesson Name</th><th class="pb-2">YouTube URL</th><th class="pb-2">Actions</th></tr></thead>
                    <tbody id="adminVideoList"></tbody>
                </table>
            </div>
        </div>
    </div>
    <!-- Interactive HTML Lessons Tab -->
    <div id="section-interactive" class="hidden">
        <div class="bg-white rounded-2xl shadow p-6">
            <div class="flex items-center justify-between mb-2 gap-4">
                <h2 class="text-xl">💻 Interactive Lessons</h2>
                <button onclick="document.getElementById('interactiveLessonForm').classList.toggle('hidden')" class="bg-purple-600 text-white px-4 py-2 rounded-xl font-bold text-sm hover:bg-purple-700">+ Upload HTML Lesson</button>
            </div>
            <p class="text-gray-500 text-sm mb-4">Upload an .html file and any images it references. Lesson number is permanent and used in the lesson link; display order can be changed later.</p>
            <div id="interactiveLessonForm" class="hidden bg-purple-50 rounded-xl p-4 mb-4 border border-purple-200">
                <h3 class="font-bold text-purple-700 mb-3">Upload Interactive HTML Lesson</h3>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <input id="interactiveLessonTitle" placeholder="Lesson name (e.g. Lesson 1: HTML Quiz)" maxlength="120" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-purple-400">
                    <label class="text-xs font-bold text-purple-800">HTML file
                        <input id="interactiveLessonFile" type="file" accept=".html,.htm,text/html" class="block w-full mt-1 border rounded-lg px-3 py-2 text-sm bg-white focus:outline-none focus:border-purple-400">
                    </label>
                    <label class="text-xs font-bold text-purple-800">Lesson images (optional)
                        <input id="interactiveLessonAssets" type="file" multiple accept="image/*,.svg" class="block w-full mt-1 border rounded-lg px-3 py-2 text-sm bg-white focus:outline-none focus:border-purple-400">
                    </label>
                    <input id="interactiveLessonNumber" type="number" min="1" required placeholder="Lesson number (e.g. 10)" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-purple-400">
                    <input id="interactiveLessonOrder" type="number" min="0" placeholder="Display order (optional)" class="border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-purple-400">
                </div>
                <p class="text-xs text-purple-700 mt-2">Images are optional. For example, if your HTML uses <code>src="steam-logo.png"</code>, select that image here and it will be embedded into the lesson automatically.</p>
                <label class="inline-flex items-center gap-2 mt-3 text-sm font-semibold text-gray-700"><input id="interactiveLessonPublished" type="checkbox" checked class="accent-purple-600"> Publish immediately for students</label>
                <div class="flex gap-2 mt-3">
                    <button onclick="uploadInteractiveLesson()" class="bg-purple-600 text-white px-4 py-2 rounded-lg text-sm font-bold hover:bg-purple-700">⬆️ Upload Lesson</button>
                    <button onclick="document.getElementById('interactiveLessonForm').classList.add('hidden')" class="bg-gray-200 px-4 py-2 rounded-lg text-sm font-bold">Cancel</button>
                </div>
                <div id="interactiveLessonMsg" class="mt-2 text-sm hidden"></div>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead><tr class="border-b text-gray-500 text-left"><th class="pb-2">Lesson No.</th><th class="pb-2">Display Order</th><th class="pb-2">Internal ID</th><th class="pb-2">Lesson Name</th><th class="pb-2">Status</th><th class="pb-2">Updated</th><th class="pb-2">Actions</th></tr></thead>
                    <tbody id="adminInteractiveLessonList"></tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- Admin Reset Student Progress Modal -->
<div id="adminProgressResetModal" class="fixed inset-0 bg-black/50 hidden items-center justify-center z-50" onclick="if(event.target===this)this.classList.add('hidden')">
    <div class="bg-white rounded-2xl p-6 w-full max-w-md shadow-2xl" onclick="event.stopPropagation()">
        <h3 class="text-lg font-bold mb-1">↺ Reset Student Progress</h3>
        <p class="text-gray-500 text-sm mb-4">Choose what to reset for <strong id="adminProgressResetName"></strong>. The student will need to complete it again.</p>
        <label class="block text-sm font-bold text-gray-700 mb-1">Reset scope</label>
        <select id="adminProgressResetLesson" class="w-full border-2 border-gray-200 rounded-xl px-3 py-2.5 text-sm bg-white focus:outline-none focus:border-red-400 mb-3">
            <option value="all">⚠️ All progress — lessons, XP, badges and streak</option>
        </select>
        <div class="bg-amber-50 border border-amber-200 rounded-xl p-3 text-xs text-amber-800 mb-3">
            A single lesson reset also removes that lesson's challenge score and recalculates XP, level and badges.
        </div>
        <div id="adminProgressResetMsg" class="text-sm mb-3 hidden"></div>
        <div class="flex gap-2">
            <button onclick="confirmAdminProgressReset()" class="flex-1 bg-red-600 text-white py-2.5 rounded-xl font-bold hover:bg-red-700">Confirm Reset</button>
            <button onclick="document.getElementById('adminProgressResetModal').classList.add('hidden')" class="flex-1 bg-gray-200 py-2.5 rounded-xl font-bold">Cancel</button>
        </div>
    </div>
</div>

<script>
let allUsers = [];
let adminProgressResetStudentId = null;
const roleColors = {admin:'bg-red-100 text-red-700',teacher:'bg-blue-100 text-blue-700',student:'bg-green-100 text-green-700',parent:'bg-yellow-100 text-yellow-700'};
const roleEmoji = {admin:'🛡️',teacher:'📚',student:'🎓',parent:'👨‍👩‍👧'};

function escHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

async function init() {
    const me = await fetch('/api/auth/me').then(r=>r.json());
    if (!me.user || me.user.role !== 'admin') { window.location.href='/login'; return; }
    document.getElementById('welcomeMsg').textContent = 'Welcome, ' + me.user.full_name;
    loadPending();
    loadUsers();
    loadClasses();
    loadLinkDropdowns();
    loadAdminVideos();
    loadAdminInteractiveLessons();
}

function showTab(tab) {
    ['pending','users','classes','links','videos','interactive'].forEach(t => {
        document.getElementById('section-'+t).classList.add('hidden');
        const btn = document.getElementById('tab-'+t);
        if (btn) btn.className = 'tab-btn bg-gray-200 text-gray-600 px-5 py-2 rounded-full font-bold text-sm';
    });
    document.getElementById('section-'+tab).classList.remove('hidden');
    const activeColors = {pending:'bg-orange-500',users:'bg-indigo-600',classes:'bg-indigo-600',links:'bg-indigo-600',videos:'bg-red-500',interactive:'bg-purple-600'};
    document.getElementById('tab-'+tab).className = \`tab-btn \${activeColors[tab]||'bg-indigo-600'} text-white px-5 py-2 rounded-full font-bold text-sm\`;
}

// ── Admin Video CRUD ─────────────────────────────────────────────────────────
function ytEmbed(url) {
    try {
        var u = new URL(url);
        var id = u.hostname === 'youtu.be' ? u.pathname.slice(1) : (u.searchParams.get('v') || '');
        return id ? 'https://www.youtube.com/embed/' + id : url;
    } catch(e) { return url; }
}

async function loadAdminVideos() {
    const videos = await fetch('/api/videos').then(r=>r.json());
    const tbody = document.getElementById('adminVideoList');
    if (!Array.isArray(videos) || !videos.length) {
        tbody.innerHTML = \`<tr><td colspan="4" class="text-center text-gray-400 py-8">No videos yet. Click "+ Add Video" to get started.</td></tr>\`;
        return;
    }
    tbody.innerHTML = videos.map(v => \`
        <tr class="border-b hover:bg-gray-50">
            <td class="py-3 px-2 text-gray-500 w-12 text-center">\${v.sort_order||'-'}</td>
            <td class="py-3 px-2 font-semibold text-gray-800">\${v.lesson_name}</td>
            <td class="py-3 px-2 text-blue-600 text-xs max-w-xs"><a href="\${v.youtube_url}" target="_blank" class="hover:underline truncate block max-w-xs">\${v.youtube_url}</a></td>
            <td class="py-3 px-2">
                <div class="flex gap-2">
                    <button onclick="openEditVideo(\${v.id})" class="bg-blue-100 hover:bg-blue-200 text-blue-700 px-3 py-1 rounded-lg text-xs font-bold">✏️ Edit</button>
                    <button onclick="deleteVideo(\${v.id})" class="bg-red-100 hover:bg-red-200 text-red-700 px-3 py-1 rounded-lg text-xs font-bold">🗑️ Delete</button>
                </div>
            </td>
        </tr>\`).join('');
}

let _adminVideos = [];
async function _fetchAdminVideos() { _adminVideos = await fetch('/api/videos').then(r=>r.json()); }

function showAddVideoForm() {
    document.getElementById('videoFormTitle').textContent = 'Add New Video';
    document.getElementById('editVideoId').value = '';
    document.getElementById('videoLessonName').value = '';
    document.getElementById('videoYoutubeUrl').value = '';
    document.getElementById('videoSortOrder').value = '';
    document.getElementById('videoFormMsg').classList.add('hidden');
    document.getElementById('videoForm').classList.remove('hidden');
}

function openEditVideo(id) {
    fetch('/api/videos').then(r=>r.json()).then(videos => {
        const v = videos.find(x => x.id === id);
        if (!v) return;
        document.getElementById('videoFormTitle').textContent = 'Edit Video';
        document.getElementById('editVideoId').value = v.id;
        document.getElementById('videoLessonName').value = v.lesson_name;
        document.getElementById('videoYoutubeUrl').value = v.youtube_url;
        document.getElementById('videoSortOrder').value = v.sort_order || '';
        document.getElementById('videoFormMsg').classList.add('hidden');
        document.getElementById('videoForm').classList.remove('hidden');
        document.getElementById('videoForm').scrollIntoView({behavior:'smooth'});
    });
}

async function saveVideo() {
    const id = document.getElementById('editVideoId').value;
    const lesson_name = document.getElementById('videoLessonName').value.trim();
    const youtube_url = document.getElementById('videoYoutubeUrl').value.trim();
    const sort_order = parseInt(document.getElementById('videoSortOrder').value) || 0;
    const msg = document.getElementById('videoFormMsg');
    if (!lesson_name || !youtube_url) {
        msg.textContent = '⚠️ Please fill in the lesson name and YouTube URL.';
        msg.className = 'mt-2 text-sm text-red-600'; msg.classList.remove('hidden'); return;
    }
    const res = await fetch(id ? '/api/admin/videos/'+id : '/api/admin/videos', {
        method: id ? 'PUT' : 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({lesson_name, youtube_url, sort_order})
    }).then(r=>r.json());
    if (res.ok) {
        document.getElementById('videoForm').classList.add('hidden');
        loadAdminVideos();
    } else {
        msg.textContent = '❌ ' + (res.error || 'Failed to save');
        msg.className = 'mt-2 text-sm text-red-600'; msg.classList.remove('hidden');
    }
}

async function deleteVideo(id) {
    if (!confirm('Delete this video?')) return;
    await fetch('/api/admin/videos/'+id, {method:'DELETE'});
    loadAdminVideos();
}
// ─────────────────────────────────────────────────────────────────────────────

// ── Admin Interactive HTML Lesson CRUD ──────────────────────────────────────
var adminInteractiveLessons = [];

async function loadAdminInteractiveLessons() {
    var tbody = document.getElementById('adminInteractiveLessonList');
    if (!tbody) return;
    try {
        var res = await fetch('/api/admin/interactive-lessons');
        adminInteractiveLessons = await res.json();
        if (!Array.isArray(adminInteractiveLessons) || !adminInteractiveLessons.length) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-gray-400 py-8">No interactive lessons yet. Upload a complete HTML file to get started.</td></tr>';
            return;
        }
            tbody.innerHTML = adminInteractiveLessons.map(function(lesson) {
            var isPublished = Number(lesson.is_published) === 1;
            var status = isPublished
                ? '<span class="bg-green-100 text-green-700 px-2 py-1 rounded-full text-xs font-bold">Published</span>'
                : '<span class="bg-gray-200 text-gray-600 px-2 py-1 rounded-full text-xs font-bold">Draft</span>';
            var updated = lesson.updated_at ? String(lesson.updated_at).slice(0, 10) : '-';
            var toggleText = isPublished ? 'Unpublish' : 'Publish';
            return '<tr class="border-b hover:bg-gray-50">' +
                '<td class="py-3 px-2 text-purple-700 font-bold w-20 text-center">' + (lesson.lesson_number > 0 ? '#' + lesson.lesson_number : 'Legacy') + '</td>' +
                '<td class="py-3 px-2 text-gray-500 w-20 text-center">' + (lesson.sort_order > 0 ? lesson.sort_order : '-') + '</td>' +
                '<td class="py-3 px-2 text-gray-400 text-xs w-16 text-center">ID ' + Number(lesson.id) + '</td>' +
                '<td class="py-3 px-2 font-semibold text-gray-800">' + escHtml(lesson.title) + '</td>' +
                '<td class="py-3 px-2">' + status + '</td>' +
                '<td class="py-3 px-2 text-gray-400">' + updated + '</td>' +
                '<td class="py-3 px-2"><div class="flex gap-2 flex-wrap">' +
                    '<button onclick="openAdminInteractiveLesson(' + Number(lesson.id) + ',' + Number(lesson.lesson_number) + ')" class="bg-blue-100 hover:bg-blue-200 text-blue-700 px-3 py-1 rounded-lg text-xs font-bold">↗ Open</button>' +
                    '<button onclick="editInteractiveLesson(' + Number(lesson.id) + ')" class="bg-indigo-100 hover:bg-indigo-200 text-indigo-700 px-3 py-1 rounded-lg text-xs font-bold">✏️ Edit</button>' +
                    '<button onclick="toggleInteractiveLesson(' + Number(lesson.id) + ')" class="bg-purple-100 hover:bg-purple-200 text-purple-700 px-3 py-1 rounded-lg text-xs font-bold">' + toggleText + '</button>' +
                    '<button onclick="deleteInteractiveLesson(' + Number(lesson.id) + ')" class="bg-red-100 hover:bg-red-200 text-red-700 px-3 py-1 rounded-lg text-xs font-bold">🗑️ Delete</button>' +
                '</div></td></tr>';
        }).join('');
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-red-500 py-8">Could not load interactive lessons.</td></tr>';
    }
}

async function uploadInteractiveLesson() {
    var title = document.getElementById('interactiveLessonTitle').value.trim();
    var fileInput = document.getElementById('interactiveLessonFile');
    var lessonNumber = parseInt(document.getElementById('interactiveLessonNumber').value);
    var orderValue = document.getElementById('interactiveLessonOrder').value.trim();
    var order = orderValue === '' ? null : (parseInt(orderValue) || 0);
    var published = document.getElementById('interactiveLessonPublished').checked;
    var msg = document.getElementById('interactiveLessonMsg');
    var file = fileInput.files && fileInput.files[0];
    msg.classList.remove('hidden');
    if (!title || !file || !Number.isInteger(lessonNumber) || lessonNumber < 1) {
        msg.className = 'mt-2 text-sm text-red-600'; msg.textContent = 'Choose a lesson name, a positive lesson number, and an HTML file.'; return;
    }
    if (!/\.html?$/i.test(file.name)) {
        msg.className = 'mt-2 text-sm text-red-600'; msg.textContent = 'Only .html or .htm files are allowed.'; return;
    }
    if (file.size > 256 * 1024) {
        msg.className = 'mt-2 text-sm text-red-600'; msg.textContent = 'The HTML file must be 256 KB or smaller.'; return;
    }
    msg.className = 'mt-2 text-sm text-gray-500'; msg.textContent = 'Embedding lesson images…';
    try {
        var html = await file.text();
        var assetInput = document.getElementById('interactiveLessonAssets');
        var assets = assetInput.files ? Array.from(assetInput.files) : [];
        var bundledHtml = await bundleInteractiveLessonAssets(html, assets);
        if (new Blob([bundledHtml]).size > 256 * 1024) {
            throw new Error('The HTML and embedded lesson images must be 256 KB or smaller.');
        }
        var res = await fetch('/api/admin/interactive-lessons', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({title:title, html_content:bundledHtml, file_name:file.name, lesson_number:lessonNumber, sort_order:order, is_published:published})
        });
        var data = await res.json();
        if (!data.ok) throw new Error(data.error || 'Upload failed');
        document.getElementById('interactiveLessonTitle').value = '';
        document.getElementById('interactiveLessonFile').value = '';
        document.getElementById('interactiveLessonAssets').value = '';
        document.getElementById('interactiveLessonNumber').value = '';
        document.getElementById('interactiveLessonOrder').value = '';
        msg.className = 'mt-2 text-sm text-green-600'; msg.textContent = '✅ Lesson uploaded successfully.';
        loadAdminInteractiveLessons();
    } catch(e) {
        msg.className = 'mt-2 text-sm text-red-600'; msg.textContent = '❌ ' + (e.message || 'Upload failed.');
    }
}

function normalizeLessonAssetPath(value) {
    try { value = decodeURIComponent(value); } catch(e) {}
    var path = String(value || '').split(String.fromCharCode(92)).join('/');
    while (path.indexOf('./') === 0) path = path.slice(2);
    while (path.indexOf('/') === 0) path = path.slice(1);
    return path;
}

function lessonAssetFileKeys(file) {
    var keys = [];
    var fullPath = normalizeLessonAssetPath(file.webkitRelativePath || file.name);
    if (fullPath) keys.push(fullPath);
    var name = fullPath.split('/').pop();
    if (name && !keys.includes(name)) keys.push(name);
    return keys;
}

function findLessonAsset(reference, assets) {
    var path = normalizeLessonAssetPath(String(reference || '').split(/[?#]/)[0]);
    if (!path) return null;
    var exact = assets.filter(function(file) {
        return lessonAssetFileKeys(file).some(function(key) { return key === path; });
    });
    if (exact.length === 1) return exact[0];
    if (exact.length > 1) return null;
    var basename = path.split('/').pop();
    var byName = assets.filter(function(file) {
        var keys = lessonAssetFileKeys(file);
        return keys.length > 0 && keys[keys.length - 1] === basename;
    });
    return byName.length === 1 ? byName[0] : null;
}

function isExternalLessonAsset(reference) {
    var raw = String(reference || '').trim();
    if (!raw) return false;
    if (raw[0] === '/' || raw[0] === '#') return true;
    if (raw.indexOf('//') === 0) return true;
    return /^[a-z][a-z0-9+.-]*:/i.test(raw);
}

function readLessonAssetAsDataUrl(file) {
    return new Promise(function(resolve, reject) {
        var reader = new FileReader();
        reader.onload = function() { resolve(String(reader.result || '')); };
        reader.onerror = function() { reject(new Error('Could not read supporting file ' + file.name)); };
        reader.readAsDataURL(file);
    });
}

async function bundleInteractiveLessonAssets(html, assets) {
    var parser = new DOMParser();
    var doc = parser.parseFromString(html, 'text/html');
    var dataUrlCache = new Map();
    var missing = new Set();
    async function replaceReference(reference) {
        var raw = String(reference || '').trim();
        if (!raw || isExternalLessonAsset(raw) || /^data:/i.test(raw)) return raw;
        var asset = findLessonAsset(raw, assets);
        if (!asset) { missing.add(raw.split(/[?#]/)[0]); return raw; }
        if (!dataUrlCache.has(asset)) dataUrlCache.set(asset, await readLessonAssetAsDataUrl(asset));
        return dataUrlCache.get(asset);
    }
    async function replaceSrcset(srcset) {
        var entries = String(srcset || '').split(',');
        var bundledEntries = [];
        for (var entry of entries) {
            var parts = entry.trim().split(' ').filter(Boolean);
            if (!parts.length) continue;
            parts[0] = await replaceReference(parts[0]);
            bundledEntries.push(parts.join(' '));
        }
        return bundledEntries.join(', ');
    }
    async function replaceCssUrls(css) {
        var matches = Array.from(String(css || '').matchAll(/url[(][ \t]*["']?([^"')]+)["']?[ \t]*[)]/gi));
        for (var match of matches) {
            var bundled = await replaceReference(match[1]);
            css = css.replace(match[0], 'url("' + bundled.replace(/"/g, '\\"') + '")');
        }
        return css;
    }
    var elements = Array.from(doc.querySelectorAll('img[src], img[srcset], video[poster], link[rel~="icon"][href], [style]'));
    for (var element of elements) {
        for (var attribute of ['src', 'href', 'poster']) {
            if (element.hasAttribute(attribute)) {
                element.setAttribute(attribute, await replaceReference(element.getAttribute(attribute)));
            }
        }
        if (element.hasAttribute('srcset')) {
            element.setAttribute('srcset', await replaceSrcset(element.getAttribute('srcset')));
        }
        if (element.hasAttribute('style')) {
            element.setAttribute('style', await replaceCssUrls(element.getAttribute('style')));
        }
    }
    var styles = Array.from(doc.querySelectorAll('style'));
    for (var style of styles) {
        style.textContent = await replaceCssUrls(style.textContent || '');
    }
    if (missing.size) {
        throw new Error('Select the supporting file(s) used by the lesson: ' + Array.from(missing).slice(0, 4).join(', '));
    }
    if (!assets.length) return html;
    return '<!doctype html>\\n' + doc.documentElement.outerHTML;
}

function openAdminInteractiveLesson(id, lessonNumber) {
    var target = Number(lessonNumber) > 0 ? '/interactive-lessons/lesson/' + Number(lessonNumber) : '/interactive-lessons/' + id;
    window.open(target, '_blank', 'noopener');
}

async function updateInteractiveLesson(lesson) {
    var res = await fetch('/api/admin/interactive-lessons/' + lesson.id, {
        method: 'PUT',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({title:lesson.title, sort_order:lesson.sort_order || 0, is_published:lesson.is_published})
    });
    var data = await res.json();
    if (!data.ok) alert('❌ ' + (data.error || 'Could not update lesson.'));
    await loadAdminInteractiveLessons();
}

function editInteractiveLesson(id) {
    var lesson = adminInteractiveLessons.find(function(item) { return Number(item.id) === Number(id); });
    if (!lesson) return;
    var title = prompt('Lesson name:', lesson.title);
    if (title === null) return;
    var order = prompt('Sort order:', lesson.sort_order || 0);
    if (order === null) return;
    updateInteractiveLesson({id:lesson.id, title:title.trim(), sort_order:parseInt(order) || 0, is_published:Number(lesson.is_published) === 1});
}

function toggleInteractiveLesson(id) {
    var lesson = adminInteractiveLessons.find(function(item) { return Number(item.id) === Number(id); });
    if (!lesson) return;
    var willPublish = Number(lesson.is_published) !== 1;
    if (!confirm((willPublish ? 'Publish' : 'Unpublish') + ' "' + lesson.title + '"?')) return;
    updateInteractiveLesson({id:lesson.id, title:lesson.title, sort_order:lesson.sort_order || 0, is_published:willPublish});
}

async function deleteInteractiveLesson(id) {
    if (!confirm('Delete this interactive lesson permanently?')) return;
    var res = await fetch('/api/admin/interactive-lessons/' + id, {method:'DELETE'});
    var data = await res.json();
    if (!data.ok) { alert('❌ ' + (data.error || 'Could not delete lesson.')); return; }
    loadAdminInteractiveLessons();
}
// ─────────────────────────────────────────────────────────────────────────────

async function loadPending() {
    const [pending, classes] = await Promise.all([
        fetch('/api/admin/pending').then(r=>r.json()),
        fetch('/api/classes').then(r=>r.json()).catch(()=>[])
    ]);
    document.getElementById('pendingBadge').textContent = pending.length;
    const list = document.getElementById('pendingList');
    if (!pending.length) {
        list.innerHTML = '<p class="text-gray-400 text-center py-8">✅ No pending registrations right now!</p>';
        return;
    }
    // Build grouped class options by school
    var schoolGroups = {};
    classes.forEach(function(c) {
        var grp = c.school_name || '📂 No School';
        if (!schoolGroups[grp]) schoolGroups[grp] = [];
        schoolGroups[grp].push(c);
    });
    var groupedOpts = Object.keys(schoolGroups).sort().map(function(grp) {
        return '<optgroup label="' + grp + '">' +
            schoolGroups[grp].map(function(c){ return '<option value="' + c.id + '">' + escHtml(c.name) + '</option>'; }).join('') +
            '</optgroup>';
    }).join('');

    list.innerHTML = \`<div class="space-y-3">\${pending.map(u => \`
        <div class="p-4 bg-orange-50 border border-orange-200 rounded-xl">
            <div class="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <div class="font-bold text-gray-800">\${escHtml(u.full_name)}</div>
                    <div class="text-gray-500 text-sm">@\${escHtml(u.username)} • registered \${u.created_at?.slice(0,10)||'today'}</div>
                </div>
                <div class="flex gap-2 flex-wrap items-center">
                    \${classes.length ? \`<select id="adminApproveClass_\${u.id}" class="border rounded-lg px-2 py-1.5 text-xs bg-white focus:outline-none focus:border-green-400 max-w-[200px]"><option value="">— No class yet —</option>\${groupedOpts}</select>\` : ''}
                    <button onclick="adminApproveAndEnroll(\${u.id})" class="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded-lg text-sm font-bold transition-all">✅ Approve</button>
                    <button onclick="approveUser(\${u.id},'reject')" class="bg-red-400 hover:bg-red-500 text-white px-4 py-2 rounded-lg text-sm font-bold transition-all">❌ Reject</button>
                </div>
            </div>
        </div>\`).join('')}</div>\`;
}

async function adminApproveAndEnroll(id) {
    const sel = document.getElementById('adminApproveClass_' + id);
    const classId = sel ? sel.value : '';
    await fetch('/api/admin/users/' + id + '/approve', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ action: 'approve', class_id: classId || null })
    });
    loadPending();
    loadUsers();
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
        <td class="py-2 font-semibold">\${escHtml(u.full_name)}</td>
        <td class="py-2 text-gray-500">@\${escHtml(u.username)}</td>
        <td class="py-2"><span class="px-2 py-1 rounded-full text-xs font-bold \${roleColors[u.role]}">\${roleEmoji[u.role]} \${escHtml(u.role)}</span></td>
        <td class="py-2"><span class="px-2 py-1 rounded-full text-xs font-bold \${u.status==='pending'?'bg-orange-100 text-orange-700':u.status==='rejected'?'bg-red-100 text-red-700':'bg-green-100 text-green-700'}">\${escHtml(u.status||'approved')}</span></td>
        <td class="py-2 text-gray-400">\${u.created_at?.slice(0,10) || '-'}</td>
        <td class="py-2 flex gap-2 items-center flex-wrap">
            \${u.role === 'student' ? \`<button onclick="openAdminProgressReset(\${u.id})" class="text-red-500 hover:text-red-700 text-xs font-bold" title="Reset one lesson or all progress">↺ Reset Progress</button><button onclick="sanitizeProgress(\${u.id}, '\${escHtml(u.username)}')" class="text-orange-400 hover:text-orange-600 text-xs font-bold" title="Recalculate XP from real lesson data">🔄 Sanitize</button>\` : \`<button onclick="cleanProgress(\${u.id}, '\${escHtml(u.username)}')" class="text-purple-400 hover:text-purple-600 text-xs font-bold" title="Remove any leftover student progress/class data">🧹 Clean DB</button>\`}
            <select onchange="changeRole(\${u.id}, this)" class="border rounded px-1 py-0.5 text-xs bg-white focus:outline-none focus:border-indigo-400" title="Change role">
                \${['student','teacher','parent','admin'].map(function(r){ return '<option value="'+r+'" '+(r===u.role?'selected':'')+'>'+r+'</option>'; }).join('')}
            </select>
            <button onclick="adminResetPw(\${u.id}, '\${escHtml(u.full_name||u.username)}')" class="text-blue-400 hover:text-blue-600 text-xs font-bold" title="Reset this user's password">🔑 Reset PW</button>
            <button onclick="deleteUser(\${u.id}, '\${escHtml(u.username)}')" class="text-red-400 hover:text-red-600 text-xs">🗑️ Delete</button>
        </td>
    </tr>\`).join('');
}

async function populateAdminProgressLessons() {
    const select = document.getElementById('adminProgressResetLesson');
    if (select.options.length > 1) return;
    try {
        const data = await fetch('/api/curriculum').then(r => r.json());
        const seen = new Set();
        const lessons = [];
        Object.values(data || {}).forEach(group => {
            if (!Array.isArray(group)) return;
            group.forEach(lesson => {
                if (!lesson || !lesson.id || lesson.id.endsWith('-challenge') || seen.has(lesson.id)) return;
                seen.add(lesson.id);
                lessons.push(lesson);
            });
        });
        lessons.forEach(lesson => {
            const option = document.createElement('option');
            option.value = lesson.id;
            option.textContent = (lesson.icon || '📖') + ' ' + lesson.title;
            select.appendChild(option);
        });
    } catch (_) {}
}

async function openAdminProgressReset(studentId) {
    adminProgressResetStudentId = studentId;
    const student = allUsers.find(user => Number(user.id) === Number(studentId));
    document.getElementById('adminProgressResetName').textContent = student ? (student.full_name || student.username) : 'this student';
    document.getElementById('adminProgressResetLesson').value = 'all';
    const msg = document.getElementById('adminProgressResetMsg');
    msg.classList.add('hidden');
    await populateAdminProgressLessons();
    document.getElementById('adminProgressResetModal').classList.remove('hidden');
    document.getElementById('adminProgressResetModal').classList.add('flex');
}

async function confirmAdminProgressReset() {
    if (!adminProgressResetStudentId) return;
    const select = document.getElementById('adminProgressResetLesson');
    const scope = select.value;
    const scopeLabel = scope === 'all' ? 'ALL progress' : select.options[select.selectedIndex].textContent;
    if (!confirm('Reset ' + scopeLabel + '? This student will have to complete it again.')) return;
    const msg = document.getElementById('adminProgressResetMsg');
    msg.className = 'text-sm mb-3 text-gray-500';
    msg.textContent = 'Resetting...';
    msg.classList.remove('hidden');
    const response = await fetch('/api/teacher/students/' + adminProgressResetStudentId + '/reset-progress', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({lesson_id: scope})
    });
    const data = await response.json();
    if (!response.ok || !data.success) {
        msg.className = 'text-sm mb-3 text-red-600';
        msg.textContent = '❌ ' + (data.error || 'Could not reset progress.');
        return;
    }
    msg.className = 'text-sm mb-3 text-green-600';
    msg.textContent = '✅ Progress reset. New XP: ' + data.xp;
    await Promise.all([loadUsers(), loadSchools()]);
    setTimeout(() => document.getElementById('adminProgressResetModal').classList.add('hidden'), 900);
}

// ── Schools + Classes admin functions ──────────────────────────────────────

var cachedTeachers = [];
var cachedAllStudents = [];

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

    [cachedTeachers, cachedAllStudents] = await Promise.all([
        fetch('/api/teachers').then(r=>r.json()).catch(()=>[]),
        fetch('/api/admin/students-with-class').then(r=>r.json()).catch(()=>[])
    ]);

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
            const students = await fetch('/api/classes/' + cls.id + '/students').then(r=>r.json());
            uc.innerHTML += buildClassHTML(cls, students);
        }
    }

    // Unassigned students banner (admin version — can pick any class from any school)
    const unenrolledStudents = await fetch('/api/students/unenrolled').then(r=>r.json()).catch(()=>[]);
    if (unenrolledStudents.length) {
        // Build grouped class options: group by school
        var schoolGroups = {};
        allClasses.forEach(function(c) {
            var grp = c.school_name || '📂 No School';
            if (!schoolGroups[grp]) schoolGroups[grp] = [];
            schoolGroups[grp].push(c);
        });
        var groupedOpts = Object.keys(schoolGroups).sort().map(function(grp) {
            var opts = schoolGroups[grp].map(function(c) {
                return \`<option value="\${c.id}">\${c.name}</option>\`;
            }).join('');
            return \`<optgroup label="\${grp}">\${opts}</optgroup>\`;
        }).join('');

        const bannerDiv = document.createElement('div');
        bannerDiv.className = 'bg-amber-50 border-2 border-amber-300 rounded-2xl p-5 mt-4';
        bannerDiv.innerHTML = \`
            <div class="flex items-center gap-2 mb-3">
                <span class="text-xl">⚠️</span>
                <h3 class="font-bold text-amber-800">\${unenrolledStudents.length} approved student\${unenrolledStudents.length > 1 ? 's are' : ' is'} not in any class</h3>
            </div>
            <div class="space-y-2">
                \${unenrolledStudents.map(s => \`
                <div class="flex items-center justify-between bg-white rounded-xl px-4 py-2.5 border border-amber-200 gap-3 flex-wrap">
                    <div>
                        <span class="font-semibold text-gray-800">\${s.full_name}</span>
                        <span class="text-gray-400 text-xs ml-2">@\${s.username}</span>
                    </div>
                    \${allClasses.length ? \`<div class="flex gap-2 items-center">
                        <select id="adminQaSel_\${s.id}" class="border rounded-lg px-2 py-1.5 text-xs bg-white focus:outline-none focus:border-indigo-400">
                            <option value="">Pick a class...</option>
                            \${groupedOpts}
                        </select>
                        <button onclick="adminQuickEnroll(\${s.id})" class="bg-indigo-600 text-white text-xs px-3 py-1.5 rounded-lg font-bold hover:bg-indigo-700">➕ Enrol</button>
                    </div>\` : ''}
                </div>\`).join('')}
            </div>
        \`;
        container.appendChild(bannerDiv);
    }
}

async function buildSchoolHTML(school, schoolClasses) {
    var teacherOpts = cachedTeachers.map(t=>\`<option value="\${t.id}">\${t.full_name} (@\${t.username})</option>\`).join('');
    var classesHTML = '';
    for (const cls of schoolClasses) {
        const students = await fetch('/api/classes/' + cls.id + '/students').then(r=>r.json());
        classesHTML += buildClassHTML(cls, students);
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

function buildClassHTML(cls, students) {
    var enrolledIds = students.map(s => s.id);
    var schoolLabel = cls.school_name
        ? \`<span class="bg-purple-100 text-purple-700 text-xs font-semibold px-2 py-0.5 rounded-full">🏫 \${cls.school_name}</span>\`
        : '';
    var studentRows = students.map(s => \`
        <tr class="border-b hover:bg-gray-50">
            <td class="py-1.5">
                <div class="font-semibold text-sm">\${s.full_name}<span class="text-gray-400 text-xs ml-1">@\${s.username}</span></div>
                \${s.school_name ? \`<div class="text-purple-600 text-xs mt-0.5">🏫 \${s.school_name}</div>\` : ''}
            </td>
            <td class="py-1.5 text-xs text-yellow-500 font-bold">⭐ \${s.xp||0}</td>
            <td class="py-1.5 text-xs"><span class="bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded-full">Lv \${s.level||1}</span></td>
            <td class="py-1.5"><button onclick="removeStudentFromClass(\${cls.id},\${s.id})" class="text-red-400 hover:text-red-600 text-xs" title="Remove from class">✕</button></td>
        </tr>\`).join('');
    var teacherOpts = cachedTeachers.map(t=>\`<option value="\${t.id}" \${cls.teacher_id==t.id?'selected':''}>\${t.full_name}</option>\`).join('');
    var totalStudents = cachedAllStudents.length;
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
        \${totalStudents > 0 ? \`
        <div class="border-t pt-3 mt-1">
            <div class="relative">
                <input type="text" id="stuSearch_\${cls.id}"
                    placeholder="🔍 Search students to add or transfer..."
                    class="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-400"
                    oninput="renderStudentSearch(\${cls.id}, this.value)"
                    onblur="setTimeout(()=>{ var r=document.getElementById('stuResults_\${cls.id}'); if(r&&!r._hovered) r.classList.add('hidden'); }, 220)"
                    onfocus="renderStudentSearch(\${cls.id}, this.value)">
                <div id="stuResults_\${cls.id}"
                    class="hidden absolute left-0 right-0 mt-1 max-h-56 overflow-y-auto border rounded-lg shadow-xl bg-white divide-y text-sm z-20"
                    onmouseenter="this._hovered=true" onmouseleave="this._hovered=false"></div>
            </div>
        </div>\` : '<p class="text-gray-400 text-xs border-t pt-2 mt-1">No approved students in the system yet.</p>'}
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

async function adminAddStudent(studentId, classId) {
    await fetch('/api/classes/' + classId + '/students', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ student_id: studentId })
    });
    loadSchools();
}

async function adminTransferStudent(studentId, toClassId, fromClassId) {
    if (!confirm('Move this student to this class? They will be removed from their current class.')) return;
    await fetch('/api/classes/' + fromClassId + '/students/' + studentId, { method: 'DELETE' });
    await fetch('/api/classes/' + toClassId + '/students', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ student_id: studentId })
    });
    loadSchools();
}

function renderStudentSearch(classId, query) {
    var container = document.getElementById('stuResults_' + classId);
    if (!container) return;
    var q = (query || '').toLowerCase().trim();
    var list = q
        ? cachedAllStudents.filter(function(s) {
            return s.full_name.toLowerCase().includes(q) || s.username.toLowerCase().includes(q);
          })
        : cachedAllStudents.slice();
    if (!list.length) {
        container.innerHTML = '<p class="text-gray-400 text-xs p-3 text-center">No students found.</p>';
        container.classList.remove('hidden');
        return;
    }
    // Group: 1) already in this class, 2) unassigned, 3) each other class alphabetically
    var inThis   = list.filter(function(s){ return s.class_id == classId; });
    var unassigned = list.filter(function(s){ return !s.class_id; });
    var inOtherMap = {};
    list.forEach(function(s){
        if (s.class_id && s.class_id != classId) {
            var key = s.class_name || ('Class ' + s.class_id);
            if (!inOtherMap[key]) inOtherMap[key] = [];
            inOtherMap[key].push(s);
        }
    });
    var otherGroups = Object.keys(inOtherMap).sort();

    function renderRow(s) {
        var isInThis  = s.class_id == classId;
        var isInOther = s.class_id && !isInThis;
        var badge = isInThis
            ? '<span class="bg-green-100 text-green-700 text-xs px-2 py-0.5 rounded-full font-bold">✓ In this class</span>'
            : isInOther
                ? '<span class="bg-amber-100 text-amber-700 text-xs px-2 py-0.5 rounded-full font-bold">📚 ' + (s.class_name||'') + '</span>'
                : '<span class="bg-gray-100 text-gray-500 text-xs px-2 py-0.5 rounded-full">Unassigned</span>';
        var btn = isInThis ? ''
            : isInOther
                ? '<button onmousedown="adminTransferStudent(' + s.id + ',' + classId + ',' + s.class_id + ')" class="bg-amber-500 hover:bg-amber-600 text-white text-xs px-3 py-1 rounded-lg font-bold flex-shrink-0">Transfer</button>'
                : '<button onmousedown="adminAddStudent(' + s.id + ',' + classId + ')" class="bg-indigo-600 hover:bg-indigo-700 text-white text-xs px-3 py-1 rounded-lg font-bold flex-shrink-0">Add</button>';
        var schoolLine = s.school_name
            ? '<div class="text-purple-600 text-xs">🏫 ' + s.school_name + '</div>'
            : '';
        return '<div class="flex items-center justify-between px-3 py-2 hover:bg-gray-50 gap-2">'
            + '<div class="min-w-0"><span class="font-medium text-gray-800 text-sm">' + s.full_name + '</span>'
            + '<span class="text-gray-400 text-xs ml-1">@' + s.username + '</span>'
            + schoolLine + '</div>'
            + '<div class="flex items-center gap-2 flex-shrink-0">' + badge + btn + '</div>'
            + '</div>';
    }

    function groupHeader(label, count, color) {
        return '<div class="px-3 py-1 text-xs font-bold uppercase tracking-wide ' + color + ' border-b">'
            + label + ' <span class="font-normal opacity-70">(' + count + ')</span></div>';
    }

    var html = '';
    if (inThis.length) {
        html += groupHeader('✓ Already in this class', inThis.length, 'bg-green-50 text-green-700');
        html += inThis.map(renderRow).join('');
    }
    if (unassigned.length) {
        html += groupHeader('⚪ Unassigned', unassigned.length, 'bg-gray-50 text-gray-600');
        html += unassigned.map(renderRow).join('');
    }
    otherGroups.forEach(function(grp) {
        html += groupHeader('📚 ' + grp, inOtherMap[grp].length, 'bg-amber-50 text-amber-700');
        html += inOtherMap[grp].map(renderRow).join('');
    });

    container.innerHTML = html;
    container.classList.remove('hidden');
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


async function changeRole(id, sel) {
    const newRole = sel.value;
    const warnings = { teacher: 'This will remove the user from class enrollment and delete their student progress.', admin: 'This grants full admin access.' };
    const warn = warnings[newRole] ? ' WARNING: ' + warnings[newRole] : '';
    if (!confirm('Change role to "' + newRole + '"?' + warn)) { loadUsers(); return; }
    const res = await fetch('/api/admin/users/' + id + '/role', {
        method: 'PUT', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ role: newRole })
    }).then(r => r.json());
    if (res.success) { loadUsers(); loadSchools && loadSchools(); }
    else alert('❌ ' + (res.error || 'Failed'));
}

async function deleteUser(id, username) {
    if (!confirm('Delete user @' + username + '?')) return;
    await fetch('/api/admin/users/' + id, { method: 'DELETE' });
    loadUsers();
}

async function cleanProgress(id, username) {
    if (!confirm('Remove all leftover student progress and class enrollment for @' + username + '? This clears stale DB data for this teacher/admin.')) return;
    const res = await fetch('/api/admin/clean-progress/' + id, { method: 'POST' }).then(r => r.json());
    if (res.success) { alert('✅ Cleaned up DB records for @' + username); loadUsers(); loadSchools && loadSchools(); }
    else alert('❌ ' + (res.error || 'Failed'));
}

async function sanitizeProgress(id, username) {
    if (!confirm("Recalculate @" + username + "'s XP from their actual completed lessons? This will correct any manipulated scores.")) return;
    const res = await fetch('/api/admin/sanitize-progress/' + id, { method: 'POST' }).then(r => r.json());
    if (res.ok) {
        alert('✅ @' + username + ' sanitized — XP: ' + res.xp + ' | Level: ' + res.level + ' | Lessons: ' + res.lessons);
        loadUsers();
    } else {
        alert('❌ ' + (res.error || 'Failed'));
    }
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

var adminResetPwTarget = null;
function adminResetPw(id, name) {
    adminResetPwTarget = id;
    document.getElementById('adminPwTarget').textContent = name;
    document.getElementById('adminPwInput').value = '';
    var msg = document.getElementById('adminPwMsg'); msg.textContent=''; msg.classList.add('hidden');
    document.getElementById('adminPwModal').classList.remove('hidden');
}
async function confirmAdminResetPw() {
    var pw = document.getElementById('adminPwInput').value;
    var msg = document.getElementById('adminPwMsg');
    msg.className='text-sm'; msg.classList.remove('hidden');
    if (!pw || pw.length < 6) { msg.classList.add('text-red-600'); msg.textContent='Password must be at least 6 characters.'; return; }
    msg.classList.add('text-gray-500'); msg.textContent='Saving…';
    const res = await fetch('/api/admin/users/' + adminResetPwTarget + '/reset-password', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ password: pw })
    }).then(r=>r.json());
    if (res.success) {
        msg.className='text-sm text-green-600'; msg.textContent='✅ Password updated!';
        setTimeout(function(){ document.getElementById('adminPwModal').classList.add('hidden'); }, 1500);
    } else {
        msg.className='text-sm text-red-600'; msg.textContent='❌ '+(res.error||'Failed.');
    }
}

async function logout() {
    await fetch('/api/auth/logout', { method:'POST' });
    window.location.href = '/login';
}

init();
</script>

<!-- Admin Reset Password Modal -->
<div id="adminPwModal" class="fixed inset-0 bg-black/50 hidden flex items-center justify-center z-50" onclick="if(event.target===this)this.classList.add('hidden')">
    <div class="bg-white rounded-2xl p-6 w-full max-w-sm shadow-2xl" onclick="event.stopPropagation()">
        <h3 class="text-lg font-bold mb-1">🔑 Reset Password</h3>
        <p class="text-gray-500 text-sm mb-4">Set a new password for <strong id="adminPwTarget"></strong>.</p>
        <input id="adminPwInput" type="password" placeholder="New password (min 6 chars)"
            class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-blue-400 mb-2">
        <div id="adminPwMsg" class="text-sm mb-3 hidden"></div>
        <div class="flex gap-2">
            <button onclick="confirmAdminResetPw()" class="flex-1 bg-blue-600 text-white py-2.5 rounded-xl font-bold hover:bg-blue-700">Set Password</button>
            <button onclick="document.getElementById('adminPwModal').classList.add('hidden')" class="flex-1 bg-gray-200 py-2.5 rounded-xl font-bold">Cancel</button>
        </div>
    </div>
</div>

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
            <button onclick="openMyPwModal()" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-full text-sm font-bold">🔒 Change Password</button>
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
        <button onclick="showTab('videos')" id="tab-videos" class="tab-btn bg-gray-200 text-gray-600 px-5 py-2 rounded-full font-bold text-sm">🎬 Video Training</button>
        <button onclick="showTab('interactive')" id="tab-interactive" class="tab-btn bg-gray-200 text-gray-600 rounded-full font-bold text-sm px-5 py-2">💻 Interactive Lessons</button>
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
    <!-- Video Training Tab -->
    <div id="section-videos" class="hidden">
        <div class="bg-white rounded-2xl shadow p-6">
            <div class="flex items-center justify-between mb-5">
                <h2 class="text-xl font-bold"><i class="fas fa-video text-red-500 mr-2"></i>Video Training</h2>
                <button onclick="loadTeacherVideos()" class="bg-indigo-100 hover:bg-indigo-200 text-indigo-700 px-4 py-2 rounded-xl text-sm font-bold transition-all">🔄 Refresh</button>
            </div>
            <p class="text-gray-500 mb-5 text-sm">Browse lesson videos to prepare your class — same library your students see.</p>
            <!-- Video player -->
            <div id="teacherVideoPlayer" class="hidden mb-6">
                <div class="bg-black rounded-2xl overflow-hidden" style="aspect-ratio:16/9;max-width:720px;margin:0 auto;">
                    <iframe id="teacherVideoFrame" width="100%" height="100%" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen style="display:block;"></iframe>
                </div>
                <div class="text-center mt-3">
                    <button onclick="document.getElementById('teacherVideoPlayer').classList.add('hidden');document.getElementById('teacherVideoFrame').src=''" class="text-gray-500 hover:text-gray-700 text-sm font-bold">✕ Close Player</button>
                </div>
            </div>
            <!-- Video list -->
            <div id="teacherVideoList" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <div class="text-gray-400 text-center py-12 col-span-3"><i class="fas fa-video text-4xl mb-3 block opacity-40"></i>Click a video to watch</div>
            </div>
        </div>
    </div>
    <!-- Interactive Lessons Tab -->
    <div id="section-interactive" class="hidden">
        <div class="bg-white rounded-2xl shadow p-6">
            <div class="flex items-center justify-between mb-5 gap-3">
                <div>
                    <h2 class="text-xl font-bold text-purple-700">💻 Interactive Lessons</h2>
                    <p class="text-gray-500 text-sm mt-1">Open the same published interactive activities available to your students.</p>
                </div>
                <button onclick="loadTeacherInteractiveLessons()" class="bg-purple-100 hover:bg-purple-200 text-purple-700 px-4 py-2 rounded-xl text-sm font-bold transition-all">🔄 Refresh</button>
            </div>
            <div id="teacherInteractiveLessonList" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <div class="text-gray-400 text-center py-12 col-span-3"><i class="fas fa-laptop-code text-4xl mb-3 block opacity-40"></i>Click the tab to load interactive lessons.</div>
            </div>
        </div>
    </div>
</div>

<!-- Self-service Change My Password Modal (teacher) -->
<div id="myPwModal" class="fixed inset-0 bg-black/50 hidden flex items-center justify-center z-50" onclick="if(event.target===this)this.classList.add('hidden')">
    <div class="bg-white rounded-2xl p-6 w-full max-w-sm shadow-2xl" onclick="event.stopPropagation()">
        <h3 class="text-lg font-bold mb-1">🔒 Change My Password</h3>
        <p class="text-gray-400 text-sm mb-4">Enter your current password to confirm, then choose a new one.</p>
        <div class="space-y-3">
            <input id="myPwCurrent" type="password" placeholder="Current password" class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-indigo-400">
            <input id="myPwNew" type="password" placeholder="New password (min 6 chars)" class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-indigo-400">
            <input id="myPwConfirm" type="password" placeholder="Confirm new password" class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-indigo-400">
            <div id="myPwMsg" class="text-sm hidden"></div>
            <div class="flex gap-2">
                <button onclick="changeMyPassword()" class="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white py-2.5 rounded-xl font-bold">Update Password</button>
                <button onclick="document.getElementById('myPwModal').classList.add('hidden')" class="flex-1 bg-gray-200 py-2.5 rounded-xl font-bold">Cancel</button>
            </div>
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

<!-- Teacher Reset Student Progress Modal -->
<div id="teacherProgressResetModal" class="fixed inset-0 bg-black/50 hidden items-center justify-center z-50" onclick="if(event.target===this)this.classList.add('hidden')">
    <div class="bg-white rounded-2xl p-6 w-full max-w-md shadow-2xl" onclick="event.stopPropagation()">
        <h3 class="text-lg font-bold mb-1">↺ Reset Student Progress</h3>
        <p class="text-gray-500 text-sm mb-4">Choose what to reset for <strong id="teacherProgressResetName"></strong>. The student will need to complete it again.</p>
        <label class="block text-sm font-bold text-gray-700 mb-1">Reset scope</label>
        <select id="teacherProgressResetLesson" class="w-full border-2 border-gray-200 rounded-xl px-3 py-2.5 text-sm bg-white focus:outline-none focus:border-red-400 mb-3"></select>
        <div class="bg-amber-50 border border-amber-200 rounded-xl p-3 text-xs text-amber-800 mb-3">
            A single lesson reset also removes that lesson's challenge score and recalculates XP, level and badges.
        </div>
        <div id="teacherProgressResetMsg" class="text-sm mb-3 hidden"></div>
        <div class="flex gap-2">
            <button onclick="confirmTeacherProgressReset()" class="flex-1 bg-red-600 text-white py-2.5 rounded-xl font-bold hover:bg-red-700">Confirm Reset</button>
            <button onclick="document.getElementById('teacherProgressResetModal').classList.add('hidden')" class="flex-1 bg-gray-200 py-2.5 rounded-xl font-bold">Cancel</button>
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
    {id:'lesson-15',title:'Variable Vault',icon:'🔢',desc:'Control STEMO with named variables',diff:'hard',xp:400,group:'🟣 Expert'},
    {id:'lesson-16',title:'Position Memory',icon:'📍',desc:'Save & return to GPS coordinates',diff:'hard',xp:450,group:'🟣 Expert'},
    {id:'lesson-17',title:'Waypoint Trail',icon:'🗺️',desc:'Replay a list of locations automatically',diff:'extreme',xp:500,group:'🟣 Expert'},
    {id:'lesson-18',title:'List Hunt',icon:'🎯',desc:'Iterate a list and act at each item',diff:'extreme',xp:600,group:'🟣 Expert'},
    {id:'lesson-19',title:'Function Factory',icon:'🔧',desc:'Write functions, call them to draw a star pattern',diff:'extreme',xp:700,group:'🟣 Expert'},
    {id:'lesson-14',title:'Master Coder',icon:'🏆',desc:'The final autonomous graduation mission',diff:'extreme',xp:1000,group:'🏆 Final'},
    {id:'lesson-art-1',title:'Rainbow Spiral',icon:'🌀',desc:'Draw a hypnotic colour spiral',diff:'easy',xp:150,group:'🎨 Art Studio'},
    {id:'lesson-art-2',title:'Rainbow Maker',icon:'🌈',desc:'Paint a bright rainbow',diff:'easy',xp:150,group:'🎨 Art Studio'},
    {id:'lesson-art-3',title:'Write Your Name',icon:'✍️',desc:'Guide STEMO like a pen to sign your art',diff:'medium',xp:200,group:'🎨 Art Studio'},
    {id:'lesson-art-4',title:'Magic Mandala',icon:'❄️',desc:'Loops inside loops make a mandala',diff:'medium',xp:250,group:'🎨 Art Studio'}
];

let allClasses = [];
let teacherProgressResetStudentId = null;

function escHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
let pwResetStudentId = null;

function showTab(tab) {
    ['classes','curriculum','pending','leaderboard','videos','interactive'].forEach(t => {
        document.getElementById('section-'+t).classList.add('hidden');
        const btn = document.getElementById('tab-'+t);
        if(btn) btn.className = 'tab-btn bg-gray-200 text-gray-600 px-5 py-2 rounded-full font-bold text-sm';
    });
    document.getElementById('section-'+tab).classList.remove('hidden');
    const active = {classes:'bg-blue-600',curriculum:'bg-indigo-600',pending:'bg-orange-500',leaderboard:'bg-yellow-500',videos:'bg-red-500',interactive:'bg-purple-600'};
    document.getElementById('tab-'+tab).className = \`tab-btn \${active[tab]||'bg-indigo-600'} text-white px-5 py-2 rounded-full font-bold text-sm\`;
    if (tab === 'leaderboard') loadTeacherLeaderboard();
    if (tab === 'videos') loadTeacherVideos();
    if (tab === 'interactive') loadTeacherInteractiveLessons();
}

function teacherYtEmbedUrl(url) {
    try { var u=new URL(url); var vid=u.hostname==='youtu.be'?u.pathname.slice(1):(u.searchParams.get('v')||''); return vid?'https://www.youtube.com/embed/'+vid:url; } catch(e){return url;}
}
function teacherYtThumb(url) {
    try { var u=new URL(url); var vid=u.hostname==='youtu.be'?u.pathname.slice(1):(u.searchParams.get('v')||''); return vid?'https://img.youtube.com/vi/'+vid+'/mqdefault.jpg':''; } catch(e){return '';}
}
function playTeacherVideo(embedUrl) {
    document.getElementById('teacherVideoFrame').src = embedUrl + '?autoplay=1';
    document.getElementById('teacherVideoPlayer').classList.remove('hidden');
    document.getElementById('teacherVideoPlayer').scrollIntoView({behavior:'smooth'});
}
async function loadTeacherVideos() {
    const list = document.getElementById('teacherVideoList');
    list.innerHTML = '<div class="text-gray-400 text-center py-12 col-span-3"><i class="fas fa-spinner fa-spin text-3xl mb-2 block"></i>Loading videos...</div>';
    try {
        const videos = await fetch('/api/videos').then(r => r.json());
        if (!Array.isArray(videos) || !videos.length) {
            list.innerHTML = '<div class="text-gray-400 text-center py-12 col-span-3"><i class="fas fa-video text-5xl mb-3 block opacity-40"></i><p class="font-semibold">No videos yet.</p><p class="text-sm mt-1">Add videos via the Admin dashboard.</p></div>';
            return;
        }
        list.innerHTML = videos.map(v => {
            const thumb = teacherYtThumb(v.youtube_url);
            const embed = teacherYtEmbedUrl(v.youtube_url);
            const thumbHtml = thumb
                ? \`<img src="\${thumb}" class="w-full object-cover rounded-xl mb-3" style="aspect-ratio:16/9;" onerror="this.remove()">\`
                : \`<div class="w-full bg-gradient-to-br from-red-400 to-red-600 rounded-xl mb-3 flex items-center justify-center text-white text-4xl" style="aspect-ratio:16/9;"><i class="fas fa-play-circle"></i></div>\`;
            return \`<div class="bg-gray-50 border border-gray-200 rounded-2xl p-4 hover:shadow-md transition-all cursor-pointer group" onclick="playTeacherVideo('\${embed}')">
                \${thumbHtml}
                <div class="flex items-start gap-2">
                    <div class="bg-red-500 text-white rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0 mt-0.5 group-hover:scale-110 transition-transform"><i class="fas fa-play text-xs"></i></div>
                    <div>
                        <p class="font-bold text-gray-800 text-sm leading-tight">\${escHtml(v.lesson_name)}</p>
                        <p class="text-gray-400 text-xs mt-1">Click to watch</p>
                    </div>
                </div>
            </div>\`;
        }).join('');
    } catch(e) {
        list.innerHTML = '<div class="text-red-400 text-center py-8 col-span-3">⚠️ Could not load videos. Please try again.</div>';
    }
}

function openTeacherInteractiveLesson(id, lessonNumber) {
    const target = Number(lessonNumber) > 0
        ? '/interactive-lessons/lesson/' + Number(lessonNumber)
        : '/interactive-lessons/' + Number(id);
    window.open(target, '_blank', 'noopener');
}

async function loadTeacherInteractiveLessons() {
    const list = document.getElementById('teacherInteractiveLessonList');
    if (!list) return;
    list.innerHTML = '<div class="text-gray-400 text-center py-12 col-span-3"><i class="fas fa-spinner fa-spin text-3xl mb-2 block"></i>Loading interactive lessons...</div>';
    try {
        const response = await fetch('/api/interactive-lessons');
        const lessons = await response.json();
        if (!response.ok || !Array.isArray(lessons)) throw new Error('Could not load interactive lessons');
        if (!lessons.length) {
            list.innerHTML = '<div class="text-gray-400 text-center py-12 col-span-3"><i class="fas fa-laptop-code text-5xl mb-3 block opacity-40"></i><p class="font-semibold">No published interactive lessons yet.</p><p class="text-sm mt-1">Published lessons will appear here for you and your students.</p></div>';
            return;
        }
        list.innerHTML = lessons.map(function(lesson) {
            const lessonNumber = Number(lesson.lesson_number);
            return '<div class="bg-gradient-to-br from-purple-50 to-indigo-50 border border-purple-100 rounded-2xl p-5 hover:shadow-md transition-all">' +
                '<div class="bg-purple-500 text-white rounded-xl w-10 h-10 flex items-center justify-center text-lg mb-3"><i class="fas fa-laptop-code"></i></div>' +
                '<h3 class="font-bold text-gray-800 leading-tight">' + escHtml(lesson.title) + '</h3>' +
                '<p class="text-gray-500 text-sm mt-1">HTML interactive activity</p>' +
                (lessonNumber > 0 ? '<p class="text-purple-600 text-xs font-bold mt-2">Lesson ' + lessonNumber + '</p>' : '') +
                '<button onclick="openTeacherInteractiveLesson(' + Number(lesson.id) + ',' + lessonNumber + ')" class="w-full mt-4 bg-purple-600 hover:bg-purple-700 text-white py-2 rounded-xl text-sm font-bold transition-all">▶ Open Lesson</button>' +
                '</div>';
        }).join('');
    } catch (error) {
        list.innerHTML = '<div class="text-red-400 text-center py-8 col-span-3">⚠️ Could not load interactive lessons. Please try again.</div>';
    }
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
                <div class="w-14 h-14 rounded-full bg-gradient-to-br \${podiumColors[idx]} flex items-center justify-center text-2xl font-bold text-white border-4 border-white">\${escHtml((s.full_name||'S')[0].toUpperCase())}</div>
                <div class="text-center">
                    <div class="font-bold text-sm text-gray-800 max-w-[80px] truncate">\${escHtml(s.full_name||s.username)}</div>
                    <div class="text-yellow-500 font-bold text-sm">⭐ \${s.xp||0}</div>
                    <div class="text-gray-400 text-xs">@\${escHtml(s.username)}</div>
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
                <div class="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-400 to-purple-500 flex items-center justify-center text-lg font-bold text-white">\${escHtml((s.full_name||'S')[0].toUpperCase())}</div>
                <div class="flex-1 min-w-0">
                    <div class="font-bold text-gray-800 truncate">\${escHtml(s.full_name||s.username)}</div>
                    <div class="text-gray-400 text-xs">@\${escHtml(s.username)} · Level \${s.level||1}</div>
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
    // Group teacher's classes by school for a cleaner dropdown
    var tSchoolGroups = {};
    allClasses.forEach(function(c) {
        var grp = c.school_name || '📂 No School';
        if (!tSchoolGroups[grp]) tSchoolGroups[grp] = [];
        tSchoolGroups[grp].push(c);
    });
    var tGroupedOpts = Object.keys(tSchoolGroups).sort().map(function(grp) {
        return '<optgroup label="' + grp + '">' +
            tSchoolGroups[grp].map(function(c){ return '<option value="' + c.id + '">' + escHtml(c.name) + '</option>'; }).join('') +
            '</optgroup>';
    }).join('');
    list.innerHTML = \`<div class="space-y-3">\${pending.map(u => \`
        <div class="p-4 bg-orange-50 border border-orange-200 rounded-xl">
            <div class="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <div class="font-bold text-gray-800">\${escHtml(u.full_name)}</div>
                    <div class="text-gray-500 text-sm">@\${escHtml(u.username)} • registered \${u.created_at?.slice(0,10)||'today'}</div>
                </div>
                <div class="flex gap-2 flex-wrap items-center">
                    \${allClasses.length ? \`<select id="approveClass_\${u.id}" class="border rounded-lg px-2 py-1.5 text-xs bg-white focus:outline-none focus:border-green-400 max-w-[200px]"><option value="">— No class yet —</option>\${tGroupedOpts}</select>\` : ''}
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
                    <div class="font-semibold text-sm">\${escHtml(s.full_name)}</div>
                    <div class="text-gray-400 text-xs">@\${escHtml(s.username)}</div>
                    \${s.school_name ? \`<div class="text-purple-600 text-xs">🏫 \${escHtml(s.school_name)}</div>\` : ''}
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
                        <button onclick="openTeacherProgressReset(\${s.id}, decodeURIComponent('\${encodeURIComponent(s.full_name || s.username)}'))" class="bg-red-100 text-red-700 hover:bg-red-200 text-xs px-2 py-1 rounded-lg font-bold" title="Reset one lesson or all progress">↺</button>
                        <button onclick="togglePwForm(\${s.id})" class="bg-blue-100 text-blue-700 hover:bg-blue-200 text-xs px-2 py-1 rounded-lg font-bold" title="Reset password">🔑</button>
                        <button onclick="removeStudent(\${cls.id},\${s.id})" class="bg-red-100 text-red-600 hover:bg-red-200 text-xs px-2 py-1 rounded-lg font-bold" title="Remove from class">✕</button>
                    </div>
                </td>
            </tr>\`;
        }).join('');
        const availableOpts = available.map(s=>\`<option value="\${s.id}">\${escHtml(s.full_name)} (@\${escHtml(s.username)})</option>\`).join('');
        const div = document.createElement('div');
        div.className = 'bg-white rounded-2xl shadow p-6';
        div.innerHTML = \`
            <div class="flex flex-wrap items-start justify-between gap-3 mb-4">
                <div>
                    <h2 class="text-xl text-blue-700">🏫 \${escHtml(cls.name)}</h2>
                    \${cls.school_name ? \`<span class="inline-flex items-center gap-1 bg-purple-100 text-purple-700 text-xs font-semibold px-2 py-0.5 rounded-full mt-0.5">🏫 \${escHtml(cls.school_name)}</span>\` : ''}
                    <p class="text-gray-400 text-sm mt-0.5">\${escHtml(cls.description||'')}</p>
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
            \${available.length ? \`<div class="border-t pt-4 mt-2">
                <input type="text" placeholder="🔍 Search unassigned students..."
                    class="w-full border rounded-lg px-3 py-2 text-sm mb-2 focus:outline-none focus:border-blue-400"
                    oninput="filterTeacherStudents(\${cls.id}, this.value)">
                <div class="flex gap-2 items-center">
                    <select id="tAddSel_\${cls.id}" class="flex-1 border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-400">
                        <option value="">+ Select student to enrol...</option>\${availableOpts}
                    </select>
                    <button onclick="teacherAddStudent(\${cls.id})" class="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-bold hover:bg-blue-700">Add</button>
                </div>
            </div>\` : '<p class="text-gray-400 text-xs border-t pt-3 mt-2">All unassigned students are already enrolled.</p>'}
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

function openTeacherProgressReset(studentId, studentName) {
    teacherProgressResetStudentId = studentId;
    document.getElementById('teacherProgressResetName').textContent = studentName || 'this student';
    const select = document.getElementById('teacherProgressResetLesson');
    select.innerHTML = '<option value="all">⚠️ All progress — lessons, XP, badges and streak</option>' +
        CURRICULUM.map(lesson => '<option value="' + lesson.id + '">' + lesson.icon + ' ' + escHtml(lesson.title) + '</option>').join('');
    select.value = 'all';
    document.getElementById('teacherProgressResetMsg').classList.add('hidden');
    const modal = document.getElementById('teacherProgressResetModal');
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

async function confirmTeacherProgressReset() {
    if (!teacherProgressResetStudentId) return;
    const select = document.getElementById('teacherProgressResetLesson');
    const scope = select.value;
    const scopeLabel = scope === 'all' ? 'ALL progress' : select.options[select.selectedIndex].textContent;
    if (!confirm('Reset ' + scopeLabel + '? This student will have to complete it again.')) return;
    const msg = document.getElementById('teacherProgressResetMsg');
    msg.className = 'text-sm mb-3 text-gray-500';
    msg.textContent = 'Resetting...';
    msg.classList.remove('hidden');
    const response = await fetch('/api/teacher/students/' + teacherProgressResetStudentId + '/reset-progress', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({lesson_id: scope})
    });
    const data = await response.json();
    if (!response.ok || !data.success) {
        msg.className = 'text-sm mb-3 text-red-600';
        msg.textContent = '❌ ' + (data.error || 'Could not reset progress.');
        return;
    }
    msg.className = 'text-sm mb-3 text-green-600';
    msg.textContent = '✅ Progress reset. New XP: ' + data.xp;
    await loadClasses();
    setTimeout(() => document.getElementById('teacherProgressResetModal').classList.add('hidden'), 900);
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

function filterTeacherStudents(classId, query) {
    var sel = document.getElementById('tAddSel_' + classId);
    if (!sel) return;
    var q = query.toLowerCase().trim();
    Array.from(sel.options).forEach(function(opt) {
        if (!opt.value) return; // keep placeholder
        opt.hidden = q ? !opt.text.toLowerCase().includes(q) : false;
    });
    sel.value = ''; // reset selection when filtering
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

async function adminQuickEnroll(studentId) {
    const sel = document.getElementById('adminQaSel_' + studentId);
    if (!sel || !sel.value) { alert('Please select a class first.'); return; }
    await fetch('/api/classes/' + sel.value + '/students', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ student_id: studentId })
    });
    loadSchools();
}

function closePwModal(e) { document.getElementById('pwModal').classList.add('hidden'); }

function openMyPwModal() {
    ['myPwCurrent','myPwNew','myPwConfirm'].forEach(function(id){ document.getElementById(id).value=''; });
    var msg = document.getElementById('myPwMsg'); msg.textContent=''; msg.classList.add('hidden');
    document.getElementById('myPwModal').classList.remove('hidden');
}
async function changeMyPassword() {
    var cur = document.getElementById('myPwCurrent').value.trim();
    var nw  = document.getElementById('myPwNew').value;
    var cf  = document.getElementById('myPwConfirm').value;
    var msg = document.getElementById('myPwMsg');
    msg.className = 'text-sm'; msg.classList.remove('hidden');
    if (!cur||!nw||!cf){ msg.classList.add('text-red-600'); msg.textContent='All fields are required.'; return; }
    if (nw.length<6)   { msg.classList.add('text-red-600'); msg.textContent='New password must be at least 6 characters.'; return; }
    if (nw!==cf)       { msg.classList.add('text-red-600'); msg.textContent='Passwords do not match.'; return; }
    msg.classList.add('text-gray-500'); msg.textContent='Saving…';
    const res = await fetch('/api/auth/change-password',{
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({current_password:cur, new_password:nw})
    }).then(r=>r.json());
    if (res.success) {
        msg.className='text-sm text-green-600'; msg.textContent='✅ Password updated!';
        setTimeout(function(){ document.getElementById('myPwModal').classList.add('hidden'); }, 1500);
    } else {
        msg.className='text-sm text-red-600'; msg.textContent='❌ '+(res.error||'Failed.');
    }
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
            <button onclick="openParentPwModal()" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-full text-sm font-bold">🔒 Change Password</button>
            <button onclick="logout()" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-full text-sm font-bold">🚪 Logout</button>
        </div>
    </div>
</nav>
<div class="max-w-4xl mx-auto p-6">
    <div id="childrenContainer" class="space-y-6"></div>
</div>
<!-- Change Password Modal (parent) -->
<div id="parentPwModal" class="fixed inset-0 bg-black/50 hidden flex items-center justify-center z-50" onclick="if(event.target===this)this.classList.add('hidden')">
    <div class="bg-white rounded-2xl p-6 w-full max-w-sm shadow-2xl" onclick="event.stopPropagation()">
        <h3 class="text-lg font-bold mb-1">🔒 Change My Password</h3>
        <p class="text-gray-400 text-sm mb-4">Enter your current password to confirm, then choose a new one.</p>
        <div class="space-y-3">
            <input id="parentPwCurrent" type="password" placeholder="Current password" class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-indigo-400">
            <input id="parentPwNew" type="password" placeholder="New password (min 6 chars)" class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-indigo-400">
            <input id="parentPwConfirm" type="password" placeholder="Confirm new password" class="w-full border-2 border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-indigo-400">
            <div id="parentPwMsg" class="text-sm hidden"></div>
            <div class="flex gap-2">
                <button onclick="changeParentPassword()" class="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white py-2.5 rounded-xl font-bold">Update Password</button>
                <button onclick="document.getElementById('parentPwModal').classList.add('hidden')" class="flex-1 bg-gray-200 py-2.5 rounded-xl font-bold">Cancel</button>
            </div>
        </div>
    </div>
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
function openParentPwModal() {
    ['parentPwCurrent','parentPwNew','parentPwConfirm'].forEach(function(id){ document.getElementById(id).value=''; });
    var msg = document.getElementById('parentPwMsg'); msg.textContent=''; msg.classList.add('hidden');
    document.getElementById('parentPwModal').classList.remove('hidden');
}
async function changeParentPassword() {
    var cur = document.getElementById('parentPwCurrent').value.trim();
    var nw  = document.getElementById('parentPwNew').value;
    var cf  = document.getElementById('parentPwConfirm').value;
    var msg = document.getElementById('parentPwMsg');
    msg.className = 'text-sm'; msg.classList.remove('hidden');
    if (!cur||!nw||!cf){ msg.classList.add('text-red-600'); msg.textContent='All fields are required.'; return; }
    if (nw.length<6)   { msg.classList.add('text-red-600'); msg.textContent='New password must be at least 6 characters.'; return; }
    if (nw!==cf)       { msg.classList.add('text-red-600'); msg.textContent='Passwords do not match.'; return; }
    msg.classList.add('text-gray-500'); msg.textContent='Saving…';
    const res = await fetch('/api/auth/change-password',{
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({current_password:cur, new_password:nw})
    }).then(r=>r.json());
    if (res.success) {
        msg.className='text-sm text-green-600'; msg.textContent='✅ Password updated!';
        setTimeout(function(){ document.getElementById('parentPwModal').classList.add('hidden'); }, 1500);
    } else {
        msg.className='text-sm text-red-600'; msg.textContent='❌ '+(res.error||'Failed.');
    }
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
        document.getElementById('regForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('regBtn');
            const err = document.getElementById('errorMsg');
            const fullName = document.getElementById('full_name').value.trim();
            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value;
            const confirm = document.getElementById('confirm').value;
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
                    body: JSON.stringify({ full_name: fullName, username, password })
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
        @media (hover: none) { .feature-card:hover { transform: none; box-shadow: none; } }
        button, a { touch-action: manipulation; }
        .stat-card { background: rgba(255,255,255,0.15); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.25); }
        .section-divider { background: linear-gradient(90deg, transparent, #7c3aed, transparent); height: 2px; }
        .glow { box-shadow: 0 0 30px rgba(139,92,246,0.4); }
        .badge-pill { display: inline-flex; align-items: center; gap: 6px; background: rgba(139,92,246,0.12); color: #6d28d9; border: 1px solid rgba(139,92,246,0.3); border-radius: 999px; padding: 4px 14px; font-size: 13px; font-weight: 700; }
         .landing-lang-toggle { min-width: 76px; }
         .landing-leader-card { transition: transform 0.25s ease, box-shadow 0.25s ease; }
         .landing-leader-card:hover { transform: translateY(-4px); box-shadow: 0 16px 28px rgba(109,40,217,0.14); }
         [dir="rtl"] .landing-rtl-text { text-align: right; }
         [dir="rtl"] .landing-hero-copy { direction: rtl; }
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
        <div class="flex items-center gap-2 sm:gap-3">
            <button id="landingLangToggle" onclick="toggleLandingLanguage()" class="landing-lang-toggle px-3 py-2 rounded-full border-2 border-purple-200 text-purple-700 font-bold hover:bg-purple-50 transition-all text-sm" aria-label="Switch language">العربية</button>
            <a href="/login" data-landing-i18n="Login" class="px-4 sm:px-5 py-2 rounded-full border-2 border-purple-600 text-purple-700 font-bold hover:bg-purple-50 transition-all text-sm">Login</a>
            <a href="/register" data-landing-i18n="Register as Student" class="hidden sm:inline-block px-5 py-2 rounded-full bg-purple-600 text-white font-bold hover:bg-purple-700 transition-all text-sm shadow-md">Register as Student</a>
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
            <div class="text-white fade-in landing-hero-copy">
                <div class="badge-pill mb-6" style="background:rgba(255,255,255,0.15);color:#e9d5ff;border-color:rgba(255,255,255,0.3);">
                    <span>🏆</span> <span data-landing-i18n="Trusted by schools across the region">Trusted by schools across the region</span>
                </div>
                <h1 class="fredoka text-5xl md:text-6xl lg:text-7xl leading-tight mb-6">
                    <span data-landing-i18n="Where Kids Learn">Where Kids Learn</span><br>
                    <span style="color:#fbbf24;" data-landing-i18n="Coding & Robotics">Coding & Robotics</span><br>
                    <span data-landing-i18n="Through Play!">Through Play!</span>
                </h1>
                <p class="text-xl text-purple-200 mb-8 leading-relaxed max-w-lg" data-landing-i18n="STEMO Coding is an AI-powered interactive platform that teaches children programming and robotics through fun games, challenges, and a friendly robot guide — no prior experience needed.">
                    STEMO Coding is an AI-powered interactive platform that teaches children programming and robotics through fun games, challenges, and a friendly robot guide — no prior experience needed.
                </p>
                <div class="flex flex-wrap gap-4">
                    <a href="/register" data-landing-i18n="🚀 Start for Free" class="px-8 py-4 rounded-full bg-yellow-400 text-gray-900 font-extrabold text-lg hover:bg-yellow-300 transition-all shadow-xl glow hover:scale-105">
                        🚀 Start for Free
                    </a>
                    <a href="/login" data-landing-i18n="🔐 Login to Platform" class="px-8 py-4 rounded-full bg-white/20 text-white font-bold text-lg hover:bg-white/30 transition-all border border-white/30">
                        🔐 Login to Platform
                    </a>
                </div>
                <div class="mt-10 flex flex-wrap gap-6">
                    <div class="flex items-center gap-2 text-purple-200 text-sm font-semibold">
                        <i class="fas fa-check-circle text-green-400"></i> <span data-landing-i18n="No credit card required">No credit card required</span>
                    </div>
                    <div class="flex items-center gap-2 text-purple-200 text-sm font-semibold">
                        <i class="fas fa-check-circle text-green-400"></i> <span data-landing-i18n="Free for students">Free for students</span>
                    </div>
                    <div class="flex items-center gap-2 text-purple-200 text-sm font-semibold">
                        <i class="fas fa-check-circle text-green-400"></i> <span data-landing-i18n="Teacher-approved content">Teacher-approved content</span>
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
                <div class="text-purple-200 text-sm font-semibold" data-landing-i18n="Lessons">Lessons</div>
            </div>
            <div class="stat-card rounded-2xl p-5">
                <div class="fredoka text-4xl text-white mb-1">4</div>
                <div class="text-purple-200 text-sm font-semibold" data-landing-i18n="Difficulty Levels">Difficulty Levels</div>
            </div>
            <div class="stat-card rounded-2xl p-5">
                <div class="fredoka text-4xl text-white mb-1">50+</div>
                <div class="text-purple-200 text-sm font-semibold" data-landing-i18n="Block Types">Block Types</div>
            </div>
            <div class="stat-card rounded-2xl p-5">
                <div class="fredoka text-4xl text-white mb-1">4</div>
                <div class="text-purple-200 text-sm font-semibold" data-landing-i18n="User Roles">User Roles</div>
            </div>
            <div class="stat-card rounded-2xl p-5">
                <div class="fredoka text-4xl text-white mb-1">AI</div>
                <div class="text-purple-200 text-sm font-semibold" data-landing-i18n="Powered Tutor">Powered Tutor</div>
            </div>
        </div>
    </div>
</section>

<!-- ========== PUBLIC LEADERBOARD ========== -->
<section id="landing-leaderboard" class="py-24 bg-white">
    <div class="max-w-6xl mx-auto px-6">
        <div class="text-center mb-12">
            <span class="badge-pill mb-4">🏆 <span data-landing-i18n="Student Spotlight">Student Spotlight</span></span>
            <h2 class="fredoka text-4xl md:text-5xl text-gray-900 mb-4" data-landing-i18n="Top STEMO Coders">Top STEMO Coders</h2>
            <p class="text-gray-500 text-lg max-w-2xl mx-auto" data-landing-i18n="See who is leading the STEMO learning journey.">See who is leading the STEMO learning journey.</p>
        </div>
        <div id="landingLeaderboardList" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" aria-live="polite">
            <div class="sm:col-span-2 lg:col-span-4 text-center text-gray-400 py-10" data-landing-i18n="Loading leaderboard...">Loading leaderboard...</div>
        </div>
        <p id="landingLeaderboardNote" class="text-center text-gray-400 text-xs mt-6" data-landing-i18n="Names are shown with limited detail for student privacy.">Names are shown with limited detail for student privacy.</p>
    </div>
</section>

<!-- ========== HOW IT WORKS ========== -->
<section class="py-24 bg-gray-50">
    <div class="max-w-6xl mx-auto px-6">
        <div class="text-center mb-16">
                <span class="badge-pill mb-4">⚡ <span data-landing-i18n="Simple & Powerful">Simple & Powerful</span></span>
                <h2 class="fredoka text-4xl md:text-5xl text-gray-900 mb-4" data-landing-i18n="How STEMO Coding Works">How STEMO Coding Works</h2>
                <p class="text-gray-500 text-lg max-w-2xl mx-auto" data-landing-i18n="From registration to mastering robotics — it's a smooth, guided journey for every child.">From registration to mastering robotics — it's a smooth, guided journey for every child.</p>
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
                <div class="text-xs mt-1" data-landing-i18n="STEM Science Games Academy">STEM Science Games Academy</div>
            </div>
        </div>
    </div>
</footer>

<script>
    (function () {
        var landingArabic = {
            'Login': 'تسجيل الدخول',
            'Register as Student': 'التسجيل كطالب',
            'Trusted by schools across the region': 'موثوق به لدى المدارس في المنطقة',
            'Where Kids Learn': 'حيث يتعلّم الأطفال',
            'Coding & Robotics': 'البرمجة والروبوتات',
            'Through Play!': 'من خلال اللعب!',
            'STEMO Coding is an AI-powered interactive platform that teaches children programming and robotics through fun games, challenges, and a friendly robot guide — no prior experience needed.': 'ستيمو كودينغ منصة تفاعلية مدعومة بالذكاء الاصطناعي تعلّم الأطفال البرمجة والروبوتات من خلال الألعاب والتحديات ومرشد روبوت ودود — ولا تحتاج إلى خبرة سابقة.',
            '🚀 Start for Free': '🚀 ابدأ مجاناً',
            '🔐 Login to Platform': '🔐 الدخول إلى المنصة',
            'No credit card required': 'لا تحتاج إلى بطاقة ائتمان',
            'Free for students': 'مجاني للطلاب',
            'Teacher-approved content': 'محتوى معتمد من المعلمين',
            'Lessons': 'درساً',
            'Difficulty Levels': 'مستويات صعوبة',
            'Block Types': 'نوعاً من اللبنات',
            'User Roles': 'أدوار للمستخدمين',
            'Powered Tutor': 'معلّم ذكي',
            'Student Spotlight': 'نجوم الطلاب',
            'Top STEMO Coders': 'أفضل مبرمجي ستيمو',
            'See who is leading the STEMO learning journey.': 'تعرّف على الطلاب المتصدرين في رحلة التعلم مع ستيمو.',
            'Names are shown with limited detail for student privacy.': 'تُعرض الأسماء بتفاصيل محدودة حفاظاً على خصوصية الطلاب.',
            'Loading leaderboard...': 'جارٍ تحميل لوحة المتصدرين...',
            'Unable to load leaderboard.': 'تعذر تحميل لوحة المتصدرين.',
            'No students have earned XP yet.': 'لم يحصل أي طالب على نقاط خبرة بعد.',
            'XP': 'نقطة خبرة',
            'Level': 'المستوى',
            'Simple & Powerful': 'بسيط وقوي',
            'How STEMO Coding Works': 'كيف يعمل ستيمو كودينغ',
            'From registration to mastering robotics — it\\'s a smooth, guided journey for every child.': 'من التسجيل إلى إتقان الروبوتات — رحلة تعليمية سهلة وموجهة لكل طفل.',
            'Register & Join a Class': 'سجّل وانضم إلى فصل',
            'Students sign up, get approved by their teacher, and are placed in a class. Parents can also create accounts to monitor progress.': 'يسجّل الطلاب، ثم يوافق عليهم المعلم ويضعهم في فصل. ويمكن للوالدين إنشاء حسابات لمتابعة التقدم.',
            'Learn with STEMO Robot': 'تعلّم مع روبوت ستيمو',
            'Drag and drop colorful coding blocks to control the STEMO robot. Complete missions, earn XP, and unlock badges as you progress.': 'اسحب وأفلت لبنات البرمجة الملونة للتحكم في روبوت ستيمو. أنجز المهام واكسب نقاط الخبرة وافتح الشارات.',
            'Grow & Get Recognized': 'تطوّر واحصل على التقدير',
            'Climb the leaderboard, complete homework challenges, and receive certificates. Teachers track progress and assign custom lessons.': 'تقدّم في لوحة المتصدرين وأنجز تحديات الواجبات واحصل على الشهادات. ويتابع المعلمون تقدم الطلاب ويخصصون الدروس.',
            'Full Curriculum': 'منهج متكامل',
            '19 Lessons. Real Skills. Real Fun.': '19 درساً. مهارات حقيقية. متعة حقيقية.',
            'A complete learning journey from "what is code?" to writing reusable functions — designed for ages 7 to 16.': 'رحلة تعليمية كاملة تبدأ من سؤال "ما هي البرمجة؟" وتصل إلى كتابة الدوال القابلة لإعادة الاستخدام — مصممة للأعمار من 7 إلى 16 عاماً.',
            'Beginner': 'مبتدئ',
            'Intermediate': 'متوسط',
            'Advanced': 'متقدم',
            'Expert': 'خبير',
            'Real Programming Skills, Taught Visually': 'مهارات برمجة حقيقية تُدرّس بصرياً',
            'By the end of STEMO Coding, every student understands these core concepts — the same ones professional developers use every day.': 'بنهاية ستيمو كودينغ، يفهم كل طالب هذه المفاهيم الأساسية — وهي نفسها التي يستخدمها المطورون المحترفون يومياً.',
            'Loops': 'التكرار',
            'Conditions': 'الشروط',
            'Variables': 'المتغيرات',
            'Functions': 'الدوال',
            'Lists & Data': 'القوائم والبيانات',
            'Sensors & I/O': 'الحساسات والمدخلات والمخرجات',
            'Platform Features': 'مزايا المنصة',
            'Everything Kids Need to Thrive': 'كل ما يحتاجه الأطفال للنجاح',
            'A complete ecosystem built for modern STEAM education — engaging, measurable, and fun.': 'منظومة متكاملة للتعليم الحديث في مجالات العلوم والتقنية والهندسة والفنون والرياضيات — ممتعة وقابلة للقياس.',
            'For Schools & Teachers': 'للمدارس والمعلمين',
            'Give Your Students a': 'امنح طلابك',
            'Coding Superpower': 'قوة البرمجة الخارقة',
            'For Parents': 'للوالدين',
            'Stay Connected to Your Child\\'s Learning': 'تابع تعلم طفلك باستمرار',
            'Ready to Start the': 'هل أنت مستعد لبدء',
            'Adventure?': 'المغامرة؟',
            'Join STEMO Coding today — it\\'s free for students and takes less than 2 minutes to get started.': 'انضم إلى ستيمو كودينغ اليوم — التسجيل مجاني للطلاب ويستغرق أقل من دقيقتين.',
            'Already a Member?': 'هل أنت عضو بالفعل؟',
            'Students, teachers, parents and admins — log in to your dashboard.': 'الطلاب والمعلمون والوالدان والمديرون — سجّل الدخول إلى لوحة التحكم.',
            '🚀 Login Now': '🚀 سجّل الدخول الآن',
            'New Student?': 'طالب جديد؟',
            'Register for free and start your coding journey with STEMO today!': 'سجّل مجاناً وابدأ رحلة البرمجة مع ستيمو اليوم!',
            '🎉 Register as Student': '🎉 التسجيل كطالب',
            'AI-Powered Coding & Robotics for Kids': 'برمجة وروبوتات للأطفال بالذكاء الاصطناعي',
            'STEM Science Games Academy': 'أكاديمية ستيم لألعاب العلوم',
            'Register': 'التسجيل'
        };
        var landingEnglish = {};
        Object.keys(landingArabic).forEach(function (key) { landingEnglish[landingArabic[key]] = key; });

        function landingTextNodes() {
            var nodes = [];
            var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
            var node;
            while ((node = walker.nextNode())) {
                if (node.parentElement && !['SCRIPT', 'STYLE'].includes(node.parentElement.tagName)) nodes.push(node);
            }
            return nodes;
        }

        window.applyLandingLanguage = function (lang) {
            var isArabic = lang === 'ar';
            document.documentElement.lang = isArabic ? 'ar' : 'en';
            document.documentElement.dir = isArabic ? 'rtl' : 'ltr';
            document.body.dir = isArabic ? 'rtl' : 'ltr';
            document.querySelectorAll('[data-landing-i18n]').forEach(function (element) {
                var key = element.getAttribute('data-landing-i18n') || '';
                element.textContent = isArabic ? (landingArabic[key] || key) : key;
            });
            landingTextNodes().forEach(function (node) {
                if (node.parentElement && node.parentElement.hasAttribute('data-landing-i18n')) return;
                var original = node.__landingOriginal || node.nodeValue;
                node.__landingOriginal = original;
                var trimmed = original.trim();
                var translated = isArabic ? landingArabic[trimmed] : trimmed;
                if (isArabic && landingArabic[trimmed]) {
                    var start = original.indexOf(trimmed);
                    node.nodeValue = original.slice(0, start) + translated + original.slice(start + trimmed.length);
                } else if (!isArabic) {
                    node.nodeValue = original;
                }
            });
            var toggle = document.getElementById('landingLangToggle');
            if (toggle) {
                toggle.textContent = isArabic ? 'English' : 'العربية';
                toggle.setAttribute('aria-label', isArabic ? 'Switch to English' : 'التبديل إلى العربية');
            }
            try { localStorage.setItem('landingLang', lang); } catch (_) {}
        };

        window.toggleLandingLanguage = function () {
            var next = (document.documentElement.lang || 'en') === 'ar' ? 'en' : 'ar';
            window.applyLandingLanguage(next);
            window.loadPublicLeaderboard();
        };

        function landingEscape(value) {
            return String(value || '').replace(/[&<>"']/g, function (char) {
                return {'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[char];
            });
        }

        window.loadPublicLeaderboard = function () {
            var list = document.getElementById('landingLeaderboardList');
            if (!list) return;
            fetch('/api/public/leaderboard')
                .then(function (response) { return response.json(); })
                .then(function (data) {
                    if (!data || !Array.isArray(data.results) || data.results.length === 0) {
                        list.innerHTML = '<div class="sm:col-span-2 lg:col-span-4 text-center text-gray-400 py-10">' +
                            ((document.documentElement.lang === 'ar') ? 'لم يحصل أي طالب على نقاط خبرة بعد.' : 'No students have earned XP yet.') + '</div>';
                        return;
                    }
                    list.innerHTML = data.results.map(function (student, index) {
                        var medal = index === 0 ? '🥇' : index === 1 ? '🥈' : index === 2 ? '🥉' : '🏅';
                        var accent = index === 0 ? 'from-yellow-100 to-amber-50 border-yellow-200' :
                            index === 1 ? 'from-slate-100 to-gray-50 border-slate-200' :
                            index === 2 ? 'from-orange-100 to-amber-50 border-orange-200' :
                            'from-purple-50 to-white border-purple-100';
                        return '<div class="landing-leader-card bg-gradient-to-br ' + accent + ' border rounded-3xl p-5 text-center">' +
                            '<div class="text-4xl mb-2">' + medal + '</div>' +
                            '<div class="text-xs font-extrabold text-purple-500 mb-1">#' + student.rank + '</div>' +
                            '<div class="font-extrabold text-gray-800 truncate">' + landingEscape(student.display_name) + '</div>' +
                            '<div class="mt-3 flex items-center justify-center gap-2 text-sm font-bold text-purple-700">' +
                            '<span>⭐ ' + student.xp + ' XP</span><span class="text-gray-300">•</span><span>' +
                            ((document.documentElement.lang === 'ar') ? 'المستوى ' : 'Level ') + student.level + '</span></div></div>';
                    }).join('');
                })
                .catch(function () {
                    list.innerHTML = '<div class="sm:col-span-2 lg:col-span-4 text-center text-gray-400 py-10">' +
                        ((document.documentElement.lang === 'ar') ? 'تعذر تحميل لوحة المتصدرين.' : 'Unable to load leaderboard.') + '</div>';
                });
        };

        document.addEventListener('DOMContentLoaded', function () {
            var savedLanguage = 'en';
            try { savedLanguage = localStorage.getItem('landingLang') || 'en'; } catch (_) {}
            window.applyLandingLanguage(savedLanguage === 'ar' ? 'ar' : 'en');
            window.loadPublicLeaderboard();
        });
    })();
</script>

</body>
</html>`

// ============================================
// PAGE ROUTES
// ============================================

app.get('/login', (c) => c.html(loginPage))
app.get('/register', (c) => c.html(registerPage))

// Dashboard routes — server-side auth guards prevent unauthenticated access
app.get('/dashboard/admin', async (c) => {
    const token = getCookieToken(c.req.header('cookie') || '')
    const user = await verifyToken(token || '', c.env)
    if (!user || user.role !== 'admin') return c.redirect('/login')
    return c.html(adminDashboard)
})
app.get('/dashboard/teacher', async (c) => {
    const token = getCookieToken(c.req.header('cookie') || '')
    const user = await verifyToken(token || '', c.env)
    if (!user || user.role !== 'teacher') return c.redirect('/login')
    return c.html(teacherDashboard)
})
app.get('/dashboard/parent', async (c) => {
    const token = getCookieToken(c.req.header('cookie') || '')
    const user = await verifyToken(token || '', c.env)
    if (!user || user.role !== 'parent') return c.redirect('/login')
    return c.html(parentDashboard)
})

// Academy demo route — teachers and admins can view the academy without being redirected
app.get('/academy', async (c) => {
    const cookie = c.req.header('cookie') || ''
    const token = getCookieToken(cookie)
    if (!token) return c.redirect('/login')
    const payload = await verifyToken(token, c.env)
    if (!payload) return c.redirect('/login')
    const backUrl = payload.role === 'admin' ? '/dashboard/admin' : '/dashboard/teacher'
    // Show academy in demo mode for teachers/admins (no progress saved)
    const demoBanner = `<div style="background:#f59e0b;color:#fff;text-align:center;padding:8px 16px;font-weight:bold;font-size:14px;position:sticky;top:0;z-index:9999;">
        🎓 Preview Mode — You are viewing the academy as a ${payload.role}. <a href="${backUrl}" style="color:#fff;text-decoration:underline;margin-left:12px;">← Back to Dashboard</a>
    </div>`
    const userJson = JSON.stringify({ id: payload.id, role: payload.role, username: payload.username, full_name: payload.full_name || payload.username })
    const page = htmlContent
        .replace('<body', demoBanner + '<body')
        .replace('id="xpCounter"', `id="xpCounter" data-demo="teacher" data-user='${userJson}'`)
    return c.html(page)
})

// Main app - show landing page if not logged in, else redirect to dashboard
app.get('/', async (c) => {
    const cookie = c.req.header('cookie') || ''
    const token = getCookieToken(cookie)
    if (!token) return c.html(landingPage)
    const payload = await verifyToken(token, c.env)
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
