# STEMO AI-Powered Robot Coding Academy

## Overview
A full-stack coding academy for children with AI-powered tutoring, visual block-based programming (Blockly), and a complete multi-role authentication system. Deployed to Cloudflare Pages with D1 database and Workers AI.

## Stack
- **Runtime**: Cloudflare Pages (Workers environment)
- **Framework**: Hono (TypeScript) — single entry point `src/index.tsx`
- **Frontend build**: Vite + `@hono/vite-dev-server` + `@hono/vite-cloudflare-pages`
- **Database**: Cloudflare D1 (`stemo-db`, ID: `ea9e6835-ab5b-4161-9268-d70b03166543`)
- **AI**: Cloudflare Workers AI (`@cf/meta/llama-3-8b-instruct`)
- **Auth**: Web Crypto API (SHA-256 password hashing, HMAC-signed JWT — URL-safe base64, no `=` padding — stored in HttpOnly cookie `stemo_token`)

## Architecture
All routes and HTML are in a single file: `src/index.tsx`. No separate frontend bundle — all pages are server-rendered HTML strings returned by Hono route handlers.

## Routes

### Auth
| Route | Description |
|-------|-------------|
| `GET /login` | Login page |
| `GET /register` | Student self-registration (class + parent optional) |
| `POST /api/auth/login` | Login — sets `stemo_token` HttpOnly cookie |
| `POST /api/auth/logout` | Logout — clears cookie |
| `GET /api/auth/me` | Returns current user from cookie |
| `POST /api/auth/register` | Student registration (pending status; accepts class_id, parent_username) |

### Pages
| Route | Description |
|-------|-------------|
| `GET /` | Student coding academy (redirects to /login if unauthenticated) |
| `GET /dashboard/admin` | Admin dashboard |
| `GET /dashboard/teacher` | Teacher dashboard (tabs: Classes, Curriculum, Pending) |
| `GET /dashboard/parent` | Parent view |

### Admin
| Route | Description |
|-------|-------------|
| `GET /api/admin/users` | List all users |
| `POST /api/admin/users` | Create user |
| `DELETE /api/admin/users/:id` | Delete user |
| `GET /api/admin/pending` | List pending registrations (admin + teacher) |
| `POST /api/admin/users/:id/approve` | Approve or reject pending user |

### Classes
| Route | Description |
|-------|-------------|
| `GET /api/classes` | List classes (admin = all, teacher = own) |
| `POST /api/classes` | Create class (accepts teacher_id for admin) |
| `GET /api/classes/:id/students` | Students enrolled in class |
| `POST /api/classes/:id/students` | Add student to class |
| `DELETE /api/classes/:id/students/:studentId` | Remove student from class |
| `GET /api/classes/:id/available-students` | Approved students NOT in class |
| `POST /api/classes/:id/assign-lesson` | Set current lesson for class (stored in assigned_lessons) |
| `GET /api/classes/:id/assigned-lesson` | Get current assigned lesson for class |
| `GET /api/public/classes` | Public classes list (no auth, used on register page) |

### Teacher
| Route | Description |
|-------|-------------|
| `GET /api/teachers` | List approved teachers (admin only) |
| `POST /api/teacher/students/:id/reset-password` | Reset student password (teacher must own class) |

### Progress & Content
| Route | Description |
|-------|-------------|
| `GET /api/progress/:studentId` | Get student progress |
| `POST /api/progress` | Save student progress (students only) |
| `GET /api/curriculum` | Full curriculum (14 lessons) |
| `GET /api/lesson/:id` | Single lesson data |
| `GET /api/badges` | Badges list |
| `GET /api/chat/history/:studentId` | Chat history |
| `POST /api/chat` | AI chat (Workers AI) |

### Parent
| Route | Description |
|-------|-------------|
| `GET /api/parent/children` | Parent's linked children + progress |
| `POST /api/parent/link` | Link parent to student (admin only) |

## User Roles
- **admin**: Full access — create/delete users, manage all classes, link parents, assign teachers to classes
- **teacher**: Manage own classes — enrol/remove students, assign lessons, reset student passwords, approve pending students
- **student**: Access coding academy, progress saved to D1; self-register with optional class + parent link
- **parent**: Read-only view of linked children's progress

## Default Admin
- Username: `admin`
- Password: `Admin@123`

## D1 Database Tables
- `users` — accounts (username, password_hash, role, full_name, status: pending/approved/rejected)
- `classes` — classes with teacher_id
- `class_students` — many-to-many class/student
- `parent_students` — parent-to-student links
- `student_progress` — XP, level, completed_lessons JSON, earned_badges JSON, streak
- `chat_history` — AI conversation logs
- `assigned_lessons` — current lesson per class (class_id, lesson_id, assigned_by, due_date)

## Teacher Dashboard Features
- **My Classes tab**: view all enrolled students (level, XP, lessons, streak), assign current lesson to class, add/remove students, reset any student's password inline
- **Curriculum tab**: browse all 14 lessons (Basic/Intermediate/Advanced), assign any lesson to a class with one click, open the academy to demonstrate
- **Pending tab**: approve or reject student registration requests

## Admin Dashboard Features
- **Pending tab**: approve/reject new student registrations
- **Users tab**: create users (any role), view all users, delete users
- **Classes tab**: create classes with teacher assignment, view enrolled students, add/remove students
- **Parent Links tab**: link a parent account to a student

## Deployment
- Cloudflare Pages project: `stemo-coding` → `stemo-coding.pages.dev`
- Account: `Khalildgamo@gmail.com`, Account ID: `558e01efe1c43312bec3a51f5df72c2b`
- D1 database ID: `ea9e6835-ab5b-4161-9268-d70b03166543`
- Deploy command (must run from /tmp, not /home/runner/workspace):
  ```bash
  cp -r dist /tmp/stemo-distN && cd /tmp && \
  CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_API_TOKEN=... \
  npx wrangler@4.54.0 pages deploy stemo-distN --project-name stemo-coding
  ```

## Development
```bash
npm run dev    # Vite dev server on port 5000 (D1/AI not available in dev)
npm run build  # Build to dist/
```

## Internationalization
- Student academy fully supports English + Arabic (RTL): UI via I18N dict + data-i18n attrs, Blockly blocks via BLOCK_AR init wrapper, palette via PALETTE_AR/data-en, lesson/challenge/badge content via AR_L/AR_CH/AR_BADGES dicts with tr* helpers. es/fr have basic UI keys only.

## Important Notes
- D1 and Workers AI bindings are only available in the deployed Cloudflare environment
- Cookie parser uses `slice('stemo_token='.length)` (not `split('=')[1]`) to avoid truncating base64 tokens
- JWT tokens are URL-safe base64 (no `=`, `+`, `/` characters) — generated by `b64url()` helper
- All pages are inline HTML template strings inside `src/index.tsx`
