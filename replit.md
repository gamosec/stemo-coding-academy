# STEMO AI-Powered Robot Coding Academy

## Overview
A full-stack coding academy for children with AI-powered tutoring, visual block-based programming (Blockly), and a complete multi-role authentication system. Deployed to Cloudflare Pages with D1 database and Workers AI.

## Stack
- **Runtime**: Cloudflare Pages (Workers environment)
- **Framework**: Hono (TypeScript) — single entry point `src/index.tsx`
- **Frontend build**: Vite + `@hono/vite-dev-server` + `@hono/vite-cloudflare-pages`
- **Database**: Cloudflare D1 (`stemo-db`, ID: `ea9e6835-ab5b-4161-9268-d70b03166543`)
- **AI**: Cloudflare Workers AI (`@cf/meta/llama-3-8b-instruct`)
- **Auth**: Web Crypto API (SHA-256 password hashing, HMAC-signed JWT in HttpOnly cookie `stemo_token`)

## Architecture
All routes and HTML are in a single file: `src/index.tsx`. No separate frontend bundle — all pages are server-rendered HTML strings returned by Hono route handlers.

## Routes
| Route | Description |
|-------|-------------|
| `GET /` | Student coding academy (redirects to /login if unauthenticated) |
| `GET /login` | Login page (username + password, no email) |
| `GET /dashboard/admin` | Admin dashboard (redirects to /login if unauthenticated) |
| `GET /dashboard/teacher` | Teacher dashboard |
| `GET /dashboard/parent` | Parent view |
| `POST /api/auth/login` | Login — sets `stemo_token` cookie |
| `POST /api/auth/logout` | Logout — clears cookie |
| `GET /api/auth/me` | Returns current user from cookie |
| `GET /api/admin/users` | List all users (admin only) |
| `POST /api/admin/users` | Create user (admin only) |
| `DELETE /api/admin/users/:id` | Delete user (admin only) |
| `GET /api/admin/students` | List students (admin/teacher) |
| `GET /api/classes` | List classes (admin sees all, teacher sees own) |
| `POST /api/classes` | Create class |
| `GET /api/classes/:id/students` | Students in a class |
| `POST /api/classes/:id/students` | Add student to class |
| `GET /api/progress/:studentId` | Get student progress |
| `POST /api/progress` | Save student progress (students only) |
| `GET /api/chat/history/:studentId` | Chat history |
| `GET /api/parent/children` | Parent's linked children + progress |
| `POST /api/parent/link` | Link parent to student (admin only) |
| `GET /api/curriculum` | Curriculum data |
| `POST /api/chat` | AI chat (Workers AI) |

## User Roles
- **admin**: Full access — create/delete users, manage classes, link parents
- **teacher**: View own classes, see student progress
- **student**: Access coding academy, progress saved to D1
- **parent**: Read-only view of linked children's progress

## Default Admin
- Username: `admin`
- Password: `Admin@123`

## D1 Database Tables
- `users` — all accounts (username, password_hash, role, full_name)
- `classes` — classes with teacher_id
- `class_students` — many-to-many class/student
- `parent_students` — parent-to-student links
- `student_progress` — XP, level, completed lessons, badges, streak
- `chat_history` — AI conversation logs
- `assigned_lessons` — lessons assigned by teachers

## Development
```bash
npm run dev          # Vite dev server on port 5000
npm run build        # Build to dist/
npm run deploy       # Build + deploy to Cloudflare Pages
```

## Deployment
- Cloudflare Pages project: `stemo-coding` → `stemo-coding.pages.dev`
- GitHub repo: `gamosec/stemo-coding-academy` (auto-deploy on push)
- Account: `Khalildgamo@gmail.com`

## Important Notes
- D1 and Workers AI bindings are only available in deployed Cloudflare environment (not in `npm run dev`)
- In dev, API routes with D1 will error — the auth system is fully functional only after deployment
- The main student app HTML is the large `htmlContent` variable in `src/index.tsx` (~3800 lines)
- Progress is saved to both localStorage (fallback) and D1
