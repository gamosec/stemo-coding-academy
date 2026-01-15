# 🤖 STEMO - AI-Powered Robot Coding Academy

**STEMO** = **S**team **T**echnology **E**ducation **M**entor & **O**rganizer

A visual block-based coding platform where kids learn programming by controlling an animated robot!

## 🌐 Live Demo

**Production URL**: https://stemo-coding-academy.pages.dev

## 🚀 Quick Start - Run Locally

### Prerequisites
- Node.js 18+ installed
- npm or yarn

### Installation

```bash
# 1. Clone or extract the project
cd stemo-coding-academy

# 2. Install dependencies
npm install

# 3. Build the project
npm run build

# 4. Run locally (choose one):

# Option A: Using Wrangler (recommended - same as production)
npm run preview

# Option B: Using Wrangler with custom port
npx wrangler pages dev dist --port 3000

# Option C: Using Vite dev server
npm run dev
```

### Access the App
Open your browser and go to: **http://localhost:8788** (or port 3000 if using Option B)

## 📊 Data Storage

**No database required!** All user data is stored in the browser's `localStorage`:

| Key | Description |
|-----|-------------|
| `stemo_xp` | Total XP earned |
| `stemo_level` | Current level |
| `stemo_completed` | Array of completed lesson IDs |
| `stemo_badges` | Array of earned badge IDs |
| `stemo_streak` | Current day streak |

To reset progress, open browser console (F12) and run:
```javascript
localStorage.clear();
location.reload();
```

## ✨ Features

### 🎮 Visual Block Coding (16 Blocks)

| Category | Blocks |
|----------|--------|
| **🚶 MOVE** | Forward, Back, Left, Right, Home, Hide |
| **🎨 DRAW** | Pen, Color, Size |
| **🔁 LOOP** | Repeat |
| **🧲 ROBOT** | Magnet ON, Magnet OFF |
| **📡 SENSOR** | Scan, Auto Move, Go Target, If Wall, Smart Turn |

### 🤖 STEMO Robot Character
- Animated 2D robot with personality
- Smooth movement animations on HTML5 Canvas
- Drawing capability (like Logo/Turtle graphics)
- Magnet for picking up metal objects
- Ultrasonic sensor for wall detection

### 🎮 Interactive Board Objects
- **🔩 Metal Objects** - Place metals for magnet pickup challenges
- **🧱 Walls** - Create obstacles for navigation
- **🎯 Target** - Set destination for auto-navigation
- **📏 Distance Indicators** - Shows steps to objects

### 💬 AI Assistant Chat
- Context-aware help system
- Kid-friendly responses with emojis
- Hints when students get stuck

### 📚 Structured Curriculum (6 Lessons)
1. **Meet STEMO!** - Learn basic movement (50 XP)
2. **Movement Master** - All directions (100 XP)
3. **Start Drawing!** - Pen and colors (100 XP)
4. **Loop Power!** - Repeat blocks (150 XP)
5. **Shape Artist** - Triangles, hexagons (200 XP)
6. **Star Power!** - Draw a 5-pointed star (300 XP)

### 🏆 Gamification System
- **XP Points**: Earn rewards for completing lessons
- **Level System**: 500 XP per level
- **6 Badges** to unlock
- **Progress Tracking** with localStorage

## 🛠️ Tech Stack

- **Backend**: Hono (TypeScript)
- **Frontend**: HTML5, TailwindCSS (CDN), Blockly
- **Canvas**: HTML5 Canvas for robot animation
- **Deployment**: Cloudflare Pages
- **Storage**: Browser localStorage (no database)

## 📁 Project Structure

```
stemo-coding-academy/
├── src/
│   └── index.tsx          # Main Hono application (ALL code here!)
├── public/                # Static assets (if any)
├── dist/                  # Built output (generated)
├── ecosystem.config.cjs   # PM2 configuration (for servers)
├── vite.config.ts         # Vite build config
├── wrangler.jsonc         # Cloudflare config
├── package.json           # Dependencies
├── tsconfig.json          # TypeScript config
└── README.md              # This file
```

## 🎯 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main application page |
| `/api/curriculum` | GET | Get all lessons data |
| `/api/lesson/:id` | GET | Get specific lesson |
| `/api/badges` | GET | Get all badges |
| `/api/chat` | POST | Send message to AI assistant |
| `/api/progress` | POST | Save user progress |

## 🚀 Deployment Options

### Option 1: Cloudflare Pages (Recommended)
```bash
npm run build
npx wrangler pages deploy dist --project-name your-project-name
```

### Option 2: Any Node.js Server
```bash
npm run build
# Serve the dist folder with any static server
npx serve dist
```

### Option 3: Docker (create your own Dockerfile)
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
EXPOSE 8788
CMD ["npx", "wrangler", "pages", "dev", "dist", "--port", "8788"]
```

## 🎓 Teaching Guide

### For Instructors:
1. **Lesson 1-3**: Basic concepts (movement, drawing)
2. **Lesson 4-6**: Advanced concepts (loops, patterns)
3. **Sensor blocks**: Teach robotics concepts
4. **Challenges**: Use walls + targets for problem-solving

### Shape Formulas:
- **Square**: Repeat 4 → Forward + Right 90°
- **Triangle**: Repeat 3 → Forward + Right 120°
- **Hexagon**: Repeat 6 → Forward + Right 60°
- **Star**: Repeat 5 → Forward + Right 144°

## 📝 License

Educational project - Free to use for teaching coding to kids!

---

**Built with 💜 for young coders everywhere!**

*STEMO believes every child can learn to code! 🤖✨*
