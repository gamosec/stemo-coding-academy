# 🤖 STEMO - AI-Powered Robot Coding Academy

**STEMO** = **S**team **T**echnology **E**ducation **M**entor & **O**rganizer

A visual block-based coding platform where kids learn programming by controlling an animated robot!

## 🌐 Live Demo

**Production URL**: https://3000-i99f94vaacd0i6dz3tkwn-5634da27.sandbox.novita.ai

## ✨ Features

### 🎮 Visual Block Coding (Blockly)
- **Drag-and-drop** code blocks - no typing required!
- **Movement blocks**: Move Forward, Turn Left, Turn Right
- **Drawing blocks**: Pen Down, Pen Up, Set Color
- **Loop blocks**: Repeat X Times
- Real-time code execution with visual feedback

### 🤖 STEMO Robot Character
- Animated 2D robot with personality
- Smooth movement animations on HTML5 Canvas
- Drawing capability (like Logo/Turtle graphics)
- Direction indicator showing where STEMO is facing
- Trail visualization for pattern creation

### 💬 AI Assistant Chat
- Context-aware help system
- Kid-friendly responses with emojis
- Hints for when students get stuck
- Encouragement and celebration messages
- Answers "How do I..." questions

### 📚 Structured Curriculum
**Beginner Track (6 lessons):**
1. **Meet STEMO!** - Learn basic movement
2. **Turn Around!** - Master left/right turns
3. **Draw a Line** - Introduction to pen drawing
4. **Repeat Magic** - Loops and repetition
5. **Shape Artist** - Create triangles and shapes
6. **Star Power** - Complex patterns with loops

### 🏆 Gamification System
- **XP Points**: Earn rewards for completing lessons
- **Level System**: Progress through levels (500 XP per level)
- **Achievement Badges**:
  - 🎯 First Steps (50 XP)
  - 🚀 Robot Mover (200 XP)
  - 🎨 Code Artist (500 XP)
  - 🔄 Loop Master (750 XP)
  - ⭐ Star Coder (1000 XP)
  - 🤖 Robot's Best Friend (1500 XP)
- **Progress Tracking**: Local storage persistence
- **Day Streaks**: Keep kids coming back!

### 🎨 Kid-Friendly UI
- Colorful, playful design with gradients
- Large, easy-to-click buttons
- Animated elements (bounce, sparkle effects)
- Fun fonts (Fredoka One, Nunito)
- Responsive layout for tablets

## 🚀 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main application page |
| `/api/curriculum` | GET | Get all lessons and curriculum data |
| `/api/lesson/:id` | GET | Get specific lesson by ID |
| `/api/badges` | GET | Get all available badges |
| `/api/chat` | POST | Send message to AI assistant |
| `/api/progress` | POST | Save user progress |

## 🛠️ Tech Stack

- **Backend**: Hono (TypeScript)
- **Frontend**: HTML5, TailwindCSS, Blockly
- **Canvas**: HTML5 Canvas for robot animation
- **Deployment**: Cloudflare Pages
- **CDN Libraries**:
  - TailwindCSS (styling)
  - Font Awesome (icons)
  - Google Blockly (visual coding)

## 📁 Project Structure

```
webapp/
├── src/
│   └── index.tsx          # Main Hono application
├── public/                # Static assets
├── dist/                  # Built output
├── ecosystem.config.cjs   # PM2 configuration
├── vite.config.ts         # Vite build config
├── wrangler.jsonc         # Cloudflare config
├── package.json           # Dependencies
└── README.md              # This file
```

## 🎯 User Guide

### For Kids:
1. **Start Learning**: Click "Start Learning!" on the welcome banner
2. **Select a Lesson**: Choose from the lesson cards
3. **Code Tab**: Drag blocks from the left panel to the workspace
4. **Run**: Click the green "Run" button to see STEMO move!
5. **Get Help**: Type questions in the chat box to ask STEMO for help
6. **Earn XP**: Complete lessons to earn XP and unlock badges!

### Block Types:
- 🚶 **Move Forward**: Move STEMO 1-10 steps
- ↩️ **Turn Left**: Rotate left by degrees
- ↪️ **Turn Right**: Rotate right by degrees
- 🖍️ **Pen Down**: Start drawing
- ✏️ **Pen Up**: Stop drawing
- 🎨 **Set Color**: Change pen color
- 🔁 **Repeat**: Loop actions X times

## 🚀 Deployment

### Local Development
```bash
npm install
npm run build
npm run dev:sandbox
```

### Deploy to Cloudflare Pages
```bash
npm run build
npx wrangler pages deploy dist --project-name stemo
```

## 📊 Data Architecture

- **User Progress**: Stored in browser localStorage
  - `stemo_xp`: Total XP earned
  - `stemo_level`: Current level
  - `stemo_completed`: Array of completed lesson IDs
  - `stemo_badges`: Array of earned badge IDs
  - `stemo_streak`: Current day streak

- **Curriculum Data**: Served via API from backend
- **Chat Context**: Sent with each message for personalized responses

## 🎯 Future Enhancements (Roadmap)

- [ ] D1 Database for persistent user accounts
- [ ] Teacher dashboard for classroom management
- [ ] More lessons (50+ planned)
- [ ] Text-based coding transition
- [ ] Mobile-responsive improvements
- [ ] Voice input/output with ElevenLabs
- [ ] Multiplayer coding challenges
- [ ] User-created lesson marketplace

## 📝 License

Educational project for STEAM Academy's Smart Coding Platform.

---

**Built with 💜 for young coders everywhere!**

*STEMO believes every child can learn to code! 🤖✨*
