import { Hono } from 'hono'
import { cors } from 'hono/cors'

const app = new Hono()

// Enable CORS
app.use('/api/*', cors())

// ============================================
// CURRICULUM DATA - Lessons & Challenges
// ============================================
const curriculum = {
  beginner: [
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
      nextLesson: 'lesson-2'
    },
    {
      id: 'lesson-2',
      title: 'Movement Master',
      description: 'Learn all movement: Forward, Back, Left, Right',
      difficulty: 'easy',
      xpReward: 100,
      icon: '🚶',
      introduction: "Great job on your first lesson! Now let's learn all the ways I can move. I can go Forward, Backward, turn Left, turn Right, and even go back Home! The number on each block tells me how much to move or turn. Try clicking on the number to change it!",
      tasks: [
        { id: 't1', text: 'Add a "Forward" block and change the number to 3', completed: false },
        { id: 't2', text: 'Add a "Right" block (turn 90 degrees)', completed: false },
        { id: 't3', text: 'Add another "Forward" block with 2 steps', completed: false },
        { id: 't4', text: 'Click Run to see me walk in an L shape!', completed: false }
      ],
      hint: 'Try: Forward 3 → Right 90 → Forward 2. I will walk in an L shape!',
      nextLesson: 'lesson-3'
    },
    {
      id: 'lesson-3',
      title: 'Start Drawing!',
      description: 'Use Pen to draw lines and change colors',
      difficulty: 'easy',
      xpReward: 100,
      icon: '🎨',
      introduction: "Now for the fun part - drawing! 🖍️ By default, my pen is UP so I don't draw when I move. To start drawing, you need to put my pen DOWN first. Then when I move, I leave a colorful trail behind me! You can also change the color and size of my pen.",
      tasks: [
        { id: 't1', text: 'Add a "Pen" block and select "Down ✏️"', completed: false },
        { id: 't2', text: 'Add a "Forward" block with 5 steps', completed: false },
        { id: 't3', text: 'Click Run to draw a line!', completed: false },
        { id: 't4', text: 'Try adding a "Color" block before Pen Down to change the color', completed: false }
      ],
      hint: 'First add Pen Down, then Forward. I will draw a line! Try Color to change it.',
      nextLesson: 'lesson-4'
    },
    {
      id: 'lesson-4',
      title: 'Loop Power!',
      description: 'Use Repeat to do actions multiple times',
      difficulty: 'medium',
      xpReward: 150,
      icon: '🔁',
      introduction: "What if you want me to do the same thing many times? Instead of adding the same blocks over and over, you can use the magic REPEAT block! 🔁 Put blocks inside it, and I will do them as many times as you say. This is called a LOOP - one of the most powerful ideas in programming!",
      tasks: [
        { id: 't1', text: 'Add a "Pen Down" block first', completed: false },
        { id: 't2', text: 'Add a "Repeat" block and set it to 4 times', completed: false },
        { id: 't3', text: 'Inside the Repeat, add "Forward 4" and "Right 90"', completed: false },
        { id: 't4', text: 'Click Run to draw a perfect square! ⬛', completed: false }
      ],
      hint: 'Repeat 4 times: Forward 4, Right 90. This draws a square!',
      nextLesson: 'lesson-5'
    },
    {
      id: 'lesson-5',
      title: 'Shape Artist',
      description: 'Create triangles, hexagons and more!',
      difficulty: 'medium',
      xpReward: 200,
      icon: '📐',
      introduction: "You are becoming a shape master! 🎯 The secret to drawing any shape is knowing how much to turn. For a square, we turn 90° (because 360÷4=90). For a triangle, we turn 120° (because 360÷3=120). For a hexagon, we turn 60° (because 360÷6=60). Let's try!",
      tasks: [
        { id: 't1', text: 'Draw a Triangle: Repeat 3 times → Forward 5, Right 120°', completed: false },
        { id: 't2', text: 'Clear and try a Hexagon: Repeat 6 times → Forward 4, Right 60°', completed: false },
        { id: 't3', text: 'Experiment with different colors and sizes!', completed: false }
      ],
      hint: 'Formula: Turn angle = 360 ÷ number of sides. Triangle=120°, Hexagon=60°',
      nextLesson: 'lesson-6'
    },
    {
      id: 'lesson-6',
      title: 'Star Power!',
      description: 'Draw a beautiful 5-pointed star',
      difficulty: 'hard',
      xpReward: 300,
      icon: '⭐',
      introduction: "The final challenge! ⭐ Drawing a star is special because we don't turn the normal amount - we turn MORE! For a 5-pointed star, we turn 144° (that's 180° minus 36°). This makes the lines cross over each other to create the star shape. At the end, use Hide to see your masterpiece!",
      tasks: [
        { id: 't1', text: 'Add "Pen Down" to start drawing', completed: false },
        { id: 't2', text: 'Add "Repeat 5 times"', completed: false },
        { id: 't3', text: 'Inside: "Forward 8" and "Right 144"', completed: false },
        { id: 't4', text: 'Add "Hide" at the end to see your star clearly!', completed: false },
        { id: 't5', text: 'Click Run and celebrate! 🎉', completed: false }
      ],
      hint: 'Star secret: Turn 144° (not 72°). Repeat 5 → Forward 8, Right 144, then Hide!',
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
  const lesson = curriculum.beginner.find(l => l.id === id)
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
  const { message, context } = await c.req.json()
  const responses = generateAIResponse(message, context)
  return c.json({ 
    response: responses,
    character: 'stemo'
  })
})

// Helper function for AI responses
function generateAIResponse(message: string, context: any): string {
  const lowerMessage = message.toLowerCase()
  
  if (lowerMessage.includes('hello') || lowerMessage.includes('hi')) {
    return "🤖 Beep boop! Hi there, young coder! I'm STEMO, your robot coding buddy! Ready to create something amazing together? Let's make magic with code! ✨"
  }
  
  if (lowerMessage.includes('move') || lowerMessage.includes('forward')) {
    return "🤖 Want to make me move? Just drag the 'Move Forward' block from the left side! Each block makes me take one step. Try stacking them to make me walk further! 🚶"
  }
  
  if (lowerMessage.includes('turn') || lowerMessage.includes('rotate')) {
    return "🤖 Turning is easy! Use the 'Turn Left' or 'Turn Right' blocks. I'll spin 90 degrees - that's like turning at a corner! Try it and watch me spin! 🔄"
  }
  
  if (lowerMessage.includes('draw') || lowerMessage.includes('pen')) {
    return "🤖 I love drawing! Use 'Pen Down' to start my crayon, then move around. I'll leave a colorful trail behind me! Use 'Pen Up' when you're done. 🖍️"
  }
  
  if (lowerMessage.includes('loop') || lowerMessage.includes('repeat')) {
    return "🤖 Loops are super cool! Instead of using the same block 4 times, put it inside a 'Repeat' block. It's like telling me 'do this 4 times' - way less work! 🔁"
  }
  
  if (lowerMessage.includes('square') || lowerMessage.includes('shape')) {
    return "🤖 A square has 4 equal sides and 4 corners! Try: Repeat 4 times → Move Forward + Turn Right. The turn makes me go around each corner! 📦"
  }
  
  if (lowerMessage.includes('triangle')) {
    return "🤖 Triangles are tricky but fun! They have 3 sides. The secret: turn 120 degrees (not 90!) between each side. Repeat 3 times → Move + Turn 120! 🔺"
  }
  
  if (lowerMessage.includes('stuck') || lowerMessage.includes('help') || lowerMessage.includes("don't know")) {
    return "🤖 Don't worry, getting stuck is part of learning! Let me give you a hint: Start with just one block, click Run, and see what happens. Then add more blocks one at a time. Baby steps! 💪"
  }
  
  if (lowerMessage.includes('error') || lowerMessage.includes('wrong') || lowerMessage.includes('not working')) {
    return "🤖 Oops! Errors are just puzzles to solve! Check your blocks - are they connected properly? Try clicking the 🗑️ to clear and start fresh. I believe in you! 🌟"
  }
  
  if (lowerMessage.includes('what can you') || lowerMessage.includes('what do you')) {
    return "🤖 I can do lots of things! I can move around, turn, draw colorful patterns, and best of all - I can help you learn coding! Just tell me what you want to create, and we'll figure it out together! 🎨"
  }
  
  if (lowerMessage.includes('hard') || lowerMessage.includes('difficult')) {
    return "🤖 Coding can feel hard at first, but guess what? You're already doing great by trying! Every expert was once a beginner. Take a deep breath, try one small step, and celebrate each win! 🎉"
  }
  
  return "🤖 Beep boop! Great question! I'm here to help you code. Try dragging blocks from the left panel and clicking 'Run' to see what happens. If you get stuck, just ask me! We're a team! 🤝"
}

// Save progress
app.post('/api/progress', async (c) => {
  const progress = await c.req.json()
  return c.json({ success: true, message: 'Progress saved!' })
})

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
            background: white;
            color: #6366f1;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .tab-inactive { background: transparent; color: white; }
        
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
                <div class="text-4xl bounce-animation">🤖</div>
                <div>
                    <h1 class="logo-text text-2xl tracking-wide">STEMO</h1>
                    <p class="text-xs text-purple-200">AI Coding Academy</p>
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
                <div class="w-10 h-10 bg-gradient-to-br from-yellow-400 to-orange-500 rounded-full flex items-center justify-center text-xl cursor-pointer">
                    👦
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="max-w-7xl mx-auto p-6">
        <!-- Tabs -->
        <div class="flex gap-2 mb-6 bg-indigo-500 rounded-full p-1 w-fit">
            <button onclick="switchTab('learn')" id="tab-learn" class="tab-active px-6 py-2 rounded-full font-bold transition-all">
                <i class="fas fa-graduation-cap mr-2"></i>Learn
            </button>
            <button onclick="switchTab('code')" id="tab-code" class="tab-inactive px-6 py-2 rounded-full font-bold transition-all">
                <i class="fas fa-code mr-2"></i>Code
            </button>
            <button onclick="switchTab('achievements')" id="tab-achievements" class="tab-inactive px-6 py-2 rounded-full font-bold transition-all">
                <i class="fas fa-trophy mr-2"></i>Achievements
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

            <h3 class="text-2xl font-bold text-gray-800 mb-4">
                <i class="fas fa-book-open text-indigo-500 mr-2"></i>Beginner Lessons
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
                    
                    <!-- Tasks -->
                    <div class="p-6">
                        <h3 class="text-lg font-bold text-gray-800 mb-4">
                            <i class="fas fa-tasks text-indigo-500 mr-2"></i>Your Tasks:
                        </h3>
                        <div id="lessonTasks" class="space-y-3">
                            <!-- Tasks will be inserted here -->
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
                <div id="robotPanel" class="bg-gradient-to-b from-cyan-50 to-blue-50 border-l-2 border-gray-200 flex flex-col flex-shrink-0 transition-all duration-300" style="width: 430px;">
                    <div class="bg-gradient-to-r from-blue-500 to-cyan-500 text-white p-2 flex items-center justify-between">
                        <div class="flex items-center gap-2">
                            <span class="text-xl">🤖</span>
                            <span class="font-bold">STEMO's World</span>
                        </div>
                        <div class="flex gap-1">
                            <button onclick="setPlacementMode('metal')" id="modeMetalBtn" class="bg-yellow-500 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Place Metal">
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
                            <button onclick="clearAll()" class="bg-white/20 hover:bg-white/30 text-white px-2 py-1 rounded-full text-xs font-bold transition-all" title="Clear All">
                                🗑️
                            </button>
                        </div>
                    </div>
                    <!-- Placement mode indicator -->
                    <div class="bg-gray-100 px-2 py-1 text-xs text-center">
                        <span id="placementModeText">Click to place: 🔩 Metal</span>
                    </div>
                    <div class="flex-1 p-2 flex items-center justify-center overflow-hidden">
                        <canvas id="robotCanvas" width="400" height="400" class="rounded-xl shadow-lg cursor-crosshair" onclick="handleCanvasClick(event)"></canvas>
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
        
        // Ultrasonic sensor settings
        var sensorRange = 100; // pixels (5 steps)
        var showSensorBeam = true;

        // ============================================
        // INITIALIZATION
        // ============================================
        document.addEventListener('DOMContentLoaded', function() {
            console.log('STEMO initializing...');
            updateUI();
            loadLessons();
            loadBadges();
            initBlockly();
            drawRobot();
            console.log('STEMO ready!');
        });

        function updateUI() {
            document.getElementById('xpCounter').textContent = stemo.xp;
            document.getElementById('levelCounter').textContent = stemo.level;
            document.getElementById('totalXP').textContent = stemo.xp;
            document.getElementById('lessonsCompleted').textContent = stemo.completedLessons.length;
            document.getElementById('streakDays').textContent = stemo.streak;
            document.getElementById('badgesEarned').textContent = stemo.badges.length;
        }

        function saveProgress() {
            localStorage.setItem('stemo_xp', stemo.xp);
            localStorage.setItem('stemo_level', stemo.level);
            localStorage.setItem('stemo_completed', JSON.stringify(stemo.completedLessons));
            localStorage.setItem('stemo_badges', JSON.stringify(stemo.badges));
            localStorage.setItem('stemo_streak', stemo.streak);
        }

        // ============================================
        // LESSONS
        // ============================================
        function loadLessons() {
            fetch('/api/curriculum')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    var grid = document.getElementById('lessonsGrid');
                    var html = '';
                    
                    data.beginner.forEach(function(lesson, index) {
                        var isCompleted = stemo.completedLessons.includes(lesson.id);
                        var isLocked = index > 0 && !stemo.completedLessons.includes(data.beginner[index-1].id);
                        var lessonIcon = lesson.icon || '📚';
                        var icon = isCompleted ? '✅' : (isLocked ? '🔒' : lessonIcon);
                        
                        var diffGradient = lesson.difficulty === 'easy' ? 'from-green-400 to-emerald-500' : 
                                          (lesson.difficulty === 'medium' ? 'from-yellow-400 to-orange-500' : 'from-red-400 to-pink-500');
                        var diffClass = lesson.difficulty === 'easy' ? 'bg-green-100 text-green-700' :
                                       (lesson.difficulty === 'medium' ? 'bg-yellow-100 text-yellow-700' : 'bg-red-100 text-red-700');
                        
                        html += '<div class="lesson-card bg-white rounded-2xl card-shadow overflow-hidden cursor-pointer ' + (isLocked ? 'opacity-60' : '') + '" ' +
                                (isLocked ? '' : 'onclick="selectLesson(\\'' + lesson.id + '\\')"') + '>' +
                                '<div class="h-3 bg-gradient-to-r ' + diffGradient + '"></div>' +
                                '<div class="p-5">' +
                                '<div class="flex items-center justify-between mb-3">' +
                                '<span class="text-3xl">' + icon + '</span>' +
                                '<span class="bg-yellow-100 text-yellow-700 px-3 py-1 rounded-full text-sm font-bold">+' + lesson.xpReward + ' XP</span>' +
                                '</div>' +
                                '<h4 class="font-bold text-lg text-gray-800 mb-1">' + lesson.title + '</h4>' +
                                '<p class="text-gray-500 text-sm mb-3">' + lesson.description + '</p>' +
                                '<div class="flex items-center gap-2">' +
                                '<span class="text-xs px-2 py-1 rounded-full ' + diffClass + '">' + lesson.difficulty + '</span>' +
                                (isCompleted ? '<span class="text-xs text-green-600 font-bold">Completed!</span>' : '') +
                                '</div></div></div>';
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
            
            // Set up the code view
            document.getElementById('currentLessonTitle').textContent = currentLesson.title;
            document.getElementById('currentLessonDesc').textContent = currentLesson.description;
            document.getElementById('hintText').textContent = currentLesson.hint;
            document.getElementById('hintPanel').classList.remove('hidden');
            
            // Hide lesson detail and switch to code
            document.getElementById('lessonDetailPanel').classList.add('hidden');
            document.getElementById('lessonsGrid').style.display = 'grid';
            
            switchTab('code');
            resetRobot();
            clearWorkspace();
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
                    .appendField(new Blockly.FieldColour('#6366f1'), "COLOR");
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
                            setTimeout(executeNext, 200);
                        });
                    }
                    return;
                }
                
                executeCommand(cmd);
                drawRobot();
                
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
                    // Magnet OFF - drop the object BEHIND the robot (so it's visible)
                    if (robot.carrying) {
                        // Drop 40 pixels behind robot's current direction
                        var dropRad = robot.angle * Math.PI / 180;
                        var dropX = robot.x - Math.cos(dropRad) * 40;
                        var dropY = robot.y - Math.sin(dropRad) * 40;
                        
                        // Keep within bounds
                        dropX = Math.max(25, Math.min(375, dropX));
                        dropY = Math.max(25, Math.min(375, dropY));
                        
                        robot.carrying.x = dropX;
                        robot.carrying.y = dropY;
                        robot.carrying.pickedUp = false;
                        addChatMessage('stemo', "🤖 🧲 Dropped the " + robot.carrying.type + " behind me! 📍");
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
                    robot.spraying = true;
                    
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
            wallObjects.forEach(function(wall) {
                ctx.save();
                
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
                
                // Horizontal brick lines
                for (var by = wall.y + 10; by < wall.y + wall.height; by += 10) {
                    ctx.beginPath();
                    ctx.moveTo(wall.x, by);
                    ctx.lineTo(wall.x + wall.width, by);
                    ctx.stroke();
                }
                
                // Vertical brick lines (staggered)
                var rowIndex = 0;
                for (var by = wall.y; by < wall.y + wall.height; by += 10) {
                    var offset = (rowIndex % 2) * 10;
                    for (var bx = wall.x + offset; bx < wall.x + wall.width; bx += 20) {
                        ctx.beginPath();
                        ctx.moveTo(bx, by);
                        ctx.lineTo(bx, Math.min(by + 10, wall.y + wall.height));
                        ctx.stroke();
                    }
                    rowIndex++;
                }
                
                ctx.restore();
            });
            
            // Draw target point
            if (targetPoint) {
                ctx.save();
                
                // Pulsing effect
                var pulse = 1 + 0.1 * Math.sin(Date.now() / 200);
                
                // Target outer ring
                ctx.strokeStyle = '#22c55e';
                ctx.lineWidth = 3;
                ctx.beginPath();
                ctx.arc(targetPoint.x, targetPoint.y, 20 * pulse, 0, Math.PI * 2);
                ctx.stroke();
                
                // Target middle ring
                ctx.strokeStyle = '#16a34a';
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.arc(targetPoint.x, targetPoint.y, 12 * pulse, 0, Math.PI * 2);
                ctx.stroke();
                
                // Target center
                ctx.fillStyle = '#22c55e';
                ctx.beginPath();
                ctx.arc(targetPoint.x, targetPoint.y, 5, 0, Math.PI * 2);
                ctx.fill();
                
                // Flag
                ctx.fillStyle = '#22c55e';
                ctx.beginPath();
                ctx.moveTo(targetPoint.x, targetPoint.y - 5);
                ctx.lineTo(targetPoint.x, targetPoint.y - 30);
                ctx.lineTo(targetPoint.x + 15, targetPoint.y - 22);
                ctx.lineTo(targetPoint.x, targetPoint.y - 15);
                ctx.fill();
                
                // Distance to target
                var dx = targetPoint.x - robot.x;
                var dy = targetPoint.y - robot.y;
                var distSteps = Math.round(Math.sqrt(dx * dx + dy * dy) / 20);
                
                ctx.fillStyle = '#166534';
                ctx.font = 'bold 10px Arial';
                ctx.textAlign = 'center';
                ctx.fillText('🎯 ' + distSteps + ' steps', targetPoint.x, targetPoint.y + 35);
                
                ctx.restore();
            }
            
            // Draw ultrasonic sensor beam
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
                ctx.arc(robot.x, robot.y, beamLength, 
                    (robot.angle - coneWidth) * Math.PI / 180,
                    (robot.angle + coneWidth) * Math.PI / 180);
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
            
            // Draw metal objects on the board with distance indicators
            metalObjects.forEach(function(metal) {
                if (!metal.pickedUp) {
                    // Calculate distance from robot to metal (in steps)
                    var dx = metal.x - robot.x;
                    var dy = metal.y - robot.y;
                    var distPixels = Math.sqrt(dx * dx + dy * dy);
                    var distSteps = Math.round(distPixels / 20); // 1 step = 20 pixels
                    
                    // Draw dashed line from robot to metal (distance indicator)
                    ctx.save();
                    ctx.strokeStyle = '#f97316';
                    ctx.lineWidth = 1;
                    ctx.setLineDash([4, 4]);
                    ctx.globalAlpha = 0.5;
                    ctx.beginPath();
                    ctx.moveTo(robot.x, robot.y);
                    ctx.lineTo(metal.x, metal.y);
                    ctx.stroke();
                    ctx.setLineDash([]);
                    ctx.globalAlpha = 1;
                    ctx.restore();
                    
                    // Draw distance label at midpoint
                    var midX = (robot.x + metal.x) / 2;
                    var midY = (robot.y + metal.y) / 2;
                    ctx.save();
                    ctx.fillStyle = '#ea580c';
                    ctx.font = 'bold 11px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillStyle = 'white';
                    ctx.beginPath();
                    ctx.roundRect(midX - 18, midY - 8, 36, 16, 4);
                    ctx.fill();
                    ctx.fillStyle = '#ea580c';
                    ctx.fillText(distSteps + ' steps', midX, midY + 4);
                    ctx.restore();
                    
                    ctx.save();
                    ctx.translate(metal.x, metal.y);
                    
                    // Glow effect for metals
                    ctx.shadowColor = '#ef4444';
                    ctx.shadowBlur = 8;
                    
                    // Draw based on metal type
                    if (metal.type === 'bolt') {
                        // Draw bolt 🔩
                        ctx.fillStyle = '#94a3b8';
                        ctx.beginPath();
                        ctx.arc(0, 0, 10, 0, Math.PI * 2);
                        ctx.fill();
                        ctx.fillStyle = '#475569';
                        ctx.beginPath();
                        ctx.arc(0, 0, 5, 0, Math.PI * 2);
                        ctx.fill();
                        // Hex pattern
                        ctx.strokeStyle = '#334155';
                        ctx.lineWidth = 2;
                        ctx.beginPath();
                        for (var h = 0; h < 6; h++) {
                            var hAngle = h * Math.PI / 3;
                            var hx = Math.cos(hAngle) * 7;
                            var hy = Math.sin(hAngle) * 7;
                            if (h === 0) ctx.moveTo(hx, hy);
                            else ctx.lineTo(hx, hy);
                        }
                        ctx.closePath();
                        ctx.stroke();
                    } else if (metal.type === 'gear') {
                        // Draw gear ⚙️
                        ctx.fillStyle = '#78716c';
                        ctx.beginPath();
                        ctx.arc(0, 0, 12, 0, Math.PI * 2);
                        ctx.fill();
                        // Teeth
                        ctx.fillStyle = '#57534e';
                        for (var t = 0; t < 8; t++) {
                            var tAngle = t * Math.PI / 4;
                            ctx.save();
                            ctx.rotate(tAngle);
                            ctx.fillRect(-3, 10, 6, 5);
                            ctx.restore();
                        }
                        // Center hole
                        ctx.fillStyle = '#fef3c7';
                        ctx.beginPath();
                        ctx.arc(0, 0, 4, 0, Math.PI * 2);
                        ctx.fill();
                    } else if (metal.type === 'screw') {
                        // Draw screw 🪛
                        ctx.fillStyle = '#a1a1aa';
                        ctx.beginPath();
                        ctx.ellipse(0, 0, 6, 10, 0, 0, Math.PI * 2);
                        ctx.fill();
                        // Slot
                        ctx.strokeStyle = '#52525b';
                        ctx.lineWidth = 2;
                        ctx.beginPath();
                        ctx.moveTo(-4, 0);
                        ctx.lineTo(4, 0);
                        ctx.stroke();
                    } else {
                        // Default metal piece
                        ctx.fillStyle = '#71717a';
                        ctx.beginPath();
                        ctx.arc(0, 0, 8, 0, Math.PI * 2);
                        ctx.fill();
                    }
                    
                    ctx.restore();
                }
            });
            
            // Draw fire objects on the board
            fireObjects.forEach(function(fire) {
                ctx.save();
                ctx.translate(fire.x, fire.y);
                
                // Pulsing/flickering effect
                var flicker = 1 + 0.2 * Math.sin(Date.now() / 100 + fire.id);
                
                // Fire glow
                ctx.shadowColor = '#ff6b35';
                ctx.shadowBlur = 20 * flicker;
                
                // Base fire - outer orange
                ctx.fillStyle = '#ff6b35';
                ctx.beginPath();
                ctx.ellipse(0, 5, 15 * flicker, 8 * flicker, 0, 0, Math.PI * 2);
                ctx.fill();
                
                // Inner yellow flame
                ctx.fillStyle = '#ffc107';
                ctx.beginPath();
                ctx.ellipse(0, 0, 10 * flicker, 18 * flicker, 0, 0, Math.PI * 2);
                ctx.fill();
                
                // Hot center
                ctx.fillStyle = '#fff3cd';
                ctx.beginPath();
                ctx.ellipse(0, 3, 5 * flicker, 10 * flicker, 0, 0, Math.PI * 2);
                ctx.fill();
                
                // Draw flame tips
                ctx.fillStyle = '#ff6b35';
                for (var f = 0; f < 5; f++) {
                    var fAngle = (f - 2) * 0.3;
                    var fHeight = 15 + Math.random() * 10;
                    ctx.beginPath();
                    ctx.moveTo(Math.sin(fAngle) * 5, 5);
                    ctx.quadraticCurveTo(
                        Math.sin(fAngle + 0.5) * 8 * flicker, -fHeight/2,
                        Math.sin(fAngle) * 3, -fHeight * flicker
                    );
                    ctx.quadraticCurveTo(
                        Math.sin(fAngle - 0.5) * 8 * flicker, -fHeight/2,
                        Math.sin(fAngle) * 5, 5
                    );
                    ctx.fill();
                }
                
                // Health indicator (how many sprays to extinguish)
                ctx.shadowBlur = 0;
                ctx.fillStyle = '#dc2626';
                ctx.font = 'bold 10px Arial';
                ctx.textAlign = 'center';
                ctx.fillText('🔥' + fire.health + '/3', 0, 35);
                
                // Distance indicator
                var dx = fire.x - robot.x;
                var dy = fire.y - robot.y;
                var distSteps = Math.round(Math.sqrt(dx * dx + dy * dy) / 20);
                
                ctx.fillStyle = '#fff';
                ctx.strokeStyle = '#dc2626';
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.roundRect(-20, -40, 40, 16, 4);
                ctx.fill();
                ctx.stroke();
                ctx.fillStyle = '#dc2626';
                ctx.fillText(distSteps + ' steps', 0, -28);
                
                ctx.restore();
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
                
                // Magnet indicator when ON
                if (robot.magnetOn) {
                    ctx.strokeStyle = '#fbbf24';
                    ctx.lineWidth = 3;
                    ctx.setLineDash([4, 4]);
                    ctx.beginPath();
                    ctx.arc(0, 0, 35, 0, Math.PI * 2);
                    ctx.stroke();
                    ctx.setLineDash([]);
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
            
            // Complete lesson if robot moved or drew anything
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
                        xp: stemo.xp
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
            document.getElementById('learn-section').classList.add('hidden');
            document.getElementById('code-section').classList.add('hidden');
            document.getElementById('achievements-section').classList.add('hidden');
            
            document.getElementById('tab-learn').className = 'tab-inactive px-6 py-2 rounded-full font-bold transition-all';
            document.getElementById('tab-code').className = 'tab-inactive px-6 py-2 rounded-full font-bold transition-all';
            document.getElementById('tab-achievements').className = 'tab-inactive px-6 py-2 rounded-full font-bold transition-all';
            
            document.getElementById(tab + '-section').classList.remove('hidden');
            document.getElementById('tab-' + tab).className = 'tab-active px-6 py-2 rounded-full font-bold transition-all';
            
            // Resize Blockly when switching to code tab
            if (tab === 'code' && workspace) {
                setTimeout(function() {
                    Blockly.svgResize(workspace);
                }, 100);
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
        
        function addFireAt(x, y) {
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
            metalObjects = [];
            wallObjects = [];
            fireObjects = [];
            targetPoint = null;
            if (robot.carrying) {
                robot.carrying = null;
                robot.magnetOn = false;
            }
            robot.waterLevel = 5; // Refill water
            robot.spraying = false;
            drawRobot();
            addChatMessage('stemo', "🤖 🗑️ Board cleared! Water refilled 💧. Click buttons to add walls, metals, fires, or targets.");
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

app.get('/', (c) => {
  return c.html(htmlContent)
})

export default app
