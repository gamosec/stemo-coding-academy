import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-pages'

const app = new Hono()

// Enable CORS
app.use('/api/*', cors())

// Serve static files
app.use('/static/*', serveStatic())

// ============================================
// CURRICULUM DATA - Lessons & Challenges
// ============================================
const curriculum = {
  beginner: [
    {
      id: 'lesson-1',
      title: 'Meet STEMO!',
      description: 'Learn to make STEMO move forward',
      difficulty: 'easy',
      xpReward: 50,
      objectives: ['Move STEMO forward', 'Understand basic commands'],
      hint: 'Use the MOVE FORWARD block to make STEMO take a step!',
      challenge: {
        goal: 'Move STEMO to the star',
        targetSteps: 3,
        starPosition: { x: 400, y: 300 }
      }
    },
    {
      id: 'lesson-2',
      title: 'Turn Around!',
      description: 'Learn to turn STEMO left and right',
      difficulty: 'easy',
      xpReward: 75,
      objectives: ['Turn STEMO left', 'Turn STEMO right', 'Combine moves and turns'],
      hint: 'Use TURN blocks to change direction, then MOVE to go that way!',
      challenge: {
        goal: 'Navigate STEMO around the obstacle',
        targetSteps: 5,
        starPosition: { x: 500, y: 200 }
      }
    },
    {
      id: 'lesson-3',
      title: 'Draw a Line',
      description: 'Make STEMO draw while moving',
      difficulty: 'easy',
      xpReward: 100,
      objectives: ['Enable pen down', 'Draw a straight line', 'Change pen color'],
      hint: 'Use PEN DOWN before moving to draw a trail!',
      challenge: {
        goal: 'Draw a line from start to finish',
        targetSteps: 4,
        starPosition: { x: 550, y: 300 }
      }
    },
    {
      id: 'lesson-4',
      title: 'Repeat Magic',
      description: 'Use loops to repeat actions',
      difficulty: 'medium',
      xpReward: 150,
      objectives: ['Use the REPEAT block', 'Draw a square using loops'],
      hint: 'A square has 4 sides - use REPEAT 4 TIMES!',
      challenge: {
        goal: 'Draw a square using a loop',
        targetSteps: 2,
        starPosition: { x: 400, y: 300 }
      }
    },
    {
      id: 'lesson-5',
      title: 'Shape Artist',
      description: 'Create triangles and other shapes',
      difficulty: 'medium',
      xpReward: 200,
      objectives: ['Draw a triangle', 'Understand angles', 'Combine shapes'],
      hint: 'A triangle has 3 sides - turn 120 degrees between each side!',
      challenge: {
        goal: 'Draw a triangle',
        targetSteps: 2,
        starPosition: { x: 400, y: 300 }
      }
    },
    {
      id: 'lesson-6',
      title: 'Star Power',
      description: 'Draw a beautiful star pattern',
      difficulty: 'hard',
      xpReward: 300,
      objectives: ['Draw a 5-pointed star', 'Master complex angles'],
      hint: 'Turn 144 degrees (that\'s 180-36) to make star points!',
      challenge: {
        goal: 'Draw a 5-pointed star',
        targetSteps: 2,
        starPosition: { x: 400, y: 300 }
      }
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
  { id: 'robot-friend', name: 'Robot\'s Best Friend', description: 'Chat with STEMO 50 times', icon: '🤖', xpRequired: 1500 }
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

// AI Chat endpoint (simulated for demo - integrates with AI in production)
app.post('/api/chat', async (c) => {
  const { message, context } = await c.req.json()
  
  // Simulated AI responses based on context
  const responses = generateAIResponse(message, context)
  
  return c.json({ 
    response: responses,
    character: 'stemo'
  })
})

// Helper function for AI responses
function generateAIResponse(message: string, context: any): string {
  const lowerMessage = message.toLowerCase()
  
  // Greeting responses
  if (lowerMessage.includes('hello') || lowerMessage.includes('hi')) {
    return "🤖 Beep boop! Hi there, young coder! I'm STEMO, your robot coding buddy! Ready to create something amazing together? Let's make magic with code! ✨"
  }
  
  // Help with moving
  if (lowerMessage.includes('move') || lowerMessage.includes('forward')) {
    return "🤖 Want to make me move? Just drag the 'Move Forward' block from the left side! Each block makes me take one step. Try stacking them to make me walk further! 🚶"
  }
  
  // Help with turning
  if (lowerMessage.includes('turn') || lowerMessage.includes('rotate')) {
    return "🤖 Turning is easy! Use the 'Turn Left' or 'Turn Right' blocks. I'll spin 90 degrees - that's like turning at a corner! Try it and watch me spin! 🔄"
  }
  
  // Help with drawing
  if (lowerMessage.includes('draw') || lowerMessage.includes('pen')) {
    return "🤖 I love drawing! Use 'Pen Down' to start my crayon, then move around. I'll leave a colorful trail behind me! Use 'Pen Up' when you're done. 🖍️"
  }
  
  // Help with loops
  if (lowerMessage.includes('loop') || lowerMessage.includes('repeat')) {
    return "🤖 Loops are super cool! Instead of using the same block 4 times, put it inside a 'Repeat' block. It's like telling me 'do this 4 times' - way less work! 🔁"
  }
  
  // Help with shapes
  if (lowerMessage.includes('square') || lowerMessage.includes('shape')) {
    return "🤖 A square has 4 equal sides and 4 corners! Try: Repeat 4 times → Move Forward + Turn Right. The turn makes me go around each corner! 📦"
  }
  
  // Help with triangle
  if (lowerMessage.includes('triangle')) {
    return "🤖 Triangles are tricky but fun! They have 3 sides. The secret: turn 120 degrees (not 90!) between each side. Repeat 3 times → Move + Turn 120! 🔺"
  }
  
  // Stuck or confused
  if (lowerMessage.includes('stuck') || lowerMessage.includes('help') || lowerMessage.includes("don't know")) {
    return "🤖 Don't worry, getting stuck is part of learning! Let me give you a hint: Start with just one block, click Run, and see what happens. Then add more blocks one at a time. Baby steps! 💪"
  }
  
  // Error or wrong
  if (lowerMessage.includes('error') || lowerMessage.includes('wrong') || lowerMessage.includes('not working')) {
    return "🤖 Oops! Errors are just puzzles to solve! Check your blocks - are they connected properly? Try clicking the 🗑️ to clear and start fresh. I believe in you! 🌟"
  }
  
  // What can you do
  if (lowerMessage.includes('what can you') || lowerMessage.includes('what do you')) {
    return "🤖 I can do lots of things! I can move around, turn, draw colorful patterns, and best of all - I can help you learn coding! Just tell me what you want to create, and we'll figure it out together! 🎨"
  }
  
  // Encouragement
  if (lowerMessage.includes('hard') || lowerMessage.includes('difficult')) {
    return "🤖 Coding can feel hard at first, but guess what? You're already doing great by trying! Every expert was once a beginner. Take a deep breath, try one small step, and celebrate each win! 🎉"
  }
  
  // Default response
  return "🤖 Beep boop! Great question! I'm here to help you code. Try dragging blocks from the left panel and clicking 'Run' to see what happens. If you get stuck, just ask me! We're a team! 🤝"
}

// Save progress
app.post('/api/progress', async (c) => {
  const progress = await c.req.json()
  // In production, this would save to D1 database
  return c.json({ success: true, message: 'Progress saved!' })
})

// ============================================
// MAIN PAGE
// ============================================
app.get('/', (c) => {
  return c.html(`<!DOCTYPE html>
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
        
        * {
            font-family: 'Nunito', sans-serif;
        }
        
        h1, h2, h3, .logo-text {
            font-family: 'Fredoka One', cursive;
        }
        
        .gradient-bg {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        
        .card-shadow {
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        
        .robot-glow {
            filter: drop-shadow(0 0 10px rgba(59, 130, 246, 0.5));
        }
        
        .bounce-animation {
            animation: bounce 2s infinite;
        }
        
        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }
        
        .pulse-ring {
            animation: pulse-ring 1.5s cubic-bezier(0.215, 0.61, 0.355, 1) infinite;
        }
        
        @keyframes pulse-ring {
            0% { transform: scale(0.8); opacity: 1; }
            80%, 100% { transform: scale(1.3); opacity: 0; }
        }
        
        .sparkle {
            animation: sparkle 1.5s ease-in-out infinite;
        }
        
        @keyframes sparkle {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(1.2); }
        }
        
        /* Blockly customization */
        .blocklyToolboxDiv {
            background: linear-gradient(180deg, #f0f9ff 0%, #e0f2fe 100%) !important;
            border-radius: 0 16px 16px 0 !important;
        }
        
        .blocklyTreeRow:hover {
            background-color: #bae6fd !important;
        }
        
        /* Canvas styles */
        #robotCanvas {
            border-radius: 16px;
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
        }
        
        /* Chat bubble */
        .chat-bubble {
            position: relative;
            background: white;
            border-radius: 20px;
            padding: 15px 20px;
        }
        
        .chat-bubble::before {
            content: '';
            position: absolute;
            bottom: -10px;
            left: 30px;
            border-width: 10px;
            border-style: solid;
            border-color: white transparent transparent transparent;
        }
        
        /* Progress bar */
        .progress-fill {
            background: linear-gradient(90deg, #22c55e, #86efac);
            transition: width 0.5s ease;
        }
        
        /* Lesson card hover */
        .lesson-card {
            transition: all 0.3s ease;
        }
        
        .lesson-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
        }
        
        /* Robot expressions */
        .robot-happy .robot-mouth {
            border-radius: 0 0 50% 50%;
        }
        
        .robot-thinking .robot-eye {
            animation: blink 0.5s ease infinite;
        }
        
        @keyframes blink {
            0%, 100% { transform: scaleY(1); }
            50% { transform: scaleY(0.1); }
        }
        
        /* Tab styles */
        .tab-active {
            background: white;
            color: #6366f1;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .tab-inactive {
            background: transparent;
            color: white;
        }
        
        /* XP popup */
        .xp-popup {
            animation: xp-float 2s ease forwards;
        }
        
        @keyframes xp-float {
            0% { opacity: 0; transform: translateY(20px) scale(0.5); }
            20% { opacity: 1; transform: translateY(0) scale(1.2); }
            80% { opacity: 1; transform: translateY(-30px) scale(1); }
            100% { opacity: 0; transform: translateY(-50px) scale(0.8); }
        }
        
        /* Badge unlock */
        .badge-unlock {
            animation: badge-pop 0.5s ease;
        }
        
        @keyframes badge-pop {
            0% { transform: scale(0) rotate(-180deg); }
            50% { transform: scale(1.3) rotate(10deg); }
            100% { transform: scale(1) rotate(0deg); }
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
                <!-- XP Counter -->
                <div class="flex items-center gap-2 bg-white/20 rounded-full px-4 py-2">
                    <span class="text-yellow-300 text-xl">⭐</span>
                    <span class="font-bold text-lg" id="xpCounter">0</span>
                    <span class="text-sm">XP</span>
                </div>
                
                <!-- Level Badge -->
                <div class="flex items-center gap-2 bg-white/20 rounded-full px-4 py-2">
                    <span class="text-2xl">🏆</span>
                    <span class="font-bold">Level <span id="levelCounter">1</span></span>
                </div>
                
                <!-- Profile -->
                <div class="flex items-center gap-2 cursor-pointer hover:opacity-80">
                    <div class="w-10 h-10 bg-gradient-to-br from-yellow-400 to-orange-500 rounded-full flex items-center justify-center text-xl">
                        👦
                    </div>
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
            <!-- Welcome Banner -->
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

            <!-- Lesson Grid -->
            <h3 class="text-2xl font-bold text-gray-800 mb-4">
                <i class="fas fa-book-open text-indigo-500 mr-2"></i>Beginner Lessons
            </h3>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="lessonsGrid">
                <!-- Lessons will be populated by JS -->
            </div>
        </div>

        <!-- Code Tab -->
        <div id="code-section" class="hidden">
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <!-- Blockly Editor -->
                <div class="lg:col-span-2 bg-white rounded-3xl card-shadow overflow-hidden">
                    <div class="bg-gradient-to-r from-indigo-500 to-purple-500 text-white p-4 flex items-center justify-between">
                        <div class="flex items-center gap-3">
                            <i class="fas fa-puzzle-piece text-2xl"></i>
                            <div>
                                <h3 class="font-bold text-lg" id="currentLessonTitle">Code Playground</h3>
                                <p class="text-sm text-purple-200" id="currentLessonDesc">Drag blocks to program STEMO!</p>
                            </div>
                        </div>
                        <div class="flex gap-2">
                            <button onclick="runCode()" class="bg-green-500 hover:bg-green-600 text-white px-5 py-2 rounded-full font-bold transition-all transform hover:scale-105 flex items-center gap-2">
                                <i class="fas fa-play"></i> Run
                            </button>
                            <button onclick="clearWorkspace()" class="bg-red-400 hover:bg-red-500 text-white px-4 py-2 rounded-full font-bold transition-all">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </div>
                    <div id="blocklyDiv" style="height: 450px;"></div>
                </div>

                <!-- Robot Canvas & Chat -->
                <div class="space-y-6">
                    <!-- Robot Canvas -->
                    <div class="bg-white rounded-3xl card-shadow overflow-hidden">
                        <div class="bg-gradient-to-r from-blue-500 to-cyan-500 text-white p-3 flex items-center gap-2">
                            <span class="text-xl">🤖</span>
                            <span class="font-bold">STEMO's World</span>
                        </div>
                        <div class="p-4">
                            <canvas id="robotCanvas" width="400" height="350" class="w-full"></canvas>
                            <div class="flex justify-center gap-3 mt-3">
                                <button onclick="resetRobot()" class="bg-gray-200 hover:bg-gray-300 px-4 py-2 rounded-full text-sm font-bold transition-all">
                                    <i class="fas fa-undo mr-1"></i> Reset
                                </button>
                                <button onclick="togglePenColor()" class="bg-gradient-to-r from-pink-400 to-purple-500 text-white px-4 py-2 rounded-full text-sm font-bold transition-all">
                                    <i class="fas fa-palette mr-1"></i> Color
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- STEMO Chat -->
                    <div class="bg-white rounded-3xl card-shadow overflow-hidden">
                        <div class="bg-gradient-to-r from-yellow-400 to-orange-500 text-white p-3 flex items-center gap-2">
                            <span class="text-xl sparkle">💬</span>
                            <span class="font-bold">Chat with STEMO</span>
                        </div>
                        <div class="p-4">
                            <div id="chatMessages" class="h-40 overflow-y-auto mb-3 space-y-3">
                                <div class="flex items-start gap-2">
                                    <span class="text-2xl">🤖</span>
                                    <div class="chat-bubble bg-blue-100 text-sm">
                                        Hi! I'm STEMO! Need help? Just ask me anything about coding! 
                                    </div>
                                </div>
                            </div>
                            <div class="flex gap-2">
                                <input type="text" id="chatInput" placeholder="Ask STEMO for help..." 
                                    class="flex-1 border-2 border-gray-200 rounded-full px-4 py-2 focus:outline-none focus:border-indigo-400"
                                    onkeypress="if(event.key==='Enter')sendChat()">
                                <button onclick="sendChat()" class="bg-indigo-500 hover:bg-indigo-600 text-white w-10 h-10 rounded-full transition-all">
                                    <i class="fas fa-paper-plane"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Hint Panel -->
            <div id="hintPanel" class="mt-6 bg-gradient-to-r from-amber-100 to-yellow-100 rounded-2xl p-5 border-2 border-yellow-300 hidden">
                <div class="flex items-center gap-3">
                    <span class="text-3xl">💡</span>
                    <div>
                        <h4 class="font-bold text-amber-800">Hint from STEMO:</h4>
                        <p id="hintText" class="text-amber-700"></p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Achievements Tab -->
        <div id="achievements-section" class="hidden">
            <!-- Progress Overview -->
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

            <!-- Badges Grid -->
            <h3 class="text-2xl font-bold text-gray-800 mb-4">
                <i class="fas fa-medal text-yellow-500 mr-2"></i>Badges Collection
            </h3>
            <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4" id="badgesGrid">
                <!-- Badges populated by JS -->
            </div>
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
            <button onclick="closeSuccessModal()" class="bg-gradient-to-r from-indigo-500 to-purple-600 text-white px-8 py-3 rounded-full font-bold hover:opacity-90 transition-all">
                Continue Learning!
            </button>
        </div>
    </div>

    <script>
        // ============================================
        // STEMO STATE MANAGEMENT
        // ============================================
        let stemo = {
            xp: parseInt(localStorage.getItem('stemo_xp') || '0'),
            level: parseInt(localStorage.getItem('stemo_level') || '1'),
            completedLessons: JSON.parse(localStorage.getItem('stemo_completed') || '[]'),
            badges: JSON.parse(localStorage.getItem('stemo_badges') || '[]'),
            streak: parseInt(localStorage.getItem('stemo_streak') || '1')
        }

        // Robot state
        let robot = {
            x: 200,
            y: 175,
            angle: 0,
            penDown: false,
            penColor: '#6366f1',
            trails: [],
            expression: 'happy'
        }

        const penColors = ['#6366f1', '#22c55e', '#f59e0b', '#ef4444', '#ec4899', '#8b5cf6']
        let currentColorIndex = 0
        let currentLesson = null
        let workspace = null

        // ============================================
        // INITIALIZATION
        // ============================================
        document.addEventListener('DOMContentLoaded', function() {
            updateUI()
            loadLessons()
            loadBadges()
            initBlockly()
            drawRobot()
        })

        function updateUI() {
            document.getElementById('xpCounter').textContent = stemo.xp
            document.getElementById('levelCounter').textContent = stemo.level
            document.getElementById('totalXP').textContent = stemo.xp
            document.getElementById('lessonsCompleted').textContent = stemo.completedLessons.length
            document.getElementById('streakDays').textContent = stemo.streak
            document.getElementById('badgesEarned').textContent = stemo.badges.length
        }

        function saveProgress() {
            localStorage.setItem('stemo_xp', stemo.xp)
            localStorage.setItem('stemo_level', stemo.level)
            localStorage.setItem('stemo_completed', JSON.stringify(stemo.completedLessons))
            localStorage.setItem('stemo_badges', JSON.stringify(stemo.badges))
            localStorage.setItem('stemo_streak', stemo.streak)
        }

        // ============================================
        // LESSONS
        // ============================================
        async function loadLessons() {
            const response = await fetch('/api/curriculum')
            const data = await response.json()
            const grid = document.getElementById('lessonsGrid')
            
            grid.innerHTML = data.beginner.map((lesson, index) => {
                const isCompleted = stemo.completedLessons.includes(lesson.id)
                const isLocked = index > 0 && !stemo.completedLessons.includes(data.beginner[index-1].id)
                
                return \`
                    <div class="lesson-card bg-white rounded-2xl card-shadow overflow-hidden cursor-pointer \${isLocked ? 'opacity-60' : ''}"
                        onclick="\${isLocked ? '' : \`selectLesson('\${lesson.id}')\`}">
                        <div class="h-3 bg-gradient-to-r \${getDifficultyGradient(lesson.difficulty)}"></div>
                        <div class="p-5">
                            <div class="flex items-center justify-between mb-3">
                                <span class="text-3xl">\${isCompleted ? '✅' : isLocked ? '🔒' : getLessonIcon(index)}</span>
                                <span class="bg-yellow-100 text-yellow-700 px-3 py-1 rounded-full text-sm font-bold">
                                    +\${lesson.xpReward} XP
                                </span>
                            </div>
                            <h4 class="font-bold text-lg text-gray-800 mb-1">\${lesson.title}</h4>
                            <p class="text-gray-500 text-sm mb-3">\${lesson.description}</p>
                            <div class="flex items-center gap-2">
                                <span class="text-xs px-2 py-1 rounded-full \${getDifficultyClass(lesson.difficulty)}">\${lesson.difficulty}</span>
                                \${isCompleted ? '<span class="text-xs text-green-600 font-bold">Completed!</span>' : ''}
                            </div>
                        </div>
                    </div>
                \`
            }).join('')
        }

        function getLessonIcon(index) {
            const icons = ['🎯', '🔄', '🖍️', '🔁', '🔺', '⭐']
            return icons[index] || '📚'
        }

        function getDifficultyGradient(difficulty) {
            const gradients = {
                easy: 'from-green-400 to-emerald-500',
                medium: 'from-yellow-400 to-orange-500',
                hard: 'from-red-400 to-pink-500'
            }
            return gradients[difficulty] || gradients.easy
        }

        function getDifficultyClass(difficulty) {
            const classes = {
                easy: 'bg-green-100 text-green-700',
                medium: 'bg-yellow-100 text-yellow-700',
                hard: 'bg-red-100 text-red-700'
            }
            return classes[difficulty] || classes.easy
        }

        async function selectLesson(lessonId) {
            const response = await fetch(\`/api/lesson/\${lessonId}\`)
            currentLesson = await response.json()
            
            document.getElementById('currentLessonTitle').textContent = currentLesson.title
            document.getElementById('currentLessonDesc').textContent = currentLesson.description
            document.getElementById('hintText').textContent = currentLesson.hint
            document.getElementById('hintPanel').classList.remove('hidden')
            
            switchTab('code')
            resetRobot()
        }

        function startFirstLesson() {
            selectLesson('lesson-1')
        }

        // ============================================
        // BADGES
        // ============================================
        async function loadBadges() {
            const response = await fetch('/api/badges')
            const badges = await response.json()
            const grid = document.getElementById('badgesGrid')
            
            grid.innerHTML = badges.map(badge => {
                const isEarned = stemo.badges.includes(badge.id) || stemo.xp >= badge.xpRequired
                
                if (isEarned && !stemo.badges.includes(badge.id)) {
                    stemo.badges.push(badge.id)
                    saveProgress()
                }
                
                return \`
                    <div class="bg-white rounded-2xl card-shadow p-4 text-center \${isEarned ? '' : 'opacity-50 grayscale'}">
                        <div class="text-4xl mb-2 \${isEarned ? 'badge-unlock' : ''}">\${badge.icon}</div>
                        <h4 class="font-bold text-sm text-gray-800">\${badge.name}</h4>
                        <p class="text-xs text-gray-500 mt-1">\${badge.description}</p>
                        <div class="text-xs text-indigo-600 mt-2">\${badge.xpRequired} XP</div>
                    </div>
                \`
            }).join('')
        }

        // ============================================
        // BLOCKLY SETUP
        // ============================================
        function initBlockly() {
            // Define custom blocks
            Blockly.Blocks['move_forward'] = {
                init: function() {
                    this.appendDummyInput()
                        .appendField("🚶 Move Forward")
                        .appendField(new Blockly.FieldNumber(1, 1, 10), "STEPS")
                        .appendField("steps")
                    this.setPreviousStatement(true, null)
                    this.setNextStatement(true, null)
                    this.setColour(230)
                    this.setTooltip("Move STEMO forward")
                }
            }

            Blockly.Blocks['turn_left'] = {
                init: function() {
                    this.appendDummyInput()
                        .appendField("↩️ Turn Left")
                        .appendField(new Blockly.FieldNumber(90, 1, 360), "DEGREES")
                        .appendField("°")
                    this.setPreviousStatement(true, null)
                    this.setNextStatement(true, null)
                    this.setColour(160)
                    this.setTooltip("Turn STEMO left")
                }
            }

            Blockly.Blocks['turn_right'] = {
                init: function() {
                    this.appendDummyInput()
                        .appendField("↪️ Turn Right")
                        .appendField(new Blockly.FieldNumber(90, 1, 360), "DEGREES")
                        .appendField("°")
                    this.setPreviousStatement(true, null)
                    this.setNextStatement(true, null)
                    this.setColour(160)
                    this.setTooltip("Turn STEMO right")
                }
            }

            Blockly.Blocks['pen_down'] = {
                init: function() {
                    this.appendDummyInput()
                        .appendField("🖍️ Pen Down")
                    this.setPreviousStatement(true, null)
                    this.setNextStatement(true, null)
                    this.setColour(330)
                    this.setTooltip("Start drawing")
                }
            }

            Blockly.Blocks['pen_up'] = {
                init: function() {
                    this.appendDummyInput()
                        .appendField("✏️ Pen Up")
                    this.setPreviousStatement(true, null)
                    this.setNextStatement(true, null)
                    this.setColour(330)
                    this.setTooltip("Stop drawing")
                }
            }

            Blockly.Blocks['set_color'] = {
                init: function() {
                    this.appendDummyInput()
                        .appendField("🎨 Set Color")
                        .appendField(new Blockly.FieldColour('#6366f1'), "COLOR")
                    this.setPreviousStatement(true, null)
                    this.setNextStatement(true, null)
                    this.setColour(330)
                    this.setTooltip("Change pen color")
                }
            }

            Blockly.Blocks['repeat_times'] = {
                init: function() {
                    this.appendDummyInput()
                        .appendField("🔁 Repeat")
                        .appendField(new Blockly.FieldNumber(4, 1, 100), "TIMES")
                        .appendField("times")
                    this.appendStatementInput("DO")
                        .appendField("do")
                    this.setPreviousStatement(true, null)
                    this.setNextStatement(true, null)
                    this.setColour(120)
                    this.setTooltip("Repeat blocks multiple times")
                }
            }

            // Define toolbox
            const toolbox = {
                kind: 'categoryToolbox',
                contents: [
                    {
                        kind: 'category',
                        name: '🚶 Movement',
                        colour: 230,
                        contents: [
                            { kind: 'block', type: 'move_forward' },
                            { kind: 'block', type: 'turn_left' },
                            { kind: 'block', type: 'turn_right' }
                        ]
                    },
                    {
                        kind: 'category',
                        name: '🎨 Drawing',
                        colour: 330,
                        contents: [
                            { kind: 'block', type: 'pen_down' },
                            { kind: 'block', type: 'pen_up' },
                            { kind: 'block', type: 'set_color' }
                        ]
                    },
                    {
                        kind: 'category',
                        name: '🔁 Loops',
                        colour: 120,
                        contents: [
                            { kind: 'block', type: 'repeat_times' }
                        ]
                    }
                ]
            }

            // Initialize workspace
            workspace = Blockly.inject('blocklyDiv', {
                toolbox: toolbox,
                scrollbars: true,
                trashcan: true,
                zoom: {
                    controls: true,
                    wheel: true,
                    startScale: 1.0,
                    maxScale: 2,
                    minScale: 0.5
                },
                grid: {
                    spacing: 20,
                    length: 3,
                    colour: '#ccc',
                    snap: true
                }
            })
        }

        // ============================================
        // CODE EXECUTION
        // ============================================
        async function runCode() {
            const blocks = workspace.getTopBlocks(true)
            if (blocks.length === 0) {
                addChatMessage('stemo', "🤖 Drag some blocks into the workspace first, then click Run!")
                return
            }

            resetRobot()
            const commands = parseBlocks(blocks[0])
            await executeCommands(commands)
        }

        function parseBlocks(block, commands = []) {
            while (block) {
                const type = block.type
                
                switch(type) {
                    case 'move_forward':
                        const steps = block.getFieldValue('STEPS')
                        for (let i = 0; i < steps; i++) {
                            commands.push({ action: 'move', value: 30 })
                        }
                        break
                    case 'turn_left':
                        commands.push({ action: 'turn', value: -block.getFieldValue('DEGREES') })
                        break
                    case 'turn_right':
                        commands.push({ action: 'turn', value: block.getFieldValue('DEGREES') })
                        break
                    case 'pen_down':
                        commands.push({ action: 'pen', value: true })
                        break
                    case 'pen_up':
                        commands.push({ action: 'pen', value: false })
                        break
                    case 'set_color':
                        commands.push({ action: 'color', value: block.getFieldValue('COLOR') })
                        break
                    case 'repeat_times':
                        const times = block.getFieldValue('TIMES')
                        const innerBlock = block.getInputTargetBlock('DO')
                        for (let i = 0; i < times; i++) {
                            if (innerBlock) {
                                parseBlocks(innerBlock, commands)
                            }
                        }
                        break
                }
                
                block = block.getNextBlock()
            }
            return commands
        }

        async function executeCommands(commands) {
            for (const cmd of commands) {
                await executeCommand(cmd)
                await sleep(150)
            }
            
            // Check if lesson completed
            if (currentLesson) {
                checkLessonCompletion()
            }
        }

        async function executeCommand(cmd) {
            const canvas = document.getElementById('robotCanvas')
            const ctx = canvas.getContext('2d')

            switch(cmd.action) {
                case 'move':
                    const rad = robot.angle * Math.PI / 180
                    const newX = robot.x + Math.cos(rad) * cmd.value
                    const newY = robot.y + Math.sin(rad) * cmd.value
                    
                    if (robot.penDown) {
                        robot.trails.push({
                            x1: robot.x, y1: robot.y,
                            x2: newX, y2: newY,
                            color: robot.penColor
                        })
                    }
                    
                    robot.x = Math.max(30, Math.min(370, newX))
                    robot.y = Math.max(30, Math.min(320, newY))
                    break
                    
                case 'turn':
                    robot.angle += cmd.value
                    break
                    
                case 'pen':
                    robot.penDown = cmd.value
                    break
                    
                case 'color':
                    robot.penColor = cmd.value
                    break
            }
            
            drawRobot()
        }

        function sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms))
        }

        // ============================================
        // ROBOT DRAWING
        // ============================================
        function drawRobot() {
            const canvas = document.getElementById('robotCanvas')
            const ctx = canvas.getContext('2d')
            
            // Clear canvas
            ctx.clearRect(0, 0, canvas.width, canvas.height)
            
            // Draw background grid
            ctx.strokeStyle = '#e5e7eb'
            ctx.lineWidth = 1
            for (let i = 0; i < canvas.width; i += 40) {
                ctx.beginPath()
                ctx.moveTo(i, 0)
                ctx.lineTo(i, canvas.height)
                ctx.stroke()
            }
            for (let i = 0; i < canvas.height; i += 40) {
                ctx.beginPath()
                ctx.moveTo(0, i)
                ctx.lineTo(canvas.width, i)
                ctx.stroke()
            }
            
            // Draw trails
            robot.trails.forEach(trail => {
                ctx.beginPath()
                ctx.strokeStyle = trail.color
                ctx.lineWidth = 4
                ctx.lineCap = 'round'
                ctx.moveTo(trail.x1, trail.y1)
                ctx.lineTo(trail.x2, trail.y2)
                ctx.stroke()
            })
            
            // Draw target star if in lesson
            if (currentLesson && currentLesson.challenge) {
                const star = currentLesson.challenge.starPosition
                drawStar(ctx, star.x, star.y, 20, 5, 0.5)
            }
            
            // Draw robot
            ctx.save()
            ctx.translate(robot.x, robot.y)
            ctx.rotate((robot.angle - 90) * Math.PI / 180)
            
            // Robot body
            ctx.fillStyle = '#3b82f6'
            ctx.beginPath()
            ctx.roundRect(-20, -25, 40, 50, 8)
            ctx.fill()
            
            // Robot head
            ctx.fillStyle = '#60a5fa'
            ctx.beginPath()
            ctx.arc(0, -15, 15, 0, Math.PI * 2)
            ctx.fill()
            
            // Eyes
            ctx.fillStyle = 'white'
            ctx.beginPath()
            ctx.arc(-6, -18, 5, 0, Math.PI * 2)
            ctx.arc(6, -18, 5, 0, Math.PI * 2)
            ctx.fill()
            
            // Pupils
            ctx.fillStyle = '#1e3a5f'
            ctx.beginPath()
            ctx.arc(-5, -17, 2, 0, Math.PI * 2)
            ctx.arc(7, -17, 2, 0, Math.PI * 2)
            ctx.fill()
            
            // Antenna
            ctx.strokeStyle = '#fbbf24'
            ctx.lineWidth = 3
            ctx.beginPath()
            ctx.moveTo(0, -30)
            ctx.lineTo(0, -40)
            ctx.stroke()
            ctx.fillStyle = '#fbbf24'
            ctx.beginPath()
            ctx.arc(0, -42, 4, 0, Math.PI * 2)
            ctx.fill()
            
            // Direction indicator
            ctx.fillStyle = '#22c55e'
            ctx.beginPath()
            ctx.moveTo(0, -25)
            ctx.lineTo(-8, -10)
            ctx.lineTo(8, -10)
            ctx.closePath()
            ctx.fill()
            
            ctx.restore()
        }

        function drawStar(ctx, cx, cy, outerRadius, points, innerRatio) {
            ctx.save()
            ctx.fillStyle = '#fbbf24'
            ctx.beginPath()
            
            for (let i = 0; i < points * 2; i++) {
                const radius = i % 2 === 0 ? outerRadius : outerRadius * innerRatio
                const angle = (i * Math.PI / points) - Math.PI / 2
                const x = cx + radius * Math.cos(angle)
                const y = cy + radius * Math.sin(angle)
                
                if (i === 0) ctx.moveTo(x, y)
                else ctx.lineTo(x, y)
            }
            
            ctx.closePath()
            ctx.fill()
            
            // Glow effect
            ctx.shadowColor = '#fbbf24'
            ctx.shadowBlur = 15
            ctx.fill()
            
            ctx.restore()
        }

        function resetRobot() {
            robot = {
                x: 200,
                y: 175,
                angle: 0,
                penDown: false,
                penColor: '#6366f1',
                trails: [],
                expression: 'happy'
            }
            drawRobot()
        }

        function togglePenColor() {
            currentColorIndex = (currentColorIndex + 1) % penColors.length
            robot.penColor = penColors[currentColorIndex]
            addChatMessage('stemo', \`🤖 Color changed to \${robot.penColor}! Looking good! 🎨\`)
        }

        function clearWorkspace() {
            workspace.clear()
            resetRobot()
        }

        // ============================================
        // LESSON COMPLETION
        // ============================================
        function checkLessonCompletion() {
            if (!currentLesson) return
            
            // Simple completion check - robot moved
            if (robot.trails.length > 0 || robot.x !== 200 || robot.y !== 175) {
                if (!stemo.completedLessons.includes(currentLesson.id)) {
                    completeLesson(currentLesson)
                }
            }
        }

        function completeLesson(lesson) {
            stemo.completedLessons.push(lesson.id)
            stemo.xp += lesson.xpReward
            
            // Level up check
            const newLevel = Math.floor(stemo.xp / 500) + 1
            if (newLevel > stemo.level) {
                stemo.level = newLevel
            }
            
            saveProgress()
            updateUI()
            loadLessons()
            loadBadges()
            
            showSuccessModal(lesson.xpReward)
        }

        function showSuccessModal(xp) {
            const modal = document.getElementById('successModal')
            const content = document.getElementById('successModalContent')
            document.getElementById('xpEarned').textContent = \`+\${xp} XP\`
            
            modal.classList.remove('hidden')
            setTimeout(() => {
                content.style.transform = 'scale(1)'
            }, 50)
        }

        function closeSuccessModal() {
            const modal = document.getElementById('successModal')
            const content = document.getElementById('successModalContent')
            content.style.transform = 'scale(0)'
            setTimeout(() => {
                modal.classList.add('hidden')
            }, 300)
        }

        // ============================================
        // CHAT FUNCTIONALITY
        // ============================================
        async function sendChat() {
            const input = document.getElementById('chatInput')
            const message = input.value.trim()
            if (!message) return
            
            // Add user message
            addChatMessage('user', message)
            input.value = ''
            
            // Get AI response
            try {
                const response = await fetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        message, 
                        context: { 
                            currentLesson: currentLesson?.id,
                            xp: stemo.xp
                        }
                    })
                })
                const data = await response.json()
                addChatMessage('stemo', data.response)
            } catch (err) {
                addChatMessage('stemo', "🤖 Oops! I'm thinking too hard. Try again!")
            }
        }

        function addChatMessage(sender, message) {
            const container = document.getElementById('chatMessages')
            const div = document.createElement('div')
            div.className = 'flex items-start gap-2'
            
            if (sender === 'stemo') {
                div.innerHTML = \`
                    <span class="text-2xl">🤖</span>
                    <div class="chat-bubble bg-blue-100 text-sm">\${message}</div>
                \`
            } else {
                div.innerHTML = \`
                    <div class="chat-bubble bg-indigo-100 text-sm ml-auto">\${message}</div>
                    <span class="text-2xl">👦</span>
                \`
            }
            
            container.appendChild(div)
            container.scrollTop = container.scrollHeight
        }

        // ============================================
        // TAB NAVIGATION
        // ============================================
        function switchTab(tab) {
            // Hide all sections
            document.getElementById('learn-section').classList.add('hidden')
            document.getElementById('code-section').classList.add('hidden')
            document.getElementById('achievements-section').classList.add('hidden')
            
            // Reset tab styles
            document.getElementById('tab-learn').className = 'tab-inactive px-6 py-2 rounded-full font-bold transition-all'
            document.getElementById('tab-code').className = 'tab-inactive px-6 py-2 rounded-full font-bold transition-all'
            document.getElementById('tab-achievements').className = 'tab-inactive px-6 py-2 rounded-full font-bold transition-all'
            
            // Show selected section
            document.getElementById(tab + '-section').classList.remove('hidden')
            document.getElementById('tab-' + tab).className = 'tab-active px-6 py-2 rounded-full font-bold transition-all'
        }
    </script>
</body>
</html>`)
})

export default app
