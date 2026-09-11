import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const sourcePath = resolve(process.argv[2] || 'src/index.tsx')
const source = readFileSync(sourcePath, 'utf8')
const errors = []

function fail(message) {
  errors.push(message)
}

// Keep these programs deliberately close to the blocks a student can place. The
// runner models the state that challenge objective checks observe; it does not
// evaluate application source or execute arbitrary curriculum expressions.
const fixtures = {
  'lesson-4': { blocks: ['set_color', 'set_pen_size'], commands: [
    ['pen', true], ['color', 'red'], ['move', 5], ['color', 'blue'], ['move', 5],
    ['color', 'green'], ['move', 5], ['color', 'purple'], ['move', 5],
  ] },
  'lesson-5': { blocks: ['repeat_times'], commands: [
    ['pen', true], ['repeat', 4, [['move', 2], ['turn', 90], ['move', 2], ['turn', -90]]],
  ] },
  'lesson-6': { blocks: ['repeat_times', 'repeat_times', 'turn_right', 'set_color'], commands: [
    ['pen', true], ['color', 'blue'],
    ['repeat', 8, [['repeat', 4, [['move', 6], ['turn', 90]]], ['turn', 45]]],
  ] },
  'lesson-7': { blocks: ['repeat_times', 'turn_right'], commands: [
    ['pen', true], ['repeat', 8, [['move', 2], ['turn', 135]]],
  ] },
  'lesson-8': { blocks: ['magnet_on', 'magnet_off'], commands: [['magnet', true], ['go_to', 130, 130], ['go_to', 420, 130], ['go_to', 420, 420], ['go_home'], ['magnet', false]] },
  'lesson-9': { blocks: ['sensor_scan', 'if_wall_ahead', 'repeat_times'], commands: [
    ['repeat', 20, [['if_wall']]], ['go_to', 395, 395],
  ] },
  'lesson-10': { blocks: ['smart_navigate'], commands: [['smart_navigate']] },
  'lesson-11': { blocks: ['smart_navigate'], commands: [['smart_navigate']] },
  'lesson-12': { blocks: ['check_temp', 'repeat_times'], commands: [['go_to', 135, 135], ['detect', 0], ['go_to', 415, 415], ['detect', 1]] },
  'lesson-13': { blocks: ['if_hot_ahead', 'spray_water'], commands: [['go_to', 135, 135], ['spray', 3], ['go_to', 415, 135], ['spray', 3], ['go_to', 275, 415], ['spray', 3]] },
  'lesson-14': { blocks: ['magnet_on', 'spray_water', 'smart_navigate'], commands: [['magnet', true], ['go_to', 135, 135], ['magnet', false], ['go_to', 135, 415], ['spray', 3], ['smart_navigate']] },
  'lesson-15': { blocks: ['set_variable', 'repeat_var_times', 'move_var_steps', 'turn_var_degrees'], commands: [
    ['pen', true], ['repeat', 4, [['move', 4], ['turn', 90]]],
  ] },
  'lesson-16': { blocks: ['save_position', 'go_to_target', 'go_to_saved'], commands: [['save'], ['smart_navigate'], ['home']] },
  'lesson-17': { blocks: ['magnet_on', 'replay_waypoints'], commands: [['magnet', true], ['replay'], ['magnet', false]] },
  'lesson-18': { blocks: ['foreach_waypoint', 'spray_water'], commands: [['foreach', 'spray']] },
  'lesson-19': { blocks: ['define_function', 'call_function'], commands: [['define', 'square'], ['define', 'star'], ['pen', true], ['repeat', 16, [['move', 1], ['turn', 90]]]] },
  'lesson-art-1': { blocks: ['repeat_times', 'set_color'], commands: [['pen', true], ['color', 'blue'], ['repeat', 16, [['move', 1], ['turn', 20]]]] },
  'lesson-art-2': { blocks: ['repeat_times', 'set_color'], commands: [['pen', true], ['color', 'red'], ['repeat', 6, [['move', 1], ['color', 'blue'], ['move', 1], ['color', 'green'], ['move', 1]]]] },
  'lesson-art-3': { blocks: ['pen_control', 'stemo_emotion'], commands: [['pen', true], ['move', 2], ['pen', false], ['move', 2], ['pen', true], ['move', 2], ['move', 2], ['emotion']] },
  'lesson-art-4': { blocks: ['repeat_times', 'repeat_times', 'set_color'], commands: [['pen', true], ['color', 'purple'], ['repeat', 4, [['repeat', 4, [['move', 3], ['turn', 90]]], ['turn', 30]]]] },
}

function challengeObjectiveIds(id) {
  const start = source.indexOf(`'${id}': {`)
  if (start === -1) return null
  const next = source.indexOf("\n            '", start + 1)
  const section = source.slice(start, next === -1 ? source.length : next)
  return [...section.matchAll(/\bid:\s*'([^']+)'/g)].map((match) => match[1])
}

function makeWorld(id) {
  const world = {
    id, x: 275, y: 275, trails: [], blocks: new Set(), colors: new Set(),
    metals: [], fires: [], target: null, waypoints: [], detected: new Set(),
    extinguished: 0, magnet: false, carrying: false, home: true, saved: false,
    functions: 0, replayed: false, foreach: false, reachedTarget: false,
  }
  if (id === 'lesson-8') world.metals = [[130, 130], [420, 130], [420, 420]]
  if (id === 'lesson-9') world.target = [395, 395]
  if (id === 'lesson-10') world.target = [440, 440]
  if (id === 'lesson-11') world.target = [415, 415]
  if (id === 'lesson-12') world.fires = [[135, 135], [415, 415]]
  if (id === 'lesson-13') world.fires = [[135, 135], [415, 135], [275, 415]]
  if (id === 'lesson-14') {
    world.metals = [[135, 135]]
    world.fires = [[135, 415], [415, 415]]
    world.target = [415, 135]
  }
  if (id === 'lesson-16') world.target = [415, 135]
  if (id === 'lesson-17') {
    world.metals = [[135, 135], [415, 275], [135, 415]]
    world.waypoints = [...world.metals]
  }
  if (id === 'lesson-18') {
    world.fires = [[135, 135], [415, 135], [275, 415]]
    world.waypoints = [...world.fires]
  }
  return world
}

function moveTo(world, x, y) {
  world.x = x; world.y = y; world.home = Math.hypot(x - 275, y - 275) < 1
  if (world.target && Math.hypot(x - world.target[0], y - world.target[1]) < 40) world.reachedTarget = true
  world.metals.forEach((metal) => {
    if (world.magnet && Math.hypot(world.x - metal[0], world.y - metal[1]) < 35) metal.collected = true
  })
}

function draw(world, count = 1) {
  for (let i = 0; i < count; i += 1) {
    world.trails.push({ color: [...world.colors].at(-1) || 'default' })
  }
  world.distance = (world.distance || 0) + count * 20
}

function runCommands(world, commands) {
  for (const command of commands) {
    const [action, ...args] = command
    if (action === 'pen' && args[0]) world.pen = true
    if (action === 'pen' && !args[0]) world.pen = false
    if (action === 'color') { world.colors.add(args[0]); world.blocks.add('set_color') }
    if (action === 'move') { if (world.pen) draw(world, args[0] || 1) }
    if (action === 'turn') world.turns = (world.turns || 0) + 1
    if (action === 'repeat') { world.blocks.add('repeat_times'); for (let i = 0; i < args[0]; i += 1) runCommands(world, args[1]) }
    if (action === 'magnet') world.magnet = args[0]
    if (action === 'go_to') moveTo(world, args[0], args[1])
    if (action === 'go_home' || action === 'home') moveTo(world, 275, 275)
    if (action === 'smart_navigate') { if (world.target) moveTo(world, ...world.target) }
    if (action === 'scan') world.scans = (world.scans || 0) + 1
    if (action === 'if_wall') {
      world.wallChecks = (world.wallChecks || 0) + 1
      world.wallConditionTrue = (world.wallConditionTrue || 0) + 1
    }
    if (action === 'detect') world.detected.add(args[0])
    if (action === 'spray') { world.extinguished += args[0] }
    if (action === 'save') world.saved = true
    if (action === 'replay') { world.replayed = true; world.waypoints.forEach(([x, y]) => moveTo(world, x, y)) }
    if (action === 'foreach') { world.foreach = true; world.extinguished += world.fires.length }
    if (action === 'define') world.functions += 1
    if (action === 'emotion') world.blocks.add('stemo_emotion')
  }
}

function satisfies(id, world, fixture) {
  const collected = world.metals.filter((metal) => metal.collected).length
  const allFires = world.fires.length > 0 && world.extinguished >= world.fires.length
  const reach = world.target && Math.hypot(world.x - world.target[0], world.y - world.target[1]) < 40
  return {
    colors: world.colors.size >= 2, size: fixture.blocks.includes('set_color') || fixture.blocks.includes('set_pen_size'),
    shape: world.trails.length >= 4, loop: fixture.blocks.includes('repeat_times'), segments: world.trails.length >= 8,
    pen: world.trails.length > 0, turns: fixture.blocks.includes('turn_right') || (world.turns || 0) > 0,
    angle: fixture.blocks.includes('turn_right') || fixture.blocks.includes('turn_left'), 'metal-1': collected >= 1,
    'metal-2': collected >= 2, 'metal-3': collected >= 3, 'go-home': collected === world.metals.length && world.home && !world.magnet,
    reach: Boolean(world.reachedTarget), detect1: world.detected.has(0), detect2: world.detected.has(1), extinguish: allFires,
    metal: collected >= 1, fire: allFires, moved: (world.distance || 0) > 200, closed: world.home,
    target: Boolean(world.reachedTarget), home: world.home, metals: collected === world.metals.length && world.replayed,
    fires: allFires && world.foreach, funcs: world.functions >= 2, pattern: world.trails.length >= 8,
    color: fixture.blocks.includes('set_color'), spiral: world.trails.length >= 15, bands: world.trails.length >= 18,
    penup: fixture.blocks.includes('pen_control'), strokes: world.trails.length >= 3, flair: fixture.blocks.includes('stemo_emotion'),
    nested: fixture.blocks.filter((block) => block === 'repeat_times').length >= 2, mandala: world.trails.length >= 16,
    boxes: world.trails.length >= 32, 'same-color': world.trails.length >= 32 && world.colors.size === 1,
    'sensor-logic': (world.wallChecks || 0) >= 2 && (world.wallConditionTrue || 0) >= 2 &&
      fixture.blocks.includes('if_wall_ahead') && fixture.blocks.includes('repeat_times') &&
      !fixture.blocks.includes('smart_navigate'),
  }[id]
}

for (const [id, fixture] of Object.entries(fixtures)) {
  const objectiveIds = challengeObjectiveIds(id)
  if (!objectiveIds) { fail(`${id} is missing from LESSON_CHALLENGES.`); continue }
  const world = makeWorld(id)
  fixture.blocks.forEach((block) => world.blocks.add(block))
  runCommands(world, fixture.commands)
  for (const objectiveId of objectiveIds) {
    if (!satisfies(objectiveId, world, fixture)) fail(`${id} objective "${objectiveId}" has no executable passing representative program.`)
  }
}

const challengeIds = [...source.matchAll(/^\s*'([^']+)':\s*\{/gm)]
  .map((match) => match[1])
  .filter((id) => id.startsWith('lesson-'))
  .filter((id) => challengeObjectiveIds(id)?.length)
const fixtureIds = new Set(Object.keys(fixtures))
for (const id of challengeIds) if (!fixtureIds.has(id)) fail(`${id} has no representative execution fixture.`)
for (const id of fixtureIds) if (!challengeIds.includes(id)) fail(`${id} fixture is not a declared challenge world.`)

if (errors.length) {
  console.error('\nChallenge execution validation failed:\n')
  errors.forEach((error) => console.error(`- ${error}`))
  process.exit(1)
}
console.log(`Challenge execution validation passed: ${Object.keys(fixtures).length} representative programs completed.`)