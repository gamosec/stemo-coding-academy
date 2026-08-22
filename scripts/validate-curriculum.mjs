import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { referencedBlocks, runtimeContracts } from './curriculum-capabilities.mjs'

const sourcePath = resolve(process.argv[2] || 'src/index.tsx')
const source = readFileSync(sourcePath, 'utf8')
const errors = []

function fail(message) {
  errors.push(message)
}

function extractObjectLiteral(marker) {
  const markerIndex = source.indexOf(marker)
  if (markerIndex === -1) throw new Error(`Could not find "${marker}" in ${sourcePath}`)

  const start = source.indexOf('{', markerIndex)
  if (start === -1) throw new Error(`Could not find object literal after "${marker}"`)

  let depth = 0
  let quote = null
  let escaped = false
  let lineComment = false
  let blockComment = false

  for (let index = start; index < source.length; index += 1) {
    const character = source[index]
    const next = source[index + 1]

    if (lineComment) {
      if (character === '\n') lineComment = false
      continue
    }
    if (blockComment) {
      if (character === '*' && next === '/') {
        blockComment = false
        index += 1
      }
      continue
    }
    if (quote) {
      if (escaped) {
        escaped = false
      } else if (character === '\\') {
        escaped = true
      } else if (character === quote) {
        quote = null
      }
      continue
    }
    if (character === '/' && next === '/') {
      lineComment = true
      index += 1
      continue
    }
    if (character === '/' && next === '*') {
      blockComment = true
      index += 1
      continue
    }
    if (character === "'" || character === '"' || character === '`') {
      quote = character
      continue
    }
    if (character === '{') depth += 1
    if (character === '}') {
      depth -= 1
      if (depth === 0) return source.slice(start, index + 1)
    }
  }

  throw new Error(`Could not find the end of the object after "${marker}"`)
}

const UNSUPPORTED_EXPRESSION = Symbol('unsupported-expression')

function parseDataLiteral(input) {
  let index = 0

  function skipWhitespaceAndComments() {
    while (index < input.length) {
      if (/\s/.test(input[index])) {
        index += 1
      } else if (input[index] === '/' && input[index + 1] === '/') {
        index = input.indexOf('\n', index + 2)
        if (index === -1) index = input.length
      } else if (input[index] === '/' && input[index + 1] === '*') {
        const end = input.indexOf('*/', index + 2)
        if (end === -1) throw new Error('Unterminated block comment in curriculum data')
        index = end + 2
      } else {
        break
      }
    }
  }

  function parseString() {
    const quote = input[index]
    let value = ''
    index += 1
    while (index < input.length) {
      const character = input[index]
      index += 1
      if (character === quote) return value
      if (character !== '\\') {
        value += character
        continue
      }

      const escaped = input[index]
      index += 1
      const escapes = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', v: '\v', 0: '\0' }
      if (escaped === 'u') {
        const hex = input.slice(index, index + 4)
        if (!/^[0-9a-f]{4}$/i.test(hex)) throw new Error('Invalid Unicode escape in curriculum data')
        value += String.fromCharCode(Number.parseInt(hex, 16))
        index += 4
      } else if (escaped === 'x') {
        const hex = input.slice(index, index + 2)
        if (!/^[0-9a-f]{2}$/i.test(hex)) throw new Error('Invalid hexadecimal escape in curriculum data')
        value += String.fromCharCode(Number.parseInt(hex, 16))
        index += 2
      } else {
        value += escapes[escaped] ?? escaped
      }
    }
    throw new Error('Unterminated string in curriculum data')
  }

  function skipExpression() {
    const stack = []
    while (index < input.length) {
      const character = input[index]
      if (character === "'" || character === '"' || character === '`') {
        parseString()
        continue
      }
      if (character === '/' && input[index + 1] === '/') {
        index = input.indexOf('\n', index + 2)
        if (index === -1) return UNSUPPORTED_EXPRESSION
        continue
      }
      if (character === '/' && input[index + 1] === '*') {
        const end = input.indexOf('*/', index + 2)
        if (end === -1) throw new Error('Unterminated block comment in curriculum expression')
        index = end + 2
        continue
      }
      if ('([{'.includes(character)) {
        stack.push(character)
        index += 1
        continue
      }
      if (')]}'.includes(character)) {
        if (stack.length === 0) break
        stack.pop()
        index += 1
        continue
      }
      if (character === ',' && stack.length === 0) break
      index += 1
    }
    return UNSUPPORTED_EXPRESSION
  }

  function parseValue() {
    skipWhitespaceAndComments()
    const character = input[index]
    if (character === '{') return parseObject()
    if (character === '[') return parseArray()
    if (character === "'" || character === '"' || character === '`') return parseString()
    const number = input.slice(index).match(/^-?\d+(?:\.\d+)?/)
    if (number) {
      index += number[0].length
      return Number(number[0])
    }
    const identifier = input.slice(index).match(/^[A-Za-z_$][\w$]*/)
    if (!identifier) return skipExpression()
    index += identifier[0].length
    if (identifier[0] === 'true') return true
    if (identifier[0] === 'false') return false
    if (identifier[0] === 'null') return null
    index -= identifier[0].length
    return skipExpression()
  }

  function parseObject() {
    const object = {}
    index += 1
    while (index < input.length) {
      skipWhitespaceAndComments()
      if (input[index] === '}') {
        index += 1
        return object
      }
      const quotedKey = input[index] === "'" || input[index] === '"'
      const key = quotedKey ? parseString() : input.slice(index).match(/^[A-Za-z_$][\w$]*/)?.[0]
      if (!key) throw new Error(`Expected object key in curriculum data near offset ${index}`)
      if (!quotedKey) index += key.length
      skipWhitespaceAndComments()
      if (input[index] !== ':') throw new Error(`Expected ":" after "${key}" in curriculum data`)
      index += 1
      object[key] = parseValue()
      skipWhitespaceAndComments()
      if (input[index] === ',') {
        index += 1
      } else if (input[index] !== '}') {
        throw new Error(`Expected "," or "}" in curriculum data near offset ${index}`)
      }
    }
    throw new Error('Unterminated object in curriculum data')
  }

  function parseArray() {
    const array = []
    index += 1
    while (index < input.length) {
      skipWhitespaceAndComments()
      if (input[index] === ']') {
        index += 1
        return array
      }
      array.push(parseValue())
      skipWhitespaceAndComments()
      if (input[index] === ',') {
        index += 1
      } else if (input[index] !== ']') {
        throw new Error(`Expected "," or "]" in curriculum data near offset ${index}`)
      }
    }
    throw new Error('Unterminated array in curriculum data')
  }

  const value = parseValue()
  skipWhitespaceAndComments()
  if (index !== input.length) throw new Error(`Unexpected content in curriculum data near offset ${index}`)
  return value
}

function extractStringArray(marker) {
  const match = source.match(marker)
  if (!match) throw new Error(`Could not find ${marker}`)
  return [...match[1].matchAll(/'([^']+)'/g)].map((entry) => entry[1])
}

function lessonText(lesson) {
  return [
    lesson.title,
    lesson.description,
    lesson.introduction,
    lesson.hint,
    lesson.homework,
    ...(lesson.tasks || []).map((task) => task.text),
  ].filter((value) => typeof value === 'string' && value.length > 0).join('\n')
}

function countSetupObjects(challengeSource, objectName) {
  const match = challengeSource.match(new RegExp(`${objectName}\\s*=\\s*\\[([\\s\\S]*?)\\];`))
  return match ? (match[1].match(/\{/g) || []).length : 0
}

function setupNumbers(challengeSource, property) {
  return [...challengeSource.matchAll(new RegExp(`\\b${property}:\\s*(\\d+)`, 'g'))]
    .map((entry) => Number(entry[1]))
}

function setupWaterLevel(challengeSource) {
  const match = challengeSource.match(/robot\.waterLevel\s*=\s*(\d+)/)
  return match ? Number(match[1]) : null
}

function parserBranchFor(type, parserSource) {
  const marker = `type === '${type}'`
  const start = parserSource.indexOf(marker)
  if (start === -1) return null
  const nextBranch = parserSource.indexOf("} else if (type === '", start + marker.length)
  return parserSource.slice(start, nextBranch === -1 ? parserSource.length : nextBranch)
}

const curriculum = parseDataLiteral(extractObjectLiteral('const curriculum ='))
const challengeLiteral = extractObjectLiteral('var LESSON_CHALLENGES =')
const challengeIds = [...challengeLiteral.matchAll(/^\s*'([^']+)':\s*\{/gm)].map((entry) => entry[1])
const challengeSources = Object.fromEntries(
  challengeIds.map((id) => [id, extractObjectLiteral(`'${id}': {`)]),
)
const challengeMeta = parseDataLiteral(extractObjectLiteral('var CHALLENGE_LESSON_META ='))
const missionLessonIds = extractStringArray(/var MISSION_LESSON_IDS\s*=\s*(\[[^;]+\])/)
const missionSet = new Set(missionLessonIds)
const teacherCurriculumMatch = source.match(/const CURRICULUM\s*=\s*(\[[\s\S]*?\]);/)
if (!teacherCurriculumMatch) throw new Error('Could not find teacher CURRICULUM')
const teacherCurriculum = [...teacherCurriculumMatch[1].matchAll(/\bid:'([^']+)'/g)].map((entry) => entry[1])
const blockTypes = new Set(
  [...source.matchAll(/Blockly\.Blocks\['([^']+)'\]\s*=/g)].map((entry) => entry[1]),
)
const paletteTypes = new Set(
  [...source.matchAll(/onclick="addBlock\('([^']+)'\)"/g)].map((entry) => entry[1]),
)
const parserSource = extractObjectLiteral('function parseBlocks(')
const commandExecutorSource = extractObjectLiteral('function executeCommands(')
const directExecutorSource = extractObjectLiteral('function executeCommand(')

const regularSections = ['basic', 'intermediate', 'advanced', 'creative']
const regularLessons = regularSections.flatMap((section) => {
  if (!Array.isArray(curriculum[section])) {
    fail(`curriculum.${section} must be an array of Learn lessons.`)
    return []
  }
  return curriculum[section]
})
const regularLessonIds = regularLessons.map((lesson) => lesson.id)
const regularLessonIdSet = new Set(regularLessonIds)

for (const section of regularSections) {
  const lessons = curriculum[section] || []
  for (let index = 0; index < lessons.length - 1; index += 1) {
    const lesson = lessons[index]
    const expectedNext = lessons[index + 1]?.id ?? null
    if (lesson.nextLesson !== expectedNext) {
      fail(`${lesson.id} has nextLesson "${lesson.nextLesson}", but ${section} order requires "${expectedNext}".`)
    }
  }
}

const mainPath = [
  ...(curriculum.basic || []),
  ...(curriculum.intermediate || []),
  ...(curriculum.advanced || []),
]
for (let index = 0; index < mainPath.length; index += 1) {
  const lesson = mainPath[index]
  const expectedNext = mainPath[index + 1]?.id ?? null
  if (lesson.nextLesson !== expectedNext) {
    fail(`${lesson.id} must point to ${expectedNext} to preserve the main Learn path order.`)
  }
}

if (regularLessonIdSet.size !== regularLessonIds.length) {
  fail('Regular Learn lesson IDs must be unique.')
}

for (const lesson of regularLessons) {
  if (!lesson.id || !lesson.title || !Array.isArray(lesson.tasks) || lesson.tasks.length === 0) {
    fail(`${lesson.id || '(missing ID)'} must include an ID, title, and at least one student task.`)
  }
}

if (teacherCurriculum.join('|') !== regularLessonIds.join('|')) {
  fail('Teacher CURRICULUM IDs and order must exactly match regular Learn lessons.')
}

for (const lesson of regularLessons) {
  const meta = challengeMeta[lesson.id]
  if (missionSet.has(lesson.id) && !meta) {
    fail(`${lesson.id} is missing from CHALLENGE_LESSON_META, which is needed to restore saved work.`)
  } else if (missionSet.has(lesson.id) && meta.nextLesson !== lesson.nextLesson) {
    fail(`${lesson.id} has a different nextLesson in CHALLENGE_LESSON_META (${meta.nextLesson}) than Learn content (${lesson.nextLesson}).`)
  }
}

const challengeSet = new Set(challengeIds)
for (const lessonId of missionSet) {
  if (!regularLessonIdSet.has(lessonId)) fail(`${lessonId} is a mission lesson but is not a regular Learn lesson.`)
  if (!challengeSet.has(lessonId)) fail(`${lessonId} is a mission lesson but has no challenge setup.`)
}
for (const lessonId of challengeSet) {
  if (!missionSet.has(lessonId)) fail(`${lessonId} has a challenge setup but is absent from MISSION_LESSON_IDS.`)
}

const baseLessons = new Map(regularLessons.map((lesson) => [lesson.id, lesson]))
for (const challenge of curriculum.challenges || []) {
  const baseId = challenge.id?.replace(/-challenge$/, '')
  const baseLesson = baseLessons.get(baseId)
  if (!baseLesson) {
    fail(`${challenge.id} has no matching regular Learn lesson.`)
  } else if (challenge.xpReward !== baseLesson.xpReward * 2) {
    fail(`${challenge.id} must award exactly 2× ${baseId}'s XP (${baseLesson.xpReward * 2}).`)
  }
  if (!missionSet.has(baseId)) {
    fail(`${challenge.id} has no matching mission lesson.`)
  }
}
for (const lessonId of missionSet) {
  if (!(curriculum.challenges || []).some((challenge) => challenge.id === `${lessonId}-challenge`)) {
    fail(`${lessonId} is missing its ${lessonId}-challenge XP entry.`)
  }
}

for (const lesson of regularLessons) {
  const text = lessonText(lesson)
  for (const reference of referencedBlocks) {
    if (!reference.patterns.some((pattern) => pattern.test(text))) continue
    for (const type of reference.types) {
      if (!blockTypes.has(type)) {
        fail(`${lesson.id} references ${reference.name}, but Blockly block "${type}" is not defined.`)
      }
      if (!paletteTypes.has(type)) {
        fail(`${lesson.id} references ${reference.name}, but Blockly block "${type}" is not available in the student palette.`)
      }
      const runtime = runtimeContracts[type]
      if (!runtime) {
        fail(`${lesson.id} references ${reference.name}, but Blockly block "${type}" has no runtime capability contract.`)
        continue
      }
      const parserBranch = parserBranchFor(type, parserSource)
      if (!parserBranch) {
        fail(`${lesson.id} references ${reference.name}, but Blockly block "${type}" has no parseBlocks runtime path.`)
        continue
      }
      if (runtime.action && !parserBranch.includes(`action: '${runtime.action}'`)) {
        fail(`${lesson.id} references ${reference.name}, but "${type}" no longer emits the "${runtime.action}" command.`)
      }
      for (const signal of runtime.parserSignals || []) {
        if (!parserBranch.includes(signal)) {
          fail(`${lesson.id} references ${reference.name}, but "${type}" is missing parser behavior "${signal}".`)
        }
      }
      for (const signal of runtime.preflightSignals || []) {
        if (!source.includes(signal)) {
          fail(`${lesson.id} references ${reference.name}, but "${type}" is missing runtime setup "${signal}".`)
        }
      }
      if (runtime.action) {
        const handler = `cmd.action === '${runtime.action}'`
        if (!commandExecutorSource.includes(handler) && !directExecutorSource.includes(handler)) {
          fail(`${lesson.id} references ${reference.name}, but "${runtime.action}" has no command execution handler.`)
        }
      }
    }
  }
}

const resourceContracts = {
  'lesson-13': {
    fires: 3,
    fireHealth: 3,
    water: 9,
    lessonClaims: [/start with 9 units/i, /every challenge fire has 3 points of health/i, /3-fire challenge/i],
  },
  'lesson-14': {
    fires: 2,
    fireHealth: 3,
    water: 6,
    lessonClaims: [/both fires/i],
  },
  'lesson-17': {
    metals: 3,
    waypoints: 3,
    lessonClaims: [/3 metal locations/i, /all 3 pre-loaded locations/i],
  },
  'lesson-18': {
    fires: 3,
    fireHealth: 3,
    water: 10,
    waypoints: 3,
    lessonClaims: [/three fires/i, /all 3 fire locations/i, /starts with 10 water units/i],
  },
}

for (const [lessonId, expected] of Object.entries(resourceContracts)) {
  const challengeSource = challengeSources[lessonId]
  if (!challengeSource) {
    fail(`${lessonId} needs a challenge setup for its resource contract.`)
    continue
  }
  if (expected.fires !== undefined) {
    const fires = countSetupObjects(challengeSource, 'fireObjects')
    if (fires !== expected.fires) fail(`${lessonId} teaches ${expected.fires} fires, but its challenge config creates ${fires}.`)
  }
  if (expected.metals !== undefined) {
    const metals = countSetupObjects(challengeSource, 'metalObjects')
    if (metals !== expected.metals) fail(`${lessonId} teaches ${expected.metals} metal pieces, but its challenge config creates ${metals}.`)
  }
  if (expected.waypoints !== undefined) {
    const waypoints = countSetupObjects(challengeSource, 'waypointList')
    if (waypoints !== expected.waypoints) fail(`${lessonId} teaches ${expected.waypoints} pre-loaded waypoints, but its challenge config creates ${waypoints}.`)
  }
  if (expected.fireHealth !== undefined) {
    const healthValues = setupNumbers(challengeSource, 'health')
    if (healthValues.length === 0 || healthValues.some((health) => health !== expected.fireHealth)) {
      fail(`${lessonId} teaches fire health of ${expected.fireHealth}, but its challenge config uses [${healthValues.join(', ') || 'none'}].`)
    }
  }
  if (expected.water !== undefined) {
    const water = setupWaterLevel(challengeSource)
    if (water !== expected.water) fail(`${lessonId} teaches a ${expected.water}-unit water tank, but its challenge config uses ${water ?? 'no explicit value'}.`)
  }
  if (expected.fires !== undefined && expected.fireHealth !== undefined && expected.water !== undefined
    && expected.water < expected.fires * expected.fireHealth) {
    fail(`${lessonId} needs at least ${expected.fires * expected.fireHealth} water units to extinguish every fire, but its challenge tank has ${expected.water}.`)
  }
  for (const claim of expected.lessonClaims || []) {
    if (!claim.test(lessonText(baseLessons.get(lessonId)))) {
      fail(`${lessonId} instructions no longer state the resource capability required by its challenge setup (${claim}).`)
    }
  }
}

const requiredProgressSections = regularSections.map((section) => `...curriculum.${section}`)
const progressRoutes = [...source.matchAll(/const allLessons\s*=\s*\[([\s\S]*?)\]\s*as any\[\]/g)]
for (const route of progressRoutes.slice(0, 2)) {
  for (const section of requiredProgressSections) {
    if (!route[1].includes(section)) fail(`Progress validation must include ${section}.`)
  }
}

if (errors.length > 0) {
  console.error('\nCurriculum validation failed:\n')
  for (const error of errors) console.error(`- ${error}`)
  process.exit(1)
}

const challengeExecution = spawnSync(process.execPath, [
  resolve('scripts/validate-challenge-execution.mjs'), sourcePath,
], { encoding: 'utf8' })
if (challengeExecution.status !== 0) {
  console.error(challengeExecution.stdout)
  console.error(challengeExecution.stderr)
  process.exit(challengeExecution.status || 1)
}

console.log(`Curriculum validation passed: ${regularLessons.length} Learn lessons, ${blockTypes.size} Blockly blocks, and ${challengeIds.length} challenge worlds are consistent.`)