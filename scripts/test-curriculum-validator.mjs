import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { referencedBlocks, runtimeContracts } from './curriculum-capabilities.mjs'

const source = readFileSync(resolve('src/index.tsx'), 'utf8')
const fixtureDirectory = mkdtempSync(resolve(tmpdir(), 'stemo-curriculum-'))
const validator = resolve('scripts/validate-curriculum.mjs')
const taughtTypes = [...new Set(referencedBlocks.flatMap((reference) => reference.types))]

function expectRejected(name, modifiedSource) {
  const fixturePath = resolve(fixtureDirectory, `${name}.tsx`)
  writeFileSync(fixturePath, modifiedSource)
  const result = spawnSync(process.execPath, [validator, fixturePath], { encoding: 'utf8' })
  if (result.status === 0) {
    throw new Error(`${name}: expected curriculum validation to reject the missing capability.`)
  }
}

function expectAccepted(name, modifiedSource) {
  const fixturePath = resolve(fixtureDirectory, `${name}.tsx`)
  writeFileSync(fixturePath, modifiedSource)
  const result = spawnSync(process.execPath, [validator, fixturePath], { encoding: 'utf8' })
  if (result.status !== 0) {
    throw new Error(`${name}: expected safe curriculum validation to pass.\n${result.stderr}`)
  }
}

try {
  for (const type of taughtTypes) {
    expectRejected(
      `${type}-definition`,
      source.replace(`Blockly.Blocks['${type}'] =`, `Blockly.Blocks['${type}_removed'] =`),
    )
    expectRejected(
      `${type}-palette`,
      source.replace(`onclick="addBlock('${type}')"`, `onclick="addBlock('${type}_removed')"`),
    )
    expectRejected(
      `${type}-parser`,
      source.replace(`if (type === '${type}')`, `if (type === '${type}_removed')`),
    )

    const runtime = runtimeContracts[type]
    if (runtime.action) {
      expectRejected(
        `${type}-executor`,
        source.replace(`cmd.action === '${runtime.action}'`, `cmd.action === '${runtime.action}_removed'`),
      )
    }
    for (const signal of runtime.preflightSignals || []) {
      expectRejected(
        `${type}-runtime-setup`,
        source.replace(
          signal,
          signal
            .replace('define_function', 'define_function_removed')
            .replace('userFunctions', 'userFunctions_removed'),
        ),
      )
    }
  }

  expectRejected(
    'lesson-13-water-instruction',
    source.replace('I start with 9 units.', 'I start with 8 units.'),
  )
  expectAccepted(
    'does-not-execute-curriculum-expressions',
    source.replace(
      'introduction: "Hello! I am STEMO',
      'introduction: (() => { process.exit(91) })(),\n            ignored: "Hello! I am STEMO',
    ),
  )

  console.log(`Curriculum validator regression checks passed for ${taughtTypes.length} taught Blockly controls.`)
} finally {
  rmSync(fixtureDirectory, { recursive: true, force: true })
}