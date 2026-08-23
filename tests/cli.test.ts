/**
 * CLI behavior that is easy to regress: piped output, and the refusal to
 * configure an insecure relay by accident.
 */

import { execFile } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'

import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { encodePairingCode } from '../src/shared/auth.js'
import { generateAgentIdentity, generateEncryptionToken } from '../src/shared/crypto.js'

/** Build an agent pairing code for the tests. */
function agentCode(relayUrl: string): string {
  return encodePairingCode({
    relayUrl,
    subject: 'agent-1',
    authSecret: generateAgentIdentity().privateKey,
    encryptionToken: generateEncryptionToken(),
  })
}

const run = promisify(execFile)
const CLI = join(process.cwd(), 'lib', 'cli.js')

let dir: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'dshrw-cli-'))
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

/** Run the built CLI with an isolated DSH_HOME. */
async function cli(args: string[]): Promise<{ stdout: string; stderr: string; code: number }> {
  try {
    const { stdout, stderr } = await run(process.execPath, [CLI, ...args], {
      env: { ...process.env, DSH_HOME: dir },
    })
    return { stdout, stderr, code: 0 }
  } catch (error) {
    const failure = error as { stdout?: string; stderr?: string; code?: number }
    return { stdout: failure.stdout ?? '', stderr: failure.stderr ?? '', code: failure.code ?? 1 }
  }
}

describe('piped output', () => {
  it('exits cleanly when the reader closes the pipe', async () => {
    // `status | head -1` closes stdout early; Node surfaces that as an EPIPE
    // 'error' event, which once crashed the command with a stack trace.
    const { stdout, stderr } = await run(
      'sh',
      ['-c', `"${process.execPath}" "${CLI}" --help | head -1`],
      { env: { ...process.env, DSH_HOME: dir } },
    )
    expect(stdout).toContain('dsh-remote-web')
    expect(stderr).not.toContain('EPIPE')
  })
})

describe('setup safety', () => {
  it('refuses a plaintext relay unless explicitly allowed', async () => {
    const result = await cli(['setup', agentCode('http://relay.example.com')])
    expect(result.code).not.toBe(0)
    expect(result.stderr).toMatch(/clear text/)
  })

  it('accepts a plaintext relay with --allow-insecure', async () => {
    const result = await cli(['setup', agentCode('http://127.0.0.1:9'), '--allow-insecure'])
    expect(result.code).toBe(0)
    expect(result.stdout).toContain('Paired with')
  })

  it('rejects a browser token where a machine code is required', async () => {
    // A browser code has no subject; telling the user which value they pasted
    // is more useful than a generic parse error.
    const browserCode = encodePairingCode({
      relayUrl: 'https://relay.example.com',
      subject: null,
      authSecret: 'access-token',
      encryptionToken: generateEncryptionToken(),
    })
    const result = await cli(['setup', browserCode])
    expect(result.code).not.toBe(0)
    expect(result.stderr).toMatch(/browser token/)
  })

  it('never prints either secret back', async () => {
    const privateKey = generateAgentIdentity().privateKey
    const encryptionToken = generateEncryptionToken()
    const code = encodePairingCode({
      relayUrl: 'http://127.0.0.1:9',
      subject: 'agent-1',
      authSecret: privateKey,
      encryptionToken,
    })
    const result = await cli(['setup', code, '--allow-insecure'])
    expect(result.stdout).not.toContain(privateKey)
    expect(result.stdout).not.toContain(encryptionToken)

    const shown = await cli(['show-config'])
    expect(shown.stdout).not.toContain(privateKey)
    expect(shown.stdout).not.toContain(encryptionToken)
  })

  it('mints a browser invite that carries the encryption token', async () => {
    // Only the DSH machine can do this: the relay never holds the encryption
    // token, so neither party alone can produce a working browser credential.
    await cli(['setup', agentCode('http://127.0.0.1:9'), '--allow-insecure'])
    const invite = await cli(['invite', 'relay-issued-token'])
    expect(invite.code).toBe(0)
    expect(invite.stdout).toContain('dshrw1.')
  })
})

describe('status without a running plugin', () => {
  it('says so plainly rather than erroring', async () => {
    const result = await cli(['status'])
    expect(result.code).toBe(0)
    expect(result.stdout).toMatch(/Not configured/)
  })
})
