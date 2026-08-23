/**
 * CLI behavior that is easy to regress: piped output, and the refusal to
 * configure an insecure relay by accident.
 */

import { execFile } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { hostname, tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'

import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { decodePairingCode, encodePairingCode } from '../src/shared/auth.js'
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

describe('one-command onboarding', () => {
  it('setup prints a browser pairing code when the agent code carries one', async () => {
    // This is what removes a round trip: the machine holds both halves at this
    // point, so it can finish the job instead of sending the operator back.
    const code = encodePairingCode({
      relayUrl: 'http://127.0.0.1:9',
      subject: 'agent-1',
      authSecret: generateAgentIdentity().privateKey,
      encryptionToken: generateEncryptionToken(),
      browserToken: 'relay-issued-browser-token',
    })
    const result = await cli(['setup', code, '--allow-insecure'])
    expect(result.code).toBe(0)
    expect(result.stdout).toContain('paste this pairing code')

    // The printed code must be a usable browser code: no subject, and the
    // encryption half attached.
    const printed = result.stdout.match(/dshrw1\.[A-Za-z0-9._-]+/g)?.pop() ?? ''
    const parsed = decodePairingCode(printed)
    expect(parsed?.subject).toBeNull()
    expect(parsed?.authSecret).toBe('relay-issued-browser-token')
    expect(parsed?.encryptionToken).toBeTruthy()
  })

  it('setup stays quiet about browsers when no token was carried', async () => {
    const code = encodePairingCode({
      relayUrl: 'http://127.0.0.1:9',
      subject: 'agent-1',
      authSecret: generateAgentIdentity().privateKey,
      encryptionToken: generateEncryptionToken(),
    })
    const result = await cli(['setup', code, '--allow-insecure'])
    expect(result.code).toBe(0)
    expect(result.stdout).not.toContain('paste this pairing code')
  })
})

describe('relay auto-registration', () => {
  /** Start the relay, let it settle, stop it; returns its non-TTY stdout. */
  async function relayOnce(state: string, port: number): Promise<string> {
    const child = execFile(process.execPath, [
      CLI, 'relay', '--host', '127.0.0.1', '--port', String(port),
      '--state', state, '--url', 'https://relay.example.com',
    ], { env: { ...process.env, DSH_HOME: dir } })
    let out = ''
    child.stdout?.on('data', (chunk: Buffer) => { out += chunk.toString() })
    await new Promise((resolve) => setTimeout(resolve, 900))
    child.kill('SIGTERM')
    await new Promise((resolve) => child.on('exit', resolve))
    return out
  }

  it('never prints a pairing code into a captured log', async () => {
    // Every documented deployment runs the relay as a daemon, so stdout is the
    // systemd journal or the Docker log. A pairing code carries the encryption
    // token, and writing it there would persist on the relay the one secret
    // this design promises the relay never holds.
    const state = join(dir, 'a.json')
    const out = await relayOnce(state, 18821)
    expect(out).toContain('listening on')
    expect(out).not.toContain('dshrw1.')
    expect(out).toMatch(/No active agents/)
  })

  it('does not resurrect access after the last agent is revoked', async () => {
    // Revoking the last agent is a lockdown. A restart must not silently mint a
    // fresh active credential to replace the one just withdrawn.
    const state = join(dir, 'b.json')
    await cli(['agent', 'add', 'laptop', '--state', state, '--url', 'https://relay.example.com'])
    const before = JSON.parse(readFileSync(state, 'utf8')) as { agents: { agentId: string }[] }
    await cli(['agent', 'revoke', before.agents[0]?.agentId ?? '', '--state', state])

    await relayOnce(state, 18822)

    const after = JSON.parse(readFileSync(state, 'utf8')) as { agents: { revoked: boolean }[] }
    expect(after.agents).toHaveLength(1)
    expect(after.agents.every((agent) => agent.revoked)).toBe(true)
  })

  it('names an unnamed machine the same way `agent add` does', async () => {
    // Both entry points register the same thing, so an unnamed machine must get
    // one name. When the relay path invented its own, `client add --agent
    // <name>` — the next command the docs give you — failed against it.
    const viaAdd = join(dir, 'c.json')
    await cli(['agent', 'add', '--state', viaAdd, '--url', 'https://relay.example.com'])
    const added = JSON.parse(readFileSync(viaAdd, 'utf8')) as { agents: { label: string }[] }
    expect(added.agents[0]?.label).toBe(hostname())
  })
})
