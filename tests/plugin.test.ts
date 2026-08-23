/**
 * Plugin behavior: which local DSH it proxies, and the file-based control
 * surface that replaced the HTTP control route.
 */

import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { apply } from '../src/index.js'
import { openCredentials, openStatus, statusPath } from '../src/plugin/config.js'
import { generateAgentIdentity } from '../src/shared/crypto.js'

/** One signing key reused across cases; identity is not what these test. */
const PRIVATE_KEY = generateAgentIdentity().privateKey

type Ctx = Parameters<typeof apply>[0]

let dir: string
let disposers: (() => void)[] = []

/** Mount the plugin, collecting effect disposers for teardown. */
function mount(webServer: Ctx['webServer'], config: Parameters<typeof apply>[1] = {}): void {
  const ctx: Ctx = {
    webServer,
    effect: (setup) => {
      disposers.push(setup())
    },
    logger: { info: () => undefined, warn: () => undefined },
  }
  apply(ctx, config)
}

/** Wait for the plugin's next status publication. */
async function nextStatus(path: string, timeoutMs = 6000): Promise<Record<string, unknown>> {
  const file = openStatus(statusPath(path))
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const value = file.value
    if (value !== null) return value as unknown as Record<string, unknown>
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
  throw new Error('plugin never published status')
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'dshrw-plugin-'))
  disposers = []
})

afterEach(() => {
  for (const dispose of disposers) dispose()
  disposers = []
  rmSync(dir, { recursive: true, force: true })
})

describe('choosing which local DSH to proxy', () => {
  // Regression: inferring the port from DSH_WEB_URL made a second DSH tunnel
  // to the FIRST instance's port, exposing the wrong machine's surface.
  it('prefers the port the host web server actually bound', async () => {
    const credentialPath = join(dir, 'agent.json')
    const previous = process.env.DSH_WEB_URL
    process.env.DSH_WEB_URL = 'http://127.0.0.1:3080'
    try {
      mount({ port: 3099, host: '127.0.0.1' }, { credentialPath })
      expect((await nextStatus(credentialPath)).localTarget).toBe('127.0.0.1:3099')
    } finally {
      if (previous === undefined) delete process.env.DSH_WEB_URL
      else process.env.DSH_WEB_URL = previous
    }
  })

  it('falls back to DSH_WEB_URL when the server exposes no port', async () => {
    const credentialPath = join(dir, 'agent.json')
    const previous = process.env.DSH_WEB_URL
    process.env.DSH_WEB_URL = 'http://127.0.0.1:4321'
    try {
      mount({}, { credentialPath })
      expect((await nextStatus(credentialPath)).localTarget).toBe('127.0.0.1:4321')
    } finally {
      if (previous === undefined) delete process.env.DSH_WEB_URL
      else process.env.DSH_WEB_URL = previous
    }
  })

  it('treats an all-interfaces bind as loopback for the proxy hop', async () => {
    // DSH's trust fence expects loopback, and 0.0.0.0 is not a dialable peer.
    const credentialPath = join(dir, 'agent.json')
    mount({ port: 5000, host: '0.0.0.0' }, { credentialPath })
    expect((await nextStatus(credentialPath)).localTarget).toBe('127.0.0.1:5000')
  })
})

describe('file-based control surface', () => {
  it('reports "unconfigured" until credentials exist', async () => {
    const credentialPath = join(dir, 'agent.json')
    mount({ port: 3080, host: '127.0.0.1' }, { credentialPath })
    expect((await nextStatus(credentialPath)).state).toBe('unconfigured')
  })

  it('adopts credentials written while it is running', async () => {
    const credentialPath = join(dir, 'agent.json')
    mount({ port: 3080, host: '127.0.0.1' }, { credentialPath })
    expect((await nextStatus(credentialPath)).state).toBe('unconfigured')

    // What `dsh-remote-web setup` does — no IPC, no control endpoint.
    openCredentials(credentialPath).write({
      version: 1,
      // Unroutable by design: the tunnel should try and fail, not connect.
      relayUrl: 'http://127.0.0.1:9',
      agentId: 'agent-1',
      privateKey: PRIVATE_KEY,
      encryptionToken: 'token-value',
      label: 'test-machine',
      enabled: true,
      requireE2e: true,
    })

    const deadline = Date.now() + 8000
    while (Date.now() < deadline) {
      const snapshot = await nextStatus(credentialPath)
      if (snapshot.state !== 'unconfigured') {
        expect(snapshot.label).toBe('test-machine')
        expect(['connecting', 'retrying', 'online']).toContain(snapshot.state)
        return
      }
      await new Promise((resolve) => setTimeout(resolve, 50))
    }
    throw new Error('plugin never adopted the credential file')
  })

  it('stops the tunnel when the file is disabled', async () => {
    const credentialPath = join(dir, 'agent.json')
    const credentials = openCredentials(credentialPath)
    credentials.write({
      version: 1,
      relayUrl: 'http://127.0.0.1:9',
      agentId: 'agent-1',
      privateKey: PRIVATE_KEY,
      encryptionToken: 'token-value',
      label: 'test-machine',
      enabled: true,
      requireE2e: true,
    })
    mount({ port: 3080, host: '127.0.0.1' }, { credentialPath })
    await nextStatus(credentialPath)

    credentials.write({ ...(credentials.value as never), enabled: false })

    const deadline = Date.now() + 8000
    while (Date.now() < deadline) {
      if ((await nextStatus(credentialPath)).state === 'disabled') return
      await new Promise((resolve) => setTimeout(resolve, 50))
    }
    throw new Error('plugin never honored the disable flag')
  })

  it('publishes a fingerprint but never either secret', async () => {
    const credentialPath = join(dir, 'agent.json')
    const token = 'super-secret-encryption-token'
    openCredentials(credentialPath).write({
      version: 1,
      relayUrl: 'http://127.0.0.1:9',
      agentId: 'agent-1',
      privateKey: PRIVATE_KEY,
      encryptionToken: token,
      label: 'test-machine',
      enabled: true,
      requireE2e: true,
    })
    mount({ port: 3080, host: '127.0.0.1' }, { credentialPath })
    await nextStatus(credentialPath)

    const raw = readFileSync(statusPath(credentialPath), 'utf8')
    expect(raw).not.toContain(token)
    expect(raw).not.toContain(PRIVATE_KEY)
  })

  it('writes state files owner-only', async () => {
    const credentialPath = join(dir, 'agent.json')
    openCredentials(credentialPath).write({
      version: 1,
      relayUrl: 'http://127.0.0.1:9',
      agentId: 'agent-1',
      privateKey: PRIVATE_KEY,
      encryptionToken: 'token-value',
      label: 'test-machine',
      enabled: false,
      requireE2e: true,
    })
    // The credential file holds a bearer token; another local user must not
    // be able to read it.
    expect(statSync(credentialPath).mode & 0o777).toBe(0o600)
  })

  it('never connects when the composition disables it', async () => {
    const credentialPath = join(dir, 'agent.json')
    openCredentials(credentialPath).write({
      version: 1,
      relayUrl: 'http://127.0.0.1:9',
      agentId: 'agent-1',
      privateKey: PRIVATE_KEY,
      encryptionToken: 'token-value',
      label: 'test-machine',
      enabled: true,
      requireE2e: true,
    })
    mount({ port: 3080, host: '127.0.0.1' }, { credentialPath, enabled: false })
    expect((await nextStatus(credentialPath)).state).toBe('disabled')
  })
})

describe('encryption posture changes', () => {
  it('rebuilds the tunnel when requireE2e is toggled', async () => {
    // The rebuild signature must cover posture: otherwise `disable E2E` would
    // report success while the live tunnel kept refusing plaintext.
    const credentialPath = join(dir, 'agent.json')
    const credentials = openCredentials(credentialPath)
    credentials.write({
      version: 1,
      relayUrl: 'http://127.0.0.1:9',
      agentId: 'agent-1',
      privateKey: PRIVATE_KEY,
      encryptionToken: 'token-value',
      label: 'test-machine',
      enabled: true,
      requireE2e: true,
    })
    mount({ port: 3080, host: '127.0.0.1' }, { credentialPath })
    await nextStatus(credentialPath)

    credentials.write({ ...(credentials.value as never), requireE2e: false })

    const deadline = Date.now() + 8000
    while (Date.now() < deadline) {
      const snapshot = await nextStatus(credentialPath)
      if (snapshot.state !== 'unconfigured') return
      await new Promise((resolve) => setTimeout(resolve, 50))
    }
    throw new Error('plugin never reacted to the posture change')
  })
})
