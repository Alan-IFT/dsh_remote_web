/**
 * Event-stream encryption.
 *
 * This is where the assistant's reply text reaches the browser, chunk by
 * chunk, so these tests check the property that matters most: what the relay
 * carries is unreadable to it.
 */
import { createServer, type Server } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import type { AddressInfo } from 'node:net'

import { WebSocket, WebSocketServer } from 'ws'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { startRelay, type RunningRelay } from '../src/relay/server.js'
import { TunnelClient } from '../src/plugin/tunnel.js'
import { resolvePluginConfig } from '../src/plugin/config.js'
import {
  deriveSessionKey,
  generateEncryptionToken,
  generateEphemeralKeyPair,
  open as openSealed,
} from '../src/shared/crypto.js'

/** The exact secret a real session would stream. */
const SECRET = 'ASSISTANT-REPLY-TEXT'

let dsh: Server, relay: RunningRelay, tunnel: TunnelClient, dir: string
let agentId: string, clientToken: string, encryptionToken: string, relayBase: string

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'wsc-'))
  dsh = createServer()
  const wss = new WebSocketServer({ noServer: true })
  dsh.on('upgrade', (request, socket, head) => {
    const path = (request.url ?? '').split('?')[0]
    if (path !== '/api/events.mux' && path !== '/api/events.host') {
      socket.destroy()
      return
    }
    wss.handleUpgrade(request, socket, head, (ws) => {
      ws.send(JSON.stringify({ method: 'session/event', payload: { text: SECRET } }))
    })
  })
  await new Promise<void>((r) => dsh.listen(0, '127.0.0.1', r))

  relay = await startRelay({
    host: '127.0.0.1', port: 0, statePath: join(dir, 's.json'),
    secure: false, trustProxy: false, sessionTtlMs: 60_000, log: () => undefined,
  })
  relayBase = `http://127.0.0.1:${String(relay.port)}`
  const agent = relay.store.createAgent('m')
  agentId = agent.record.agentId
  encryptionToken = agent.encryptionToken
  clientToken = relay.store.createClient('p', agentId, null).token

  tunnel = new TunnelClient(
    {
      version: 1, relayUrl: relayBase, agentId,
      privateKey: agent.privateKey, encryptionToken: agent.encryptionToken,
      label: 'm', enabled: true, requireE2e: true,
    },
    resolvePluginConfig({ localHost: '127.0.0.1', localPort: (dsh.address() as AddressInfo).port }),
    { info: () => undefined, warn: () => undefined },
  )
  tunnel.start()
  const deadline = Date.now() + 8000
  while (Date.now() < deadline && tunnel.status().state !== 'online') {
    await new Promise((r) => setTimeout(r, 25))
  }
}, 30_000)

afterAll(async () => {
  tunnel.stop()
  await relay.close()
  dsh.closeAllConnections()
  await new Promise<void>((r) => dsh.close(() => r()))
  rmSync(dir, { recursive: true, force: true })
})

/** Log in and return the session cookie. */
async function login(): Promise<string> {
  const response = await fetch(`${relayBase}/__auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token: clientToken }).toString(),
    redirect: 'manual',
  })
  return (response.headers.get('set-cookie') ?? '').split(';')[0] ?? ''
}

describe('event stream confidentiality', () => {
  it('carries the reply text as ciphertext the relay cannot read', async () => {
    const cookie = await login()
    const browser = generateEphemeralKeyPair()
    const socket = new WebSocket(
      `ws://127.0.0.1:${String(relay.port)}/a/${agentId}/api/events.mux` +
        `?dshrw_epk=${encodeURIComponent(browser.publicKey)}`,
      { headers: { cookie } },
    )
    const [raw] = (await once(socket, 'message')) as [Buffer]
    const wire = raw.toString('utf8')

    // The decisive assertion: the bytes crossing the relay reveal nothing.
    expect(wire).not.toContain(SECRET)
    expect(wire).not.toContain('session/event')

    const envelope = JSON.parse(wire) as { epk: string; n: string; c: string; t: string }
    const key = deriveSessionKey(browser.privateKey, envelope.epk, encryptionToken)
    // Authenticated against the stream path, so a relay cannot move a frame
    // between the two downlinks.
    const opened = openSealed(envelope, key, '/api/events.mux')
    expect(opened?.toString('utf8')).toContain(SECRET)
    socket.close()
  })

  it('refuses a frame authenticated against the other downlink', async () => {
    const cookie = await login()
    const browser = generateEphemeralKeyPair()
    const socket = new WebSocket(
      `ws://127.0.0.1:${String(relay.port)}/a/${agentId}/api/events.mux` +
        `?dshrw_epk=${encodeURIComponent(browser.publicKey)}`,
      { headers: { cookie } },
    )
    const [raw] = (await once(socket, 'message')) as [Buffer]
    const envelope = JSON.parse(raw.toString('utf8')) as { epk: string; n: string; c: string; t: string }
    const key = deriveSessionKey(browser.privateKey, envelope.epk, encryptionToken)
    expect(openSealed(envelope, key, '/api/events.host')).toBeNull()
    socket.close()
  })

  it('refuses a frame opened with the wrong encryption token', async () => {
    const cookie = await login()
    const browser = generateEphemeralKeyPair()
    const socket = new WebSocket(
      `ws://127.0.0.1:${String(relay.port)}/a/${agentId}/api/events.mux` +
        `?dshrw_epk=${encodeURIComponent(browser.publicKey)}`,
      { headers: { cookie } },
    )
    const [raw] = (await once(socket, 'message')) as [Buffer]
    const envelope = JSON.parse(raw.toString('utf8')) as { epk: string; n: string; c: string; t: string }
    // This is the relay's position exactly: it can carry, but not read.
    const wrong = deriveSessionKey(browser.privateKey, envelope.epk, generateEncryptionToken())
    expect(openSealed(envelope, wrong, '/api/events.mux')).toBeNull()
    socket.close()
  })

  it('refuses an unencrypted stream when the host requires E2E', async () => {
    // A relay that stripped the key would otherwise get a readable stream.
    const cookie = await login()
    const socket = new WebSocket(
      `ws://127.0.0.1:${String(relay.port)}/a/${agentId}/api/events.mux`,
      { headers: { cookie } },
    )
    const [code] = (await once(socket, 'close')) as [number]
    expect(code).not.toBe(1000)
  })
})
