/**
 * End-to-end: a stand-in DSH server, a real relay, and a real tunnel.
 *
 * This is the test that proves the product claim — a browser with a valid
 * token reaches a DSH server that never opened an inbound port — and that the
 * security boundaries hold on the same wire the feature runs on.
 */

import { createServer, type Server } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import { AddressInfo } from 'node:net'

import { WebSocketServer, WebSocket } from 'ws'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { startRelay, type RunningRelay } from '../src/relay/server.js'
import { TunnelClient } from '../src/plugin/tunnel.js'
import type { AgentCredentials } from '../src/plugin/config.js'
import { resolvePluginConfig } from '../src/plugin/config.js'

/** A minimal stand-in for the DSH web server, including its trust fence. */
interface FakeDsh {
  server: Server
  port: number
  /** Requests it saw, for asserting what the tunnel actually forwarded. */
  seen: { path: string; headers: Record<string, string | string[] | undefined> }[]
  close: () => Promise<void>
}

/** The authority the tunnel presents; the fake DSH trusts it like the real one. */
const TRUSTED_HOSTS = ['dsh-remote-web.internal']

/** DSH's own privileged set, verbatim from dsh-client-connection. */
const PRIVILEGED_METHODS = new Set([
  'host.pickDirectory',
  'host.openPath',
  'settings.describe',
  'settings.openDocument',
  'settings.update',
  'settings.replace',
  'settings.mutate',
  'credentials.describe',
  'credentials.set',
  'credentials.unset',
  'agentPreset.read',
  'agentPreset.copy',
  'agentPreset.openDocument',
  'agentPreset.remove',
  'llm.discoverModels',
])

async function startFakeDsh(): Promise<FakeDsh> {
  const seen: FakeDsh['seen'] = []
  const server = createServer((request, response) => {
    seen.push({ path: request.url ?? '', headers: { ...request.headers } })

    // Mirror DSH's real two-tier fence, which is what the tunnel relies on:
    //   - the ordinary fence admits loopback OR a declared trustedHosts entry;
    //   - PRIVILEGED_METHODS additionally require loopback specifically.
    // Modelling both tiers is the point: it proves DSH refuses the privileged
    // plane to the tunnel's named authority without this package listing them.
    const host = request.headers.host ?? ''
    const hostname = host.replace(/:\d+$/, '')
    const isLoopback = /^(127\.|localhost|\[?::1\]?)/.test(hostname)
    const isTrusted = isLoopback || TRUSTED_HOSTS.includes(hostname)
    const origin = request.headers.origin
    if (!isTrusted || (origin !== undefined && new URL(origin).host !== host)) {
      response.writeHead(403, { 'content-type': 'text/plain' })
      response.end('forbidden')
      return
    }
    if (request.headers['sec-fetch-site'] === 'cross-site') {
      response.writeHead(403, { 'content-type': 'text/plain' })
      response.end('forbidden')
      return
    }
    const method = (request.url ?? '').startsWith('/api/')
      ? (request.url ?? '').slice('/api/'.length).split('?')[0] ?? ''
      : ''
    if (PRIVILEGED_METHODS.has(method) && !isLoopback) {
      response.writeHead(403, { 'content-type': 'text/plain' })
      response.end('forbidden')
      return
    }

    if (request.url === '/') {
      response.writeHead(200, { 'content-type': 'text/html' })
      response.end('<html><body>DSH surface</body></html>')
      return
    }
    if (request.url === '/echo' && request.method === 'POST') {
      const chunks: Buffer[] = []
      request.on('data', (chunk: Buffer) => chunks.push(chunk))
      request.on('end', () => {
        response.writeHead(200, { 'content-type': 'application/json' })
        response.end(JSON.stringify({ received: Buffer.concat(chunks).toString('utf8') }))
      })
      return
    }
    if (request.url === '/big') {
      response.writeHead(200, { 'content-type': 'application/octet-stream' })
      response.end(Buffer.alloc(3 * 1024 * 1024, 0x41))
      return
    }
    response.writeHead(404, { 'content-type': 'text/plain' })
    response.end('not found')
  })

  // The two downlink sockets DSH exposes; the tunnel is allowed to proxy these.
  const wss = new WebSocketServer({ noServer: true })
  server.on('upgrade', (request, socket, head) => {
    const path = (request.url ?? '').split('?')[0]
    if (path !== '/api/events.mux' && path !== '/api/events.host') {
      socket.destroy()
      return
    }
    wss.handleUpgrade(request, socket, head, (ws) => {
      ws.send(JSON.stringify({ hello: path }))
      ws.on('message', (raw) => {
        ws.send(`echo:${raw.toString('utf8')}`)
      })
    })
  })

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = (server.address() as AddressInfo).port
  return {
    server,
    port,
    seen,
    close: async () => {
      wss.close()
      server.closeAllConnections()
      await new Promise<void>((resolve) => server.close(() => resolve()))
    },
  }
}

let dsh: FakeDsh
let relay: RunningRelay
let tunnel: TunnelClient
let dir: string
let clientToken: string
let agentId: string
let encryptionToken: string
let relayBase: string

/** Log in and return the session cookie. */
async function login(token: string): Promise<string> {
  const response = await fetch(`${relayBase}/__auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token }).toString(),
    redirect: 'manual',
  })
  const cookie = response.headers.get('set-cookie')
  if (cookie === null) throw new Error(`login failed: ${String(response.status)}`)
  return cookie.split(';')[0] ?? ''
}

/**
 * Issue a GET with the path bytes exactly as given.
 *
 * `fetch` normalizes traversal sequences before sending, which would hide the
 * very input these tests exist to check.
 *
 * @returns The response status code.
 */
async function rawGet(path: string, cookie: string): Promise<number> {
  const { request } = await import('node:http')
  return await new Promise<number>((resolve, reject) => {
    const req = request(
      { host: '127.0.0.1', port: relay.port, path, method: 'GET', headers: { cookie } },
      (response) => {
        response.resume()
        response.on('end', () => resolve(response.statusCode ?? 0))
      },
    )
    req.on('error', reject)
    req.end()
  })
}

/** Wait until the tunnel reports it is online. */
async function waitOnline(client: TunnelClient, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (client.status().state === 'online') return
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
  throw new Error(`tunnel never came online (state: ${client.status().state})`)
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'dshrw-e2e-'))
  dsh = await startFakeDsh()

  relay = await startRelay({
    host: '127.0.0.1',
    port: 0,
    statePath: join(dir, 'state.json'),
    secure: false,
    trustProxy: false,
    sessionTtlMs: 60_000,
    log: () => undefined,
  })
  relayBase = `http://127.0.0.1:${String(relay.port)}`

  const agent = relay.store.createAgent('test-machine')
  agentId = agent.record.agentId
  encryptionToken = agent.encryptionToken
  const client = relay.store.createClient('test-browser', '*', null)
  clientToken = client.token

  const credentials: AgentCredentials = {
    version: 1,
    relayUrl: relayBase,
    agentId,
    privateKey: agent.privateKey,
    encryptionToken: agent.encryptionToken,
    label: 'test-machine',
    enabled: true,
  }
  tunnel = new TunnelClient(
    credentials,
    resolvePluginConfig({ localHost: '127.0.0.1', localPort: dsh.port }),
    { info: () => undefined, warn: () => undefined },
  )
  tunnel.start()
  await waitOnline(tunnel)
}, 30_000)

afterAll(async () => {
  tunnel.stop()
  await relay.close()
  await dsh.close()
  rmSync(dir, { recursive: true, force: true })
})

describe('the tunnel', () => {
  it('connects outbound and registers as online', () => {
    expect(tunnel.status().state).toBe('online')
    expect(relay.tunnels.get(agentId)).toBeDefined()
  })
})

describe('authentication', () => {
  it('refuses an unauthenticated browser and shows the login page', async () => {
    const response = await fetch(`${relayBase}/a/${agentId}/`, { redirect: 'manual' })
    expect(response.status).toBe(401)
    expect(await response.text()).toContain('Access token')
  })

  it('refuses an invalid token', async () => {
    const response = await fetch(`${relayBase}/__auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: 'not-a-real-token' }).toString(),
      redirect: 'manual',
    })
    expect(response.status).toBe(401)
    expect(response.headers.get('set-cookie')).toBeNull()
  })

  it('issues a hardened session cookie on success', async () => {
    const response = await fetch(`${relayBase}/__auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: clientToken }).toString(),
      redirect: 'manual',
    })
    expect(response.status).toBe(303)
    const cookie = response.headers.get('set-cookie') ?? ''
    expect(cookie).toContain('HttpOnly')
    expect(cookie).toContain('SameSite=Lax')
  })

  it('refuses a revoked token', async () => {
    const throwaway = relay.store.createClient('temp', '*', null)
    expect(relay.store.revokeClient(throwaway.record.clientId)).toBe(true)
    const response = await fetch(`${relayBase}/__auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: throwaway.token }).toString(),
      redirect: 'manual',
    })
    expect(response.status).toBe(401)
  })
})

describe('proxying an authenticated browser to DSH', () => {
  it('serves the DSH surface through the relay', async () => {
    const cookie = await login(clientToken)
    const response = await fetch(`${relayBase}/a/${agentId}/`, { headers: { cookie } })
    expect(response.status).toBe(200)
    expect(await response.text()).toContain('DSH surface')
  })

  it('rewrites headers so the DSH trust fence accepts the request', async () => {
    const cookie = await login(clientToken)
    dsh.seen.length = 0
    // A legitimate request carries the relay's own origin, which can never
    // match the authority the host presents; without the rewrite DSH would
    // reject a request the operator authorized.
    const response = await fetch(`${relayBase}/a/${agentId}/`, {
      headers: { cookie, origin: relayBase, 'sec-fetch-site': 'same-origin' },
    })
    expect(response.status).toBe(200)
    const observed = dsh.seen.at(-1)
    expect(observed?.headers.host).toBe('dsh-remote-web.internal')
    expect(observed?.headers.origin).toBe('http://dsh-remote-web.internal')
    expect(observed?.headers['sec-fetch-site']).toBe('same-origin')
  })

  it('refuses a cross-site request instead of laundering it', async () => {
    // The rewrite that lets a proxied request pass DSH's fence also destroys
    // the evidence that fence depends on: forwarded verbatim, every request
    // would reach DSH marked same-origin. The judgement therefore has to be
    // made here, while the browser's own marker still means something.
    // Without it, an attacker's page could drive the DSH surface using the
    // victim's session.
    const cookie = await login(clientToken)
    dsh.seen.length = 0
    const response = await fetch(`${relayBase}/a/${agentId}/`, {
      headers: { cookie, origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' },
    })
    expect(response.status).toBe(403)
    // Refused at the boundary: nothing reached the host at all.
    expect(dsh.seen).toHaveLength(0)
  })

  it('does not leak the relay session cookie to DSH', async () => {
    const cookie = await login(clientToken)
    dsh.seen.length = 0
    await fetch(`${relayBase}/a/${agentId}/`, { headers: { cookie } })
    expect(dsh.seen.at(-1)?.headers.cookie).toBeUndefined()
  })

  it('round-trips a request body', async () => {
    const cookie = await login(clientToken)
    const response = await fetch(`${relayBase}/a/${agentId}/echo`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'text/plain' },
      body: 'hello through the tunnel',
    })
    expect(await response.json()).toEqual({ received: 'hello through the tunnel' })
  })

  it('streams a response larger than one frame', async () => {
    const cookie = await login(clientToken)
    const response = await fetch(`${relayBase}/a/${agentId}/big`, { headers: { cookie } })
    const body = Buffer.from(await response.arrayBuffer())
    // 3 MiB exceeds the 512 KiB chunk bound, so this exercises reassembly.
    expect(body.length).toBe(3 * 1024 * 1024)
    expect(body.every((byte) => byte === 0x41)).toBe(true)
  })

  it('passes through upstream status codes', async () => {
    const cookie = await login(clientToken)
    const response = await fetch(`${relayBase}/a/${agentId}/nope`, { headers: { cookie } })
    expect(response.status).toBe(404)
  })
})

describe('websocket proxying', () => {
  it('proxies an allowed DSH downlink socket end to end', async () => {
    const cookie = await login(clientToken)
    const socket = new WebSocket(`ws://127.0.0.1:${String(relay.port)}/a/${agentId}/api/events.mux`, {
      headers: { cookie },
    })
    await once(socket, 'open')

    const [greeting] = (await once(socket, 'message')) as [Buffer]
    expect(JSON.parse(greeting.toString('utf8'))).toEqual({ hello: '/api/events.mux' })

    socket.send('ping')
    const [echo] = (await once(socket, 'message')) as [Buffer]
    expect(echo.toString('utf8')).toBe('echo:ping')

    socket.close()
  })

  it('refuses an upgrade to any path outside the allowlist', async () => {
    const cookie = await login(clientToken)
    const socket = new WebSocket(
      `ws://127.0.0.1:${String(relay.port)}/a/${agentId}/sidebar/api/terminal`,
      { headers: { cookie } },
    )
    const [error] = (await once(socket, 'error')) as [Error]
    // A shell-bearing socket reached from a remote browser would defeat the
    // point of proxying only the conversation surface.
    expect(error.message).toMatch(/403|Unexpected server response/)
  })

  it('refuses an unauthenticated upgrade', async () => {
    const socket = new WebSocket(`ws://127.0.0.1:${String(relay.port)}/a/${agentId}/api/events.mux`)
    const [error] = (await once(socket, 'error')) as [Error]
    expect(error.message).toMatch(/401|Unexpected server response/)
  })
})

describe('revocation', () => {
  it('ends a live session immediately, not at the next restart', async () => {
    const victim = relay.store.createClient('to-be-revoked', '*', null)
    const cookie = await login(victim.token)

    const before = await fetch(`${relayBase}/a/${agentId}/`, { headers: { cookie } })
    expect(before.status).toBe(200)

    // Revoke through a SEPARATE store instance, as the CLI does in its own
    // process while the relay keeps running.
    const cli = new (await import('../src/relay/store.js')).RelayStore(join(dir, 'state.json'))
    expect(cli.revokeClient(victim.record.clientId)).toBe(true)

    const after = await fetch(`${relayBase}/a/${agentId}/`, { headers: { cookie } })
    expect(after.status).toBe(401)
  })

  it('refuses a websocket upgrade on a revoked session', async () => {
    const victim = relay.store.createClient('ws-revoked', '*', null)
    const cookie = await login(victim.token)
    relay.store.revokeClient(victim.record.clientId)

    const socket = new WebSocket(
      `ws://127.0.0.1:${String(relay.port)}/a/${agentId}/api/events.mux`,
      { headers: { cookie } },
    )
    const [error] = (await once(socket, 'error')) as [Error]
    expect(error.message).toMatch(/401|Unexpected server response/)
  })
})

describe('privileged methods over the tunnel', () => {
  // Exploit verified before the fix: the tunnel rewrites Host to loopback, so
  // DSH's fence saw a local caller and served credentials.set to a remote
  // browser. The rewrite must withhold what the fence was protecting.
  it('lets DSH refuse the whole privileged plane, including llm.discoverModels', async () => {
    // No list in this package decides these; DSH does, because the tunnel is a
    // named authority rather than loopback. `llm.discoverModels` is included
    // deliberately: an earlier hand-maintained blacklist here missed it.
    const cookie = await login(clientToken)
    for (const method of [
      'credentials.set',
      'credentials.describe',
      'settings.update',
      'host.openPath',
      'host.pickDirectory',
      'agentPreset.remove',
      'llm.discoverModels',
    ]) {
      const response = await fetch(`${relayBase}/a/${agentId}/api/${method}`, {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: '{}',
      })
      expect(response.status, method).toBe(403)
    }
  })

  it('still serves the ordinary conversation surface', async () => {
    const cookie = await login(clientToken)
    const response = await fetch(`${relayBase}/a/${agentId}/`, { headers: { cookie } })
    expect(response.status).toBe(200)
  })
})

describe('authorization scope', () => {
  it('confines a scoped credential to its own agent', async () => {
    const scoped = relay.store.createClient('scoped', 'some-other-agent', null)
    const cookie = await login(scoped.token)
    const response = await fetch(`${relayBase}/a/${agentId}/`, { headers: { cookie } })
    expect(response.status).toBe(403)
  })
})

describe('path safety at the relay edge', () => {
  it('rejects traversal attempts before they reach the tunnel', async () => {
    const cookie = await login(clientToken)
    // `fetch` normalizes `%2e%2e` away before it ever leaves the client, so a
    // raw request is the only way to put the hostile bytes on the wire — which
    // is exactly what an attacker would do.
    const status = await rawGet(`/a/${agentId}/%2e%2e/secret`, cookie)
    expect(status).toBe(400)
  })

  it('rejects protocol-relative paths', async () => {
    const cookie = await login(clientToken)
    expect(await rawGet('//evil.example/path', cookie)).toBe(400)
  })
})

describe('agent offline behavior', () => {
  it('answers 503 for an agent with no live tunnel', async () => {
    const cookie = await login(clientToken)
    const other = relay.store.createAgent('never-connects')
    const response = await fetch(`${relayBase}/a/${other.record.agentId}/`, { headers: { cookie } })
    expect(response.status).toBe(503)
    expect(await response.text()).toContain('offline')
  })
})

describe('relay health', () => {
  it('reports liveness without requiring authentication', async () => {
    const response = await fetch(`${relayBase}/__health`)
    expect(response.status).toBe(200)
    const body = (await response.json()) as { ok: boolean; agents: number }
    expect(body.ok).toBe(true)
    expect(body.agents).toBeGreaterThanOrEqual(1)
  })
})

describe('signature login keeps the token off the wire', () => {
  it('enrolls on first login, then authenticates by signature', async () => {
    const { generateAgentIdentity, signMessage } = await import('../src/shared/crypto.js')
    const credential = relay.store.createClient('device', '*', null)
    const identity = generateAgentIdentity()

    // First login carries the token once and enrolls the key.
    const first = await fetch(`${relayBase}/__auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token: credential.token,
        publicKey: identity.publicKey,
      }).toString(),
      redirect: 'manual',
    })
    expect(first.status).toBe(303)

    // Every later login is a signature: the token never travels again, which
    // is what makes a plain-HTTP relay survivable.
    const challenge = (await (await fetch(`${relayBase}/__auth/challenge`)).json()) as {
      nonce: string
    }
    const verify = await fetch(`${relayBase}/__auth/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        nonce: challenge.nonce,
        signature: signMessage(`dsh-remote-web/login|${challenge.nonce}`, identity.privateKey),
      }).toString(),
    })
    expect(verify.status).toBe(200)
    expect(verify.headers.get('set-cookie')).toContain('HttpOnly')
  })

  it('refuses a replayed challenge', async () => {
    const { generateAgentIdentity, signMessage } = await import('../src/shared/crypto.js')
    const credential = relay.store.createClient('replay', '*', null)
    const identity = generateAgentIdentity()
    await fetch(`${relayBase}/__auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: credential.token, publicKey: identity.publicKey }).toString(),
      redirect: 'manual',
    })
    const challenge = (await (await fetch(`${relayBase}/__auth/challenge`)).json()) as {
      nonce: string
    }
    const body = new URLSearchParams({
      nonce: challenge.nonce,
      signature: signMessage(`dsh-remote-web/login|${challenge.nonce}`, identity.privateKey),
    }).toString()
    const opts = { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body }
    expect((await fetch(`${relayBase}/__auth/verify`, opts)).status).toBe(200)
    // A captured signature must not work twice.
    expect((await fetch(`${relayBase}/__auth/verify`, opts)).status).toBe(401)
  })

  it('caps concurrent sessions so a leaked token cannot exhaust memory', async () => {
    const credential = relay.store.createClient('flood', '*', null)
    for (let i = 0; i < 60; i += 1) {
      await fetch(`${relayBase}/__auth/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: credential.token }).toString(),
        redirect: 'manual',
      })
    }
    expect(relay.sessions.size).toBeLessThanOrEqual(256)
  })
})
