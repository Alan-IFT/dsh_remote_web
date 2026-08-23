/**
 * End-to-end encryption over a real relay and a real tunnel.
 *
 * The claim under test is the strong one: a browser holding both tokens can
 * drive DSH, while the relay carrying every byte can neither read the traffic
 * nor forge it — even though the relay is fully trusted to route it.
 */

import { createServer, type Server } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { AddressInfo } from 'node:net'

import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { startRelay, type RunningRelay } from '../src/relay/server.js'
import { TunnelClient } from '../src/plugin/tunnel.js'
import { resolvePluginConfig, type AgentCredentials } from '../src/plugin/config.js'
import {
  deriveSessionKey,
  generateEncryptionToken,
  generateEphemeralKeyPair,
  open as openSealed,
  seal,
} from '../src/shared/crypto.js'
import type { SealedEnvelope } from '../src/shared/protocol.js'

/** A stand-in DSH that echoes what it received, so we can prove round-trips. */
async function startFakeDsh(): Promise<{ server: Server; port: number; close: () => Promise<void> }> {
  const server = createServer((request, response) => {
    if (request.url === '/secret') {
      response.writeHead(200, { 'content-type': 'application/json', 'x-marker': 'from-dsh' })
      response.end(JSON.stringify({ confidential: 'THE-SECRET-PAYLOAD' }))
      return
    }
    response.writeHead(404)
    response.end('nope')
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  return {
    server,
    port: (server.address() as AddressInfo).port,
    close: async () => {
      server.closeAllConnections()
      await new Promise<void>((resolve) => server.close(() => resolve()))
    },
  }
}

/**
 * The browser half of the encryption scheme.
 *
 * This mirrors what a browser does with WebCrypto: generate an ephemeral key,
 * derive the session key from it plus the encryption token, and seal the
 * request. It exists here so the test exercises the real wire format rather
 * than a mock of it.
 */
class BrowserCryptoClient {
  readonly #ephemeral = generateEphemeralKeyPair()
  readonly #token: string

  constructor(token: string) {
    this.#token = token
  }

  /** Seal a request for the host, bound to its exchange id. */
  sealRequest(
    rid: string,
    hostPublicKey: string,
    request: { method: string; path: string; headers: Record<string, string> },
  ): SealedEnvelope {
    const key = deriveSessionKey(this.#ephemeral.privateKey, hostPublicKey, this.#token)
    const sealed = seal(Buffer.from(JSON.stringify(request), 'utf8'), key, rid)
    return { epk: this.#ephemeral.publicKey, salt: '', n: sealed.n, c: sealed.c, t: sealed.t }
  }

  /** Open a response the host sealed for us. */
  openResponse(rid: string, envelope: SealedEnvelope): Buffer | null {
    const key = deriveSessionKey(this.#ephemeral.privateKey, envelope.epk, this.#token)
    return openSealed({ n: envelope.n, c: envelope.c, t: envelope.t }, key, rid)
  }
}

let dsh: Awaited<ReturnType<typeof startFakeDsh>>
let relay: RunningRelay
let tunnel: TunnelClient
let dir: string
let encryptionToken: string

/** Wait until the tunnel reports it is online. */
async function waitOnline(client: TunnelClient, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (client.status().state === 'online') return
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
  throw new Error(`tunnel never came online (${client.status().state})`)
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'dshrw-e2ec-'))
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
  const agent = relay.store.createAgent('crypto-machine')
  encryptionToken = agent.encryptionToken

  const credentials: AgentCredentials = {
    version: 1,
    relayUrl: `http://127.0.0.1:${String(relay.port)}`,
    agentId: agent.record.agentId,
    privateKey: agent.privateKey,
    encryptionToken: agent.encryptionToken,
    label: 'crypto-machine',
    enabled: true,
    requireE2e: true,
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

describe('what the relay stores', () => {
  it('holds a public key and no agent secret', () => {
    const agent = relay.store.listAgents()[0]
    expect(agent?.publicKey).toBeDefined()
    expect(JSON.stringify(agent)).not.toContain(encryptionToken)
    // The decisive property: nothing in the relay's record is a secret.
    expect(Object.keys(agent ?? {})).not.toContain('tokenHash')
  })

  it('never learns the encryption token', () => {
    // The relay minted it during `createAgent` and handed it away; it must not
    // appear anywhere in persisted state.
    const persisted = JSON.stringify(relay.store.listAgents())
    expect(persisted).not.toContain(encryptionToken)
  })
})

describe('two-token enforcement', () => {
  it('refuses an agent whose signature does not verify', async () => {
    const victim = relay.store.createAgent('victim')
    // An attacker who read the relay's state file has the public key only.
    const attacker = new TunnelClient(
      {
        version: 1,
        relayUrl: `http://127.0.0.1:${String(relay.port)}`,
        agentId: victim.record.agentId,
        privateKey: victim.record.publicKey, // the stolen value
        encryptionToken: 'irrelevant',
        label: 'attacker',
        enabled: true,
        requireE2e: false,
      },
      resolvePluginConfig({ localHost: '127.0.0.1', localPort: dsh.port }),
      { info: () => undefined, warn: () => undefined },
    )
    attacker.start()
    await new Promise((resolve) => setTimeout(resolve, 1500))
    // Impersonation with the relay's own stored material must fail.
    expect(attacker.status().state).not.toBe('online')
    attacker.stop()
  })
})

describe('payload confidentiality', () => {
  it('lets a browser with both tokens reach DSH, and hides the traffic from the relay', async () => {
    const browser = new BrowserCryptoClient(encryptionToken)
    const rid = 'exchange-1'
    const hostKey = tunnel.publicKey

    const envelope = browser.sealRequest(rid, hostKey, {
      method: 'GET',
      path: '/secret',
      headers: {},
    })

    // What the relay would see on the wire carries neither path nor payload.
    expect(JSON.stringify(envelope)).not.toContain('/secret')
    expect(JSON.stringify(envelope)).not.toContain('THE-SECRET-PAYLOAD')

    const result = await tunnel.handleSealedRequestForTest(rid, envelope)
    expect(result.status).toBe(200)

    const body = browser.openResponse(rid, result.bodyEnvelope)
    expect(body?.toString('utf8')).toContain('THE-SECRET-PAYLOAD')

    // And the response the relay carried was opaque to it as well.
    expect(JSON.stringify(result.bodyEnvelope)).not.toContain('THE-SECRET-PAYLOAD')
  })

  it('rejects a payload sealed with the wrong encryption token', async () => {
    const impostor = new BrowserCryptoClient(generateEncryptionToken())
    const envelope = impostor.sealRequest('exchange-2', tunnel.publicKey, {
      method: 'GET',
      path: '/secret',
      headers: {},
    })
    // This is the relay's position exactly: it can route, but not compose.
    const result = await tunnel.handleSealedRequestForTest('exchange-2', envelope)
    expect(result.status).toBe(403)
  })

  it('rejects a payload replayed onto a different exchange', async () => {
    const browser = new BrowserCryptoClient(encryptionToken)
    const envelope = browser.sealRequest('exchange-3', tunnel.publicKey, {
      method: 'GET',
      path: '/secret',
      headers: {},
    })
    const result = await tunnel.handleSealedRequestForTest('different-exchange', envelope)
    expect(result.status).toBe(403)
  })

  it('rejects a tampered payload', async () => {
    const browser = new BrowserCryptoClient(encryptionToken)
    const envelope = browser.sealRequest('exchange-4', tunnel.publicKey, {
      method: 'GET',
      path: '/secret',
      headers: {},
    })
    const flipped = Buffer.from(envelope.c, 'base64url')
    flipped[0] ^= 0xff
    const result = await tunnel.handleSealedRequestForTest('exchange-4', {
      ...envelope,
      c: flipped.toString('base64url'),
    })
    expect(result.status).toBe(403)
  })
})

describe('downgrade resistance', () => {
  it('refuses an unencrypted request when the host requires E2E', async () => {
    // A relay that stripped the envelope would silently downgrade the session
    // to something it can read; the host must not accept that.
    const result = await tunnel.handlePlainRequestForTest('exchange-5', '/secret')
    expect(result.status).toBe(403)
    expect(result.body).toContain('end-to-end')
  })
})

describe('key distribution', () => {
  it('publishes the host public key and posture to an authorized browser', async () => {
    const relayBase = `http://127.0.0.1:${String(relay.port)}`
    const agent = relay.store.listAgents().find((a) => a.label === 'crypto-machine')
    const credential = relay.store.createClient('reader', agent!.agentId, null)

    const login = await fetch(`${relayBase}/__auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: credential.token }).toString(),
      redirect: 'manual',
    })
    const cookie = (login.headers.get('set-cookie') ?? '').split(';')[0] ?? ''

    const response = await fetch(`${relayBase}/a/${agent!.agentId}/__e2e/host`, {
      headers: { cookie },
    })
    const body = (await response.json()) as {
      ok: boolean
      publicKey: string
      requiresE2e: boolean
    }
    expect(body.ok).toBe(true)
    expect(body.requiresE2e).toBe(true)
    // This is the key the browser combines with its own token; the relay
    // forwards it but cannot use it.
    expect(body.publicKey).toBe(tunnel.publicKey)
  })

  it('refuses the key to an unauthenticated caller', async () => {
    const relayBase = `http://127.0.0.1:${String(relay.port)}`
    const agent = relay.store.listAgents()[0]
    const response = await fetch(`${relayBase}/a/${agent!.agentId}/__e2e/host`)
    expect(response.status).toBe(401)
  })
})
