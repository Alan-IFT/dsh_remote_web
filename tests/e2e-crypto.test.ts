/**
 * What a compromised relay gets, over a real relay and a real tunnel.
 *
 * The browser-facing "end-to-end encryption" this file once tested was removed:
 * the code performing it was served by the relay, so it could not defend against
 * the relay. What survives are the properties that do not depend on relay-served
 * code — the relay stores no secret capable of impersonating a machine, and a
 * tunnel presenting only that stored material is refused.
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
    // The relay minted it during `createAgent` and handed it away. It must not
    // appear in persisted state: a relay that kept it could assemble a browser
    // pairing code by itself, which the two-token split exists to prevent.
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

describe('proxying', () => {
  it('serves a local response through the tunnel path', async () => {
    // The plain path is now the only path, so it carries the assertion that
    // the sealed cases used to: a request is re-issued locally and answered.
    const result = await tunnel.handlePlainRequestForTest('exchange-1', '/secret')
    expect(result.status).toBe(200)
    expect(result.body).toContain('THE-SECRET-PAYLOAD')
  })
})
