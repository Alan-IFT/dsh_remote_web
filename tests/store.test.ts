/**
 * Relay store: credential lifecycle, revocation, and the guarantee that no
 * plaintext secret is ever persisted.
 */

import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { RelayStore, scopeMayReach } from '../src/relay/store.js'
import { hashToken } from '../src/shared/auth.js'
import { signMessage, verifySignature } from '../src/shared/crypto.js'

let dir: string
let statePath: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'dshrw-store-'))
  statePath = join(dir, 'state.json')
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

describe('agent lifecycle', () => {
  it('issues a signing key that verifies, and stores only the public half', () => {
    const store = new RelayStore(statePath)
    const { record, privateKey } = store.createAgent('laptop')

    const signature = signMessage('challenge', privateKey)
    expect(store.verifyAgentSignature(record.agentId, 'challenge', signature)).toBeDefined()

    const onDisk = readFileSync(statePath, 'utf8')
    expect(onDisk).not.toContain(privateKey)
    expect(onDisk).toContain(record.publicKey)
  })

  // The vulnerability that drove the redesign: proofs were HMACs keyed by the
  // stored value, so reading the relay's state file was enough to impersonate
  // any machine. A public key cannot produce a signature.
  it('cannot be impersonated by a reader of the relay state file', () => {
    const store = new RelayStore(statePath)
    const { record } = store.createAgent('laptop')
    const stolen = JSON.parse(readFileSync(statePath, 'utf8')) as {
      agents: { publicKey: string }[]
    }
    const publicKey = stolen.agents[0]!.publicKey

    let forged = ''
    try {
      forged = signMessage('challenge', publicKey)
    } catch {
      forged = ''
    }
    expect(store.verifyAgentSignature(record.agentId, 'challenge', forged)).toBeUndefined()
    expect(verifySignature('challenge', forged, publicKey)).toBe(false)
  })

  it('issues an encryption token the relay does not retain', () => {
    const store = new RelayStore(statePath)
    const { encryptionToken } = store.createAgent('laptop')
    // The relay must never be able to read payloads it forwards.
    expect(readFileSync(statePath, 'utf8')).not.toContain(encryptionToken)
  })

  it('writes state with owner-only permissions', () => {
    const store = new RelayStore(statePath)
    store.createAgent('laptop')
    // 0600: a relay state file readable by other local users would leak the
    // digests used to authenticate every agent.
    expect(statSync(statePath).mode & 0o777).toBe(0o600)
  })

  it('rejects a wrong signature and an unknown agent', () => {
    const store = new RelayStore(statePath)
    const { record, privateKey } = store.createAgent('laptop')
    const other = store.createAgent('other')
    expect(
      store.verifyAgentSignature(record.agentId, 'challenge', signMessage('challenge', other.privateKey)),
    ).toBeUndefined()
    expect(
      store.verifyAgentSignature('no-such-agent', 'challenge', signMessage('challenge', privateKey)),
    ).toBeUndefined()
  })

  it('stops verifying once revoked', () => {
    const store = new RelayStore(statePath)
    const { record, privateKey } = store.createAgent('laptop')
    expect(store.revokeAgent(record.agentId)).toBe(true)
    expect(
      store.verifyAgentSignature(record.agentId, 'c', signMessage('c', privateKey)),
    ).toBeUndefined()
    expect(store.findAgent(record.agentId)).toBeUndefined()
    // A second revoke is a no-op rather than an error.
    expect(store.revokeAgent(record.agentId)).toBe(false)
  })

  it('persists across instances', () => {
    const first = new RelayStore(statePath)
    const { record, privateKey } = first.createAgent('laptop')
    const second = new RelayStore(statePath)
    expect(
      second.verifyAgentSignature(record.agentId, 'c', signMessage('c', privateKey)),
    ).toBeDefined()
  })

  it('refuses duplicate agent ids', () => {
    const store = new RelayStore(statePath)
    const { record } = store.createAgent('laptop')
    expect(() => store.createAgent('other', record.agentId)).toThrow(/already exists/)
  })
})

describe('client credentials', () => {
  it('resolves a valid token to its record', () => {
    const store = new RelayStore(statePath)
    const { record, token } = store.createClient('phone', '*', null)
    expect(store.verifyClientToken(token)?.clientId).toBe(record.clientId)
  })

  it('refuses expired credentials', () => {
    const store = new RelayStore(statePath)
    const { token } = store.createClient('phone', '*', 1000)
    expect(store.verifyClientToken(token, Date.now())).toBeDefined()
    expect(store.verifyClientToken(token, Date.now() + 5000)).toBeUndefined()
  })

  it('refuses revoked credentials immediately', () => {
    const store = new RelayStore(statePath)
    const { record, token } = store.createClient('phone', '*', null)
    expect(store.revokeClient(record.clientId)).toBe(true)
    expect(store.verifyClientToken(token)).toBeUndefined()
  })

  it('revokes by fingerprint as well as by id', () => {
    const store = new RelayStore(statePath)
    const { record, token } = store.createClient('phone', '*', null)
    const print = `${record.tokenHash.slice(0, 4)}-${record.tokenHash.slice(4, 8)}-${record.tokenHash.slice(8, 12)}`
    expect(store.revokeClient(print)).toBe(true)
    expect(store.verifyClientToken(token)).toBeUndefined()
  })

  it('never persists a client token in clear text', () => {
    const store = new RelayStore(statePath)
    const { token } = store.createClient('phone', '*', null)
    expect(readFileSync(statePath, 'utf8')).not.toContain(token)
  })
})

describe('credential scope', () => {
  it('confines a scoped credential to its agent', () => {
    expect(scopeMayReach('agent-a', 'agent-a')).toBe(true)
    expect(scopeMayReach('agent-a', 'agent-b')).toBe(false)
  })

  it('lets a wildcard credential reach every agent', () => {
    expect(scopeMayReach('*', 'anything')).toBe(true)
  })
})

describe('cross-process consistency', () => {
  // Regression: the relay runs as a long-lived process while `client revoke`
  // runs in a separate one. A cached snapshot made the relay ignore the
  // revocation AND overwrite it on its next write, silently restoring access.
  it('sees a revocation performed by another process', () => {
    const relay = new RelayStore(statePath)
    const { token } = relay.createClient('phone', '*', null)
    expect(relay.verifyClientToken(token)).toBeDefined()

    const cli = new RelayStore(statePath)
    const target = cli.listClients()[0]
    expect(cli.revokeClient(target!.clientId)).toBe(true)

    expect(relay.verifyClientToken(token)).toBeUndefined()
  })

  it('does not resurrect a revoked credential on its next write', () => {
    const relay = new RelayStore(statePath)
    const { record, token } = relay.createClient('phone', '*', null)
    // The relay had already resolved this client before the revocation.
    expect(relay.verifyClientToken(token)).toBeDefined()

    new RelayStore(statePath).revokeClient(record.clientId)

    // A relay-side write (e.g. touching another record) must not clobber it.
    relay.touchClient(record.clientId)
    expect(new RelayStore(statePath).verifyClientToken(token)).toBeUndefined()
    expect(relay.verifyClientToken(token)).toBeUndefined()
  })

  it('sees an agent revoked by another process', () => {
    const relay = new RelayStore(statePath)
    const { record, privateKey } = relay.createAgent('laptop')
    const sig = signMessage('c', privateKey)
    expect(relay.verifyAgentSignature(record.agentId, 'c', sig)).toBeDefined()

    new RelayStore(statePath).revokeAgent(record.agentId)

    expect(relay.verifyAgentSignature(record.agentId, 'c', sig)).toBeUndefined()
  })

  it('sees an agent added by another process', () => {
    const relay = new RelayStore(statePath)
    expect(relay.listAgents()).toHaveLength(0)
    const cli = new RelayStore(statePath)
    cli.createAgent('added-elsewhere')
    expect(relay.listAgents()).toHaveLength(1)
  })
})

describe('corrupt state', () => {
  it('refuses to read rather than silently resetting', () => {
    writeFileSync(statePath, '{not json')
    // A blank store would revoke every device without the operator noticing,
    // so failing loudly is the safer behavior.
    expect(() => new RelayStore(statePath).listAgents()).toThrow(/unreadable/)
  })

  it('refuses an unrecognized schema version', () => {
    writeFileSync(statePath, JSON.stringify({ version: 99, agents: [], clients: [] }))
    expect(() => new RelayStore(statePath).listAgents()).toThrow(/unrecognized/)
  })
})

describe('resolving an agent by name', () => {
  // People name their machines; making them copy a UUID back out of `agent add`
  // is friction the tool can absorb.
  it('resolves by label as well as by id', () => {
    const store = new RelayStore(statePath)
    const { record } = store.createAgent('laptop')
    expect(store.resolveAgent('laptop')?.agentId).toBe(record.agentId)
    expect(store.resolveAgent(record.agentId)?.agentId).toBe(record.agentId)
  })

  it('never lets a label become ambiguous', () => {
    // Resolution used to answer "neither" when two live agents shared a label,
    // which made `agent revoke <label>` report nothing to revoke while both
    // machines stayed connected. The ambiguity is now refused where it would be
    // created, so every caller gets one answer without handling that case.
    const store = new RelayStore(statePath)
    store.createAgent('laptop')
    expect(() => store.createAgent('laptop')).toThrow(/already named/)
    expect(store.resolveAgent('laptop')).toBeDefined()
  })

  it('frees a name once its agent is revoked', () => {
    // Re-pairing a rebuilt machine under its own name must stay possible; only
    // a live collision is a problem.
    const store = new RelayStore(statePath)
    const { record } = store.createAgent('laptop')
    store.revokeAgent(record.agentId)
    const replacement = store.createAgent('laptop')
    expect(store.resolveAgent('laptop')?.agentId).toBe(replacement.record.agentId)
  })

  it('ignores revoked agents', () => {
    const store = new RelayStore(statePath)
    const { record } = store.createAgent('laptop')
    store.revokeAgent(record.agentId)
    expect(store.resolveAgent('laptop')).toBeUndefined()
  })

  it('prefers an exact id over a colliding label', () => {
    const store = new RelayStore(statePath)
    const first = store.createAgent('a')
    store.createAgent(first.record.agentId === 'x' ? 'y' : first.record.agentId)
    expect(store.resolveAgent(first.record.agentId)?.label).toBe('a')
  })
})
