/**
 * Browser enrollment and signature login.
 *
 * The property under test: after first use the access token never travels
 * again, so a relay reached over plain HTTP leaks no reusable credential.
 */
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { RelayStore } from '../src/relay/store.js'
import { generateAgentIdentity, signMessage } from '../src/shared/crypto.js'

let dir: string, store: RelayStore

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'bauth-'))
  store = new RelayStore(join(dir, 's.json'))
})
afterEach(() => rmSync(dir, { recursive: true, force: true }))

describe('enrollment', () => {
  it('binds a key once and refuses a second binding', () => {
    const c = store.createClient('phone', '*', null)
    const first = generateAgentIdentity()
    expect(store.enrollClientKey(c.record.clientId, first.publicKey)).toBe(true)

    // Whoever observed the token must not be able to take the credential over.
    const attacker = generateAgentIdentity()
    expect(store.enrollClientKey(c.record.clientId, attacker.publicKey)).toBe(false)
    expect(store.verifyClientSignature('ch', signMessage('ch', attacker.privateKey))).toBeUndefined()
  })

  it('lets the enrolled browser log in by signature', () => {
    const c = store.createClient('phone', '*', null)
    const id = generateAgentIdentity()
    store.enrollClientKey(c.record.clientId, id.publicKey)
    const found = store.verifyClientSignature('challenge', signMessage('challenge', id.privateKey))
    expect(found?.clientId).toBe(c.record.clientId)
  })

  it('refuses a signature over different content', () => {
    const c = store.createClient('phone', '*', null)
    const id = generateAgentIdentity()
    store.enrollClientKey(c.record.clientId, id.publicKey)
    expect(store.verifyClientSignature('other', signMessage('challenge', id.privateKey))).toBeUndefined()
  })

  it('stores only the public key', () => {
    const c = store.createClient('phone', '*', null)
    const id = generateAgentIdentity()
    store.enrollClientKey(c.record.clientId, id.publicKey)
    const persisted = JSON.stringify(store.listClients())
    expect(persisted).not.toContain(id.privateKey)
    expect(persisted).toContain(id.publicKey)
  })

  it('stops verifying once revoked', () => {
    const c = store.createClient('phone', '*', null)
    const id = generateAgentIdentity()
    store.enrollClientKey(c.record.clientId, id.publicKey)
    store.revokeClient(c.record.clientId)
    expect(store.verifyClientSignature('ch', signMessage('ch', id.privateKey))).toBeUndefined()
  })

  it('stops verifying once expired', () => {
    const c = store.createClient('phone', '*', 1000)
    const id = generateAgentIdentity()
    store.enrollClientKey(c.record.clientId, id.publicKey)
    const sig = signMessage('ch', id.privateKey)
    expect(store.verifyClientSignature('ch', sig, Date.now())).toBeDefined()
    expect(store.verifyClientSignature('ch', sig, Date.now() + 5000)).toBeUndefined()
  })
})
