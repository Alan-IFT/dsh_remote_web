/**
 * The two-token cryptography.
 *
 * These tests pin the two properties the design rests on:
 *   - the relay's stored verifier cannot forge an agent proof;
 *   - the relay cannot read or tamper with payloads.
 */

import { describe, expect, it } from 'vitest'

import {
  deriveSessionKey,
  generateAgentIdentity,
  generateEncryptionToken,
  generateEphemeralKeyPair,
  open,
  seal,
  signMessage,
  verifySignature,
} from '../src/shared/crypto.js'

describe('agent identity', () => {
  it('generates distinct keypairs', () => {
    const keys = new Set(Array.from({ length: 50 }, () => generateAgentIdentity().publicKey))
    expect(keys.size).toBe(50)
  })

  it('verifies its own signature', () => {
    const identity = generateAgentIdentity()
    const signature = signMessage('challenge', identity.privateKey)
    expect(verifySignature('challenge', signature, identity.publicKey)).toBe(true)
  })

  it('rejects a signature over different content', () => {
    const identity = generateAgentIdentity()
    const signature = signMessage('challenge', identity.privateKey)
    expect(verifySignature('other', signature, identity.publicKey)).toBe(false)
  })

  it('rejects a signature from a different key', () => {
    const signature = signMessage('challenge', generateAgentIdentity().privateKey)
    expect(verifySignature('challenge', signature, generateAgentIdentity().publicKey)).toBe(false)
  })

  it('rejects malformed keys and signatures without throwing', () => {
    const identity = generateAgentIdentity()
    expect(verifySignature('m', 'not-a-signature', identity.publicKey)).toBe(false)
    expect(verifySignature('m', signMessage('m', identity.privateKey), 'not-a-key')).toBe(false)
    expect(verifySignature('m', '', '')).toBe(false)
  })

  // The vulnerability that motivated this module: proofs were HMACs keyed by
  // the value the relay stored, so reading the relay's state file was enough
  // to impersonate any agent.
  it('cannot be impersonated by someone holding only the public key', () => {
    const identity = generateAgentIdentity()
    // An attacker with the relay's stored verifier tries to sign with it.
    let forged: string
    try {
      forged = signMessage('challenge', identity.publicKey)
    } catch {
      // Rejecting outright is also an acceptable outcome.
      expect(true).toBe(true)
      return
    }
    expect(verifySignature('challenge', forged, identity.publicKey)).toBe(false)
  })
})

describe('payload encryption', () => {
  const token = generateEncryptionToken()
  // The key production actually uses: an ephemeral exchange folded with the
  // encryption token, so these tests exercise the deployed construction.
  const peer = generateEphemeralKeyPair()
  const key = deriveSessionKey(generateEphemeralKeyPair().privateKey, peer.publicKey, token)

  it('round-trips a payload', () => {
    const sealed = seal(Buffer.from('secret conversation'), key)
    expect(open(sealed, key)?.toString('utf8')).toBe('secret conversation')
  })

  it('hides the plaintext from the wire form', () => {
    const sealed = seal(Buffer.from('secret conversation'), key)
    expect(JSON.stringify(sealed)).not.toContain('secret')
  })

  it('fails authentication under the wrong key', () => {
    const sealed = seal(Buffer.from('secret'), key)
    const otherKey = deriveSessionKey(
      generateEphemeralKeyPair().privateKey,
      peer.publicKey,
      generateEncryptionToken(),
    )
    // The relay holds no encryption token, so this is its position exactly.
    expect(open(sealed, otherKey)).toBeNull()
  })

  it('detects tampering with the ciphertext', () => {
    const sealed = seal(Buffer.from('transfer 100'), key)
    const flipped = Buffer.from(sealed.c, 'base64url')
    flipped[0] ^= 0xff
    expect(open({ ...sealed, c: flipped.toString('base64url') }, key)).toBeNull()
  })

  it('detects tampering with the tag or nonce', () => {
    const sealed = seal(Buffer.from('payload'), key)
    expect(open({ ...sealed, t: Buffer.alloc(16).toString('base64url') }, key)).toBeNull()
    expect(open({ ...sealed, n: Buffer.alloc(12).toString('base64url') }, key)).toBeNull()
  })

  it('binds a payload to its exchange through AAD', () => {
    const sealed = seal(Buffer.from('body'), key, 'request-1')
    expect(open(sealed, key, 'request-1')?.toString('utf8')).toBe('body')
    // Replaying a valid payload onto another exchange must fail.
    expect(open(sealed, key, 'request-2')).toBeNull()
    expect(open(sealed, key)).toBeNull()
  })

  it('never reuses a nonce', () => {
    const nonces = new Set(
      Array.from({ length: 200 }, () => seal(Buffer.from('x'), key).n),
    )
    expect(nonces.size).toBe(200)
  })

  it('derives a different key per exchange', () => {
    const a = deriveSessionKey(generateEphemeralKeyPair().privateKey, peer.publicKey, token)
    const b = deriveSessionKey(generateEphemeralKeyPair().privateKey, peer.publicKey, token)
    expect(a.equals(b)).toBe(false)
  })

})

describe('ephemeral key exchange', () => {
  const token = generateEncryptionToken()

  it('lets two peers agree on the same key', () => {
    const host = generateEphemeralKeyPair()
    const browser = generateEphemeralKeyPair()
    const hostKey = deriveSessionKey(host.privateKey, browser.publicKey, token)
    const browserKey = deriveSessionKey(browser.privateKey, host.publicKey, token)
    expect(hostKey.equals(browserKey)).toBe(true)
  })

  it('denies the key to a relay that substitutes its own public key', () => {
    // The relay carries these messages, so it can swap a public key — but it
    // has no encryption token, so the derived key still differs.
    const host = generateEphemeralKeyPair()
    const browser = generateEphemeralKeyPair()
    const attacker = generateEphemeralKeyPair()

    const honest = deriveSessionKey(host.privateKey, browser.publicKey, token)
    const mitm = deriveSessionKey(attacker.privateKey, host.publicKey, generateEncryptionToken())
    expect(honest.equals(mitm)).toBe(false)
  })

  it('produces a different key when the token differs', () => {
    const host = generateEphemeralKeyPair()
    const browser = generateEphemeralKeyPair()
    const withToken = deriveSessionKey(host.privateKey, browser.publicKey, token)
    const withOther = deriveSessionKey(host.privateKey, browser.publicKey, generateEncryptionToken())
    expect(withToken.equals(withOther)).toBe(false)
  })

  it('gives each session a fresh key', () => {
    const host = generateEphemeralKeyPair()
    const first = deriveSessionKey(host.privateKey, generateEphemeralKeyPair().publicKey, token)
    const second = deriveSessionKey(host.privateKey, generateEphemeralKeyPair().publicKey, token)
    expect(first.equals(second)).toBe(false)
  })
})
