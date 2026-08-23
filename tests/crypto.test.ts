/**
 * The two-token credential material.
 *
 * These tests pin the two properties the design rests on:
 *   - the relay's stored verifier cannot forge an agent proof;
 *   - the encryption token is unguessable, so a relay that never received it
 *     cannot assemble a browser pairing code on its own.
 *
 * Payload-encryption tests used to live here too. They covered a browser-facing
 * feature that was removed, because the code performing it was served by the
 * relay it was meant to defend against.
 */

import { describe, expect, it } from 'vitest'

import {
  generateAgentIdentity,
  generateEncryptionToken,
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

describe('encryption token', () => {
  it('generates distinct, high-entropy values', () => {
    const tokens = new Set(Array.from({ length: 200 }, () => generateEncryptionToken()))
    expect(tokens.size).toBe(200)
    // 32 bytes base64url. This is the value a relay must not be able to guess:
    // holding an auth token it issued plus a guessed encryption token would let
    // it forge a browser pairing code that names a machine it never paired.
    for (const token of tokens) {
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/)
    }
  })
})
