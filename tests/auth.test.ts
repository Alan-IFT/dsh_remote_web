/**
 * Authentication primitives. These tests pin the properties the whole security
 * story depends on, so a refactor that weakens one fails loudly here.
 */

import { describe, expect, it } from 'vitest'

import {
  OneTimeValues,
  RateLimiter,
  decodePairingCode,
  encodePairingCode,
  fingerprint,
  generateToken,
  hashToken,
  safeEqual,
} from '../src/shared/auth.js'

describe('token generation and hashing', () => {
  it('produces distinct high-entropy tokens', () => {
    const tokens = new Set(Array.from({ length: 200 }, () => generateToken()))
    expect(tokens.size).toBe(200)
    for (const token of tokens) {
      // 32 random bytes in base64url is 43 characters.
      expect(token.length).toBe(43)
      expect(token).toMatch(/^[A-Za-z0-9_-]+$/)
    }
  })

  it('hashes deterministically and irreversibly', () => {
    const token = generateToken()
    expect(hashToken(token)).toBe(hashToken(token))
    expect(hashToken(token)).toHaveLength(64)
    expect(hashToken(token)).not.toContain(token)
  })

  it('compares equal and unequal values correctly', () => {
    expect(safeEqual('abc', 'abc')).toBe(true)
    expect(safeEqual('abc', 'abd')).toBe(false)
    // Differing lengths must not throw, which a naive timingSafeEqual would.
    expect(safeEqual('a', 'aaaaaaaaaaaaaaaa')).toBe(false)
  })

  it('renders a short, stable fingerprint', () => {
    const digest = hashToken('example')
    expect(fingerprint(digest)).toMatch(/^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$/)
    expect(fingerprint(digest)).toBe(fingerprint(digest))
  })
})

describe('one-time values', () => {
  it('accepts a value once', () => {
    const values = new OneTimeValues()
    expect(values.add('nonce-1')).toBe(true)
    expect(values.add('nonce-1')).toBe(false)
  })

  it('forgets entries once the window passes', () => {
    const values = new OneTimeValues(1000)
    expect(values.add('a', 0)).toBe(true)
    expect(values.add('a', 500)).toBe(false)
    expect(values.add('a', 2000)).toBe(true)
  })

  it('take() consumes, so a challenge cannot be redeemed twice', () => {
    const values = new OneTimeValues(1000)
    values.add('challenge', 0)
    expect(values.take('challenge', 10)).toBe(true)
    expect(values.take('challenge', 20)).toBe(false)
  })

  it('take() refuses an expired value', () => {
    const values = new OneTimeValues(1000)
    values.add('challenge', 0)
    expect(values.take('challenge', 5000)).toBe(false)
  })

  it('take() refuses a value that was never issued', () => {
    expect(new OneTimeValues().take('never-seen')).toBe(false)
  })

  it('caps retained values, since they are accepted before authentication', () => {
    // Without a cap an unauthenticated caller could grow this without bound.
    const values = new OneTimeValues(60_000, 3)
    expect(values.add('a')).toBe(true)
    expect(values.add('b')).toBe(true)
    expect(values.add('c')).toBe(true)
    expect(values.add('d')).toBe(false)
    expect(values.size).toBe(3)
  })

  it('accepts new values again after expiry frees room', () => {
    const values = new OneTimeValues(1000, 2)
    values.add('a', 0)
    values.add('b', 0)
    expect(values.add('c', 10)).toBe(false)
    expect(values.add('c', 2000)).toBe(true)
  })
})

describe('rate limiter', () => {
  it('throttles after the limit and recovers after the window', () => {
    const limiter = new RateLimiter(3, 1000)
    expect(limiter.allow('ip', 0)).toBe(true)
    expect(limiter.allow('ip', 10)).toBe(true)
    expect(limiter.allow('ip', 20)).toBe(true)
    expect(limiter.allow('ip', 30)).toBe(false)
    expect(limiter.allow('ip', 1500)).toBe(true)
  })

  it('tracks keys independently and resets on demand', () => {
    const limiter = new RateLimiter(1, 1000)
    expect(limiter.allow('a', 0)).toBe(true)
    expect(limiter.allow('b', 0)).toBe(true)
    expect(limiter.allow('a', 0)).toBe(false)
    limiter.reset('a')
    expect(limiter.allow('a', 0)).toBe(true)
  })
})

describe('pairing codes', () => {
  it('round-trips an agent code carrying both secrets', () => {
    const code = encodePairingCode({
      relayUrl: 'https://relay.example.com',
      subject: 'agent-1',
      authSecret: 'signing-key',
      encryptionToken: 'encryption-token',
    })
    expect(decodePairingCode(code)).toEqual({
      relayUrl: 'https://relay.example.com',
      subject: 'agent-1',
      authSecret: 'signing-key',
      encryptionToken: 'encryption-token',
    })
  })

  it('round-trips a browser code, which has no subject', () => {
    const code = encodePairingCode({
      relayUrl: 'https://relay.example.com',
      subject: null,
      authSecret: 'access-token',
      encryptionToken: 'encryption-token',
    })
    expect(decodePairingCode(code)?.subject).toBeNull()
    expect(decodePairingCode(code)?.authSecret).toBe('access-token')
    expect(decodePairingCode(code)?.encryptionToken).toBe('encryption-token')
  })

  it('rejects a code missing either secret', () => {
    const url = Buffer.from('https://r.example', 'utf8').toString('base64url')
    // Half a credential must never parse as a whole one.
    expect(decodePairingCode(`dshrw1.${url}..auth-only.`)).toBeNull()
    expect(decodePairingCode(`dshrw1.${url}..`)).toBeNull()
    expect(decodePairingCode(`dshrw1.${url}..auth`)).toBeNull()
  })

  it('rejects malformed codes', () => {
    for (const bad of ['', 'nope', 'dshrw1.a.b.c', 'dshrw2.a.b.c.d', 'dshrw1...a.b']) {
      expect(decodePairingCode(bad)).toBeNull()
    }
  })

  it('rejects a code whose URL segment is not a URL', () => {
    const encoded = Buffer.from('not a url', 'utf8').toString('base64url')
    expect(decodePairingCode(`dshrw1.${encoded}..auth.enc`)).toBeNull()
  })
})
