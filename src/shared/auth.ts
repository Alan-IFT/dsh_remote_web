/**
 * Token generation, hashing, and constant-time proof verification shared by
 * the plugin, the relay, and the CLI.
 *
 * Rules this module exists to enforce:
 *
 * - A raw token is shown to a human exactly once and is never persisted in
 *   clear text. Storage always holds a SHA-256 digest.
 * - Every comparison of a secret uses {@link timingSafeEqual}.
 * - A proof is bound to a purpose and a subject, so an agent proof cannot be
 *   replayed as a browser proof, and it expires with a bounded clock window.
 *
 * @module dsh-remote-web/shared/auth
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

import { AUTH_PROOF_SKEW_MS } from './protocol.js'

/** Bytes of entropy in a generated token. */
const TOKEN_BYTES = 32

/**
 * Generate a fresh token with 256 bits of entropy.
 *
 * The alphabet is base64url so the value survives QR codes, URLs, shell
 * arguments, and environment variables without escaping.
 *
 * @returns A raw token; the caller must show it once and store only its digest.
 */
export function generateToken(): string {
  return randomBytes(TOKEN_BYTES).toString('base64url')
}

/**
 * Hash a token for storage or comparison.
 *
 * @param token - The raw token.
 * @returns Lowercase hex SHA-256 digest.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex')
}

/**
 * Compare two strings without leaking their contents through timing.
 *
 * Lengths are compared first through the digest trick: both sides are hashed
 * so unequal lengths cannot short-circuit the comparison itself.
 *
 * @returns True when the inputs are byte-identical.
 */
export function safeEqual(a: string, b: string): boolean {
  const left = createHash('sha256').update(a, 'utf8').digest()
  const right = createHash('sha256').update(b, 'utf8').digest()
  return timingSafeEqual(left, right)
}

/**
 * A short, human-readable fingerprint of a token digest, safe to display and
 * to log. It identifies which credential is in play without revealing it.
 *
 * @param digest - Hex digest from {@link hashToken}.
 * @returns Twelve hex characters in three dash-separated groups.
 */
export function fingerprint(digest: string): string {
  const head = digest.slice(0, 12)
  return `${head.slice(0, 4)}-${head.slice(4, 8)}-${head.slice(8, 12)}`
}

/**
 * A set of one-time values that expire.
 *
 * Two things need exactly this: an agent's handshake nonce (accept once, within
 * a clock window) and a browser's login challenge (issue, then redeem once).
 * They were separate implementations until the second one needed the same
 * bounds the first already had, which is the signal that one primitive was
 * enough.
 *
 * Both bounds matter and neither is optional: entries expire so a long-running
 * relay does not accumulate them, and the count is capped because these values
 * are accepted before authentication — an unbounded set would be a free memory
 * sink for any unauthenticated caller.
 */
export class OneTimeValues {
  readonly #seen = new Map<string, number>()
  readonly #windowMs: number
  readonly #limit: number

  /**
   * @param windowMs - How long a value stays remembered.
   * @param limit - Maximum retained values; further additions are refused.
   */
  constructor(windowMs: number = AUTH_PROOF_SKEW_MS * 2, limit = 1000) {
    this.#windowMs = windowMs
    this.#limit = limit
  }

  #prune(now: number): void {
    for (const [value, at] of this.#seen) {
      if (now - at > this.#windowMs) this.#seen.delete(value)
    }
  }

  /**
   * Record a value, rejecting a repeat.
   *
   * @returns True when the value is new and was retained.
   */
  add(value: string, now: number = Date.now()): boolean {
    this.#prune(now)
    if (this.#seen.has(value) || this.#seen.size >= this.#limit) return false
    this.#seen.set(value, now)
    return true
  }

  /**
   * Consume a previously added value.
   *
   * @returns True when the value was present and unexpired; it is removed, so
   *          a second attempt with the same value fails.
   */
  take(value: string, now: number = Date.now()): boolean {
    this.#prune(now)
    const present = this.#seen.delete(value)
    return present
  }

  /** Retained value count; for tests and diagnostics. */
  get size(): number {
    return this.#seen.size
  }
}

/**
 * Fixed-window rate limiter for authentication attempts.
 *
 * Brute-forcing a 256-bit token is infeasible, but the limiter still matters:
 * it caps the cost of a flood of forged proofs, each of which would otherwise
 * force an HMAC computation.
 */
export class RateLimiter {
  readonly #hits = new Map<string, { count: number; resetAt: number }>()
  readonly #limit: number
  readonly #windowMs: number

  /**
   * @param limit - Attempts allowed per key within one window.
   * @param windowMs - Window length in milliseconds.
   */
  constructor(limit = 20, windowMs = 60_000) {
    this.#limit = limit
    this.#windowMs = windowMs
  }

  /**
   * Consume one attempt for `key`.
   *
   * @returns True when the attempt is allowed, false when the key is throttled.
   */
  allow(key: string, now: number = Date.now()): boolean {
    for (const [existing, state] of this.#hits) {
      if (state.resetAt <= now) this.#hits.delete(existing)
    }
    const current = this.#hits.get(key)
    if (current === undefined || current.resetAt <= now) {
      this.#hits.set(key, { count: 1, resetAt: now + this.#windowMs })
      return true
    }
    if (current.count >= this.#limit) return false
    current.count += 1
    return true
  }

  /** Forget a key, e.g. after a successful authentication. */
  reset(key: string): void {
    this.#hits.delete(key)
  }
}

/**
 * A pairing code: everything the receiving side needs, in one copyable string.
 *
 * One format serves both directions. An **agent** code carries the machine's
 * signing key plus the encryption token; a **browser** code carries the auth
 * token plus the same encryption token. Either way the two secrets travel
 * together to the endpoint and never separately to the relay — which is the
 * point: the relay issues the auth half and never learns the encryption half.
 *
 * Format: `dshrw1.<relayUrl>.<subject>.<auth>.<encryption>`, the first two
 * base64url so the string survives QR codes, URLs, and shell arguments
 * unescaped. An empty subject means "browser token".
 */
export interface PairingCode {
  relayUrl: string
  /** Agent id for an agent code; `null` for a browser token. */
  subject: string | null
  /** Signing key (agent) or access token (browser). */
  authSecret: string
  /** Payload encryption token, shared by the machine and its browsers. */
  encryptionToken: string
}

/** Encode a pairing code. */
export function encodePairingCode(code: PairingCode): string {
  const url = Buffer.from(code.relayUrl, 'utf8').toString('base64url')
  const subject =
    code.subject === null ? '' : Buffer.from(code.subject, 'utf8').toString('base64url')
  return `dshrw1.${url}.${subject}.${code.authSecret}.${code.encryptionToken}`
}

/**
 * Parse a pairing code.
 *
 * @returns The decoded code, or `null` when the string is not well-formed.
 */
export function decodePairingCode(input: string): PairingCode | null {
  const parts = input.trim().split('.')
  if (parts.length !== 5 || parts[0] !== 'dshrw1') return null
  const [, encodedUrl, encodedSubject, authSecret, encryptionToken] = parts
  if (
    encodedUrl === undefined ||
    encodedUrl === '' ||
    authSecret === undefined ||
    authSecret === '' ||
    encryptionToken === undefined ||
    encryptionToken === ''
  ) {
    return null
  }
  let relayUrl: string
  try {
    relayUrl = Buffer.from(encodedUrl, 'base64url').toString('utf8')
    new URL(relayUrl)
  } catch {
    return null
  }
  return {
    relayUrl,
    subject:
      encodedSubject === undefined || encodedSubject === ''
        ? null
        : Buffer.from(encodedSubject, 'base64url').toString('utf8'),
    authSecret,
    encryptionToken,
  }
}
