/**
 * Browser session handling on the relay.
 *
 * A browser authenticates once by presenting its access token, and receives a
 * session cookie. The cookie is the credential for every later request, so the
 * token itself stops travelling after login.
 *
 * Cookie posture, and why:
 *
 * - `HttpOnly` — the DSH surface runs arbitrary rendered content; script must
 *   not be able to read the session value.
 * - `SameSite=Lax` — the relay is a full application surface reached by
 *   top-level navigation. `Strict` would drop the cookie on the first click
 *   from a chat app; `None` would invite cross-site posting.
 * - `Secure` — set whenever the relay believes it is behind TLS, which is the
 *   only supported public deployment.
 * - `Path=/` — the session governs the whole proxied surface.
 *
 * @module dsh-remote-web/relay/sessions
 */

import { randomBytes } from 'node:crypto'

import { hashToken, safeEqual } from '../shared/auth.js'

/**
 * Upper bound on concurrent sessions.
 *
 * Sized well above any real person's device count, so it never interferes with
 * ordinary use while still bounding what a leaked token can consume.
 */
const MAX_SESSIONS = 256

/** Name of the session cookie. The `__Host-` prefix pins it to this exact
 *  origin with `Path=/` and no `Domain`, which browsers enforce for us. */
export const SESSION_COOKIE = '__Host-dshrw'

/** Fallback name used when the relay is not on TLS, where `__Host-` is illegal. */
export const SESSION_COOKIE_INSECURE = 'dshrw'

/** An authenticated browser session. */
export interface Session {
  /** SHA-256 of the session id; the raw id lives only in the cookie. */
  idHash: string
  clientId: string
  label: string
  /** Agent this session may reach, or `'*'`. */
  agentId: string
  createdAt: number
  lastSeenAt: number
  expiresAt: number
}

/**
 * In-memory session table.
 *
 * Sessions are deliberately not persisted: a relay restart forces every
 * browser to re-present its token, which is a cheap way to bound the damage of
 * a stolen cookie and costs the operator nothing.
 */
export class SessionStore {
  readonly #sessions = new Map<string, Session>()
  readonly #ttlMs: number

  /**
   * @param ttlMs - Idle lifetime of a session; refreshed on each request.
   */
  constructor(ttlMs = 12 * 60 * 60 * 1000) {
    this.#ttlMs = ttlMs
  }

  /** Live session count, after pruning expired entries. */
  get size(): number {
    this.#prune()
    return this.#sessions.size
  }

  #prune(now: number = Date.now()): void {
    for (const [key, session] of this.#sessions) {
      if (session.expiresAt <= now) this.#sessions.delete(key)
    }
  }

  /**
   * Create a session for an authenticated browser.
   *
   * @returns The raw session id to place in the cookie; only its hash is kept.
   */
  create(
    clientId: string,
    label: string,
    agentId: string,
    now: number = Date.now(),
  ): string {
    this.#prune(now)
    // A valid token could otherwise mint sessions without limit — successful
    // logins reset the rate limiter, so nothing else bounds this. Evicting the
    // oldest keeps a person's newest devices working while capping memory.
    while (this.#sessions.size >= MAX_SESSIONS) {
      const oldest = [...this.#sessions.entries()].reduce((a, b) =>
        a[1].createdAt <= b[1].createdAt ? a : b,
      )
      this.#sessions.delete(oldest[0])
    }
    const raw = randomBytes(32).toString('base64url')
    const session: Session = {
      idHash: hashToken(raw),
      clientId,
      label,
      agentId,
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + this.#ttlMs,
    }
    this.#sessions.set(session.idHash, session)
    return raw
  }

  /**
   * Resolve a raw cookie value to its session, refreshing the idle deadline.
   *
   * @returns The session, or `undefined` when unknown or expired.
   */
  resolve(raw: string | undefined, now: number = Date.now()): Session | undefined {
    if (raw === undefined || raw === '') return undefined
    this.#prune(now)
    const digest = hashToken(raw)
    const session = this.#sessions.get(digest)
    if (session === undefined) return undefined
    if (!safeEqual(session.idHash, digest)) return undefined
    session.lastSeenAt = now
    session.expiresAt = now + this.#ttlMs
    return session
  }

  /** Drop one session (logout). */
  destroy(raw: string | undefined): void {
    if (raw === undefined || raw === '') return
    this.#sessions.delete(hashToken(raw))
  }

  /** Drop every session belonging to a client credential (revocation). */
  destroyByClient(clientId: string): number {
    let removed = 0
    for (const [key, session] of this.#sessions) {
      if (session.clientId !== clientId) continue
      this.#sessions.delete(key)
      removed += 1
    }
    return removed
  }

  /** Drop every session; used when the relay revokes broadly. */
  clear(): void {
    this.#sessions.clear()
  }
}

/**
 * Parse a `Cookie` header into a map.
 *
 * @param header - Raw header value, possibly undefined.
 */
export function parseCookies(header: string | undefined): Map<string, string> {
  const out = new Map<string, string>()
  if (header === undefined) return out
  for (const part of header.split(';')) {
    const index = part.indexOf('=')
    if (index <= 0) continue
    const key = part.slice(0, index).trim()
    const value = part.slice(index + 1).trim()
    if (key !== '') out.set(key, decodeURIComponent(value))
  }
  return out
}

/**
 * Build the `Set-Cookie` value for a new session.
 *
 * @param value - Raw session id.
 * @param secure - Whether the relay is served over TLS.
 * @param maxAgeSeconds - Cookie lifetime.
 */
export function buildSessionCookie(
  value: string,
  secure: boolean,
  maxAgeSeconds: number,
): string {
  const name = secure ? SESSION_COOKIE : SESSION_COOKIE_INSECURE
  const attributes = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${String(maxAgeSeconds)}`,
  ]
  if (secure) attributes.push('Secure')
  return attributes.join('; ')
}

/** Build the `Set-Cookie` value that clears a session. */
export function buildClearCookie(secure: boolean): string {
  const name = secure ? SESSION_COOKIE : SESSION_COOKIE_INSECURE
  const attributes = [`${name}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0']
  if (secure) attributes.push('Secure')
  return attributes.join('; ')
}

/**
 * Read the session cookie under whichever name applies.
 *
 * Both names are accepted regardless of the current TLS posture so a relay
 * that gains or loses TLS does not strand browsers holding the other name.
 */
export function readSessionCookie(header: string | undefined): string | undefined {
  const cookies = parseCookies(header)
  return cookies.get(SESSION_COOKIE) ?? cookies.get(SESSION_COOKIE_INSECURE)
}
