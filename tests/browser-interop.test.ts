/**
 * Cross-implementation compatibility.
 *
 * The browser seals with WebCrypto and the host opens with `node:crypto`. Two
 * independent implementations of one wire format is precisely where a subtle
 * mismatch hides — GCM tag placement, HKDF inputs, key encoding — and a
 * mismatch would either break every session or, worse, appear to work while
 * degrading the guarantee. These tests run the real browser script.
 */

import { webcrypto } from 'node:crypto'
import { describe, expect, it } from 'vitest'

import {
  deriveSessionKey,
  generateEncryptionToken,
  generateEphemeralKeyPair,
  open as nodeOpen,
  seal as nodeSeal,
} from '../src/shared/crypto.js'
import { BROWSER_CRYPTO_SCRIPT } from '../src/relay/browser-crypto.js'

/**
 * Evaluate the served browser script in a Node context that provides the
 * globals it expects, then hand back the API it installs.
 *
 * Running the actual shipped string — not a copy — is what makes this a
 * compatibility test rather than a restatement of the same assumptions.
 */
function loadBrowserClient(): {
  init: (token: string, hostPublicKey: string) => Promise<void>
  seal: (rid: string, payload: unknown) => Promise<Record<string, string>>
  open: (rid: string, envelope: Record<string, string>) => Promise<Uint8Array | null>
  ready: () => boolean
  calls: { url: string; headers: Record<string, string> }[]
  opened: string[]
  openSocket: (url: string) => unknown
  fetch: (url: string, init?: unknown) => Promise<unknown>
} {
  const calls: { url: string; headers: Record<string, string> }[] = []
  const opened: string[] = []
  const sandbox: Record<string, unknown> = {
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    atob: (value: string) => Buffer.from(value, 'base64').toString('binary'),
    btoa: (value: string) => Buffer.from(value, 'binary').toString('base64'),
    location: { origin: 'https://relay.example.com' },
    WebSocket: class {
      static CONNECTING = 0
      static OPEN = 1
      static CLOSING = 2
      static CLOSED = 3
      url: string
      constructor(url: string) {
        this.url = url
        opened.push(url)
      }
      addEventListener(): void {}
    },
    fetch: (input: string, init?: { headers?: Record<string, string> }) => {
      calls.push({ url: input, headers: init?.headers ?? {} })
      return Promise.resolve({ ok: true })
    },
  }
  sandbox.window = sandbox
  const factory = new Function(
    'window',
    'crypto',
    'TextEncoder',
    'TextDecoder',
    'atob',
    'btoa',
    `${BROWSER_CRYPTO_SCRIPT}; return window.__dshRemoteWebE2E__`,
  )
  const api = factory(
    sandbox,
    sandbox.crypto,
    sandbox.TextEncoder,
    sandbox.TextDecoder,
    sandbox.atob,
    sandbox.btoa,
  ) as ReturnType<typeof loadBrowserClient>
  api.calls = calls
  api.opened = opened
  // Read through to the sandbox at call time: install() replaces
  // window.WebSocket during init(), so a captured reference would test the
  // native constructor instead of the wrapper.
  api.openSocket = (url: string) =>
    new (sandbox.window as { WebSocket: new (u: string) => unknown }).WebSocket(url)
  api.fetch = (url: string, init?: unknown) =>
    (sandbox.fetch as (u: string, i?: unknown) => Promise<unknown>)(url, init)
  return api
}

describe('browser → host', () => {
  it('produces an envelope the host can open', async () => {
    const token = generateEncryptionToken()
    const host = generateEphemeralKeyPair()

    const browser = loadBrowserClient()
    await browser.init(token, host.publicKey)
    expect(browser.ready()).toBe(true)

    const rid = 'exchange-1'
    const envelope = await browser.seal(rid, { method: 'GET', path: '/secret' })

    // The host derives the same key from the browser's ephemeral public key.
    const key = deriveSessionKey(host.privateKey, envelope.epk ?? '', token)
    const opened = nodeOpen(
      { n: envelope.n ?? '', c: envelope.c ?? '', t: envelope.t ?? '' },
      key,
      rid,
    )
    expect(opened).not.toBeNull()
    expect(JSON.parse(opened!.toString('utf8'))).toEqual({ method: 'GET', path: '/secret' })
  })

  it('produces ciphertext that hides the payload', async () => {
    const browser = loadBrowserClient()
    await browser.init(generateEncryptionToken(), generateEphemeralKeyPair().publicKey)
    const envelope = await browser.seal('rid', { path: '/CONFIDENTIAL-PATH' })
    expect(JSON.stringify(envelope)).not.toContain('CONFIDENTIAL-PATH')
  })

  it('fails to open under a different token, as the relay would', async () => {
    const host = generateEphemeralKeyPair()
    const browser = loadBrowserClient()
    await browser.init(generateEncryptionToken(), host.publicKey)
    const envelope = await browser.seal('rid', { path: '/secret' })

    // The relay has no encryption token; this models its exact position.
    const wrongKey = deriveSessionKey(host.privateKey, envelope.epk ?? '', generateEncryptionToken())
    expect(
      nodeOpen({ n: envelope.n ?? '', c: envelope.c ?? '', t: envelope.t ?? '' }, wrongKey, 'rid'),
    ).toBeNull()
  })
})

describe('host → browser', () => {
  it('produces an envelope the browser can open', async () => {
    const token = generateEncryptionToken()
    const host = generateEphemeralKeyPair()

    const browser = loadBrowserClient()
    await browser.init(token, host.publicKey)
    // Establish the browser's ephemeral key by sealing once.
    const fromBrowser = await browser.seal('rid', {})

    const key = deriveSessionKey(host.privateKey, fromBrowser.epk ?? '', token)
    const sealed = nodeSeal(Buffer.from('THE-RESPONSE-BODY', 'utf8'), key, 'rid')

    const opened = await browser.open('rid', {
      epk: host.publicKey,
      salt: '',
      n: sealed.n,
      c: sealed.c,
      t: sealed.t,
    })
    expect(opened).not.toBeNull()
    expect(Buffer.from(opened!).toString('utf8')).toBe('THE-RESPONSE-BODY')
  })

  it('refuses a response bound to a different exchange', async () => {
    const token = generateEncryptionToken()
    const host = generateEphemeralKeyPair()
    const browser = loadBrowserClient()
    await browser.init(token, host.publicKey)
    const fromBrowser = await browser.seal('rid-a', {})

    const key = deriveSessionKey(host.privateKey, fromBrowser.epk ?? '', token)
    const sealed = nodeSeal(Buffer.from('body', 'utf8'), key, 'rid-a')

    const opened = await browser.open('rid-b', {
      epk: host.publicKey,
      salt: '',
      n: sealed.n,
      c: sealed.c,
      t: sealed.t,
    })
    expect(opened).toBeNull()
  })

  it('refuses a tampered response', async () => {
    const token = generateEncryptionToken()
    const host = generateEphemeralKeyPair()
    const browser = loadBrowserClient()
    await browser.init(token, host.publicKey)
    const fromBrowser = await browser.seal('rid', {})

    const key = deriveSessionKey(host.privateKey, fromBrowser.epk ?? '', token)
    const sealed = nodeSeal(Buffer.from('body', 'utf8'), key, 'rid')
    const flipped = Buffer.from(sealed.c, 'base64url')
    flipped[0] ^= 0xff

    const opened = await browser.open('rid', {
      epk: host.publicKey,
      salt: '',
      n: sealed.n,
      c: flipped.toString('base64url'),
      t: sealed.t,
    })
    expect(opened).toBeNull()
  })
})

describe('fetch wrapping', () => {
  it('seals a same-origin request and carries it in headers', async () => {
    const token = generateEncryptionToken()
    const host = generateEphemeralKeyPair()
    const browser = loadBrowserClient()
    await browser.init(token, host.publicKey)

    await browser.fetch('/api/session.list', { method: 'POST' })
    const call = browser.calls.at(-1)

    // The envelope rides as headers, so the relay forwards ciphertext with no
    // knowledge of encryption and no second code path.
    expect(call?.headers['x-dshrw-rid']).toBeTruthy()
    const raw = call?.headers['x-dshrw-sealed'] ?? ''
    expect(raw).toBeTruthy()

    // The host can open what the browser sealed.
    const envelope = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')) as {
      epk: string; n: string; c: string; t: string
    }
    const key = deriveSessionKey(host.privateKey, envelope.epk, token)
    const opened = nodeOpen({ n: envelope.n, c: envelope.c, t: envelope.t }, key,
      call?.headers['x-dshrw-rid'] ?? '')
    expect(opened).not.toBeNull()
    expect(JSON.parse(opened!.toString('utf8')).path).toBe('/api/session.list')
  })

  it('does not seal a cross-origin request', async () => {
    // Encrypting toward a third party would hand it our envelope.
    const browser = loadBrowserClient()
    await browser.init(generateEncryptionToken(), generateEphemeralKeyPair().publicKey)
    await browser.fetch('https://other.example.com/x')
    expect(browser.calls.at(-1)?.headers['x-dshrw-sealed']).toBeUndefined()
  })

  it('leaves fetch untouched before init', async () => {
    const browser = loadBrowserClient()
    await browser.fetch('/api/session.list')
    expect(browser.calls.at(-1)?.headers['x-dshrw-sealed']).toBeUndefined()
  })
})

describe('WebSocket wrapping', () => {
  it('attaches the ephemeral public key so the host can derive the stream key', async () => {
    const token = generateEncryptionToken()
    const host = generateEphemeralKeyPair()
    const browser = loadBrowserClient()
    await browser.init(token, host.publicKey)

    browser.openSocket('wss://relay.example.com/a/x/api/events.mux')
    const url = browser.opened.at(-1) ?? ''

    // A browser cannot set handshake headers, so the key rides the query
    // string; only a public key goes there.
    expect(url).toContain('dshrw_epk=')
    const key = new URL(url).searchParams.get('dshrw_epk') ?? ''
    expect(key.length).toBeGreaterThan(0)
    // The host derives the same key from it plus the encryption token.
    expect(deriveSessionKey(host.privateKey, key, token)).toHaveLength(32)
  })

  it('leaves the socket untouched before init', () => {
    const browser = loadBrowserClient()
    browser.openSocket('wss://relay.example.com/a/x/api/events.mux')
    expect(browser.opened.at(-1)).not.toContain('dshrw_epk')
  })
})
