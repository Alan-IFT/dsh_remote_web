/**
 * Header rewriting and path policy: the rules that let proxied requests pass
 * DSH's trust fence without letting a remote peer smuggle authority.
 */

import { describe, expect, it } from 'vitest'

import {
  REMOTE_AUTHORITY,
  isAllowedWebSocketPath,
  isSafeProxyPath,
  normalizeHeaders,
  rewriteRequestHeaders,
  rewriteResponseHeaders,
} from '../src/shared/headers.js'

describe('normalizeHeaders', () => {
  it('lowercases keys and joins repeated values', () => {
    expect(normalizeHeaders({ 'X-Test': 'a', Accept: ['b', 'c'] })).toEqual({
      'x-test': 'a',
      accept: 'b, c',
    })
  })

  it('drops undefined values and set-cookie', () => {
    expect(normalizeHeaders({ a: undefined, 'Set-Cookie': ['x=1', 'y=2'] })).toEqual({})
  })

  it('caps header count and oversized values', () => {
    const many: Record<string, string> = {}
    for (let i = 0; i < 200; i += 1) many[`h${String(i)}`] = 'v'
    expect(Object.keys(normalizeHeaders(many)).length).toBe(100)

    const huge = { big: 'x'.repeat(9000) }
    expect(normalizeHeaders(huge)).toEqual({})
  })
})

describe('rewriteRequestHeaders', () => {

  it('re-originates the request under the named authority', () => {
    const out = rewriteRequestHeaders({ host: 'relay.example.com', origin: 'https://relay.example.com' })
    expect(out.host).toBe(REMOTE_AUTHORITY)
    expect(out.origin).toBe(`http://${REMOTE_AUTHORITY}`)
    expect(out['sec-fetch-site']).toBe('same-origin')
  })

  it('strips forwarding claims a remote peer could forge', () => {
    const out = rewriteRequestHeaders({
        'x-forwarded-for': '10.0.0.1',
        'x-forwarded-host': 'evil.example',
        'x-real-ip': '10.0.0.1',
        forwarded: 'for=10.0.0.1',
        via: '1.1 proxy',
      })
    for (const key of ['x-forwarded-for', 'x-forwarded-host', 'x-real-ip', 'forwarded', 'via']) {
      expect(out).not.toHaveProperty(key)
    }
  })

  it('strips cross-site fetch markers rather than forwarding them', () => {
    const out = rewriteRequestHeaders({ 'sec-fetch-site': 'cross-site' })
    // Overwritten, never passed through: cross-site would fail DSH's fence.
    expect(out['sec-fetch-site']).toBe('same-origin')
  })

  it('strips hop-by-hop plumbing and websocket handshake headers', () => {
    const out = rewriteRequestHeaders({
        connection: 'upgrade',
        upgrade: 'websocket',
        'sec-websocket-key': 'abc',
        'transfer-encoding': 'chunked',
        te: 'trailers',
      })
    expect(Object.keys(out).sort()).toEqual(
      ['accept-encoding', 'host', 'origin', 'sec-fetch-site'].sort(),
    )
  })

  it('forces identity encoding so tunneled bodies are not doubly encoded', () => {
    const out = rewriteRequestHeaders({ 'accept-encoding': 'gzip, br' })
    expect(out['accept-encoding']).toBe('identity')
  })

  it('preserves ordinary application headers', () => {
    const out = rewriteRequestHeaders({ 'content-type': 'application/json', 'x-dsh-thing': 'keep' })
    expect(out['content-type']).toBe('application/json')
    expect(out['x-dsh-thing']).toBe('keep')
  })
})

describe('rewriteResponseHeaders', () => {
  it('drops hop-by-hop and stale length/encoding headers', () => {
    const out = rewriteResponseHeaders({
      'content-type': 'text/html',
      'content-length': '123',
      'content-encoding': 'gzip',
      connection: 'keep-alive',
      'transfer-encoding': 'chunked',
    })
    expect(out).toEqual({ 'content-type': 'text/html' })
  })
})

describe('websocket path policy', () => {
  it('allows exactly the two DSH downlink streams', () => {
    expect(isAllowedWebSocketPath('/api/events.mux')).toBe(true)
    expect(isAllowedWebSocketPath('/api/events.host')).toBe(true)
    expect(isAllowedWebSocketPath('/api/events.mux?x=1')).toBe(true)
  })

  it('refuses every other upgrade, including plugin sockets', () => {
    for (const path of [
      '/sidebar/api/terminal',
      '/api/events.muxx',
      '/api',
      '/',
      '/api/events.mux/../../x',
    ]) {
      expect(isAllowedWebSocketPath(path)).toBe(false)
    }
  })
})

describe('proxy path safety', () => {
  it('accepts ordinary root-relative paths', () => {
    for (const path of ['/', '/api', '/assets/app.js?rev=1', '/a/b/c']) {
      expect(isSafeProxyPath(path)).toBe(true)
    }
  })

  it('rejects traversal, protocol-relative, and control characters', () => {
    for (const path of [
      '../etc/passwd',
      '/../etc/passwd',
      '/%2e%2e/secret',
      '//evil.example/path',
      '/a\\b',
      'http://evil.example/',
    ]) {
      expect(isSafeProxyPath(path)).toBe(false)
    }
  })

  it('rejects malformed percent-encoding rather than guessing', () => {
    expect(isSafeProxyPath('/%zz')).toBe(false)
  })
})

describe('privilege boundary by authority', () => {
  // The tunnel presents a named authority rather than impersonating loopback.
  // DSH's fence admits a declared authority for ordinary methods and refuses it
  // the privileged plane — so DSH enforces that boundary with its own list and
  // this package keeps no copy. An earlier blacklist here silently missed
  // `llm.discoverModels`, which is the drift this removes.
  it('never claims to be loopback', () => {
    const out = rewriteRequestHeaders({ host: 'relay.example.com' })
    expect(out.host).toBe(REMOTE_AUTHORITY)
    expect(out.host).not.toMatch(/^127\.|^localhost|^\[?::1/)
  })

  it('presents Origin matching Host, as the fence requires', () => {
    const out = rewriteRequestHeaders({ origin: 'https://relay.example.com' })
    expect(out.origin).toBe(`http://${REMOTE_AUTHORITY}`)
    expect(new URL(out.origin!).host).toBe(out.host)
  })

  it('is a bare authority DSH will accept in trustedHosts', () => {
    // A trustedHosts entry must be a bare host[:port] that WHATWG parsing reads
    // back unchanged, or DSH fails the plugin load loudly.
    const parsed = new URL(`http://${REMOTE_AUTHORITY}`)
    expect(parsed.host).toBe(REMOTE_AUTHORITY)
    expect(REMOTE_AUTHORITY).not.toContain('/')
  })
})
