/**
 * Header handling for the proxy hop between the relay and the local DSH
 * server.
 *
 * The delicate part is DSH's `/api` browser-trust fence. It rejects a request
 * whose `Host` is not a loopback authority, and rejects an `Origin` that does
 * not match that `Host` (a DNS-rebinding defence). A remote browser's headers
 * therefore cannot be forwarded verbatim.
 *
 * The plugin instead **terminates** the browser's identity at the tunnel and
 * re-originates the request on the host machine as a loopback request:
 * `Host` and `Origin` are rewritten to the local DSH authority, and every
 * hop-by-hop or client-supplied trust marker is dropped.
 *
 * That is sound only because authentication happens earlier and elsewhere: a
 * frame reaches this code only after the relay verified the browser's token
 * and the host accepted the tunnel. The rewrite grants no authority that the
 * token did not already grant; it restates a request the host itself is
 * making. Everything a remote peer could use to smuggle extra trust —
 * `x-forwarded-*`, cookies for other origins, upgrade plumbing — is stripped
 * rather than mapped.
 *
 * @module dsh-remote-web/shared/headers
 */

/**
 * Headers never forwarded from the browser to the local DSH server.
 *
 * Three groups, all removed for the same reason — the receiving side must see
 * a request that this host originated, not one a remote party shaped:
 *
 * - **Trust markers** (`host`, `origin`, `referer`, `sec-fetch-*`) are
 *   re-derived below; a forwarded value would either fail the fence or, worse,
 *   pass it while describing a different origin.
 * - **Forwarding claims** (`x-forwarded-*`, `forwarded`, `via`) are dropped so
 *   a remote peer cannot forge a chain that a future middlebox might believe.
 * - **Hop-by-hop plumbing** (`connection`, `upgrade`, `te`, encodings) belongs
 *   to the browser↔relay hop and is meaningless on this one.
 */
const STRIPPED_REQUEST_HEADERS = new Set([
  'host',
  'origin',
  'referer',
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'via',
  'forwarded',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-forwarded-port',
  'x-real-ip',
  'sec-fetch-site',
  'sec-fetch-mode',
  'sec-fetch-dest',
  'sec-fetch-user',
  'sec-websocket-key',
  'sec-websocket-version',
  'sec-websocket-extensions',
  'sec-websocket-protocol',
  // Compression is negotiated per hop; the tunnel moves identity bytes so the
  // host must not answer with an encoding the far browser never negotiated.
  'accept-encoding',
])

/**
 * Response headers dropped on the way back to the browser: hop-by-hop
 * plumbing plus lengths that no longer describe the re-chunked body.
 */
const STRIPPED_RESPONSE_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'content-encoding',
  'content-length',
])

/** Maximum number of headers accepted from a remote peer. */
const MAX_HEADER_COUNT = 100

/** Maximum size of a single header value accepted from a remote peer. */
const MAX_HEADER_VALUE_BYTES = 8 * 1024

/**
 * Normalize raw incoming headers into a flat, bounded, lowercase map.
 *
 * Array values (repeated headers) are joined with `, ` except `set-cookie`,
 * which is dropped: DSH's API does not rely on it and merging it would corrupt
 * multiple cookies into one malformed value.
 *
 * @param headers - Node-style incoming headers.
 * @returns A flat map safe to serialize into a protocol frame.
 */
export function normalizeHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const out: Record<string, string> = {}
  let count = 0
  for (const [rawKey, value] of Object.entries(headers)) {
    if (count >= MAX_HEADER_COUNT) break
    if (value === undefined) continue
    const key = rawKey.toLowerCase()
    if (key === 'set-cookie') continue
    const joined = Array.isArray(value) ? value.join(', ') : value
    if (Buffer.byteLength(joined, 'utf8') > MAX_HEADER_VALUE_BYTES) continue
    out[key] = joined
    count += 1
  }
  return out
}

/**
 * The authority a proxied request claims to come from.
 *
 * Deliberately **not** a loopback address. DSH's `/api` fence recognizes two
 * kinds of caller: a loopback one, which may reach the privileged plane
 * (credentials, settings, `host.openPath`, and the rest of `PRIVILEGED_METHODS`),
 * and a declared `trustedHosts` authority, which passes the ordinary fence but
 * is refused those methods.
 *
 * A remote browser belongs in the second category, so the tunnel presents
 * itself as this named authority instead of impersonating loopback. DSH then
 * enforces the privileged boundary itself, using its own list, which stays
 * correct as that list grows.
 *
 * The alternative — claiming loopback and re-implementing the exclusions here —
 * was tried and rejected: it silently missed `llm.discoverModels`, and every
 * future DSH release would risk another silent gap.
 */
export const REMOTE_AUTHORITY = 'dsh-remote-web.internal'

/**
 * Rewrite browser request headers so the local DSH server sees a request this
 * host originated on behalf of a remote, non-privileged caller.
 *
 * @param headers - Normalized headers from the remote browser.
 * @returns Headers to send on the local request.
 */
export function rewriteRequestHeaders(
  headers: Record<string, string>,
): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(headers)) {
    if (STRIPPED_REQUEST_HEADERS.has(key.toLowerCase())) continue
    out[key.toLowerCase()] = value
  }
  // Same-origin under the named authority: the fence compares Origin against
  // Host, and a mismatch (or a cross-site marker) fails it.
  out.host = REMOTE_AUTHORITY
  out.origin = `http://${REMOTE_AUTHORITY}`
  out['sec-fetch-site'] = 'same-origin'
  // Identity encoding: the tunnel frames raw bytes and re-chunks them, so a
  // compressed upstream body would arrive with a stale content-encoding.
  out['accept-encoding'] = 'identity'
  return out
}

/**
 * Filter response headers for the trip back to the browser.
 *
 * @param headers - Headers from the local DSH server.
 * @returns Headers safe to replay to the remote browser.
 */
export function rewriteResponseHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const normalized = normalizeHeaders(headers)
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(normalized)) {
    if (STRIPPED_RESPONSE_HEADERS.has(key)) continue
    out[key] = value
  }
  return out
}

/**
 * Paths the tunnel is willing to proxy.
 *
 * This is an allowlist by prefix rather than a denylist because the DSH web
 * surface is a single-page app: anything outside these prefixes is either a
 * static asset (served through the SPA fallback, which the last entry covers)
 * or something the remote surface has no business reaching.
 */
const ALLOWED_WS_PATHS = new Set(['/api/events.mux', '/api/events.host'])

/**
 * Decide whether a proxied WebSocket upgrade may proceed.
 *
 * Only the two DSH downlink streams are permitted. Any other upgrade — a
 * plugin's own socket, a terminal, an unknown future route — is refused,
 * because a shell-bearing socket reached through a remote browser would defeat
 * the point of proxying only the conversation surface.
 *
 * @param path - Request path including query string.
 */
export function isAllowedWebSocketPath(path: string): boolean {
  const pathname = path.split('?')[0] ?? ''
  return ALLOWED_WS_PATHS.has(pathname)
}

/**
 * Reject paths that try to escape the proxied surface.
 *
 * Traversal is checked on the raw and the percent-decoded form, since the
 * receiving server decodes before routing.
 *
 * @returns True when the path is a plain, root-relative request path.
 */
export function isSafeProxyPath(path: string): boolean {
  if (!path.startsWith('/') || path.startsWith('//')) return false
  if (path.includes('\\') || path.includes('\0')) return false
  let decoded: string
  try {
    decoded = decodeURIComponent(path)
  } catch {
    return false
  }
  if (decoded.includes('..') || decoded.includes('\0')) return false
  return true
}
