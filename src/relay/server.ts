/**
 * The relay server: a self-hosted rendezvous point between DSH hosts behind
 * NAT and remote browsers.
 *
 * What it does:
 *
 * 1. Accepts outbound agent tunnels on {@link RELAY_AGENT_PATH} after token
 *    authentication. This is the NAT traversal: the host dials out, so no
 *    inbound port, no UPnP, no port forwarding.
 * 2. Authenticates browsers against issued tokens and gives them a session.
 * 3. Forwards each authenticated browser request through the chosen agent's
 *    tunnel and streams the response back.
 *
 * What it deliberately does not do: interpret DSH payloads, store session
 * plaintext beyond the in-flight buffer, or grant any access that an issued
 * token did not already carry.
 *
 * @module dsh-remote-web/relay/server
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { randomUUID } from 'node:crypto'
import type { Duplex } from 'node:stream'

import { WebSocketServer, type WebSocket } from 'ws'

import {
  AUTH_PROOF_SKEW_MS,
  CLOSE_AGENT_OFFLINE,
  CLOSE_AGENT_REPLACED,
  CLOSE_AUTH_FAILED,
  CLOSE_RATE_LIMITED,
  CLOSE_REVOKED,
  CLOSE_UNSUPPORTED_VERSION,
  HEARTBEAT_INTERVAL_MS,
  MAX_BODY_CHUNK_BYTES,
  MAX_CONTROL_FRAME_BYTES,
  MAX_REQUEST_BODY_BYTES,
  PROTOCOL_VERSION,
  RELAY_AGENT_PATH,
  agentChallenge,
  parseFrame,
  type AgentHelloFrame,
  type BodyChunkFrame,
  type HttpResponseFrame,
  type TunnelFrame,
  type WsCloseFrame,
  type WsMessageFrame,
} from '../shared/protocol.js'
import { OneTimeValues, RateLimiter, decodePairingCode } from '../shared/auth.js'
import { isAllowedWebSocketPath, isSafeProxyPath, normalizeHeaders } from '../shared/headers.js'
import { RelayStore, scopeMayReach } from './store.js'
import { Tunnel, TunnelRegistry } from './tunnels.js'
import {
  SessionStore,
  buildClearCookie,
  buildSessionCookie,
  readSessionCookie,
  type Session,
} from './sessions.js'
import { renderAgentPicker, renderErrorPage, renderLoginPage, type AgentChoice } from './pages.js'

/** Relay configuration. */
export interface RelayOptions {
  /** Bind host; `0.0.0.0` for a public deployment. */
  host: string
  port: number
  /** Path to the JSON state file. */
  statePath: string
  /**
   * Whether the relay is reached over TLS. Controls the `Secure` cookie flag
   * and HSTS. Set it when a reverse proxy terminates TLS in front.
   */
  secure: boolean
  /** Trust `X-Forwarded-For` for rate-limit keys (only behind a known proxy). */
  trustProxy: boolean
  /** Session idle lifetime in milliseconds. */
  sessionTtlMs: number
  /** Optional log sink; defaults to stdout. */
  log?: (message: string) => void
}

/** Defaults for options a caller may omit. */
export const DEFAULT_RELAY_OPTIONS = {
  host: '0.0.0.0',
  port: 8787,
  secure: true,
  trustProxy: false,
  sessionTtlMs: 12 * 60 * 60 * 1000,
} as const

/** Version reported to agents in `hello.ack`. */
const RELAY_VERSION = '0.1.0'

/** A running relay, with the handles needed to inspect and stop it. */
export interface RunningRelay {
  server: Server
  port: number
  close: () => Promise<void>
  store: RelayStore
  tunnels: TunnelRegistry
  sessions: SessionStore
}

/** Per-request state while a browser request is streamed through a tunnel. */
interface ActiveRequest {
  response: ServerResponse
  detach: () => void
  finished: boolean
}

/**
 * Start the relay.
 *
 * @param options - Bind, storage, and posture settings.
 * @returns Handles for the running server.
 */
export async function startRelay(options: RelayOptions): Promise<RunningRelay> {
  const log = options.log ?? ((message: string) => process.stdout.write(`${message}\n`))
  const store = new RelayStore(options.statePath)
  const tunnels = new TunnelRegistry()
  const sessions = new SessionStore(options.sessionTtlMs)
  const loginLimiter = new RateLimiter(10, 60_000)
  const agentLimiter = new RateLimiter(30, 60_000)
  // One primitive serves both: agent handshake nonces are added and never
  // reused, browser challenges are added at issue and taken at redemption.
  const handshakeNonces = new OneTimeValues()
  const challenges = new OneTimeValues(120_000)

  /** Client address used for rate limiting. */
  const clientKey = (request: IncomingMessage): string => {
    if (options.trustProxy) {
      const forwarded = request.headers['x-forwarded-for']
      const raw = Array.isArray(forwarded) ? forwarded[0] : forwarded
      const first = raw?.split(',')[0]?.trim()
      if (first !== undefined && first !== '') return first
    }
    return request.socket.remoteAddress ?? 'unknown'
  }

  /** Security headers applied to every relay-owned response. */
  const securityHeaders = (): Record<string, string> => {
    const headers: Record<string, string> = {
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      // The relay must never be framed: the proxied surface can act on the
      // user's machine, so clickjacking would be a remote-execution vector.
      'x-frame-options': 'DENY',
      'cache-control': 'no-store',
    }
    if (options.secure) {
      headers['strict-transport-security'] = 'max-age=31536000; includeSubDomains'
    }
    return headers
  }

  const sendHtml = (
    response: ServerResponse,
    status: number,
    html: string,
    extra: Record<string, string> = {},
  ): void => {
    response.writeHead(status, {
      ...securityHeaders(),
      ...extra,
      'content-type': 'text/html; charset=utf-8',
    })
    response.end(html)
  }

  const sendJson = (response: ServerResponse, status: number, body: unknown): void => {
    response.writeHead(status, {
      ...securityHeaders(),
      'content-type': 'application/json; charset=utf-8',
    })
    response.end(JSON.stringify(body))
  }

  /* ───────────────────────── agent tunnel endpoint ──────────────────────── */

  const agentWss = new WebSocketServer({ noServer: true, maxPayload: MAX_CONTROL_FRAME_BYTES })
  const clientWss = new WebSocketServer({ noServer: true, maxPayload: MAX_CONTROL_FRAME_BYTES })

  /**
   * Drive one attached agent socket: authenticate it, then pump frames.
   *
   * The handshake is strict — an agent that does not send a well-formed
   * `hello` within the deadline is dropped without a hint about why.
   */
  const handleAgentSocket = (socket: WebSocket, request: IncomingMessage): void => {
    const key = clientKey(request)
    let tunnel: Tunnel | null = null

    const handshakeTimer = setTimeout(() => {
      if (tunnel === null) socket.close(CLOSE_AUTH_FAILED, 'handshake timeout')
    }, 10_000)

    socket.on('message', (raw, isBinary) => {
      if (isBinary) {
        socket.close(CLOSE_AUTH_FAILED, 'binary frame')
        return
      }
      const frame = parseFrame(raw.toString('utf8'))
      if (frame === null) {
        socket.close(CLOSE_AUTH_FAILED, 'malformed frame')
        return
      }

      if (tunnel === null) {
        if (frame.type !== 'hello') {
          socket.close(CLOSE_AUTH_FAILED, 'expected hello')
          return
        }
        const hello = frame as AgentHelloFrame
        if (hello.v !== PROTOCOL_VERSION) {
          socket.close(CLOSE_UNSUPPORTED_VERSION, `protocol ${String(PROTOCOL_VERSION)} required`)
          return
        }
        if (!agentLimiter.allow(key)) {
          socket.close(CLOSE_RATE_LIMITED, 'too many attempts')
          return
        }
        if (typeof hello.agentId !== 'string' || hello.agentId === '') {
          socket.close(CLOSE_AUTH_FAILED, 'invalid agent')
          return
        }
        const record = store.findAgent(hello.agentId)
        if (record === undefined) {
          socket.close(CLOSE_AUTH_FAILED, 'invalid agent')
          return
        }
        // Signature check. The relay holds only this agent's PUBLIC key, so a
        // reader of its state file can verify a proof and produce none.
        const skew = Math.abs(Date.now() - hello.ts)
        if (!Number.isFinite(hello.ts) || skew > AUTH_PROOF_SKEW_MS) {
          socket.close(CLOSE_AUTH_FAILED, 'authentication failed')
          return
        }
        if (
          typeof hello.nonce !== 'string' ||
          hello.nonce.length < 16 ||
          hello.nonce.length > 128 ||
          !handshakeNonces.add(hello.nonce)
        ) {
          socket.close(CLOSE_AUTH_FAILED, 'authentication failed')
          return
        }
        if (
          store.verifyAgentSignature(
            hello.agentId,
            agentChallenge(hello.agentId, hello.ts, hello.nonce),
            hello.signature,
          ) === undefined
        ) {
          log(`[relay] agent ${hello.agentId} signature refused`)
          socket.close(CLOSE_AUTH_FAILED, 'authentication failed')
          return
        }
        agentLimiter.reset(key)
        clearTimeout(handshakeTimer)

        const tunnelId = randomUUID()
        tunnel = new Tunnel(record.agentId, tunnelId, record.label, socket)
        const displaced = tunnels.add(tunnel)
        if (displaced !== undefined) {
          try {
            displaced.socket.close(CLOSE_AGENT_REPLACED, 'replaced by a newer tunnel')
          } catch {
            // Already gone; replacement is what mattered.
          }
        }
        store.touchAgent(record.agentId)
        tunnel.send({
          type: 'hello.ack',
          v: PROTOCOL_VERSION,
          tunnelId,
          heartbeatIntervalMs: HEARTBEAT_INTERVAL_MS,
          maxControlFrameBytes: MAX_CONTROL_FRAME_BYTES,
          maxBodyChunkBytes: MAX_BODY_CHUNK_BYTES,
          relayVersion: RELAY_VERSION,
        })
        log(`[relay] agent online: ${record.label} (${record.agentId})`)
        return
      }

      tunnel.lastSeenAt = Date.now()
      routeAgentFrame(tunnel, frame)
    })

    socket.on('close', () => {
      clearTimeout(handshakeTimer)
      if (tunnel !== null) {
        tunnels.remove(tunnel)
        log(`[relay] agent offline: ${tunnel.label} (${tunnel.agentId})`)
      }
    })

    socket.on('error', () => {
      // `close` always follows; cleanup lives there.
    })
  }

  /** Route a frame from an agent to whichever exchange owns it. */
  const routeAgentFrame = (tunnel: Tunnel, frame: TunnelFrame): void => {
    switch (frame.type) {
      case 'http.response':
      case 'body.chunk':
      case 'body.end':
      case 'abort': {
        const id = (frame as { rid?: string }).rid
        if (typeof id === 'string') tunnel.dispatch(id, frame)
        return
      }
      case 'ws.open.ack':
      case 'ws.message':
      case 'ws.close': {
        const id = (frame as { sid?: string }).sid
        if (typeof id === 'string') tunnel.dispatch(id, frame)
        return
      }
      case 'pong':
        return
      case 'ping':
        tunnel.send({ type: 'pong', nonce: frame.nonce })
        return
      default:
        // Unknown or agent-illegal frame types are ignored; the agent is
        // authenticated but still not trusted to drive relay control flow.
        return
    }
  }

  /* ─────────────────────── browser request forwarding ───────────────────── */

  /**
   * Forward one authenticated browser request through an agent tunnel.
   *
   * The body is streamed in bounded chunks in both directions, and the
   * exchange is torn down on any of: client abort, tunnel loss, or an `abort`
   * frame from the agent.
   */
  const forwardHttp = (
    tunnel: Tunnel,
    request: IncomingMessage,
    response: ServerResponse,
    session: Session,
    path: string,
  ): void => {
    // CSRF, checked here because here is the last place the browser's own
    // markers still mean something. Forwarding rewrites Origin and Host to the
    // named authority so DSH's fence accepts a proxied request at all, which
    // necessarily makes that fence describe this relay rather than the browser.
    // The duty therefore moves to the relay rather than disappearing.
    //
    // SameSite=Lax already withholds the session cookie from cross-site writes,
    // so this is the second of two independent barriers; it also covers the
    // case Lax permits, a cross-site top-level GET, which DSH would have
    // refused on its own had the markers reached it.
    if (normalizeHeaders(request.headers)['sec-fetch-site'] === 'cross-site') {
      sendHtml(response, 403, renderErrorPage(403, '跨站请求被拒绝 / Cross-site request refused'))
      return
    }

    const rid = randomUUID()
    const state: ActiveRequest = {
      response,
      detach: () => undefined,
      finished: false,
    }

    const finish = (): void => {
      if (state.finished) return
      state.finished = true
      state.detach()
    }

    state.detach = tunnel.attach(rid, {
      onFrame: (frame) => {
        switch (frame.type) {
          case 'http.response': {
            const head = frame as HttpResponseFrame
            if (response.headersSent) return
            response.writeHead(head.status, {
              ...head.headers,
              ...securityHeaders(),
              // Restate content-type from the agent: securityHeaders() must not
              // override what DSH actually produced.
              ...(head.headers['content-type'] === undefined
                ? {}
                : { 'content-type': head.headers['content-type'] }),
              ...(head.headers['cache-control'] === undefined
                ? {}
                : { 'cache-control': head.headers['cache-control'] }),
            })
            return
          }
          case 'body.chunk': {
            const chunk = frame as BodyChunkFrame
            const buffer = Buffer.from(chunk.data, 'base64')
            if (!response.writableEnded) response.write(buffer)
            return
          }
          case 'body.end': {
            if (!response.writableEnded) response.end()
            finish()
            return
          }
          case 'abort': {
            if (!response.headersSent) {
              sendHtml(response, 502, renderErrorPage(502, '主机中断了该请求 / Host aborted'))
            } else if (!response.writableEnded) {
              response.end()
            }
            finish()
            return
          }
          default:
            return
        }
      },
      onTunnelLost: () => {
        if (!response.headersSent) {
          sendHtml(response, 503, renderErrorPage(503, '主机已离线 / Host went offline'))
        } else if (!response.writableEnded) {
          response.end()
        }
        finish()
      },
    })

    const headers = normalizeHeaders(request.headers)
    // The browser's own cookie belongs to the relay session, not to DSH.
    delete headers.cookie
    delete headers.authorization

    const hasBody = request.method !== 'GET' && request.method !== 'HEAD'
    const sent = tunnel.send({
      type: 'http.request',
      rid,
      method: request.method ?? 'GET',
      path,
      headers,
      noBody: !hasBody,
      clientId: session.clientId,
    })
    if (!sent) {
      sendHtml(response, 503, renderErrorPage(503, '主机已离线 / Host went offline'))
      finish()
      return
    }

    if (hasBody) {
      let received = 0
      request.on('data', (chunk: Buffer) => {
        received += chunk.length
        if (received > MAX_REQUEST_BODY_BYTES) {
          tunnel.send({ type: 'abort', rid, reason: 'request body too large' })
          if (!response.headersSent) {
            sendHtml(response, 413, renderErrorPage(413, '请求体过大 / Request body too large'))
          }
          request.destroy()
          finish()
          return
        }
        for (let offset = 0; offset < chunk.length; offset += MAX_BODY_CHUNK_BYTES) {
          const slice = chunk.subarray(offset, offset + MAX_BODY_CHUNK_BYTES)
          tunnel.send({ type: 'body.chunk', rid, data: slice.toString('base64') })
        }
      })
      request.on('end', () => {
        if (!state.finished) tunnel.send({ type: 'body.end', rid })
      })
    }

    response.on('close', () => {
      if (!state.finished) {
        tunnel.send({ type: 'abort', rid, reason: 'client disconnected' })
        finish()
      }
    })
  }

  /* ──────────────────────────── HTTP dispatch ───────────────────────────── */

  /**
   * Resolve which agent a request targets.
   *
   * URLs are `/a/<agentId>/<path>`; the prefix is stripped before forwarding
   * so the DSH surface sees the paths it expects.
   */
  const parseAgentPath = (
    url: string,
  ): { agentId: string; rest: string } | null => {
    const match = /^\/a\/([^/]+)(\/.*)?$/.exec(url)
    if (match === null) return null
    const agentId = decodeURIComponent(match[1] ?? '')
    const rest = match[2] ?? '/'
    return agentId === '' ? null : { agentId, rest }
  }

  /**
   * Resolve a cookie to a session that is still backed by a live credential.
   *
   * Revocation must take effect immediately, not at the next relay restart, so
   * every authenticated request re-checks that the credential behind the
   * session still exists and is neither revoked nor expired. The store reads
   * through to disk on change, so a `client revoke` in another process ends
   * live sessions on their very next request.
   */
  const resolveLiveSession = (cookie: string | undefined): Session | undefined => {
    const session = sessions.resolve(cookie)
    if (session === undefined) return undefined
    if (store.findLiveClient(session.clientId) === undefined) {
      sessions.destroyByClient(session.clientId)
      return undefined
    }
    return session
  }

  /**
   * Resolve the live tunnel for an agent that is still authorized.
   *
   * `agent revoke` runs in a separate process, so the check must happen on the
   * request path rather than only at attach time. A tunnel whose agent has been
   * revoked is closed here, which both ends the current abuse and stops the
   * host from reattaching (its token no longer validates).
   */
  const liveAuthorizedTunnel = (agentId: string): Tunnel | undefined => {
    const tunnel = tunnels.get(agentId)
    if (tunnel === undefined) return undefined
    if (store.findAgent(agentId) === undefined) {
      tunnels.remove(tunnel)
      try {
        tunnel.socket.close(CLOSE_REVOKED, 'agent revoked')
      } catch {
        // Already gone; eviction is what mattered.
      }
      log(`[relay] dropped revoked agent tunnel: ${agentId}`)
      return undefined
    }
    return tunnel
  }

  const agentChoices = (session: Session): AgentChoice[] =>
    store
      .listAgents()
      .filter((agent) => !agent.revoked && scopeMayReach(session.agentId, agent.agentId))
      .map((agent) => {
        const live = tunnels.get(agent.agentId)
        return {
          agentId: agent.agentId,
          label: agent.label,
          online: live !== undefined,
          connectedAt: live?.connectedAt ?? null,
        }
      })

  const handleRequest = (request: IncomingMessage, response: ServerResponse): void => {
    const rawUrl = request.url ?? '/'
    if (!isSafeProxyPath(rawUrl)) {
      sendHtml(response, 400, renderErrorPage(400, '非法路径 / Invalid path'))
      return
    }
    const pathname = rawUrl.split('?')[0] ?? '/'
    const cookie = readSessionCookie(request.headers.cookie)

    /* health check: unauthenticated on purpose, reveals nothing */
    if (pathname === '/__health') {
      sendJson(response, 200, { ok: true, agents: tunnels.list().length })
      return
    }

    /* login */
    if (pathname === '/__auth/login') {
      if (request.method === 'GET') {
        sendHtml(response, 200, renderLoginPage())
        return
      }
      if (request.method !== 'POST') {
        sendHtml(response, 405, renderErrorPage(405, 'Method not allowed'))
        return
      }
      const key = clientKey(request)
      if (!loginLimiter.allow(key)) {
        sendHtml(response, 429, renderLoginPage({ error: '尝试过于频繁，请稍后再试 / Too many attempts' }))
        return
      }
      let body = ''
      let tooLarge = false
      request.on('data', (chunk: Buffer) => {
        body += chunk.toString('utf8')
        if (body.length > 8192) {
          tooLarge = true
          request.destroy()
        }
      })
      request.on('end', () => {
        if (tooLarge) return
        const form = new URLSearchParams(body)
        const submitted = (form.get('token') ?? '').trim()
        const next = form.get('next') ?? ''
        // A pairing code carries the relay URL and the encryption token too.
        // Only the auth half concerns the relay; the encryption half is for the
        // browser to keep, and the relay deliberately never records it.
        const decoded = decodePairingCode(submitted)
        const token = decoded?.authSecret ?? submitted
        const client = store.verifyClientToken(token)
        if (client === undefined) {
          log(`[relay] login refused from ${key}`)
          sendHtml(response, 401, renderLoginPage({ error: '令牌无效或已过期 / Invalid or expired token' }))
          return
        }
        loginLimiter.reset(key)
        // First login also enrolls the browser's signing key when it offered
        // one, so every later login is a signature and the token goes dormant.
        const offeredKey = form.get('publicKey')
        if (offeredKey !== null && offeredKey !== '') {
          store.enrollClientKey(client.clientId, offeredKey)
        }
        store.touchClient(client.clientId)
        const raw = sessions.create(client.clientId, client.label, client.agentId)
        const cookieValue = buildSessionCookie(
          raw,
          options.secure,
          Math.floor(options.sessionTtlMs / 1000),
        )
        const target = next.startsWith('/') && !next.startsWith('//') ? next : '/'
        log(`[relay] login: ${client.label} (${client.clientId})`)
        response.writeHead(303, {
          ...securityHeaders(),
          'set-cookie': cookieValue,
          location: target,
        })
        response.end()
      })
      return
    }

    /* signature login: the token stays on the device after enrollment */
    if (pathname === '/__auth/challenge') {
      // A challenge is public and single-use; binding it to the nonce cache is
      // what stops a captured signature from being replayed.
      const nonce = randomUUID()
      if (!challenges.add(nonce)) {
        sendJson(response, 429, { ok: false, error: 'too many pending challenges' })
        return
      }
      sendJson(response, 200, { nonce })
      return
    }

    if (pathname === '/__auth/verify' && request.method === 'POST') {
      const key = clientKey(request)
      if (!loginLimiter.allow(key)) {
        sendJson(response, 429, { ok: false, error: 'too many attempts' })
        return
      }
      let body = ''
      let tooLarge = false
      request.on('data', (chunk: Buffer) => {
        body += chunk.toString('utf8')
        if (body.length > 8192) {
          tooLarge = true
          request.destroy()
        }
      })
      request.on('end', () => {
        if (tooLarge) return
        const form = new URLSearchParams(body)
        const nonce = form.get('nonce') ?? ''
        const signature = form.get('signature') ?? ''
        // take() both validates and consumes, so a captured signature cannot
        // be replayed against the same challenge.
        if (!challenges.take(nonce)) {
          sendJson(response, 401, { ok: false, error: 'unknown or expired challenge' })
          return
        }
        const client = store.verifyClientSignature(`dsh-remote-web/login|${nonce}`, signature)
        if (client === undefined) {
          sendJson(response, 401, { ok: false, error: 'invalid signature' })
          return
        }
        loginLimiter.reset(key)
        store.touchClient(client.clientId)
        const raw = sessions.create(client.clientId, client.label, client.agentId)
        response.writeHead(200, {
          ...securityHeaders(),
          'set-cookie': buildSessionCookie(raw, options.secure, Math.floor(options.sessionTtlMs / 1000)),
          'content-type': 'application/json; charset=utf-8',
        })
        response.end(JSON.stringify({ ok: true }))
      })
      return
    }

    /* logout */
    if (pathname === '/__auth/logout') {
      sessions.destroy(cookie)
      response.writeHead(303, {
        ...securityHeaders(),
        'set-cookie': buildClearCookie(options.secure),
        location: '/__auth/login',
      })
      response.end()
      return
    }

    /* everything below requires a session backed by a live credential */
    const session = resolveLiveSession(cookie)
    if (session === undefined) {
      sendHtml(response, 401, renderLoginPage({ next: rawUrl }), {
        'set-cookie': buildClearCookie(options.secure),
      })
      return
    }

    /* agent picker */
    if (pathname === '/' || pathname === '/__agents') {
      const choices = agentChoices(session)
      // One reachable agent: skip the picker entirely.
      if (pathname === '/' && choices.length === 1 && choices[0]?.online === true) {
        response.writeHead(303, {
          ...securityHeaders(),
          location: `/a/${encodeURIComponent(choices[0].agentId)}/`,
        })
        response.end()
        return
      }
      sendHtml(response, 200, renderAgentPicker(choices))
      return
    }

    /* proxied surface */
    const target = parseAgentPath(rawUrl)
    if (target === null) {
      // A DSH asset requested at the origin root (the SPA sometimes emits
      // absolute paths) is redirected into the agent scope when unambiguous.
      const choices = agentChoices(session).filter((choice) => choice.online)
      if (choices.length === 1 && choices[0] !== undefined) {
        response.writeHead(307, {
          ...securityHeaders(),
          location: `/a/${encodeURIComponent(choices[0].agentId)}${rawUrl}`,
        })
        response.end()
        return
      }
      sendHtml(response, 404, renderErrorPage(404, '未找到 / Not found'))
      return
    }

    if (!scopeMayReach(session.agentId, target.agentId)) {
      sendHtml(response, 403, renderErrorPage(403, '无权访问该主机 / Not authorized for this host'))
      return
    }

    const tunnel = liveAuthorizedTunnel(target.agentId)
    if (tunnel === undefined) {
      sendHtml(response, 503, renderErrorPage(503, '主机当前离线 / Host is offline'))
      return
    }

    forwardHttp(tunnel, request, response, session, target.rest)
  }

  /* ─────────────────────── WebSocket upgrade dispatch ───────────────────── */

  /**
   * Proxy a browser WebSocket through the agent tunnel.
   *
   * Only the DSH downlink paths are allowed; the check happens before the
   * upgrade is accepted so a refused socket never reaches the host.
   */
  const proxyClientSocket = (
    socket: WebSocket,
    tunnel: Tunnel,
    session: Session,
    path: string,
    headers: Record<string, string>,
  ): void => {
    const sid = randomUUID()
    let closed = false

    const detach = tunnel.attach(sid, {
      onFrame: (frame) => {
        switch (frame.type) {
          case 'ws.message': {
            const message = frame as WsMessageFrame
            if (socket.readyState !== socket.OPEN) return
            if (message.kind === 'text') {
              socket.send(message.data)
            } else {
              socket.send(Buffer.from(message.data, 'base64'))
            }
            return
          }
          case 'ws.close': {
            const close = frame as WsCloseFrame
            closed = true
            detach()
            try {
              socket.close(close.code >= 1000 && close.code < 5000 ? close.code : 1011, close.reason)
            } catch {
              socket.terminate()
            }
            return
          }
          default:
            return
        }
      },
      onTunnelLost: () => {
        closed = true
        try {
          socket.close(CLOSE_AGENT_OFFLINE, 'host offline')
        } catch {
          socket.terminate()
        }
      },
    })

    tunnel.send({ type: 'ws.open', sid, path, headers, clientId: session.clientId })

    socket.on('message', (raw, isBinary) => {
      if (closed) return
      if (isBinary) {
        tunnel.send({
          type: 'ws.message',
          sid,
          kind: 'binary',
          data: Buffer.from(raw as Buffer).toString('base64'),
        })
      } else {
        tunnel.send({ type: 'ws.message', sid, kind: 'text', data: raw.toString('utf8') })
      }
    })

    socket.on('close', (code, reason) => {
      if (closed) return
      closed = true
      detach()
      tunnel.send({ type: 'ws.close', sid, code, reason: reason.toString('utf8') })
    })

    socket.on('error', () => {
      if (closed) return
      closed = true
      detach()
      tunnel.send({ type: 'ws.close', sid, code: 1011, reason: 'client error' })
    })
  }

  const handleUpgrade = (request: IncomingMessage, socket: Duplex, head: Buffer): void => {
    const rawUrl = request.url ?? '/'
    const reject = (status: string): void => {
      socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`)
      socket.destroy()
    }

    if (!isSafeProxyPath(rawUrl)) {
      reject('400 Bad Request')
      return
    }
    const pathname = rawUrl.split('?')[0] ?? '/'

    /* agent tunnel attachment */
    if (pathname === RELAY_AGENT_PATH) {
      agentWss.handleUpgrade(request, socket, head, (ws) => {
        handleAgentSocket(ws, request)
      })
      return
    }

    /* browser socket into a proxied agent */
    // Same reasoning as the HTTP path: this is the last point at which the
    // browser's own markers are still its own. A WebSocket upgrade is not
    // covered by CORS, so the marker is the check that exists.
    if (normalizeHeaders(request.headers)['sec-fetch-site'] === 'cross-site') {
      reject('403 Forbidden')
      return
    }
    const session = resolveLiveSession(readSessionCookie(request.headers.cookie))
    if (session === undefined) {
      reject('401 Unauthorized')
      return
    }
    const target = parseAgentPath(rawUrl)
    if (target === null) {
      reject('404 Not Found')
      return
    }
    if (!isAllowedWebSocketPath(target.rest)) {
      reject('403 Forbidden')
      return
    }
    if (!scopeMayReach(session.agentId, target.agentId)) {
      reject('403 Forbidden')
      return
    }
    const tunnel = liveAuthorizedTunnel(target.agentId)
    if (tunnel === undefined) {
      reject('503 Service Unavailable')
      return
    }
    const headers = normalizeHeaders(request.headers)
    delete headers.cookie
    clientWss.handleUpgrade(request, socket, head, (ws) => {
      proxyClientSocket(ws, tunnel, session, target.rest, headers)
    })
  }

  /* ───────────────────────────── lifecycle ──────────────────────────────── */

  const server = createServer((request, response) => {
    try {
      handleRequest(request, response)
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      log(`[relay] request failed: ${detail}`)
      if (!response.headersSent) {
        sendHtml(response, 500, renderErrorPage(500, '服务器内部错误 / Internal error'))
      } else if (!response.writableEnded) {
        response.end()
      }
    }
  })

  server.on('upgrade', (request, socket, head) => {
    try {
      handleUpgrade(request, socket as Duplex, head)
    } catch {
      socket.destroy()
    }
  })

  // Liveness: ping every attached agent, evict the ones that stopped answering.
  const heartbeat = setInterval(() => {
    tunnels.evictStale()
    for (const tunnel of tunnels.list()) {
      tunnel.send({ type: 'ping', nonce: randomUUID() })
    }
  }, HEARTBEAT_INTERVAL_MS)
  heartbeat.unref()

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(options.port, options.host, () => {
      server.removeListener('error', reject)
      resolve()
    })
  })

  const address = server.address()
  const port = typeof address === 'object' && address !== null ? address.port : options.port

  const close = async (): Promise<void> => {
    clearInterval(heartbeat)
    tunnels.closeAll(CLOSE_AGENT_OFFLINE, 'relay shutting down')
    sessions.clear()
    agentWss.close()
    clientWss.close()
    await new Promise<void>((resolve) => {
      server.closeAllConnections()
      server.close(() => {
        resolve()
      })
    })
  }

  return { server, port, close, store, tunnels, sessions }
}
