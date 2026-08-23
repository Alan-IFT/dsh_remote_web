/**
 * The outbound tunnel: the host half of the remote-access path.
 *
 * It dials the relay over WebSocket, proves possession of the agent token, and
 * then serves whatever the relay forwards by re-issuing each request against
 * the local DSH server on loopback.
 *
 * The direction of the connection is the whole point. Because the host dials
 * out, the machine running DSH needs no inbound port, no router configuration,
 * and no public address — which is what makes this work from a home network,
 * a corporate LAN, or a laptop on hotel Wi-Fi.
 *
 * @module dsh-remote-web/plugin/tunnel
 */

import { request as httpRequest, type ClientRequest, type IncomingMessage } from 'node:http'
import { randomBytes } from 'node:crypto'

import WebSocket from 'ws'

import {
  CLOSE_AUTH_FAILED,
  CLOSE_E2E_REQUIRED,
  CLOSE_REVOKED,
  CLOSE_UNSUPPORTED_VERSION,
  HEARTBEAT_TIMEOUT_MS,
  MAX_BODY_CHUNK_BYTES,
  MAX_CONTROL_FRAME_BYTES,
  MAX_REQUEST_BODY_BYTES,
  MAX_WS_MESSAGE_BYTES,
  PROTOCOL_VERSION,
  RELAY_AGENT_PATH,
  E2E_ENVELOPE_HEADER,
  E2E_ID_HEADER,
  E2E_KEY_PARAM,
  agentChallenge,
  parseFrame,
  type HttpRequestFrame,
  type SealedEnvelope,
  type TunnelFrame,
  type WsOpenFrame,
} from '../shared/protocol.js'
import { fingerprint, hashToken } from '../shared/auth.js'
import {
  deriveSessionKey,
  generateEphemeralKeyPair,
  open as openSealed,
  seal,
  signMessage,
} from '../shared/crypto.js'
import {
  isAllowedWebSocketPath,
  isSafeProxyPath,
  readEnvelopeHeader,
  rewriteRequestHeaders,
  rewriteResponseHeaders,
} from '../shared/headers.js'
import type { AgentCredentials, ResolvedPluginConfig } from './config.js'

/** Observable state of the tunnel, surfaced to the status route and the CLI. */
export type TunnelState =
  | 'disabled'
  | 'connecting'
  | 'online'
  | 'retrying'
  | 'refused'

/** Snapshot for the status view. */
export interface TunnelStatus {
  state: TunnelState
  relayUrl: string | null
  agentId: string | null
  label: string | null
  /** Short fingerprint of the loaded token; never the token itself. */
  tokenFingerprint: string
  /** Populated when the relay refused us permanently. */
  lastError: string | null
  connectedAt: number | null
  /** Requests currently in flight through the tunnel. */
  activeRequests: number
  activeSockets: number
}

/** Close codes after which retrying is pointless until the operator acts. */
const TERMINAL_CLOSE_CODES = new Set([
  CLOSE_AUTH_FAILED,
  CLOSE_UNSUPPORTED_VERSION,
  CLOSE_E2E_REQUIRED,
  CLOSE_REVOKED,
])

/** Logger shape accepted from the cordis context. */
export interface TunnelLogger {
  info: (message: string) => void
  warn: (message: string) => void
}

/**
 * Manages one outbound tunnel, including reconnection.
 *
 * Lifecycle: {@link start} begins dialing and keeps redialing with exponential
 * backoff until {@link stop}, or until the relay refuses us in a way that
 * cannot be fixed by retrying (bad token, revoked agent, protocol mismatch).
 */
export class TunnelClient {
  readonly #credentials: AgentCredentials
  readonly #config: ResolvedPluginConfig
  readonly #log: TunnelLogger

  #socket: WebSocket | null = null
  #state: TunnelState = 'disabled'
  #stopped = true
  #retryDelay: number
  #retryTimer: NodeJS.Timeout | null = null
  #livenessTimer: NodeJS.Timeout | null = null
  #connectedAt: number | null = null
  #lastError: string | null = null

  /**
   * In-flight loopback requests, keyed by the relay's request id.
   *
   * The received-byte count lives on the entry rather than in a parallel map:
   * the two share a key and a lifetime, and keeping them apart meant every
   * cleanup path had to remember to delete twice — five such pairs, where one
   * missed line would have leaked.
   */
  readonly #requests = new Map<string, { upstream: ClientRequest; received: number }>()
  /** Proxied sockets to the local DSH server, keyed by the relay's socket id. */
  readonly #sockets = new Map<string, WebSocket>()
  /**
   * Session key per exchange, present only for end-to-end encrypted requests.
   *
   * Derived from the browser's ephemeral public key and this machine's
   * encryption token, so the relay — which has neither — cannot reconstruct it
   * even though it carried the handshake.
   */
  /**
   * Encryption state per encrypted context, keyed by exchange id or socket id.
   *
   * One table serves both planes because they need the same two things: the
   * session key, and the value that key's payloads are authenticated against.
   * Only the AAD differs — an HTTP exchange binds to its request id, a stream
   * binds to its path — and that difference is data, not structure.
   */
  readonly #contexts = new Map<string, { key: Buffer; aad: string }>()

  /**
   * This host's ephemeral X25519 keypair for the lifetime of the client.
   *
   * Browsers combine their own ephemeral key with this one and the shared
   * encryption token, so the relay carrying both public keys still derives
   * nothing.
   */
  readonly #ephemeral = generateEphemeralKeyPair()

  constructor(
    credentials: AgentCredentials,
    config: ResolvedPluginConfig,
    log: TunnelLogger,
  ) {
    this.#credentials = credentials
    this.#config = config
    this.#log = log
    this.#retryDelay = config.initialRetryMs
  }

  /**
   * This host's ephemeral public key.
   *
   * A browser needs it to derive the session key. It is public by design: on
   * its own it yields nothing, because deriving the key also requires the
   * encryption token, which the relay never receives.
   */
  get publicKey(): string {
    return this.#ephemeral.publicKey
  }

  /**
   * Serve one sealed exchange directly, bypassing the relay socket.
   *
   * Exposed so tests can drive the real decrypt → proxy → encrypt path against
   * a live local server without standing up a browser. It uses exactly the
   * production code path; nothing here is a test-only shortcut.
   */
  async handleSealedRequestForTest(
    rid: string,
    envelope: SealedEnvelope,
  ): Promise<{ status: number; bodyEnvelope: SealedEnvelope }> {
    return await this.#captureExchange(rid, () => {
      this.#openLocalRequest({
        type: 'http.request',
        rid,
        method: 'GET',
        path: '/',
        // Exercised through the same header carrier production uses, so the
        // seam cannot pass while the real path is broken.
        headers: {
          [E2E_ID_HEADER]: rid,
          [E2E_ENVELOPE_HEADER]: Buffer.from(JSON.stringify(envelope), 'utf8').toString('base64url'),
        },
        noBody: true,
        clientId: 'test',
      })
    })
  }

  /** Serve one unencrypted exchange directly; see {@link handleSealedRequestForTest}. */
  async handlePlainRequestForTest(
    rid: string,
    path: string,
  ): Promise<{ status: number; body: string }> {
    const captured = await this.#captureExchange(rid, () => {
      this.#openLocalRequest({
        type: 'http.request',
        rid,
        method: 'GET',
        path,
        headers: {},
        noBody: true,
        clientId: 'test',
      })
    })
    return { status: captured.status, body: captured.plainBody }
  }

  /**
   * Intercept the frames one exchange would have sent to the relay.
   *
   * The interception point is `#send`, so the frames observed are byte-for-byte
   * the ones a relay would receive — which is what makes the confidentiality
   * assertions meaningful.
   */
  async #captureExchange(
    rid: string,
    start: () => void,
  ): Promise<{ status: number; bodyEnvelope: SealedEnvelope; plainBody: string }> {
    const original = this.#testSink
    return await new Promise((resolve) => {
      let status = 0
      let bodyEnvelope: SealedEnvelope = { epk: '', salt: '', n: '', c: '', t: '' }
      let plainBody = ''
      this.#testSink = (frame) => {
        if (frame.type === 'http.response' && frame.rid === rid) status = frame.status
        if (frame.type === 'body.chunk' && frame.rid === rid) {
          if (frame.sealed !== undefined) bodyEnvelope = frame.sealed
          else plainBody += Buffer.from(frame.data, 'base64').toString('utf8')
        }
        if (frame.type === 'body.end' && frame.rid === rid) {
          this.#testSink = original
          resolve({ status, bodyEnvelope, plainBody })
        }
      }
      start()
    })
  }

  /** Optional frame interceptor used by the test seams above. */
  #testSink: ((frame: TunnelFrame) => void) | null = null

  /** Current status snapshot. */
  status(): TunnelStatus {
    return {
      state: this.#state,
      relayUrl: this.#credentials.relayUrl,
      agentId: this.#credentials.agentId,
      label: this.#credentials.label,
      tokenFingerprint: fingerprint(hashToken(this.#credentials.encryptionToken)),
      lastError: this.#lastError,
      connectedAt: this.#connectedAt,
      activeRequests: this.#requests.size,
      activeSockets: this.#sockets.size,
    }
  }

  /** Begin connecting and keep the tunnel up until {@link stop}. */
  start(): void {
    if (!this.#stopped) return
    this.#stopped = false
    this.#lastError = null
    this.#connect()
  }

  /** Tear the tunnel down and cancel any pending reconnect. */
  stop(): void {
    this.#stopped = true
    this.#state = 'disabled'
    if (this.#retryTimer !== null) {
      clearTimeout(this.#retryTimer)
      this.#retryTimer = null
    }
    if (this.#livenessTimer !== null) {
      clearInterval(this.#livenessTimer)
      this.#livenessTimer = null
    }
    this.#teardownExchanges()
    const socket = this.#socket
    this.#socket = null
    if (socket !== null) {
      try {
        socket.close(1000, 'plugin shutting down')
      } catch {
        socket.terminate()
      }
    }
  }

  /** Abort every in-flight exchange; used on disconnect and shutdown. */
  #teardownExchanges(): void {
    for (const entry of this.#requests.values()) {
      entry.upstream.destroy()
    }
    this.#requests.clear()
    this.#contexts.clear()
    for (const socket of this.#sockets.values()) {
      try {
        socket.close(1001, 'tunnel closed')
      } catch {
        socket.terminate()
      }
    }
    this.#sockets.clear()
    
  }

  /** Absolute WebSocket URL of the relay's agent endpoint. */
  #relayWsUrl(): string {
    const url = new URL(this.#credentials.relayUrl)
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
    url.pathname = `${url.pathname.replace(/\/$/, '')}${RELAY_AGENT_PATH}`
    url.search = ''
    return url.toString()
  }

  #scheduleRetry(): void {
    if (this.#stopped) return
    this.#state = 'retrying'
    const jitter = Math.floor(Math.random() * 500)
    const delay = Math.min(this.#retryDelay, this.#config.maxRetryMs) + jitter
    this.#retryTimer = setTimeout(() => {
      this.#retryTimer = null
      this.#connect()
    }, delay)
    this.#retryTimer.unref?.()
    this.#retryDelay = Math.min(this.#retryDelay * 2, this.#config.maxRetryMs)
  }

  #connect(): void {
    if (this.#stopped) return
    this.#state = 'connecting'
    let socket: WebSocket
    try {
      socket = new WebSocket(this.#relayWsUrl(), {
        maxPayload: MAX_CONTROL_FRAME_BYTES,
        handshakeTimeout: 15_000,
      })
    } catch (error) {
      this.#lastError = error instanceof Error ? error.message : String(error)
      this.#scheduleRetry()
      return
    }
    this.#socket = socket

    socket.on('open', () => {
      // Sign a fresh challenge. The private key never leaves this machine, and
      // the relay holds only the public half — so the relay can admit us and
      // cannot become us.
      const ts = Date.now()
      const nonce = randomBytes(16).toString('hex')
      socket.send(
        JSON.stringify({
          type: 'hello',
          v: PROTOCOL_VERSION,
          agentId: this.#credentials.agentId,
          ts,
          nonce,
          signature: signMessage(
            agentChallenge(this.#credentials.agentId, ts, nonce),
            this.#credentials.privateKey,
          ),
          label: this.#credentials.label,
          agentVersion: '0.1.0',
          e2e: this.#credentials.requireE2e,
          epk: this.#ephemeral.publicKey,
        }),
      )
    })

    let lastFrameAt = Date.now()
    this.#livenessTimer = setInterval(() => {
      if (Date.now() - lastFrameAt > HEARTBEAT_TIMEOUT_MS) {
        this.#log.warn('[dsh-remote-web] relay went quiet; reconnecting')
        try {
          socket.close(1001, 'heartbeat timeout')
        } catch {
          socket.terminate()
        }
      }
    }, 15_000)
    this.#livenessTimer.unref?.()

    socket.on('message', (raw, isBinary) => {
      if (isBinary) return
      lastFrameAt = Date.now()
      const frame = parseFrame(raw.toString('utf8'))
      if (frame === null) return
      this.#handleFrame(socket, frame)
    })

    socket.on('close', (code, reason) => {
      if (this.#livenessTimer !== null) {
        clearInterval(this.#livenessTimer)
        this.#livenessTimer = null
      }
      this.#teardownExchanges()
      this.#connectedAt = null
      if (this.#socket === socket) this.#socket = null
      if (this.#stopped) return

      const detail = reason.toString('utf8')
      if (TERMINAL_CLOSE_CODES.has(code)) {
        this.#state = 'refused'
        this.#lastError = detail === '' ? `relay refused the tunnel (code ${String(code)})` : detail
        this.#log.warn(
          `[dsh-remote-web] relay refused this host: ${this.#lastError}. ` +
            'Run `dsh-remote-web setup` again to re-pair.',
        )
        return
      }
      this.#lastError = detail === '' ? `disconnected (code ${String(code)})` : detail
      this.#scheduleRetry()
    })

    socket.on('error', (error) => {
      this.#lastError = error.message
    })
  }

  #send(frame: TunnelFrame): void {
    if (this.#testSink !== null) {
      this.#testSink(frame)
      return
    }
    const socket = this.#socket
    if (socket === null || socket.readyState !== WebSocket.OPEN) return
    socket.send(JSON.stringify(frame))
  }

  #handleFrame(socket: WebSocket, frame: TunnelFrame): void {
    switch (frame.type) {
      case 'hello.ack': {
        this.#state = 'online'
        this.#connectedAt = Date.now()
        this.#retryDelay = this.#config.initialRetryMs
        this.#lastError = null
        this.#log.info(
          `[dsh-remote-web] tunnel online at ${this.#credentials.relayUrl} ` +
            `as "${this.#credentials.label}"`,
        )
        return
      }
      case 'ping': {
        this.#send({ type: 'pong', nonce: frame.nonce })
        return
      }
      case 'error': {
        this.#lastError = frame.message
        if (frame.fatal) {
          this.#state = 'refused'
          this.#log.warn(`[dsh-remote-web] relay error: ${frame.message}`)
          try {
            socket.close(1000, 'fatal relay error')
          } catch {
            socket.terminate()
          }
        }
        return
      }
      case 'http.request':
        this.#openLocalRequest(frame)
        return
      case 'body.chunk': {
        const entry = this.#requests.get(frame.rid)
        if (entry === undefined) return
        const buffer = Buffer.from(frame.data, 'base64')
        entry.received += buffer.length
        if (entry.received > MAX_REQUEST_BODY_BYTES) {
          this.#send({ type: 'abort', rid: frame.rid, reason: 'request body too large' })
          entry.upstream.destroy()
          this.#requests.delete(frame.rid)
          return
        }
        entry.upstream.write(buffer)
        return
      }
      case 'body.end': {
        // The entry stays: the body is complete, but the response is not.
        this.#requests.get(frame.rid)?.upstream.end()
        return
      }
      case 'abort': {
        const entry = this.#requests.get(frame.rid)
        if (entry !== undefined) {
          entry.upstream.destroy()
          this.#requests.delete(frame.rid)
        }
        return
      }
      case 'ws.open':
        this.#openLocalSocket(frame)
        return
      case 'ws.message': {
        const socketToLocal = this.#sockets.get(frame.sid)
        if (socketToLocal === undefined || socketToLocal.readyState !== WebSocket.OPEN) return
        if (frame.sealed !== undefined) {
          const opened = this.#openFor(frame.sid, frame.sealed)
          if (opened === null) return
          socketToLocal.send(opened)
          return
        }
        if (frame.kind === 'text') socketToLocal.send(frame.data)
        else socketToLocal.send(Buffer.from(frame.data, 'base64'))
        return
      }
      case 'ws.close': {
        const socketToLocal = this.#sockets.get(frame.sid)
        this.#sockets.delete(frame.sid)
        this.#contexts.delete(frame.sid)
        if (socketToLocal === undefined) return
        try {
          socketToLocal.close(
            frame.code >= 1000 && frame.code < 5000 ? frame.code : 1001,
            frame.reason,
          )
        } catch {
          socketToLocal.terminate()
        }
        return
      }
      default:
        return
    }
  }

  /**
   * Establish an encryption context from a peer's envelope, and open it.
   *
   * The counterpart to {@link #openFor}, which uses a context already
   * established. HTTP establishes one per request because each request carries
   * its own ephemeral key; a stream establishes one at open and reuses it. The
   * two planes differ in when this runs, not in what it does.
   *
   * @returns Plaintext, or `null` when authentication fails — covering a
   *          tampered payload, a wrong token, and a misdirected one alike.
   */
  #establishContext(envelope: SealedEnvelope, id: string): Buffer | null {
    try {
      const key = deriveSessionKey(
        this.#ephemeral.privateKey,
        envelope.epk,
        this.#credentials.encryptionToken,
      )
      const plaintext = openSealed({ n: envelope.n, c: envelope.c, t: envelope.t }, key, id)
      if (plaintext !== null) this.#contexts.set(id, { key, aad: id })
      return plaintext
    } catch {
      return null
    }
  }

  /**
   * Seal an outbound payload for whichever peer owns this context.
   *
   * @param id - Exchange id for an HTTP response, socket id for a stream frame.
   * @returns The envelope, or `null` when that context is not encrypted, which
   *          is how the plaintext path stays a single branch at each call site.
   */
  #sealFor(id: string, plaintext: Buffer): SealedEnvelope | null {
    const context = this.#contexts.get(id)
    if (context === undefined) return null
    const sealed = seal(plaintext, context.key, context.aad)
    return {
      epk: this.#ephemeral.publicKey,
      salt: '',
      n: sealed.n,
      c: sealed.c,
      t: sealed.t,
    }
  }

  /**
   * Open an inbound payload on an established context.
   *
   * @returns Plaintext, or `null` when authentication fails — covering a
   *          tampered frame, a wrong token, and a frame moved to another
   *          context alike.
   */
  #openFor(id: string, envelope: SealedEnvelope): Buffer | null {
    const context = this.#contexts.get(id)
    if (context === undefined) return null
    return openSealed({ n: envelope.n, c: envelope.c, t: envelope.t }, context.key, context.aad)
  }

  /** Answer an exchange with a plain status and no upstream call. */
  #refuse(rid: string, status: number, reason: string): void {
    this.#send({
      type: 'http.response',
      rid,
      status,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    })
    this.#send({
      type: 'body.chunk',
      rid,
      data: Buffer.from(reason, 'utf8').toString('base64'),
    })
    this.#send({ type: 'body.end', rid })
    this.#contexts.delete(rid)
  }

  /**
   * Re-issue a forwarded request against the local DSH server.
   *
   * The request is rebuilt rather than replayed: headers are rewritten so DSH
   * sees a loopback, same-origin request (see `shared/headers.ts` for why that
   * is safe), and the response is streamed back in bounded chunks.
   */
  #openLocalRequest(frame: HttpRequestFrame): void {
    if (!isSafeProxyPath(frame.path)) {
      this.#send({ type: 'abort', rid: frame.rid, reason: 'invalid path' })
      return
    }

    // End-to-end layer. The envelope arrives either as a frame field or in the
    // browser's own headers, which the relay forwards verbatim without needing
    // to understand them.
    const sealed = readEnvelopeHeader(frame.headers)
    const rid = frame.headers[E2E_ID_HEADER] ?? frame.rid
    let request: { method: string; path: string; headers: Record<string, string> }
    if (sealed !== undefined) {
      const opened = this.#establishContext(sealed, rid)
      if (opened === null) {
        this.#refuse(frame.rid, 403, 'end-to-end decryption failed')
        return
      }
      try {
        request = JSON.parse(opened.toString('utf8')) as typeof request
      } catch {
        this.#refuse(frame.rid, 400, 'malformed encrypted request')
        return
      }
      if (!isSafeProxyPath(request.path)) {
        this.#refuse(frame.rid, 400, 'invalid path')
        return
      }
      // Responses must seal under the id the browser will verify against,
      // which is its own — not the one the relay assigned.
      const opened2 = this.#contexts.get(rid)
      if (opened2 !== undefined) this.#contexts.set(frame.rid, opened2)
    } else if (this.#credentials.requireE2e) {
      // A relay that stripped the envelope would downgrade the session to
      // something it can read; refusing is the whole point of requiring E2E.
      this.#refuse(frame.rid, 403, 'this host requires end-to-end encryption')
      return
    } else {
      request = { method: frame.method, path: frame.path, headers: frame.headers }
    }

    // Presented as the named remote authority, so DSH refuses its privileged
    // plane on its own terms rather than ours.
    const headers = rewriteRequestHeaders(request.headers)

    const upstream = httpRequest(
      {
        host: this.#config.localHost,
        port: this.#config.localPort,
        method: request.method,
        path: request.path,
        headers,
      },
      (response: IncomingMessage) => {
        const responseHeaders = rewriteResponseHeaders(response.headers)
        const sealedHead = this.#sealFor(
          frame.rid,
          Buffer.from(JSON.stringify(responseHeaders), 'utf8'),
        )
        this.#send({
          type: 'http.response',
          rid: frame.rid,
          status: response.statusCode ?? 502,
          // Headers move inside the envelope when encrypted; the relay sees an
          // empty map rather than the response metadata.
          headers: sealedHead === null ? responseHeaders : {},
          ...(sealedHead === null ? {} : { sealed: sealedHead }),
        })
        const isHtml = (responseHeaders['content-type'] ?? '').includes('text/html')
        response.on('data', (rawChunk: Buffer) => {
          // Inject the resume shim into the app shell so the page re-arms
          // encryption after the login redirect. Done here rather than at the
          // relay because the host already owns this response and knows its own
          // public key, so no buffering proxy layer is needed.
          const chunk =
            isHtml && this.#contexts.has(frame.rid)
              ? Buffer.from(
                  rawChunk
                    .toString('utf8')
                    .replace(
                      '<head>',
                      `<head><script src="/__e2e/client.js"></script><script>` +
                        `window.__dshRemoteWebE2E__&&window.__dshRemoteWebE2E__.resume(` +
                        `${JSON.stringify(this.#ephemeral.publicKey)});</script>`,
                    ),
                  'utf8',
                )
              : rawChunk
          for (let offset = 0; offset < chunk.length; offset += MAX_BODY_CHUNK_BYTES) {
            const slice = chunk.subarray(offset, offset + MAX_BODY_CHUNK_BYTES)
            const sealed = this.#sealFor(frame.rid, slice)
            this.#send(
              sealed === null
                ? { type: 'body.chunk', rid: frame.rid, data: slice.toString('base64') }
                : { type: 'body.chunk', rid: frame.rid, data: '', sealed },
            )
          }
        })
        response.on('end', () => {
          this.#send({ type: 'body.end', rid: frame.rid })
          this.#requests.delete(frame.rid)
          this.#contexts.delete(frame.rid)
        })
        response.on('error', () => {
          this.#send({ type: 'abort', rid: frame.rid, reason: 'upstream read failed' })
          this.#requests.delete(frame.rid)
        })
      },
    )

    upstream.on('error', (error) => {
      this.#send({ type: 'abort', rid: frame.rid, reason: error.message })
      this.#requests.delete(frame.rid)
    })

    this.#requests.set(frame.rid, { upstream, received: 0 })
    if (frame.noBody) upstream.end()
  }

  /**
   * Open a WebSocket against the local DSH server for a proxied browser socket.
   *
   * The path allowlist is enforced here as well as on the relay: the host must
   * not depend on a remote party's checks for what it exposes locally.
   */
  #openLocalSocket(frame: WsOpenFrame): void {
    if (!isAllowedWebSocketPath(frame.path)) {
      this.#send({ type: 'ws.close', sid: frame.sid, code: 1008, reason: 'path not allowed' })
      return
    }
    // A browser cannot set headers on a WebSocket handshake, so the stream's
    // ephemeral public key rides the query string — which carries nothing
    // secret and which the relay already forwards verbatim. The path used for
    // authentication excludes it, so both ends agree without the relay's help.
    const [streamPath = frame.path, query = ''] = frame.path.split('?')
    const browserKey = new URLSearchParams(query).get(E2E_KEY_PARAM)
    if (browserKey !== null && browserKey !== '') {
      try {
        this.#contexts.set(frame.sid, {
          key: deriveSessionKey(
            this.#ephemeral.privateKey,
            browserKey,
            this.#credentials.encryptionToken,
          ),
          aad: streamPath,
        })
      } catch {
        this.#send({ type: 'ws.close', sid: frame.sid, code: 1008, reason: 'bad key exchange' })
        return
      }
    } else if (this.#credentials.requireE2e) {
      // Refusing loudly matters: a relay that stripped the envelope would
      // otherwise get a readable event stream, which is the whole exposure.
      this.#send({
        type: 'ws.close',
        sid: frame.sid,
        code: CLOSE_E2E_REQUIRED,
        reason: 'this host requires end-to-end encryption',
      })
      return
    }

    const authority = `${this.#config.localHost}:${String(this.#config.localPort)}`
    const headers = rewriteRequestHeaders(frame.headers)
    // `ws` sets its own handshake headers; leaving copies here would duplicate them.
    delete headers.connection
    delete headers.upgrade

    let local: WebSocket
    try {
      local = new WebSocket(`ws://${authority}${frame.path}`, {
        headers,
        maxPayload: MAX_WS_MESSAGE_BYTES,
        handshakeTimeout: 15_000,
      })
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      this.#send({ type: 'ws.close', sid: frame.sid, code: 1011, reason: detail })
      return
    }
    this.#sockets.set(frame.sid, local)

    local.on('open', () => {
      this.#send({ type: 'ws.open.ack', sid: frame.sid })
    })
    local.on('message', (raw, isBinary) => {
      const kind = isBinary ? 'binary' : 'text'
      const bytes = isBinary ? Buffer.from(raw as Buffer) : Buffer.from(raw.toString('utf8'), 'utf8')
      // This is where the assistant's reply text leaves the machine, so it is
      // sealed whenever the browser opened the stream encrypted.
      const sealed = this.#sealFor(frame.sid, bytes)
      this.#send(
        sealed === null
          ? { type: 'ws.message', sid: frame.sid, kind, data: bytes.toString(isBinary ? 'base64' : 'utf8') }
          : { type: 'ws.message', sid: frame.sid, kind, data: '', sealed },
      )
    })
    local.on('close', (code, reason) => {
      this.#sockets.delete(frame.sid)
      this.#contexts.delete(frame.sid)
      this.#send({
        type: 'ws.close',
        sid: frame.sid,
        code,
        reason: reason.toString('utf8'),
      })
    })
    local.on('error', (error) => {
      this.#sockets.delete(frame.sid)
      this.#contexts.delete(frame.sid)
      this.#send({ type: 'ws.close', sid: frame.sid, code: 1011, reason: error.message })
    })
  }
}
