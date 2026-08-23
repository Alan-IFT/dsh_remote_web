/**
 * Wire protocol between the DSH host plugin (agent), the relay server, and
 * remote browsers.
 *
 * Design constraints that shape every frame below:
 *
 * - The host makes **outbound connections only**. It dials the relay over
 *   WebSocket and never listens on a public port, so the frames must be able
 *   to carry a full request/response cycle in the reverse direction.
 * - The relay is a **dumb pipe with an auth gate**. It matches a browser
 *   session to an agent tunnel and forwards bytes; it never interprets DSH
 *   API payloads.
 * - Everything is length-bounded. A remote peer must not be able to make the
 *   host or the relay allocate without limit.
 *
 * Frames are JSON text messages except HTTP/WebSocket payload bodies, which
 * ride as base64 inside the JSON envelope. Keeping one encoding avoids a
 * second framing layer over the WebSocket the relay already gives us.
 *
 * @module dsh-remote-web/shared/protocol
 */

/** Protocol version; a mismatch is refused at handshake time. */
export const PROTOCOL_VERSION = 1

/** Largest control frame accepted on either side (256 KiB). */
export const MAX_CONTROL_FRAME_BYTES = 256 * 1024

/** Largest single HTTP body chunk carried in one frame (512 KiB pre-base64). */
export const MAX_BODY_CHUNK_BYTES = 512 * 1024

/**
 * Largest aggregate request body the host will reassemble (160 MiB), matching
 * the DSH `/api` bridge bound so image prompts behave the same remotely.
 */
export const MAX_REQUEST_BODY_BYTES = 160 * 1024 * 1024

/** Largest WebSocket message proxied in either direction (8 MiB). */
export const MAX_WS_MESSAGE_BYTES = 8 * 1024 * 1024

/** Heartbeat interval and liveness deadline for the agent tunnel. */
export const HEARTBEAT_INTERVAL_MS = 25_000
export const HEARTBEAT_TIMEOUT_MS = 75_000

/** WebSocket close codes with agreed meaning across the three parties. */
export const CLOSE_AUTH_FAILED = 4001
export const CLOSE_AGENT_REPLACED = 4002
export const CLOSE_AGENT_OFFLINE = 4003
export const CLOSE_UNSUPPORTED_VERSION = 4004
export const CLOSE_RATE_LIMITED = 4005
export const CLOSE_REVOKED = 4006
// 4007 is retired. It meant "the peer required end-to-end encryption", a
// feature that was removed because the relay served the browser code that
// performed it. Older builds still treat 4007 as a permanent refusal, so a new
// code must not reuse the number.

/** Path on the relay where an agent (DSH host plugin) dials in. */
export const RELAY_AGENT_PATH = '/tunnel/v1/agent'

/* ────────────────────────────── agent → relay ────────────────────────────── */

/**
 * First frame an agent sends; the relay answers `hello.ack` or closes.
 *
 * Authentication is a **signature**, not a shared secret. The relay stores only
 * the agent's public key, so its state file lets it verify this frame and forge
 * nothing — reading the relay's disk does not yield the ability to impersonate
 * an agent.
 */
export interface AgentHelloFrame {
  type: 'hello'
  v: number
  /** Stable id of this agent installation, chosen at pairing time. */
  agentId: string
  /** Freshness values the signature covers. */
  ts: number
  nonce: string
  /** Ed25519 signature over the challenge string; see `agentChallenge`. */
  signature: string
  /** Human-facing label shown in the relay UI, e.g. the machine hostname. */
  label: string
  /** Version of the plugin, for diagnostics only. */
  agentVersion: string
}

/**
 * The exact string an agent signs to prove its identity.
 *
 * Every field that scopes the proof is inside it: the purpose (so an agent
 * signature is useless elsewhere), the agent id (so it speaks for one machine),
 * and the freshness pair (so a captured signature expires and cannot repeat).
 */
export function agentChallenge(agentId: string, ts: number, nonce: string): string {
  return `${AGENT_AUTH_PURPOSE}|${agentId}|${String(ts)}|${nonce}`
}

/** Relay accepted the agent and published it as online. */
export interface HelloAckFrame {
  type: 'hello.ack'
  v: number
  /** Server-assigned id for this tunnel attachment. */
  tunnelId: string
  heartbeatIntervalMs: number
  maxControlFrameBytes: number
  maxBodyChunkBytes: number
  relayVersion: string
}

/* ─────────────────────── relay → agent: HTTP forwarding ───────────────────── */

/**
 * A browser request the relay forwards to the host. `bodyChunk`/`bodyEnd`
 * frames follow when the request carries a body.
 */
export interface HttpRequestFrame {
  type: 'http.request'
  /** Correlates every frame of one request/response exchange. */
  rid: string
  method: string
  /** Path plus query, always root-relative. */
  path: string
  headers: Record<string, string>
  /** True when the request has no body at all. */
  noBody: boolean
  /** Identity of the browser session that issued it, for host-side auditing. */
  clientId: string
}

/** One chunk of a request or response body. */
export interface BodyChunkFrame {
  type: 'body.chunk'
  rid: string
  /** base64 of at most {@link MAX_BODY_CHUNK_BYTES} raw bytes. */
  data: string
}

/** Terminates a request or response body stream. */
export interface BodyEndFrame {
  type: 'body.end'
  rid: string
}

/** The peer aborted the exchange; the other side should stop and clean up. */
export interface AbortFrame {
  type: 'abort'
  rid: string
  reason: string
}

/* ─────────────────────── agent → relay: HTTP responses ───────────────────── */

/** Response head; `body.chunk`/`body.end` frames follow. */
export interface HttpResponseFrame {
  type: 'http.response'
  rid: string
  status: number
  headers: Record<string, string>
}

/* ──────────────────── WebSocket proxying (both directions) ───────────────── */

/** Relay asks the host to open a WebSocket against the local DSH server. */
export interface WsOpenFrame {
  type: 'ws.open'
  /** Correlates every frame of one proxied socket. */
  sid: string
  path: string
  headers: Record<string, string>
  clientId: string
}

/** Host reports the upstream socket opened (or failed, via `ws.close`). */
export interface WsOpenAckFrame {
  type: 'ws.open.ack'
  sid: string
}

/** One WebSocket message in either direction. */
export interface WsMessageFrame {
  type: 'ws.message'
  sid: string
  /** `text` carries UTF-8 in `data`; `binary` carries base64 in `data`. */
  kind: 'text' | 'binary'
  data: string
}

/** Either side closing a proxied socket. */
export interface WsCloseFrame {
  type: 'ws.close'
  sid: string
  code: number
  reason: string
}

/* ─────────────────────────────── liveness ────────────────────────────────── */

export interface PingFrame {
  type: 'ping'
  nonce: string
}

export interface PongFrame {
  type: 'pong'
  nonce: string
}

/** Relay-originated fatal notice; the agent should stop retrying when `fatal`. */
export interface ErrorFrame {
  type: 'error'
  code: string
  message: string
  fatal: boolean
}

/** Any frame legal on the agent tunnel. */
export type TunnelFrame =
  | AgentHelloFrame
  | HelloAckFrame
  | HttpRequestFrame
  | HttpResponseFrame
  | BodyChunkFrame
  | BodyEndFrame
  | AbortFrame
  | WsOpenFrame
  | WsOpenAckFrame
  | WsMessageFrame
  | WsCloseFrame
  | PingFrame
  | PongFrame
  | ErrorFrame

/* ────────────────────────────── authentication ───────────────────────────── */

/**
 * Domain-separation label folded into an agent's signed challenge, so a
 * signature made here can never validate in another context.
 */
export const AGENT_AUTH_PURPOSE = 'dsh-remote-web/agent'

/** Maximum clock skew tolerated when verifying a proof (±2 minutes). */
export const AUTH_PROOF_SKEW_MS = 2 * 60 * 1000

/* ──────────────────────────────── guards ─────────────────────────────────── */

/** Narrow untrusted JSON to a tunnel frame with a `type` string. */
export function isTunnelFrame(value: unknown): value is TunnelFrame {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { type?: unknown }).type === 'string'
  )
}

/**
 * Parse a text frame, enforcing the size bound before `JSON.parse` so a hostile
 * peer cannot force a large allocation.
 *
 * @returns The decoded frame, or `null` when oversized or malformed.
 */
export function parseFrame(raw: string): TunnelFrame | null {
  if (raw.length > MAX_CONTROL_FRAME_BYTES) return null
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return null
  }
  return isTunnelFrame(parsed) ? parsed : null
}
