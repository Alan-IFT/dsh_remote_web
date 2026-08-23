/**
 * Live tunnel registry on the relay.
 *
 * One entry per attached agent. Each entry owns the agent's WebSocket plus the
 * set of in-flight exchanges (HTTP requests and proxied sockets) that browsers
 * have routed through it, so dropping an agent tears down exactly the work
 * that depended on it and nothing else.
 *
 * @module dsh-remote-web/relay/tunnels
 */

import type { WebSocket } from 'ws'

import {
  CLOSE_AGENT_OFFLINE,
  HEARTBEAT_TIMEOUT_MS,
  type TunnelFrame,
} from '../shared/protocol.js'

/** Callbacks a pending HTTP exchange registers with its tunnel. */
export interface PendingExchange {
  /** Frames arriving from the agent for this exchange. */
  onFrame: (frame: TunnelFrame) => void
  /** Called when the tunnel dies before the exchange completed. */
  onTunnelLost: () => void
}

/** An agent currently attached to the relay. */
export class Tunnel {
  readonly agentId: string
  readonly tunnelId: string
  readonly label: string
  readonly socket: WebSocket
  readonly connectedAt = Date.now()
  /** Last time we saw any frame from the agent; drives liveness eviction. */
  lastSeenAt = Date.now()

  /** In-flight exchanges keyed by request id or socket id. */
  readonly #exchanges = new Map<string, PendingExchange>()

  constructor(agentId: string, tunnelId: string, label: string, socket: WebSocket) {
    this.agentId = agentId
    this.tunnelId = tunnelId
    this.label = label
    this.socket = socket
  }

  /** Number of exchanges currently routed through this tunnel. */
  get activeExchanges(): number {
    return this.#exchanges.size
  }

  /**
   * Register an exchange so agent frames carrying `id` reach it.
   *
   * @returns A disposer that unregisters the exchange.
   */
  attach(id: string, exchange: PendingExchange): () => void {
    this.#exchanges.set(id, exchange)
    return () => {
      this.#exchanges.delete(id)
    }
  }

  /** Route one agent frame to its exchange, if still registered. */
  dispatch(id: string, frame: TunnelFrame): void {
    this.#exchanges.get(id)?.onFrame(frame)
  }

  /**
   * Send a frame to the agent.
   *
   * @returns True when the frame was handed to the socket.
   */
  send(frame: TunnelFrame): boolean {
    if (this.socket.readyState !== this.socket.OPEN) return false
    this.socket.send(JSON.stringify(frame))
    return true
  }

  /** Notify every exchange that the tunnel is gone, then clear the table. */
  failAll(): void {
    for (const exchange of [...this.#exchanges.values()]) {
      try {
        exchange.onTunnelLost()
      } catch {
        // One failing consumer must not prevent the rest from being cleaned up.
      }
    }
    this.#exchanges.clear()
  }
}

/**
 * Registry of attached agents.
 *
 * At most one tunnel per agent id: a second attachment for the same agent
 * replaces the first, because the common cause is a host that reconnected
 * after a network change while the relay has not yet noticed the dead socket.
 */
export class TunnelRegistry {
  readonly #byAgent = new Map<string, Tunnel>()

  /** Live tunnel for an agent, if attached. */
  get(agentId: string): Tunnel | undefined {
    return this.#byAgent.get(agentId)
  }

  /** Every attached tunnel. */
  list(): readonly Tunnel[] {
    return [...this.#byAgent.values()]
  }

  /**
   * Attach a tunnel, displacing any existing one for the same agent.
   *
   * @returns The displaced tunnel, so the caller can close it with the right
   *          code after its exchanges have been failed.
   */
  add(tunnel: Tunnel): Tunnel | undefined {
    const previous = this.#byAgent.get(tunnel.agentId)
    this.#byAgent.set(tunnel.agentId, tunnel)
    if (previous !== undefined) previous.failAll()
    return previous
  }

  /**
   * Detach a tunnel if it is still the registered one.
   *
   * The identity check matters during replacement: the displaced tunnel's
   * close event fires *after* the new one registered, and must not evict it.
   */
  remove(tunnel: Tunnel): void {
    if (this.#byAgent.get(tunnel.agentId) === tunnel) {
      this.#byAgent.delete(tunnel.agentId)
    }
    tunnel.failAll()
  }

  /**
   * Close tunnels that have not produced a frame within the liveness window.
   *
   * @returns The number of tunnels evicted.
   */
  evictStale(now: number = Date.now(), timeoutMs: number = HEARTBEAT_TIMEOUT_MS): number {
    let evicted = 0
    for (const tunnel of [...this.#byAgent.values()]) {
      if (now - tunnel.lastSeenAt <= timeoutMs) continue
      this.remove(tunnel)
      try {
        tunnel.socket.close(CLOSE_AGENT_OFFLINE, 'heartbeat timeout')
      } catch {
        // The socket may already be destroyed; eviction is what mattered.
      }
      evicted += 1
    }
    return evicted
  }

  /** Close every tunnel; used on relay shutdown. */
  closeAll(code: number, reason: string): void {
    for (const tunnel of [...this.#byAgent.values()]) {
      this.remove(tunnel)
      try {
        tunnel.socket.close(code, reason)
      } catch {
        // Shutdown is best-effort per socket.
      }
    }
  }
}
