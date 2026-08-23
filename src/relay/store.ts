/**
 * Durable state for the relay: which machines may attach, and which browser
 * credentials may reach them.
 *
 * The store holds **no plaintext secrets** — tokens live as SHA-256 digests,
 * so a leaked state file permits enumeration and revocation, never
 * impersonation.
 *
 * Cross-process consistency is not this file's concern: {@link WatchedFile}
 * owns it, so every read here is current and every write is atomic. That is
 * why no method below remembers to reload anything.
 *
 * @module dsh-remote-web/relay/store
 */

import { randomUUID } from 'node:crypto'

import { fingerprint, generateToken, hashToken, safeEqual } from '../shared/auth.js'
import {
  generateAgentIdentity,
  generateEncryptionToken,
  verifySignature,
} from '../shared/crypto.js'
import { WatchedFile } from '../shared/watched-file.js'

/**
 * One machine authorized to attach to this relay.
 *
 * The relay stores a **public key**, not a secret. It can verify an agent's
 * signature and forge none, so reading this file does not grant the ability to
 * impersonate a machine — the property a stored digest failed to provide.
 */
export interface AgentRecord {
  agentId: string
  label: string
  /** Ed25519 public key, base64url. */
  publicKey: string
  createdAt: number
  lastSeenAt: number | null
  revoked: boolean
}

/** One browser credential permitted to reach an agent through this relay. */
export interface ClientRecord {
  clientId: string
  label: string
  /**
   * SHA-256 digest of the browser's access token.
   *
   * Retained for the login path where a browser posts its token over TLS. It
   * is a verifier, never an HMAC key: keying a proof with this value would make
   * the stored digest itself a usable credential, which is exactly the flaw
   * that removed digests from the agent path.
   */
  tokenHash: string
  /**
   * Ed25519 public key the browser registered, base64url.
   *
   * Present once the browser has enrolled a key. From then on it logs in by
   * signature, so the token never crosses the wire again — which is what makes
   * a plain-HTTP relay survivable.
   */
  publicKey?: string
  /** Agent this credential may reach; `'*'` means every registered agent. */
  agentId: string
  createdAt: number
  lastSeenAt: number | null
  expiresAt: number | null
  revoked: boolean
}

/** On-disk shape; `version` guards future migrations. */
interface StoreState {
  version: 1
  agents: AgentRecord[]
  clients: ClientRecord[]
}

/** Result of issuing a browser credential; the raw token is shown once. */
export interface IssuedCredential<T> {
  record: T
  /** Raw token — show it now; only its digest is ever stored. */
  token: string
}

/**
 * Result of registering an agent.
 *
 * Two independent secrets leave the relay here and are never retained by it:
 * the signing key proves identity, and the encryption token binds browser
 * credentials to this machine. The relay keeps only the public key, so it can
 * admit this agent without being able to impersonate it, and cannot mint a
 * working browser credential for it alone.
 *
 * It can still read the session: it terminates TLS. That is the trust the
 * design asks for, and `SECURITY.md` says so rather than implying otherwise.
 */
export interface IssuedAgent {
  record: AgentRecord
  /** Ed25519 private key for the agent. The relay does not store it. */
  privateKey: string
  /** Payload encryption token. The relay never sees this again. */
  encryptionToken: string
}

/** Validate parsed JSON as store state, rejecting anything unrecognized. */
function parseState(raw: unknown): StoreState {
  const state = raw as StoreState
  if (state?.version !== 1 || !Array.isArray(state.agents) || !Array.isArray(state.clients)) {
    throw new Error('unrecognized state shape')
  }
  return state
}

/** Whether a credential is currently usable. */
function isLive(record: { revoked: boolean; expiresAt?: number | null }, now: number): boolean {
  if (record.revoked) return false
  const expiry = record.expiresAt
  return expiry === undefined || expiry === null || expiry > now
}

/**
 * Relay credential store.
 *
 * Mutations write through immediately: the data set is small, and an operator
 * who kills the relay right after issuing a token must not lose it.
 */
export class RelayStore {
  readonly #file: WatchedFile<StoreState>

  /**
   * @param path - JSON state file; parent directories are created as needed.
   */
  constructor(path: string) {
    this.#file = new WatchedFile<StoreState>(path, parseState, () => ({
      version: 1,
      agents: [],
      clients: [],
    }))
  }

  /** Absolute path of the backing file. */
  get path(): string {
    return this.#file.path
  }

  /* ─────────────────────────────── agents ──────────────────────────────── */

  /** Every registered agent, including revoked ones. */
  listAgents(): readonly AgentRecord[] {
    return this.#file.value.agents
  }

  /**
   * Register a new agent and issue its token.
   *
   * @param label - Human-facing name for the machine.
   * @param agentId - Optional explicit id; generated when omitted.
   */
  createAgent(label: string, agentId?: string): IssuedAgent {
    // The signing key is generated here and the private half handed to the
    // operator once; the relay keeps only the public half.
    const identity = generateAgentIdentity()
    const encryptionToken = generateEncryptionToken()
    const record: AgentRecord = {
      agentId: agentId ?? randomUUID(),
      label,
      publicKey: identity.publicKey,
      createdAt: Date.now(),
      lastSeenAt: null,
      revoked: false,
    }
    this.#file.update((state) => {
      if (state.agents.some((agent) => agent.agentId === record.agentId)) {
        throw new Error(`agent "${record.agentId}" already exists`)
      }
      // A label is how every other command names this machine, so two live
      // agents sharing one is not a cosmetic clash: `resolveAgent` would find
      // two and answer neither, and `agent revoke <label>` would then report
      // nothing to revoke while both stayed connected. Refusing here is the
      // only place that keeps the ambiguity from ever existing.
      if (state.agents.some((agent) => !agent.revoked && agent.label === label)) {
        throw new Error(
          `an active agent is already named "${label}" — pick another name, ` +
            'or revoke that one first',
        )
      }
      return { next: { ...state, agents: [...state.agents, record] }, result: null }
    })
    return { record, privateKey: identity.privateKey, encryptionToken }
  }

  /**
   * Look up an agent by id, ignoring revoked entries.
   *
   * @returns The record, or `undefined` when absent or revoked.
   */
  findAgent(agentId: string): AgentRecord | undefined {
    const record = this.#file.value.agents.find((agent) => agent.agentId === agentId)
    return record !== undefined && !record.revoked ? record : undefined
  }

  /**
   * Find one agent by id or by label.
   *
   * Labels exist because a person names their machines; requiring them to copy
   * a UUID back out of `agent add` is friction the tool can absorb.
   *
   * A label names at most one live agent because {@link createAgent} refuses to
   * create a second, so this cannot be ambiguous. It once could, and returning
   * `undefined` for that case made two very different situations look alike:
   * `agent revoke <label>` reported nothing to revoke while both machines
   * stayed connected. The fix belongs at creation, not in every caller's error
   * message.
   *
   * @returns The match, or `undefined` when no live agent has that id or label.
   */
  resolveAgent(idOrLabel: string): AgentRecord | undefined {
    return (
      this.findAgent(idOrLabel) ??
      this.#file.value.agents.find((agent) => !agent.revoked && agent.label === idOrLabel)
    )
  }

  /**
   * Verify an agent's signature over a challenge.
   *
   * Revocation is checked first, so a revoked agent fails exactly like an
   * unknown one.
   */
  verifyAgentSignature(
    agentId: string,
    challenge: string,
    signature: string,
  ): AgentRecord | undefined {
    const record = this.findAgent(agentId)
    if (record === undefined) return undefined
    return verifySignature(challenge, signature, record.publicKey) ? record : undefined
  }

  /** Record that an agent was seen, for the status view. */
  touchAgent(agentId: string): void {
    this.#file.update((state) => ({
      next: {
        ...state,
        agents: state.agents.map((agent) =>
          agent.agentId === agentId ? { ...agent, lastSeenAt: Date.now() } : agent,
        ),
      },
      result: null,
    }))
  }

  /**
   * Revoke an agent: its token stops validating and the relay drops its tunnel.
   *
   * @returns True when an agent was revoked, false when unknown or already so.
   */
  revokeAgent(agentId: string): boolean {
    return this.#file.update((state) => {
      const target = state.agents.find((agent) => agent.agentId === agentId)
      if (target === undefined || target.revoked) return { next: state, result: false }
      return {
        next: {
          ...state,
          agents: state.agents.map((agent) =>
            agent.agentId === agentId ? { ...agent, revoked: true } : agent,
          ),
        },
        result: true,
      }
    })
  }

  /* ─────────────────────────────── clients ─────────────────────────────── */

  /** Every issued browser credential, including revoked ones. */
  listClients(): readonly ClientRecord[] {
    return this.#file.value.clients
  }

  /**
   * Issue a browser credential.
   *
   * @param label - Who it is for, e.g. `phone`.
   * @param agentId - Agent it may reach, or `'*'` for all.
   * @param ttlMs - Lifetime; `null` never expires.
   */
  createClient(label: string, agentId: string, ttlMs: number | null): IssuedCredential<ClientRecord> {
    const token = generateToken()
    const record: ClientRecord = {
      clientId: randomUUID(),
      label,
      tokenHash: hashToken(token),
      agentId,
      createdAt: Date.now(),
      lastSeenAt: null,
      expiresAt: ttlMs === null ? null : Date.now() + ttlMs,
      revoked: false,
    }
    this.#file.update((state) => ({
      next: { ...state, clients: [...state.clients, record] },
      result: null,
    }))
    return { record, token }
  }

  /**
   * Resolve a raw browser token to its credential.
   *
   * Every stored credential is examined so an unknown token costs the same as
   * a known one; revoked and expired records never match.
   */
  verifyClientToken(token: string, now: number = Date.now()): ClientRecord | undefined {
    const digest = hashToken(token)
    let matched: ClientRecord | undefined
    for (const record of this.#file.value.clients) {
      if (!isLive(record, now)) continue
      if (safeEqual(record.tokenHash, digest)) matched = record
    }
    return matched
  }

  /**
   * Look up a client credential that is still usable.
   *
   * The relay calls this on every authenticated request, which is what makes
   * revocation take effect immediately rather than at the next restart.
   */
  findLiveClient(clientId: string, now: number = Date.now()): ClientRecord | undefined {
    const record = this.#file.value.clients.find((client) => client.clientId === clientId)
    return record !== undefined && isLive(record, now) ? record : undefined
  }

  /**
   * Bind a browser's signing key to its credential, on first use.
   *
   * Enrollment happens once, over whatever channel carried the token. After
   * that the token is dormant: every later login is a signature, so a passive
   * observer on an unencrypted hop learns nothing reusable.
   *
   * A second enrollment for the same credential is refused — otherwise anyone
   * who observed the token could replace the key and take the credential over.
   *
   * @returns True when the key was bound, false when one already exists.
   */
  enrollClientKey(clientId: string, publicKey: string): boolean {
    return this.#file.update((state) => {
      const target = state.clients.find((client) => client.clientId === clientId)
      if (target === undefined || target.publicKey !== undefined) {
        return { next: state, result: false }
      }
      return {
        next: {
          ...state,
          clients: state.clients.map((client) =>
            client.clientId === clientId ? { ...client, publicKey } : client,
          ),
        },
        result: true,
      }
    })
  }

  /**
   * Resolve a browser that proved its identity by signature.
   *
   * @param challenge - The exact string the browser signed.
   * @param signature - Base64url Ed25519 signature.
   */
  verifyClientSignature(
    challenge: string,
    signature: string,
    now: number = Date.now(),
  ): ClientRecord | undefined {
    for (const record of this.#file.value.clients) {
      if (!isLive(record, now) || record.publicKey === undefined) continue
      if (verifySignature(challenge, signature, record.publicKey)) return record
    }
    return undefined
  }

  /** Record that a credential was used. */
  touchClient(clientId: string): void {
    this.#file.update((state) => ({
      next: {
        ...state,
        clients: state.clients.map((client) =>
          client.clientId === clientId ? { ...client, lastSeenAt: Date.now() } : client,
        ),
      },
      result: null,
    }))
  }

  /**
   * Revoke a browser credential by id or by token fingerprint.
   *
   * @returns True when a credential was revoked.
   */
  revokeClient(idOrFingerprint: string): boolean {
    return this.#file.update((state) => {
      const matches = (client: ClientRecord): boolean =>
        client.clientId === idOrFingerprint || fingerprint(client.tokenHash) === idOrFingerprint
      const target = state.clients.find(matches)
      if (target === undefined || target.revoked) return { next: state, result: false }
      return {
        next: {
          ...state,
          clients: state.clients.map((client) =>
            matches(client) ? { ...client, revoked: true } : client,
          ),
        },
        result: true,
      }
    })
  }
}

/**
 * Whether a credential scope authorizes reaching a given agent.
 *
 * @param scope - A credential's `agentId`: a specific id, or `'*'` for all.
 * @param agentId - The agent being reached.
 */
export function scopeMayReach(scope: string, agentId: string): boolean {
  return scope === '*' || scope === agentId
}
