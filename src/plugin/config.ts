/**
 * Plugin state: the credential file the CLI writes, and the status file the
 * plugin publishes back.
 *
 * These two files are the entire interface between the running plugin and the
 * `dsh-remote-web` command. There is deliberately **no HTTP control endpoint**.
 *
 * That is a security decision, not a convenience one. The tunnel serves remote
 * requests by re-issuing them against local DSH from loopback, so any route on
 * that server looks local to the code handling it — a "loopback-only" control
 * route would in fact be reachable by every authenticated remote browser, and
 * closing that hole means maintaining a path blocklist on both sides of the
 * tunnel forever. Files carry OS permissions instead: `0600` under `$DSH_HOME`
 * is enforced by the kernel, cannot be reached through a proxied request at
 * all, and needs no code to defend.
 *
 * @module dsh-remote-web/plugin/config
 */

import { homedir } from 'node:os'
import { join } from 'node:path'

import { WatchedFile } from '../shared/watched-file.js'

/** Resolve `$DSH_HOME`, falling back to the documented default. */
export function dshHome(): string {
  return process.env.DSH_HOME ?? join(homedir(), '.dsh')
}

/** Directory holding this plugin's state. */
export function stateDir(): string {
  return join(dshHome(), 'remote-web')
}

/** Default path of the agent credential file. */
export function defaultCredentialPath(): string {
  return join(stateDir(), 'agent.json')
}

/** Path of the status file the running plugin publishes. */
export function statusPath(credentialPath: string): string {
  return credentialPath.replace(/agent\.json$/, 'status.json')
}

/**
 * Credentials written by `dsh-remote-web setup`.
 *
 * Two independent secrets, deliberately never combined:
 *
 * - `privateKey` answers "may this machine connect?" to the relay. It signs a
 *   challenge; the relay holds only the matching public key.
 * - `encryptionToken` answers "who may read this session?" and is shared only
 *   with browsers the operator authorizes. The relay never receives it, which
 *   is what makes the relay unable to read traffic it carries.
 */
export interface AgentCredentials {
  version: 1
  /** Base URL of the relay, e.g. `https://relay.example.com`. */
  relayUrl: string
  agentId: string
  /** Ed25519 private key, base64url. Never sent; only signs challenges. */
  privateKey: string
  /** Payload encryption token. Never sent to the relay in any form. */
  encryptionToken: string
  /** Label shown in the relay UI. */
  label: string
  /** Whether the tunnel should connect. `enable`/`disable` flip this. */
  enabled: boolean
  /**
   * Refuse to serve any request that did not arrive end-to-end encrypted.
   *
   * **Off by default, deliberately.** The cryptography and its wire format are
   * complete and tested on both sides, but the browser transport is not: the
   * relay does not yet carry a browser-sealed envelope on the HTTP plane, so
   * nothing a real browser sends can satisfy this check. Defaulting it on
   * would make a fresh install answer 403 to every request — a security
   * setting that only breaks the product protects nobody.
   *
   * Turn it on once a client that seals is in use. Until then the session is
   * protected by TLS to the relay, and the relay is trusted with plaintext —
   * which the README and SECURITY.md state plainly rather than implying
   * otherwise.
   */
  requireE2e: boolean
}

/** Validate parsed JSON as credentials. */
function parseCredentials(raw: unknown): AgentCredentials {
  const value = raw as AgentCredentials
  if (
    value?.version !== 1 ||
    typeof value.relayUrl !== 'string' ||
    typeof value.agentId !== 'string' ||
    typeof value.privateKey !== 'string' ||
    typeof value.encryptionToken !== 'string'
  ) {
    throw new Error('unrecognized credential shape')
  }
  return {
    version: 1,
    relayUrl: value.relayUrl,
    agentId: value.agentId,
    privateKey: value.privateKey,
    encryptionToken: value.encryptionToken,
    label: typeof value.label === 'string' ? value.label : value.agentId,
    enabled: value.enabled !== false,
    requireE2e: value.requireE2e === true,
  }
}

/**
 * Open the credential file.
 *
 * The returned handle re-reads on change, which is what lets `setup`,
 * `enable`, and `disable` take effect in a running DSH without an IPC channel.
 */
export function openCredentials(path: string): WatchedFile<AgentCredentials | null> {
  return new WatchedFile<AgentCredentials | null>(
    path,
    (raw) => parseCredentials(raw),
    () => null,
  )
}

/** Snapshot the plugin publishes for `dsh-remote-web status`. */
export interface StatusSnapshot {
  version: 1
  state: string
  relayUrl: string | null
  label: string | null
  /** Which local DSH this tunnel proxies, e.g. `127.0.0.1:3080`. */
  localTarget: string
  /** Short fingerprint of the loaded token; never the token itself. */
  tokenFingerprint: string | null
  lastError: string | null
  connectedAt: number | null
  activeRequests: number
  activeSockets: number
  /** When this snapshot was written, so a stale file is detectable. */
  updatedAt: number
  pid: number
}

/** Open the status file for reading or publishing. */
export function openStatus(path: string): WatchedFile<StatusSnapshot | null> {
  return new WatchedFile<StatusSnapshot | null>(
    path,
    (raw) => raw as StatusSnapshot,
    () => null,
  )
}

/** Resolved plugin settings after schema defaults are applied. */
export interface ResolvedPluginConfig {
  credentialPath: string
  /** Composition-level kill switch: `false` prevents any outbound connection. */
  enabled: boolean
  /** Local DSH authority the tunnel proxies to. */
  localHost: string
  localPort: number
  initialRetryMs: number
  maxRetryMs: number
}

/** Raw config as it may appear in `cordis.patch.yml`. */
export interface PluginConfigInput {
  credentialPath?: string
  enabled?: boolean
  localHost?: string
  localPort?: number
  initialRetryMs?: number
  maxRetryMs?: number
}

/**
 * Apply defaults to loader-supplied config.
 *
 * `0` and `''` are the schema's "unset" sentinels and are treated exactly like
 * an absent key, so a caller can pass the schema's own defaults through.
 */
export function resolvePluginConfig(input: PluginConfigInput = {}): ResolvedPluginConfig {
  let inferredPort = 3080
  let inferredHost = '127.0.0.1'
  const webUrl = process.env.DSH_WEB_URL
  if (webUrl !== undefined) {
    try {
      const parsed = new URL(webUrl)
      if (parsed.port !== '') inferredPort = Number.parseInt(parsed.port, 10)
      if (parsed.hostname !== '') inferredHost = parsed.hostname
    } catch {
      // Keep the defaults when the variable is malformed.
    }
  }
  const path = input.credentialPath
  const host = input.localHost
  const port = input.localPort
  return {
    credentialPath: path === undefined || path === '' ? defaultCredentialPath() : path,
    enabled: input.enabled !== false,
    localHost: host === undefined || host === '' ? inferredHost : host,
    localPort: port === undefined || port === 0 ? inferredPort : port,
    initialRetryMs: input.initialRetryMs ?? 1000,
    maxRetryMs: input.maxRetryMs ?? 60_000,
  }
}
