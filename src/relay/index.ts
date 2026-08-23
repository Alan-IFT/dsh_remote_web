/**
 * Public entry of the relay component.
 *
 * The relay is published as part of this package so the same artifact an
 * operator installs on their DSH machine also runs on their own server; there
 * is no separate download and no version skew between the two halves.
 *
 * @module dsh-remote-web/relay
 */

export { startRelay, DEFAULT_RELAY_OPTIONS } from './server.js'
export type { RelayOptions, RunningRelay } from './server.js'
export { RelayStore, scopeMayReach } from './store.js'
export type { AgentRecord, ClientRecord, IssuedCredential } from './store.js'
export { SessionStore } from './sessions.js'
export { Tunnel, TunnelRegistry } from './tunnels.js'
