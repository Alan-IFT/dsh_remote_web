/**
 * DSH plugin entry: `dsh-remote-web`.
 *
 * Mounted into a DSH profile, it keeps an outbound tunnel to a self-hosted
 * relay so the local DSH web surface can be reached from anywhere.
 *
 * The plugin opens **no listening socket and registers no HTTP route**. Its
 * only inbound surface is the tunnel it dialed, and its only control surface
 * is the credential file on disk — see `plugin/config.ts` for why that is a
 * security property rather than a limitation.
 *
 * @module dsh-remote-web
 */

import Schema from '@deepseek-ai/schemastery'

import {
  openCredentials,
  openStatus,
  resolvePluginConfig,
  statusPath,
  type AgentCredentials,
  type PluginConfigInput,
} from './plugin/config.js'
import { TunnelClient, type TunnelLogger } from './plugin/tunnel.js'

/** Plugin name as it appears in the loader tree. */
export const name = 'dsh-remote-web'

/**
 * Services required before this plugin mounts.
 *
 * `webServer` is injected only to learn the port DSH actually bound — the one
 * value that stays correct under `--port`, port `0`, or a second DSH on the
 * same machine. No route is registered on it.
 */
export const inject = ['webServer']

/** Configuration schema surfaced to the loader and the settings UI. */
export const Config: Schema<PluginConfigInput> = Schema.object({
  enabled: Schema.boolean()
    .default(true)
    .description('Whether the outbound tunnel may connect at all.'),
  credentialPath: Schema.string()
    .default('')
    .description('Path to agent.json; empty uses $DSH_HOME/remote-web/agent.json.'),
  localHost: Schema.string()
    .default('')
    .description('Local DSH host to proxy; empty uses the bound host.'),
  localPort: Schema.number()
    .default(0)
    .description('Local DSH port to proxy; 0 uses the bound port.'),
  initialRetryMs: Schema.number().default(1000).description('Initial reconnect delay.'),
  maxRetryMs: Schema.number().default(60_000).description('Maximum reconnect delay.'),
}) as unknown as Schema<PluginConfigInput>

/** Minimal shape this plugin needs from the cordis context. */
interface PluginContext {
  webServer: {
    /** The port DSH is actually listening on (OS-assigned when configured 0). */
    port?: number
    /** The bind host DSH was configured with. */
    host?: string
  }
  effect: (setup: () => () => void, label?: string) => void
  logger?: { info: (message: string) => void; warn: (message: string) => void }
}

/** How often the plugin re-reads the credential file and publishes status. */
const POLL_INTERVAL_MS = 2000

/**
 * Mount the plugin.
 *
 * @param ctx - The cordis context, carrying `webServer` and effect ownership.
 * @param input - Loader-provided configuration.
 */
export function apply(ctx: PluginContext, input: PluginConfigInput = {}): void {
  // Where to proxy, in descending order of authority: explicit config, then
  // the port DSH actually bound, then DSH_WEB_URL. Reading the live service
  // matters — inferring from the environment once made a second DSH instance
  // tunnel to the *first* instance's port.
  const bound = ctx.webServer
  const boundPort = typeof bound.port === 'number' && bound.port > 0 ? bound.port : undefined
  // A server bound to 0.0.0.0 is still reachable on loopback, and loopback is
  // what DSH's own trust fence expects to see.
  const boundHost = bound.host === undefined || bound.host === '0.0.0.0' ? undefined : bound.host

  const config = resolvePluginConfig({
    ...input,
    localHost: input.localHost === undefined || input.localHost === '' ? boundHost : input.localHost,
    localPort: input.localPort === undefined || input.localPort === 0 ? boundPort : input.localPort,
  })

  const log: TunnelLogger = {
    info: (message) => ctx.logger?.info(message),
    warn: (message) => ctx.logger?.warn(message),
  }

  ctx.effect(() => {
    const credentials = openCredentials(config.credentialPath)
    const status = openStatus(statusPath(config.credentialPath))
    const target = `${config.localHost}:${String(config.localPort)}`

    let client: TunnelClient | null = null
    let signature = ''
    let announcedUnconfigured = false

    /** Values whose change requires rebuilding the tunnel. */
    const signatureOf = (current: AgentCredentials | null): string =>
      current === null || !current.enabled
        ? ''
        : [
            current.relayUrl,
            current.agentId,
            current.privateKey,
            current.encryptionToken,
          ].join('|')

    /**
     * Reconcile the running tunnel with the credential file.
     *
     * Polling the file is what replaces an IPC channel: `setup`, `enable`, and
     * `disable` simply write, and the next tick adopts the change.
     */
    const sync = (): void => {
      let current: AgentCredentials | null
      try {
        current = credentials.value
      } catch (error) {
        log.warn(error instanceof Error ? error.message : String(error))
        return
      }

      if (current === null && !announcedUnconfigured) {
        announcedUnconfigured = true
        log.info('[dsh-remote-web] not configured. Run `dsh-remote-web setup` on this machine.')
      }
      if (current !== null) announcedUnconfigured = false

      const next = config.enabled ? signatureOf(current) : ''
      if (next !== signature) {
        signature = next
        client?.stop()
        client = null
        if (next !== '' && current !== null) {
          client = new TunnelClient(current, config, log)
          client.start()
        } else if (current !== null && !current.enabled) {
          log.info('[dsh-remote-web] remote access is turned off')
        }
      }

      const snapshot = client?.status()
      status.write({
        version: 1,
        state: snapshot?.state ?? (current === null ? 'unconfigured' : 'disabled'),
        relayUrl: current?.relayUrl ?? null,
        label: current?.label ?? null,
        localTarget: target,
        tokenFingerprint: snapshot?.tokenFingerprint ?? null,
        lastError: snapshot?.lastError ?? null,
        connectedAt: snapshot?.connectedAt ?? null,
        activeRequests: snapshot?.activeRequests ?? 0,
        activeSockets: snapshot?.activeSockets ?? 0,
        updatedAt: Date.now(),
        pid: process.pid,
      })
    }

    sync()
    const timer = setInterval(sync, POLL_INTERVAL_MS)
    timer.unref?.()

    return () => {
      clearInterval(timer)
      client?.stop()
      client = null
    }
  }, 'dsh-remote-web: outbound tunnel')
}

export { TunnelClient } from './plugin/tunnel.js'
export type { TunnelStatus, TunnelState } from './plugin/tunnel.js'
export {
  openCredentials,
  openStatus,
  resolvePluginConfig,
  defaultCredentialPath,
  statusPath,
  stateDir,
  dshHome,
} from './plugin/config.js'
export type { AgentCredentials, StatusSnapshot } from './plugin/config.js'
