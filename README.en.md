<h1 align="center">DSH Remote Web</h1>

<p align="center">Reach the DeepSeek Harness on your computer from any browser, through a relay you host yourself, behind a token.</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#security-model">Security model</a> ·
  <a href="#hosting-the-relay">Hosting the relay</a> ·
  <a href="README.md">中文</a>
</p>

---

`dsh-remote-web` is a DeepSeek Harness plugin. Once installed, the DSH on your computer dials **outbound** to a relay server you run. From anywhere else, open a browser, present your token, and continue in the same sessions, workspaces, and tools.

It does not modify DSH, and it opens no inbound port on your machine.

## What you get

- **Access from anywhere** — phone, tablet, another laptop; the interface is DSH's own web surface.
- **No public IP, no port forwarding** — works from home broadband, an office LAN, hotel Wi-Fi, or behind carrier-grade NAT.
- **Your own relay** — no third-party service; traffic passes only through a machine you control.
- **Two tokens** — an **auth token** decides *who may connect* (the relay stores only a public key) and an **encryption token** decides *who may read* (the relay never receives it).
- **End-to-end encryption works** (`setup --require-e2e`): the relay forwards ciphertext it cannot read, and contains **no encryption code at all** — the envelope rides as request headers it already forwards verbatim.
- **The token crosses the wire once.** After the first login a browser authenticates by signature, so even a plain-HTTP relay leaks no reusable credential.
- **Revocation is immediate**, taking effect on the very next request.
- **Minimal surface** — only the DSH web interface is proxied. Terminal sockets and other sensitive channels are refused.

## Quick start

Once installed, **each machine takes one pasted command**.

### 1. On your server

```bash
npm i -g github:Alan-IFT/dsh_remote_web
dsh-remote-web relay --host 127.0.0.1 --port 8787 --trust-proxy --url https://relay.example.com
```

Run in a terminal, the first start **registers a machine automatically** and
prints the exact command to run next — there is no separate registration step.
Put TLS in front ([examples below](#hosting-the-relay)).

> Started as a service instead (systemd, Docker), it prints no pairing code:
> that output is the journal, and a pairing code carries the encryption token
> the relay must never store. It points you at `agent add`, which shows the
> code once in your terminal without logging it.

> `--url` is your public address; it is baked into the pairing code and decides
> where your computer dials.

### 2. On the computer running DSH

Install the plugin, then paste what the relay printed:

```bash
dsh plugin --profile web add github:Alan-IFT/dsh_remote_web
dsh-remote-web setup dshrw1.....        # ← copied from the server
```

`setup` prints a **browser pairing code** when it finishes. Open the relay URL,
paste it, and you are in. A running DSH picks the credentials up within
seconds — no restart.

> The repository ships its build output, so there is nothing else to run. The
> code is shown once; it carries this machine's signing key and encryption
> token, neither of which the relay keeps.

### Adding more devices later

```bash
dsh-remote-web client add tablet --agent my-computer   # on the server
dsh-remote-web invite <token printed above>            # on the computer
```

The split is deliberate: the relay can mint the auth half but **never holds the
encryption token**, so it cannot issue a working credential alone.

## How it works

```
   Your computer (behind NAT)          Your server                 Any browser
┌──────────────────────┐      ┌──────────────────┐        ┌──────────────┐
│  DSH  127.0.0.1:3080 │      │      Relay       │        │              │
│         ▲            │      │                  │        │   Browser    │
│         │ loopback   │      │  ┌────────────┐  │        │              │
│  ┌──────┴────────┐   │      │  │ token auth │  │        │              │
│  │ dsh-remote-web│───┼──────┼─▶│ sessions   │◀─┼────────┼─── HTTPS ────┤
│  │    plugin     │   │ dials│  │ forwarding │  │  HTTPS │              │
│  └───────────────┘   │  out └──┴────────────┘  │        │              │
└──────────────────────┘      └──────────────────┘        └──────────────┘
      no inbound port           the only public machine
```

1. The plugin dials the relay over WebSocket and proves its identity with an **Ed25519 signature** — the private key never leaves the machine, and the relay holds only the public half.
2. A browser logs in with its token and receives an `HttpOnly` session cookie.
3. The relay frames each browser request and forwards it down the tunnel.
4. The plugin **re-issues** the request locally against `127.0.0.1:3080` and streams the response back.

Because the connection is outbound, any amount of NAT between you and the relay is irrelevant.

## Security model

This is a door into a machine that runs code, so every layer denies by default.

### Two credentials: connecting and reading are different questions

One shared secret would mean the relay holds everything needed to read the
session. So the credential is split, and **both halves are required**:

| | Auth credential | Encryption token |
|---|---|---|
| Agent form | Ed25519 keypair | 256-bit random |
| Relay stores | **public key only** | **nothing** |
| Governs | who may connect | who may read |

- **Agents authenticate by signature.** The private key never leaves the
  machine; the relay verifies with a public key. **Reading the relay's disk
  does not let you impersonate a machine.**
  > This was fixed, not designed. An earlier version keyed the proof with the
  > *stored digest*, making that digest a bearer credential — a proof-of-concept
  > confirmed impersonation from the state file alone before the redesign.
- **The encryption token never reaches the relay.** It is minted at `agent add`,
  handed to you once in the pairing code, and used only between your machine
  and the browsers you authorize.

### End-to-end encryption

Working and verified against a live DSH: the correct encryption token returns
200, a wrong one returns 403.

The envelope travels as **two request headers**, so the relay holds no
encryption code (verified: zero references). That is both the smallest possible
implementation and the reason there is no second code path to drift from the
plaintext one.

- **Both the HTTP plane and the event stream are encrypted.** The stream is how the assistant's reply text arrives, chunk by chunk, so it uses the same sealing rather than being left as an exception.
- Each exchange is sealed with **AES-256-GCM** under a key derived by HKDF from
  an **X25519** ephemeral exchange *and* the encryption token. Both are needed:
  the exchange gives forward secrecy, and the token means **a relay that swaps
  in its own public key still derives nothing**.
- Path, headers, and body all travel inside the envelope. The relay sees opaque
  bytes, an exchange id, and a length.
- GCM authenticates as well as encrypts, so **a modified byte fails decryption**
  rather than becoming different content.
- The exchange id is bound as AAD, so a valid payload replayed onto another
  exchange fails.
- **The host refuses downgrade, not the relay.** With `requireE2e` enabled, a
  host answers 403 to any unencrypted request, so stripping the envelope cannot
  buy a readable session.
- The browser half uses WebCrypto and is served as **readable source** at
  `/__e2e/client.js`; the token stays in tab memory.

### Authentication

### Only what should be proxied

- **WebSocket allowlist** — only DSH's two event downlinks (`/api/events.mux`, `/api/events.host`). Terminal sockets and plugin sockets are refused: a remote browser has no business holding a shell.
- **The plugin exposes no HTTP surface at all** — toggling and status go through files under `$DSH_HOME/remote-web/` at mode `0600`, so there is no control endpoint a proxied request could ever reach. See "Bugs found in testing" for why.
- **Path checks** — `..`, `%2e%2e`, and `//`-prefixed paths are rejected, checked both raw and percent-decoded.
- **DSH itself refuses privileged methods.** The tunnel does **not** impersonate loopback; it presents the named authority `dsh-remote-web.internal`. DSH's fence already distinguishes loopback (may reach the privileged plane) from a declared authority (ordinary methods only), so `credentials.*`, `settings.*`, `host.openPath` and the rest are refused by DSH using **its own** list — this package keeps no copy.
  > An earlier version claimed loopback and hand-maintained a blacklist; an audit showed it silently missed `llm.discoverModels`. Under the named authority, methods DSH adds later are refused automatically.

### Header rewriting

DSH ships a DNS-rebinding fence: it accepts a request only when `Host` is a loopback authority and `Origin` matches it. A remote browser's headers cannot pass that check.

So the plugin **re-originates** the request locally instead of forwarding headers verbatim: `Host` and `Origin` are rewritten to the local authority, and every forgeable trust signal — `x-forwarded-*`, `forwarded`, `via`, `sec-fetch-site` — is **dropped rather than mapped**.

This is sound because authentication happened earlier: reaching this code means the relay already verified the token. The rewrite grants no authority the token did not; it restates an authorized request in the host's own voice.

### Three things it deliberately does not do

- **Metadata is visible to the relay.** It routes by agent id and observes sizes and timing. Contents are sealed; traffic patterns are not.
- **The encryption token is long-lived and shared** between a machine and its authorized browsers; rotating it re-pairs them. There is no per-browser key.
- **Metadata is visible to the relay**: frame counts, sizes, and timing. Contents are sealed; traffic patterns are not.
- **The encryption token is long-lived** and shared between a machine and its browsers; rotating it re-pairs them.
- **No P2P/WebRTC hole punching.** Everything goes through the relay: simple, predictable, and it works behind symmetric NAT. The cost is bandwidth on your server.
- **No multi-tenant isolation.** A token reaches everything on the machines it is scoped to. This is a single-operator tool.

## What works remotely, and what does not

Measured against a live DSH carrying third-party plugins:

| Capability | Remote | Notes |
|---|---|---|
| Conversation, sessions, model choice | ✅ | Both event downlinks are allowed |
| Workspace, skills, subagents, jobs, plan | ✅ | Ordinary `/api` forwarding |
| Directory picker | ✅ | The browse variant works in-browser |
| Image/attachment upload | ✅ | 160 MiB request-body ceiling |
| **Sidebar terminal** | ❌ | Not on the WebSocket allowlist — **a remote browser should not get a shell** |
| **Settings / credentials panes** | ❌ | Privileged methods, local-only |
| **Open a path on the host desktop** | ❌ | `host.openPath` is abuse-only when called remotely |
| Mobile layout | ⚠️ | Serves DSH's own UI; **no mobile adaptation** is added |

The three ❌ rows are deliberate security tradeoffs, not gaps. If you need a
remote shell, use SSH rather than making this channel carry one.

## Everyday commands

On **your computer**:

```bash
dsh-remote-web status         # tunnel state
dsh-remote-web disable        # turn remote access off
dsh-remote-web enable         # turn it back on
dsh-remote-web show-config    # where things live (no plaintext secrets)
dsh-remote-web invite <token> # combine a relay token into a browser pairing code
```

On the **relay**:

```bash
dsh-remote-web agent list                  # registered computers
dsh-remote-web agent revoke <name>         # drop a computer (tunnel closes at once)
dsh-remote-web client add tablet --agent my-laptop --ttl 24  # expires in 24h
dsh-remote-web client add phone --agent my-laptop           # scoped to one machine
dsh-remote-web client list                 # issued tokens (fingerprints only)
dsh-remote-web client revoke <id|fingerprint>
```

## Hosting the relay

### Docker Compose (recommended; automatic HTTPS)

```bash
cd deploy
RELAY_DOMAIN=relay.example.com docker compose up -d
docker compose exec relay dsh-remote-web agent add my-laptop --state /data/state.json
```

Caddy obtains and renews certificates automatically. See [`deploy/docker-compose.yml`](deploy/docker-compose.yml) and [`deploy/Caddyfile`](deploy/Caddyfile).

### systemd behind an existing proxy

See [`deploy/dsh-remote-web-relay.service`](deploy/dsh-remote-web-relay.service) (fully sandboxed) and [`deploy/nginx.conf`](deploy/nginx.conf).

> In the nginx config, `proxy_buffering off` and the `Upgrade`/`Connection` pair are not optional: without them the surface loads but never receives live updates.

### Without TLS?

`--no-tls` is only for a fully trusted private network or VPN. It prints a warning, because tokens and all traffic are then readable on the wire.

## Configuration

The plugin normally needs none. When it does, add it to your profile's `cordis.patch.yml`:

```yaml
- id: remote-web
  config:
    enabled: true        # false disables the plugin entirely
    localPort: 8080      # pin the local DSH port (auto-detected by default)
    maxRetryMs: 60000    # reconnect backoff ceiling
```

`localPort` defaults to the port DSH actually bound, so `--port` and multiple DSH instances on one machine need no configuration.

## Bugs found in testing

This plugin was validated against a live DSH instance. Where a defect appeared,
the fix changed the design rather than adding a guard — each one below makes the
whole class of mistake impossible instead of blocking one instance of it:

1. **Revocation did not take effect.** The relay is long-lived while `revoke`
   runs in another process. The relay's cached state ignored the revocation and
   **overwrote it** on its next write.
   *Fix:* extract `WatchedFile`, where reads go through a getter that reloads on
   change. Ten hand-written refresh calls became zero, so "forgot to refresh" is
   no longer a mistake anyone can make here.

2. **Wrong DSH instance.** The plugin inferred its port from an environment
   variable, so a second DSH tunneled to the **first** instance.
   *Fix:* read `ctx.webServer.port`, the port DSH actually bound.

3. **Control-plane exposure (security).** The tunnel re-originates requests
   **from loopback**, so a "loopback-only" control route was reachable by any
   authenticated remote browser. It was possible to disable the tunnel remotely.
   *Fix:* not a path blocklist — that would mean maintaining two copies of a
   list forever — but **removing the HTTP control route entirely**. Control moved
   to files, where the kernel's `0600` enforces the boundary and a proxied
   request cannot reach at all. The vulnerability and both blocklists disappeared
   together.

4. **A revoked machine stayed reachable.** Verifying a documentation claim
   showed a revoked agent still served traffic.
   *Fix:* check authorization on the request path and drop the tunnel.

5. **The CLI crashed when piped.** `status | head` produced an EPIPE stack trace.
   *Fix:* guard the single output function and the process stream.

## Compatibility

- Node.js ≥ 20
- DeepSeek Harness `0.1.0-rc.5` – `0.1.0-rc.8`
- The tunnel depends only on DSH's HTTP surface, not its internal services, so DSH upgrades rarely affect it

## Development

```bash
pnpm install
pnpm test          # 163 tests, including end-to-end and crypto interop
pnpm build
```

## License

[MIT](LICENSE)
