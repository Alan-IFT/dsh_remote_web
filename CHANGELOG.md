# Changelog

## 0.1.0 — unreleased

First working version.

### Features

- **Outbound tunnel.** The DSH machine dials a relay you host, so it needs no
  inbound port, no router configuration, and no public address.
- **Two independent credentials.** An Ed25519 signing key answers *who may
  connect* (the relay stores only the public half); a separate encryption token
  binds a browser credential to one machine, so the relay cannot mint a working
  credential by itself (it never receives that token).
- **Signature login.** A browser enrols a signing key on first login and
  authenticates by challenge signature afterwards, so the access token crosses
  the wire once. The key is non-extractable and lives in IndexedDB, so page
  script cannot read it. Falls back to token login where WebCrypto or IndexedDB
  is unavailable.
- **Privilege boundary enforced by DSH.** The tunnel presents a named authority
  instead of impersonating loopback, so DSH refuses `credentials.*`,
  `settings.*`, `host.openPath` and the rest using its own list.
- **Immediate revocation.** Revoking a browser credential ends its live
  sessions on the next request; revoking a machine drops its tunnel at once.
- **Zero-configuration install.** `dsh plugin add` registers the bundle and
  declares the trusted authority; nothing needs editing by hand.

### Deliberate limitations

- Terminal sockets, the settings and credentials panes, and native desktop
  actions are **not** proxied. A remote browser should not hold a shell, and
  actions on the host's physical desktop are abuse-only when triggered
  remotely.
- **The relay sees session plaintext.** It terminates TLS, so host it yourself.
  An in-browser encryption mode was removed rather than shipped: the relay
  served the very code meant to defend against it, so the guarantee could not
  hold. See
  [docs/DECISIONS.md](docs/DECISIONS.md#browser-side-end-to-end-encryption-was-removed).
- Metadata (frame sizes, counts, timing) is visible to the relay. Hiding it
  needs padding and constant-rate cover traffic, whose cost exceeds the benefit.
- The encryption token is long-lived and shared between a machine and the
  browsers it authorizes; rotating it re-pairs them.
- No mobile-specific layout: the DSH web surface is served as-is.

### Notable fixes made during development

Each of these was found by testing against a live DSH rather than by reading
code, and each was fixed by changing the design rather than adding a guard.

- **Stored digests were usable credentials.** Agent proofs were HMACs keyed by
  the value the relay stored, so reading its state file allowed impersonating
  any machine. A proof-of-concept confirmed it. Replaced with Ed25519
  signatures, where the stored value verifies and cannot forge.
- **Privileged methods were reachable remotely.** Rewriting requests to look
  like loopback — needed to pass DSH's fence — also unlocked the privileged
  plane DSH reserves for the local user. A hand-maintained blacklist fixed the
  symptom but silently missed `llm.discoverModels`; presenting a named
  authority instead lets DSH enforce the boundary with its own list.
- **Revocation could be undone.** The relay cached state while the CLI wrote to
  the same file, so a revocation was both ignored and overwritten. State now
  reloads on change through one shared primitive.
- **The wrong DSH instance could be tunneled.** The port was inferred from an
  environment variable, so a second instance proxied the first. It now reads
  the port the web server actually bound.
- **The CLI crashed when piped.** `status | head` produced an EPIPE stack
  trace.
- **The relay logged the encryption token.** Auto-registering on first start
  printed a pairing code to stdout — which under systemd or Docker is the
  journal, writing the one secret the relay must never hold to its own disk.
  The code is now printed only to a terminal.
- **A restart could undo a lockdown.** Auto-registration triggered on "no
  active agents", so revoking the last one and restarting minted a fresh
  working credential. It now triggers only on a store that never held an agent.
- **Duplicate machine names broke revocation.** Two live agents could share a
  label, after which `agent revoke <label>` reported "No active agent" while
  both stayed connected. Duplicate live labels are refused at creation; a
  revoked name can be reused.
- **Concurrent writes could erase a revocation.** The relay and CLI write the
  same state file from different processes, and a write landing mid-update was
  silently overwritten. `WatchedFile.update()` now holds a lock across read and
  write; three concurrent writers kept 107 of 360 writes before, 360 of 360
  after. See [`docs/DECISIONS.md`](docs/DECISIONS.md) for why a stamp-based
  optimistic retry does not work here.
- **Onboarding named machines two ways.** `agent add` defaulted to the
  hostname while the relay's first start invented `my-computer`, so the
  `client add --agent <name>` that the README tells you to run next failed.
  Both paths now share one function.
