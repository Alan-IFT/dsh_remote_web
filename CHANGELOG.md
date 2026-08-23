# Changelog

## 0.1.0 — unreleased

First working version.

### Features

- **Outbound tunnel.** The DSH machine dials a relay you host, so it needs no
  inbound port, no router configuration, and no public address.
- **Two independent credentials.** An Ed25519 signing key answers *who may
  connect* (the relay stores only the public half); a separate encryption token
  answers *who may read* (the relay never receives it).
- **End-to-end encryption** on both the HTTP plane and the event stream, under
  X25519 + HKDF + AES-256-GCM. The relay forwards ciphertext and holds no key.
- **Signature login.** A browser presents its token once, enrolls a key, and
  authenticates by signature afterwards — so the token stops crossing the wire
  and a relay reached over plain HTTP leaks no reusable credential.
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
