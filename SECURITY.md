# Security

`dsh-remote-web` exposes a machine that runs code to a network. This document
states exactly what it protects, what it does not, and how to report a problem.

## Reporting a vulnerability

Please report privately through GitHub Security Advisories rather than a public
issue. Include the version, deployment shape (relay TLS posture, reverse proxy),
and a reproduction. Expect an acknowledgement within a few days.

## Threat model

### What an attacker is assumed to be able to do

- Reach the relay's public address and make arbitrary HTTP/WebSocket requests.
- Observe that the relay exists and probe it without credentials.
- Replay any traffic they captured.
- Run a browser on the same LAN as the DSH machine.

### What the design assumes is trustworthy

- **The relay.** It terminates TLS, so it sees your session in the clear. Host
  it on a machine you control. It still cannot impersonate your computer (it
  holds only a public key) and cannot issue a working browser credential by
  itself (that needs the encryption token, which it never receives) — but it
  can read what passes through. In-browser encryption cannot remove this trust,
  because the relay is what serves the browser its code; see
  [docs/DECISIONS.md](docs/DECISIONS.md#browser-side-end-to-end-encryption-was-removed).
- **The DSH machine itself**, and any local user who can read `$DSH_HOME`. The
  credential file is mode `0600`, so control is limited to the owning user.
- **The token holder.** A valid token reaches everything the DSH surface
  exposes on the machines it is scoped to.

If you cannot trust your own relay, this design is not for you; a Noise-based,
end-to-end-encrypted alternative exists in
[deepseek-harness-remote](https://github.com/liguobao/deepseek-harness-remote).

## Controls

### Two independent credentials

A single shared secret would conflate two different questions. The relay must
answer *may this party connect?*, and must not be able to answer *may this
party read?* — so the credential is split, and both halves are required:

| | Auth credential | Encryption token |
|---|---|---|
| Agent form | Ed25519 keypair | 256-bit random |
| Relay holds | public key only | **nothing** |
| Purpose | admission | confidentiality |

- **Agents authenticate by signature.** The agent signs
  `purpose \| agentId \| timestamp \| nonce` with a private key that never
  leaves its machine; the relay verifies with the public key it stores. Reading
  the relay's state file yields no ability to impersonate a machine.

  *This replaced an earlier design in which the proof was an HMAC keyed by the
  stored digest. That made the digest a bearer credential: anyone who read the
  relay's disk could impersonate any agent, defeating the point of storing
  "only a hash". A proof-of-concept confirmed the attack before the redesign.*

- **Browsers authenticate by token once, then by signature.** The first login
  enrolls an Ed25519 public key; every later login answers a single-use
  challenge. The token therefore stops travelling after enrollment, so a relay
  reached over plain HTTP leaks no reusable credential. Re-enrollment is
  refused, so observing that first login does not let an attacker take over.
- **The encryption token is never sent to the relay in any form.** It is minted
  during `agent add`, handed to the operator once inside the pairing code, and
  travels only between the DSH machine and the browsers it authorizes.
- Handshake nonces and login challenges share one bounded, expiring set, so a
  captured proof cannot be replayed and neither table can be grown without
  bound by an unauthenticated caller.
- State files are written atomically with mode `0600`.

### Why there is no in-browser end-to-end encryption

An opt-in `--require-e2e` mode once sealed browser traffic so the relay would
route ciphertext. It was removed, because it could not deliver that property.

The JavaScript performing the encryption was served **by the relay**, and the
relay is exactly the party the mode distrusts. A malicious or compelled relay
serves a build that leaks the token, and nothing in the page can detect it. A
Service Worker does not help: it is delivered the same way.

This is the general limitation of browser-delivered cryptography, stated by
Freedom of the Press Foundation as ["if you don't trust the server not to keep
user secrets, you can't trust them to deliver security
code"](https://securedrop.org/news/browser-based-cryptography/). Their answer,
[WEBCAT](https://github.com/freedomofpress/webcat), needs a browser extension
plus signing and transparency logs — the assurance has to come from outside the
page. Subresource Integrity does not close it either, since a compromised
server generates the hashes.

Shipping the feature anyway would have produced a false assurance, which is
worse than none: a user who believes the relay cannot read the session behaves
differently from one who knows it can.

What protects you instead: TLS to a relay **you** host, an agent key the relay
cannot forge, and a browser credential the relay cannot mint alone. If you need
a relay that genuinely cannot read your traffic, use a transport that does not
depend on browser-delivered code — the Noise-based alternative linked above.

### Sessions

- The browser token is accepted only in a POST body, so it never appears in a
  URL, access log, `Referer`, or browser history.
- Session cookies are `HttpOnly`, `SameSite=Lax`, `Secure` under TLS, and use
  the `__Host-` prefix so the browser pins them to the exact origin.
- Sessions live in memory only: a relay restart forces re-authentication.
- Every authenticated request re-checks that the backing credential still
  exists and is neither revoked nor expired, so **revocation is immediate**.
- The same check applies to agents: a request routed to a revoked machine
  closes that tunnel and answers 503, rather than serving it until a restart.

### Exposure

- Only DSH's two event downlinks may be upgraded to WebSocket. Terminal and
  plugin sockets are refused at both the relay and the host.
- The plugin registers **no HTTP route at all**. Because the tunnel
  re-originates requests from loopback, any route on the DSH server would look
  local to the code serving it, so a "loopback-only" endpoint would in fact be
  reachable by every authenticated remote browser. Control therefore lives in
  files under `$DSH_HOME/remote-web/` at mode `0600`: the kernel enforces the
  boundary, and a proxied HTTP request cannot address the filesystem.
- Path traversal is rejected on the raw and percent-decoded forms.
- Request bodies are capped at 160 MiB; control frames at 256 KiB; WebSocket
  messages at 8 MiB.
- Login attempts are rate-limited per client address, as are agent attaches.
- Relay responses carry `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, and
  HSTS under TLS.

### Header rewriting, and why it is safe

DSH refuses requests whose `Host` is not loopback or whose `Origin` disagrees
with it — a DNS-rebinding defence. Forwarded remote headers cannot satisfy it.

The plugin therefore re-issues each request locally: `Host` and `Origin` are set
to the local authority, and every forgeable trust signal (`x-forwarded-*`,
`forwarded`, `via`, `sec-fetch-*`, cookies, `authorization`) is **dropped, not
mapped**.

This grants no authority the token did not already grant, because
authentication happens strictly earlier: the relay verifies the token before any
frame is forwarded. The rewrite restates an already-authorized request in the
host's own voice; it is not a trust decision.

## Operational guidance

- **Always terminate TLS** in front of the relay for anything reachable from the
  internet. `--no-tls` is for trusted private networks only and warns loudly.
- **Only pass `--trust-proxy` when a known reverse proxy is the sole ingress.**
  Otherwise a client could forge `X-Forwarded-For` and evade rate limiting.
- **Scope tokens** with `--agent` when a credential needs only one machine, and
  use `--ttl` for temporary access.
- **Revoke rather than rotate** when a device is lost: `client revoke` takes
  effect on the next request.
- Run the relay as an unprivileged user; the shipped systemd unit sandboxes it.

## Known limitations

- **Metadata is visible to the relay.** It routes by agent id and sees request
  sizes and timing. Contents are sealed; traffic patterns are not.
- **The encryption token is long-lived and shared** between a machine and the
  browsers it authorizes. Rotating it means re-pairing those browsers. There is
  no per-browser encryption key.
- No multi-user isolation or per-token audit trail beyond `lastSeenAt`.
- **Metadata remains visible to the relay**: it routes by agent id and sees
  frame sizes and timing. Hiding those needs padding and constant-rate cover
  traffic, whose cost exceeds the benefit here.
- **The encryption token is long-lived** and shared between a machine and its
  authorized browsers; rotating it re-pairs them.
- All traffic traverses the relay; there is no P2P path.
