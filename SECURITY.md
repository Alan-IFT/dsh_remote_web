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

- **NOT the relay, when `--require-e2e` is on.** It holds only public keys and
  routes ciphertext it cannot read. Without that flag it does see plaintext, so
  enable it — or host the relay yourself and accept that trust.
- **The DSH machine**, and any local user who can read `$DSH_HOME`.
- **The token holder.** A valid token reaches the conversation surface of the
  machines it is scoped to.
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

### End-to-end encryption

Active and verified end to end. Enable it per machine with
`dsh-remote-web setup <code> --require-e2e`.

The envelope travels as two request headers, so **the relay contains no
encryption code at all** — it forwards headers verbatim, which is why there is
no second code path that could diverge from the plaintext one and no relay
change that could weaken it.

- Each exchange is sealed with **AES-256-GCM** under a key derived by HKDF from
  an **X25519** exchange *and* the encryption token. Both inputs are required:
  the ephemeral exchange provides forward secrecy, and folding in the token
  means a relay that substituted its own public key still derives nothing.
- The request path, headers, and body all travel inside the envelope, as do
  event-stream frames — the channel carrying the assistant's reply text. The
  relay sees an opaque blob, an exchange id, and a size.
- Stream frames are authenticated against the stream path, not the
  relay-assigned socket id, so a relay cannot move a frame between the two
  downlinks; it assigns that id, so binding to it would let it choose its own
  authenticated data.
- GCM's tag authenticates as well as encrypts, so a relay that modified a byte
  causes a decryption failure rather than altered content.
- The exchange id is bound as additional authenticated data, so a valid payload
  replayed onto a different exchange fails.
- **Downgrade is refused by the host, not the relay.** With `requireE2e`
  enabled, a host answers 403 to any request that did not arrive encrypted —
  a relay that stripped the envelope cannot silently obtain a readable session.
- The browser half runs in WebCrypto and is served as readable source at
  `/__e2e/client.js`; the token stays in tab memory and is never persisted.

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
