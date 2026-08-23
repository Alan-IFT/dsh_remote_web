# Contributing

## Getting set up

```bash
pnpm install
pnpm test        # 163 tests, including end-to-end against a real tunnel
pnpm typecheck
pnpm build
```

Node.js ≥ 20 is required (the crypto layer uses native X25519 and Ed25519).

## Running it locally

Two processes and one pairing, all on one machine:

```bash
# terminal 1 — the relay
node lib/cli.js relay --host 127.0.0.1 --port 8787 --state /tmp/relay.json --no-tls

# terminal 2 — register a machine and pair it
export DSH_REMOTE_WEB_URL=http://127.0.0.1:8787
node lib/cli.js agent add dev --state /tmp/relay.json
node lib/cli.js setup <printed-code> --allow-insecure --require-e2e

# issue a browser credential (needs both machines, by design)
node lib/cli.js client add browser --agent dev --state /tmp/relay.json
node lib/cli.js invite <printed-token>
```

`--no-tls` and `--allow-insecure` exist for exactly this loop. They print
warnings because they are wrong for anything reachable from a network.

## What the tests cover

| File | Covers |
|---|---|
| `crypto.test.ts` | Signatures, sealing, key derivation |
| `browser-interop.test.ts` | The shipped browser script against the Node implementation |
| `e2e.test.ts` | A real relay and tunnel over a stand-in DSH |
| `e2e-crypto.test.ts` | Malicious-relay scenarios |
| `ws-crypto.test.ts` | Event-stream confidentiality |
| `store.test.ts`, `watched-file.test.ts` | Credential lifecycle, cross-process state |
| `plugin.test.ts`, `cli.test.ts` | Plugin mounting, CLI behavior |

The end-to-end tests stand up an actual relay and tunnel rather than mocking
them, because the properties worth testing here — "the relay cannot read this",
"a revoked credential stops working" — are only meaningful on the real wire.

## Conventions this codebase holds to

- **Reuse before adding.** Encryption, replay defence, and state persistence
  each have exactly one implementation. A second one is a signal that the first
  should have been generalized instead.
- **Let the owner enforce its own rules.** The tunnel presents a named
  authority rather than impersonating loopback, so DSH refuses its privileged
  methods using DSH's own list. Copying such a list here would guarantee drift.
- **Comments explain *why*.** What the code does is readable; the reasoning
  behind a non-obvious choice is not.
- **Fail closed and loudly.** A security control that silently degrades is
  worse than none, because it is believed.

## Before opening a pull request

```bash
pnpm typecheck && pnpm test && pnpm build
```

`lib/` is committed on purpose — installing from git must not require a build
step — so **run `pnpm build` and commit the result** whenever `src/` changes.
A pull request whose `lib/` lags behind `src/` ships stale code to every user.

`noUnusedLocals` and `noUnusedParameters` are on: dead code fails the build
rather than accumulating.

For anything touching the security model, please also describe what an
attacker gains or loses. A change that makes the relay more capable needs a
clear argument for why that is acceptable.

## Reporting vulnerabilities

Please use GitHub Security Advisories rather than a public issue. See
[SECURITY.md](SECURITY.md).
