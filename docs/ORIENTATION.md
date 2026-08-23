# Orientation

Start here when picking this project up cold — a new session, a new machine, or
a return after time away. Read this file, then `git log`, then the code.

## What this is

A DeepSeek Harness plugin. The DSH machine dials **outbound** to a relay you
host; a browser reaches DSH through that relay, behind a token. No inbound port
is opened on the machine running DSH.

Three pieces, in `src/`:

| Path | Runs where | Role |
|---|---|---|
| `plugin/` | the DSH machine | Dials the relay, re-issues requests at `127.0.0.1` |
| `relay/` | your server | Rendezvous: auth, sessions, forwarding |
| `shared/` | both | Crypto, pairing codes, the shared-state primitive |
| `cli.ts` | both | `setup`/`status` on the machine; `relay`/`agent`/`client` on the server |

The relay is deliberately incapable: it holds a public key, forwards
ciphertext, and can neither impersonate a machine nor read its traffic.

## Get it running in two minutes

```bash
pnpm install
pnpm typecheck && pnpm test && pnpm build
```

For a live loop on one machine — two terminals, a real relay and tunnel — see
[CONTRIBUTING.md](../CONTRIBUTING.md#running-it-locally).

## Where the knowledge lives

Documentation here is deliberately not one big file. Each kind of question has
one home, so nothing has to be kept in sync in two places:

| Question | Read |
|---|---|
| What is this, how do I use it? | [`README.md`](../README.md) / [`README.en.md`](../README.en.md) |
| What can an attacker do? | [`SECURITY.md`](../SECURITY.md) |
| Why is the code like this? What was already tried? | [`docs/DECISIONS.md`](DECISIONS.md) |
| How do I build, test, contribute? | [`CONTRIBUTING.md`](../CONTRIBUTING.md) |
| What changed between versions? | [`CHANGELOG.md`](../CHANGELOG.md) |
| Why was *this specific line* written? | `git log`, `git blame` |

**Commit messages are the primary record.** This project writes them long: what
changed, why, what was rejected, and how it was verified. `git log` is not a
list of file edits here — it is the design history. Before changing anything
non-obvious, run `git log -p -- <file>` on it.

`docs/DECISIONS.md` holds the subset that outlived its commit: decisions a
later change is likely to reopen. If you are about to simplify something, check
there first — the simplification may already have been tried and measured.

## Conventions that will surprise you

- **`lib/` is committed.** Installing from git needs no build step. Run
  `pnpm build` and commit the result whenever `src/` changes; CI fails on any
  difference. Chunk filenames carry a content hash, so a rebuild shows old
  names deleted and new ones untracked — that is normal.
- **Errors carry no tool-name prefix.** `fail()` in the CLI adds it. Library
  code that adds its own produces `dsh-remote-web: dsh-remote-web: …`.
- **Tests stand up a real relay and tunnel.** They are not mocked, because the
  properties worth testing ("the relay cannot read this", "a revoked credential
  stops working") are only meaningful on the wire. Expect the suite to take a
  few seconds.
- **Dead code fails the build.** `noUnusedLocals` and `noUnusedParameters` are
  on.

## Before you finish a change

```bash
pnpm typecheck && pnpm test && pnpm build
```

Commit `lib/` alongside `src/`. Write the commit message for someone who will
read it in six months with no memory of today: state what was rejected and how
you verified the result. If the reasoning is one a future change might reopen,
add it to `docs/DECISIONS.md` instead of only the commit.
