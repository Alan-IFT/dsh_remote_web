# Design decisions

Why the code looks the way it does, and which alternatives were ruled out.

Commit messages carry the reasoning for individual changes. This file carries
the decisions that outlived their commit: the ones a later change is likely to
reopen, and the ones where the obvious approach is the wrong one. If you are
about to "simplify" something here, read its entry first — it probably explains
why that simplification was already tried.

Each entry states the decision, what breaks without it, and what was rejected.
Add one when a choice is not self-evident from the code. Delete one when it
stops being true.

---

## The relay never stores the encryption token

**Decision.** Two independent credentials: an Ed25519 signing key answers *who
may connect*, a separate 256-bit token answers *who may read*. The relay holds
the public key and nothing else.

**Why.** One shared secret would let whoever reads the relay's disk both
impersonate a machine and read its traffic. The split means the relay can admit
a machine it cannot impersonate, and forward traffic it cannot decrypt.

**Consequence to preserve.** Anything that would put the encryption token on the
relay — even transiently, even in a log — breaks the property the project exists
for. Two later decisions below are downstream of this one.

**Rejected.** A single token with the relay holding a digest. An earlier version
did this for agents, and the digest turned out to be a usable bearer credential:
a proof-of-concept impersonated a machine from the state file alone.

---

## The relay rewrites origin markers, and therefore owns the CSRF check

**Decision.** Forwarding sets `Host`, `Origin` and `sec-fetch-site` to the named
authority, and the relay refuses `sec-fetch-site: cross-site` on both the HTTP
and WebSocket paths before forwarding.

**Why the rewrite.** DSH's fence
(`dsh-client-connection`, `isTrustedApiRequest`) admits a request when the
`Host` is loopback or a declared `trustedHosts` authority, refuses
`sec-fetch-site: cross-site`, and requires `Origin.host` to equal `Host`. A
browser reaching a relay sends markers describing the *relay's* origin, which
can never equal the authority the host presents. Forwarded verbatim, every
legitimate request would fail. This is not a DSH defect: it is what any reverse
proxy does, and why `proxy_set_header Host` exists.

**Why the relay must then check.** The rewrite destroys the evidence the fence
relies on. Forwarded verbatim, everything arrives marked `same-origin`, so
DSH's answer describes the relay rather than the browser. The duty does not
disappear with the evidence — it moves to the last point where the browser's
own marker still means something, which is the relay.

`SameSite=Lax` is the first barrier and withholds the cookie from cross-site
writes. It permits a cross-site top-level GET, which DSH would have refused had
the markers survived, so the marker check restores exactly what the rewrite
removed. Two independent barriers, neither load-bearing alone.

**Rejected.** Claiming loopback and re-implementing DSH's privileged-method
exclusions here. Tried: it silently missed `llm.discoverModels`, and every DSH
release would risk another gap. The named authority lets DSH enforce its own
list.

**Rejected.** Leaving CSRF to `SameSite=Lax` alone. It is one mechanism, in one
place, defending a surface that runs code — and it does not cover the GET case
the rewrite made reachable.

---

## Pairing codes are printed only to a terminal

**Decision.** `relay` auto-registers a first machine and prints its pairing code
only when `process.stdout.isTTY`. As a daemon it prints instructions instead.

**Why.** Every deployment in `deploy/` runs the relay under systemd or Docker,
where stdout is the journal or the container log. A pairing code carries the
encryption token, so printing it there writes to disk, on the relay, the one
secret the relay must never hold.

**Verified.** Running the documented command with stdout redirected produced a
journal file containing the signing key and encryption token.

**Rejected.** A `--no-auto-register` opt-out flag. It required the operator to
know about it, which is a rule to remember rather than a thing that cannot go
wrong. The TTY check makes the safe case automatic.

---

## Auto-registration triggers on an empty store, not an idle one

**Decision.** The relay auto-registers only when no agent has *ever* been
registered — `agents.length === 0`, not "no active agents".

**Why.** Revoking the last agent is a lockdown. If the condition were "nothing
active", the next restart would mint a fresh working credential to replace the
one just withdrawn, silently undoing a deliberate security action.

---

## `agent add` and the relay's first start are one function

**Decision.** Both call `registerAgent()`, which also resolves the label and the
public URL and does the printing.

**Why.** They are the same operation reached two ways. When they were two code
paths, adding the browser token to the pairing code required the same edit in
both places, and the label default silently diverged: `agent add` used the
hostname while the relay path invented `my-computer`. That broke the very next
command the README tells you to run, `client add --agent <name>`.

**Preserve.** Printing belongs inside the function. The signing key and
encryption token exist only within that call and are never stored, so there is
no later opportunity to print them. Whether the output is a safe destination is
the caller's decision, because only the caller knows whether a human asked.

**Rejected.** Passing `url` and an `inferred` boolean as separate parameters.
They are one fact, and two parameters can contradict each other — a call could
claim a configured URL was guessed. The function resolves both itself.

---

## Duplicate agent labels are refused at creation

**Decision.** `createAgent` throws if a live agent already has that label.

**Why.** Labels are how every other command names a machine. Two live agents
sharing one made `resolveAgent` find two and return neither, so
`agent revoke <label>` reported "No active agent" **while both stayed
connected** — a revocation that silently did nothing.

**Preserve.** Revoked agents do not block the name, so a rebuilt machine can
re-pair under its own name.

**Rejected.** Handling ambiguity in each caller's error message. The information
needed was already destroyed by the time the caller saw `undefined`, and
refusing at creation made `resolveAgent` shorter rather than longer.

---

## `WatchedFile.update()` holds a lock across read and write

**Decision.** The read-modify-write is serialized by a `mkdir` lock. Stale locks
expire; the wait times out with an actionable message.

**Why.** The relay and the CLI write the same file from different processes.
Without the lock, a write landing between another process's read and write is
erased. The lost operation can be a revocation, and it fails silently — the CLI
still prints "Revoked … cannot reattach".

**Honest about frequency.** The window is small: one update is well under a
millisecond, and the relay writes on attach and login, *not* on every request.
An unlucky overlap is rare. The guard is justified by consequence, not
frequency: the operation at risk is revocation, it is invoked exactly when a
credential is compromised, and the attacker's own attach/login traffic is what
opens the window. Batch writers lose updates regardless of timing — three
concurrent processes kept 107 of 360 writes before the lock, 360 of 360 after.

**Rejected — and this one was actually tried.** An optimistic retry comparing
the `mtimeMs:size` stamp before and after the mutation. It does not work here:
`touchAgent` rewrites a timestamp, leaving the file the same size within the
same millisecond, so the two writes are indistinguishable to `stat`. Measured:
292 of 300 rapid same-size writes shared one `mtimeMs`. The stamp keeps a
*reader* current, which is its job; it cannot detect a concurrent *writer*.

**Cost.** 0.069 ms → 0.084 ms per write. A lock timeout throws, but both relay
entry points already wrap handlers in `try/catch`, so it degrades to one failed
request rather than a crash — verified by holding the lock and confirming the
relay stayed up and recovered.

---

## `lib/` is committed, and CI enforces that it is fresh

**Decision.** Build output is committed so installing from git needs no build
step, and CI rebuilds and fails on any difference.

**Why.** Committing `lib/` introduced a risk with no mechanical guard: changing
`src/` without rebuilding ships stale code. The only protection was a line in
CONTRIBUTING asking people to remember.

**Note.** `lib/` chunk filenames contain a content hash, so a rebuild shows old
names as deleted and new ones as untracked. That is normal, not a broken build.

---

## Errors do not prefix themselves with the tool name

**Decision.** Library code throws bare messages; the CLI's `fail()` adds the
`dsh-remote-web:` prefix.

**Why.** Both once added it, producing `dsh-remote-web: dsh-remote-web: …`.
One owner for the prefix means it cannot be doubled or forgotten.

---

## `--require-e2e` is off by default, and cannot currently be turned on

**Decision.** `requireE2e` defaults to false. The relay is trusted with
plaintext, and `README`/`SECURITY.md` say so plainly.

**Why it cannot yet be enabled — a bootstrap deadlock.** Both crypto sides are
complete and tested. What is missing is a way to seal the *first* request:

1. The login page is relay-owned HTML. It loads `/__e2e/client.js` and keeps
   the encryption token in the tab. This works.
2. The browser then navigates to `/a/<agent>/`. A top-level navigation is a
   plain browser GET; no `fetch` wrapper is involved, so it carries no
   `x-dshrw-sealed` header.
3. With `requireE2e` on, the host refuses that unsealed request with 403
   (`tunnel.ts`, the `else if (this.#credentials.requireE2e)` branch).
4. The shim that would arm encryption is injected into HTML responses only
   when `#contexts.has(frame.rid)` — that is, only for requests that already
   arrived sealed.

So the page that installs encryption can only arrive through a request that is
already encrypted. Turning the flag on today makes a fresh install answer 403 to
everything. A security setting that only breaks the product protects nobody.

**Also incomplete.** The `fetch` wrapper seals request *metadata* only; the body
rides as-is (`browser-crypto.ts`, "Only the metadata is sealed here"). Response
bodies are sealed by the host.

**What would fix it, in order of preference.** Give the *first* navigation a
sealed form rather than adding an exception to the check: have the login page,
which already holds the token, fetch the shell through the sealed `fetch` path
and install the document itself. That keeps one rule — nothing unsealed is
served — instead of carving out a bootstrap hole that an attacker could aim
for. Exempting `text/html` navigations would be less code and strictly worse:
it reintroduces exactly the downgrade path `requireE2e` exists to close.

**Do not** flip the default without closing this. The flag is honest today
precisely because it is documented as off.
