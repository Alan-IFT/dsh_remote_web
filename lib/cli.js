#!/usr/bin/env node
import { decodePairingCode, encodePairingCode, fingerprint, hashToken } from "./headers-BoJKLZo1.js";
import { defaultCredentialPath, openCredentials, openStatus, stateDir, statusPath } from "./config-ulTq7JKy.js";
import { DEFAULT_RELAY_OPTIONS, RelayStore, startRelay } from "./server-DJbLiuUd.js";
import { hostname } from "node:os";
import { join } from "node:path";

//#region src/cli.ts
/** Parse argv into flags and positionals. */
function parseArgs(argv) {
	const positional = [];
	const flags = new Map();
	const booleans = new Set();
	for (let index = 0; index < argv.length; index += 1) {
		const token = argv[index];
		if (token === void 0) continue;
		if (!token.startsWith("--")) {
			positional.push(token);
			continue;
		}
		const body = token.slice(2);
		const equals = body.indexOf("=");
		if (equals >= 0) {
			flags.set(body.slice(0, equals), body.slice(equals + 1));
			continue;
		}
		const next = argv[index + 1];
		if (next !== void 0 && !next.startsWith("--")) {
			flags.set(body, next);
			index += 1;
		} else booleans.add(body);
	}
	return {
		positional,
		flags,
		booleans
	};
}
/**
* Print a line to stdout.
*
* EPIPE is swallowed because these commands are meant to be piped: `status |
* head` closes the pipe early, and a crash with a stack trace would be a worse
* answer than simply stopping. Node raises this as an unhandled 'error' event
* on the socket, so the guard belongs at the one place that writes.
*/
function say(message = "") {
	try {
		process.stdout.write(`${message}\n`);
	} catch (error) {
		if (error.code !== "EPIPE") throw error;
	}
}
/** Print to stderr and exit nonzero. */
function fail(message) {
	process.stderr.write(`dsh-remote-web: ${message}\n`);
	process.exit(1);
}
/** Default relay state path when the operator does not pass `--state`. */
function defaultStatePath() {
	return process.env.DSH_REMOTE_WEB_STATE ?? join(stateDir(), "relay-state.json");
}
const USAGE = `dsh-remote-web — secure remote access to a local DeepSeek Harness

On the machine running DSH:
  setup <pairing-code>       Pair this machine with a relay
  status                     Show tunnel state
  invite <token>             Turn a relay browser token into a pairing code
  enable | disable           Turn remote access on or off
  show-config                Print where things live (never a token)

On your own server (the relay):
  relay [--host 0.0.0.0] [--port 8787] [--state <file>]
        [--no-tls] [--trust-proxy] [--session-ttl <hours>]
  agent add <label> [--url <relay-url>]     Register a machine, print its code
  agent list | agent revoke <name|id>
  client add <label> --agent <machine-name> [--ttl <hours>]
  client list | client revoke <clientId|fingerprint>

Common flags:
  --state <file>   Relay state file (default: $DSH_HOME/remote-web/relay-state.json)
  --json           Machine-readable output where supported
`;
/** `setup`: write the credential file this machine uses to dial the relay. */
function commandSetup(args) {
	const path = args.flags.get("credentials") ?? defaultCredentialPath();
	const label = args.flags.get("label") ?? hostname();
	const raw = args.positional[1] ?? args.flags.get("code");
	let relayUrl = args.flags.get("relay");
	let privateKey = args.flags.get("key");
	let encryptionToken = args.flags.get("encryption-token");
	let agentId = args.flags.get("agent-id");
	let browserToken;
	if (raw !== void 0) {
		const code = decodePairingCode(raw);
		if (code === null) fail("invalid pairing code; use the string printed by `agent add`");
		if (code.subject === null) fail("that is a browser token, not a machine pairing code — paste it into the relay web page instead");
		relayUrl = code.relayUrl;
		agentId = code.subject;
		privateKey = code.authSecret;
		encryptionToken = code.encryptionToken;
		browserToken = code.browserToken;
	}
	if (relayUrl === void 0 || privateKey === void 0 || encryptionToken === void 0 || agentId === void 0 || agentId === "") fail("provide the pairing code printed by `agent add`");
	try {
		const parsed = new URL(relayUrl);
		if (parsed.protocol !== "https:" && parsed.protocol !== "http:") fail("relay URL must be http(s)");
		if (parsed.protocol === "http:" && !args.booleans.has("allow-insecure")) fail("refusing an http:// relay: tokens and traffic would travel in clear text. Use https://, or pass --allow-insecure on a trusted private network.");
	} catch (error) {
		if (error instanceof Error && error.message.includes("clear text")) throw error;
		fail(`invalid relay URL: ${relayUrl}`);
	}
	const credentials = openCredentials(path);
	credentials.write({
		version: 1,
		relayUrl,
		agentId,
		privateKey,
		encryptionToken,
		label,
		enabled: true
	});
	say(`Paired with ${relayUrl}`);
	say(`  agent id     ${agentId}`);
	say(`  label        ${label}`);
	say(`  signing key  ${fingerprint(hashToken(privateKey))} (fingerprint)`);
	say(`  encryption   ${fingerprint(hashToken(encryptionToken))} (fingerprint)`);
	say(`  credentials  ${path}`);
	say();
	if (browserToken !== void 0) {
		say("Open this in a browser to connect:");
		say();
		say(`  ${relayUrl}`);
		say();
		say("and paste this pairing code:");
		say();
		say(`  ${encodePairingCode({
			relayUrl,
			subject: null,
			authSecret: browserToken,
			encryptionToken
		})}`);
		say();
		say("Issue more with `client add` on the relay, then `invite` here.");
	}
	say("A running DSH picks this up within a few seconds; otherwise it connects at next start.");
}
/** `status`: read the snapshot the running plugin publishes. */
function commandStatus(args) {
	const path = args.flags.get("credentials") ?? defaultCredentialPath();
	const snapshot = openStatus(statusPath(path)).value;
	if (args.booleans.has("json")) {
		say(JSON.stringify(snapshot, null, 2));
		return;
	}
	if (snapshot === null) {
		const credentials = openCredentials(path).value;
		say(credentials === null ? "Not configured. Run `dsh-remote-web setup <pairing-code>`." : "Configured, but no running DSH has reported status yet.");
		return;
	}
	const ageMs = Date.now() - snapshot.updatedAt;
	const stale = ageMs > 15e3;
	say(`State        ${stale ? `${snapshot.state} (stale — is DSH running?)` : snapshot.state}`);
	say(`Relay        ${snapshot.relayUrl ?? "-"}`);
	say(`Label        ${snapshot.label ?? "-"}`);
	say(`Proxying     ${snapshot.localTarget}`);
	say(`Token        ${snapshot.tokenFingerprint ?? "-"}`);
	say(`In flight    ${String(snapshot.activeRequests)} requests, ${String(snapshot.activeSockets)} sockets`);
	if (snapshot.lastError !== null && snapshot.lastError !== "") say(`Last error   ${snapshot.lastError}`);
}
/** `enable` / `disable`: flip the credential file; the plugin follows. */
function commandToggle(enabled, args) {
	const path = args.flags.get("credentials") ?? defaultCredentialPath();
	const credentials = openCredentials(path);
	const current = credentials.value;
	if (current === null) fail("not configured; run `dsh-remote-web setup` first");
	credentials.write({
		...current,
		enabled
	});
	say(`Remote access ${enabled ? "enabled" : "disabled"}.`);
	say("A running DSH applies this within a few seconds.");
}
/**
* `invite`: turn a relay-issued browser token into a complete pairing code.
*
* This runs on the DSH machine because that is the only place both halves
* exist: the relay minted the auth token but has never held the encryption
* token. Neither machine alone can produce a working browser credential, which
* is exactly the guarantee the two-token split is meant to provide.
*/
function commandInvite(args) {
	const path = args.flags.get("credentials") ?? defaultCredentialPath();
	const credentials = openCredentials(path).value;
	if (credentials === null) fail("not configured; run `dsh-remote-web setup` first");
	const authToken = args.positional[1];
	if (authToken === void 0 || authToken === "") fail("usage: invite <token-from-`client add`>");
	const code = encodePairingCode({
		relayUrl: credentials.relayUrl,
		subject: null,
		authSecret: authToken,
		encryptionToken: credentials.encryptionToken
	});
	say("Browser pairing code:");
	say();
	say(`  ${code}`);
	say();
	say(`Open ${credentials.relayUrl} in a browser and paste it.`);
	say("It carries the relay access token and this machine's encryption token,");
	say("so the relay can admit the browser without being able to read the session.");
}
/** `show-config`: where things live, without printing any secret. */
function commandShowConfig(args) {
	const path = args.flags.get("credentials") ?? defaultCredentialPath();
	const credentials = openCredentials(path).value;
	say(`Credential file  ${path}`);
	say(`Status file      ${statusPath(path)}`);
	say(`State directory  ${stateDir()}`);
	if (credentials === null) {
		say("Status           not configured");
		return;
	}
	say(`Relay            ${credentials.relayUrl}`);
	say(`Agent id         ${credentials.agentId}`);
	say(`Label            ${credentials.label}`);
	say(`Enabled          ${String(credentials.enabled)}`);
	say(`Signing key      ${fingerprint(hashToken(credentials.privateKey))} (fingerprint)`);
	say(`Encryption       ${fingerprint(hashToken(credentials.encryptionToken))} (fingerprint)`);
}
/** `relay`: run the rendezvous server. */
async function commandRelay(args) {
	const host = args.flags.get("host") ?? process.env.DSH_REMOTE_WEB_HOST ?? DEFAULT_RELAY_OPTIONS.host;
	const portRaw = args.flags.get("port") ?? process.env.DSH_REMOTE_WEB_PORT;
	const port = portRaw === void 0 ? DEFAULT_RELAY_OPTIONS.port : Number.parseInt(portRaw, 10);
	if (!Number.isInteger(port) || port < 0 || port > 65535) fail(`invalid port: ${String(portRaw)}`);
	const statePath = args.flags.get("state") ?? defaultStatePath();
	const ttlHours = Number.parseFloat(args.flags.get("session-ttl") ?? "12");
	if (!Number.isFinite(ttlHours) || ttlHours <= 0) fail("invalid --session-ttl");
	const secure = !args.booleans.has("no-tls");
	const relay = await startRelay({
		host,
		port,
		statePath,
		secure,
		trustProxy: args.booleans.has("trust-proxy"),
		sessionTtlMs: Math.round(ttlHours * 60 * 60 * 1e3)
	});
	const agents = relay.store.listAgents();
	const active = agents.filter((agent) => !agent.revoked);
	say(`dsh-remote-web relay listening on ${host}:${String(relay.port)}`);
	say(`  state file   ${statePath}`);
	say(`  cookies      ${secure ? "Secure (expects TLS in front)" : "insecure (--no-tls)"}`);
	say(`  agents       ${String(active.length)} registered`);
	if (agents.length === 0 && process.stdout.isTTY === true) {
		say();
		registerAgent(relay.store, args, `http${secure ? "s" : ""}://${host === "0.0.0.0" ? "YOUR-RELAY-HOST" : host}:${String(relay.port)}`);
	} else if (active.length === 0) {
		say();
		say("No active agents: this relay can serve nobody yet. Run");
		say();
		say(`  dsh-remote-web agent add <name> --state ${statePath} --url <public-url>`);
		say();
		say("in a terminal, which prints the pairing code once without writing it");
		say("to this process's log.");
	}
	if (!secure) {
		say();
		say("WARNING: running without TLS. Tokens and session traffic are readable on the wire.");
		say("Only do this inside a trusted private network or a VPN.");
	}
	const shutdown = () => {
		say("\nShutting down…");
		relay.close().then(() => process.exit(0));
	};
	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);
}
/** Public relay URL used when printing pairing codes. */
function relayUrlFor(args) {
	return args.flags.get("url") ?? process.env.DSH_REMOTE_WEB_URL;
}
/**
* Register a machine and print the one command that pairs it.
*
* `agent add` and the relay's first start are the same operation reached two
* ways, so they are one function. When they were two, adding the browser token
* to the pairing code meant making the same edit twice — a divergence this
* removes rather than asks the next author to remember.
*
* Printing is part of the operation, not a step after it: the signing key and
* encryption token exist only inside this call, and nothing is stored that
* could print them later. Whether this output is a safe place for them is the
* caller's question, because only the caller knows whether a human asked.
*
* The address is resolved here rather than passed in, so "which URL" and "was
* it configured" cannot disagree — the caller supplies only its guess, and
* whether that guess was used is this function's own answer. Saying so matters:
* a wrong address pairs a machine that then dials somewhere it cannot reach.
*
* The label is resolved here for the same reason. `agent add <label>` and a
* first start name the same thing, so they must not disagree about what an
* unnamed machine is called — the relay path once answered `my-computer` while
* the documented path answered the hostname, which quietly broke the very
* `client add --agent <name>` the docs tell you to run next.
*
* @param fallbackUrl - Address to embed when the operator configured none.
*/
function registerAgent(store, args, fallbackUrl) {
	const configured = relayUrlFor(args);
	const url = configured ?? fallbackUrl;
	const label = args.positional[2] ?? hostname();
	const issued = store.createAgent(label);
	const browser = store.createClient(`${label} browser`, issued.record.agentId, null);
	say(`Registered "${label}"`);
	say(`  agent id     ${issued.record.agentId}`);
	say(`  public key   ${fingerprint(hashToken(issued.record.publicKey))} (relay keeps this)`);
	say();
	say("Run this on the machine that runs DSH:");
	say();
	say(`  dsh-remote-web setup ${encodePairingCode({
		relayUrl: url,
		subject: issued.record.agentId,
		authSecret: issued.privateKey,
		encryptionToken: issued.encryptionToken,
		browserToken: browser.token
	})}`);
	say();
	if (configured === void 0) {
		say(`NOTE: set --url or DSH_REMOTE_WEB_URL to your public address; the code`);
		say(`      above embeds ${url}, which must be reachable from your devices.`);
		say();
	}
	say("Shown once. It carries this machine's signing key and encryption token,");
	say("neither of which the relay keeps — it can admit this machine, and neither");
	say("impersonate it nor read its traffic.");
}
/** `agent …`: manage which machines may attach. */
function commandAgent(args) {
	const store = new RelayStore(args.flags.get("state") ?? defaultStatePath());
	const action = args.positional[1];
	if (action === "add") {
		registerAgent(store, args, "https://relay.example.com");
		return;
	}
	if (action === "list") {
		const agents = store.listAgents();
		if (agents.length === 0) {
			say("No agents registered.");
			return;
		}
		if (args.booleans.has("json")) {
			say(JSON.stringify(agents, null, 2));
			return;
		}
		for (const agent of agents) {
			const seen = agent.lastSeenAt === null ? "never" : new Date(agent.lastSeenAt).toISOString();
			say(`${agent.agentId}  ${(agent.revoked ? "REVOKED" : "active").padEnd(8)} ${agent.label}  (last seen ${seen})`);
		}
		return;
	}
	if (action === "revoke") {
		const target = args.positional[2];
		if (target === void 0) fail("usage: agent revoke <name|id>");
		const agentId = store.resolveAgent(target)?.agentId ?? target;
		say(store.revokeAgent(agentId) ? `Revoked ${agentId}. Its tunnel is dropped and it cannot reattach.` : `No active agent with id ${agentId}.`);
		return;
	}
	fail("usage: agent <add|list|revoke>");
}
/** `client …`: manage browser access tokens. */
function commandClient(args) {
	const store = new RelayStore(args.flags.get("state") ?? defaultStatePath());
	const action = args.positional[1];
	if (action === "add") {
		const label = args.positional[2] ?? "browser";
		const agentScope = args.flags.get("agent") ?? "*";
		const ttlRaw = args.flags.get("ttl");
		const ttlMs = ttlRaw === void 0 ? null : Math.round(Number.parseFloat(ttlRaw) * 36e5);
		if (ttlMs !== null && (!Number.isFinite(ttlMs) || ttlMs <= 0)) fail("invalid --ttl");
		if (agentScope === "*") fail("name one machine with --agent <name|id>: a browser credential is bound to that machine's encryption token.");
		const host = store.resolveAgent(agentScope);
		if (host === void 0) {
			const known = store.listAgents().filter((agent) => !agent.revoked).map((agent) => agent.label);
			fail(`no such agent: ${agentScope}` + (known.length > 0 ? ` (known: ${known.join(", ")})` : ""));
		}
		const issued = store.createClient(label, host.agentId, ttlMs);
		say(`Issued browser token for "${label}"`);
		say(`  client id  ${issued.record.clientId}`);
		say(`  scope      ${agentScope === "*" ? "all agents" : agentScope}`);
		say(`  expires    ${issued.record.expiresAt === null ? "never" : new Date(issued.record.expiresAt).toISOString()}`);
		say();
		say(`  token      ${issued.token}`);
		say();
		say("Now run this on the DSH machine to produce the browser pairing code:");
		say();
		say(`  dsh-remote-web invite ${issued.token}`);
		say();
		say("The relay cannot produce that code itself: it would need the encryption");
		say("token, which only the DSH machine holds. That is the property working.");
		say();
		say("This token is shown once and cannot be recovered.");
		return;
	}
	if (action === "list") {
		const clients = store.listClients();
		if (clients.length === 0) {
			say("No browser tokens issued.");
			return;
		}
		if (args.booleans.has("json")) {
			say(JSON.stringify(clients.map(({ tokenHash,...rest }) => rest), null, 2));
			return;
		}
		for (const client of clients) {
			const expired = client.expiresAt !== null && client.expiresAt <= Date.now();
			const state = client.revoked ? "REVOKED" : expired ? "expired" : "active";
			const seen = client.lastSeenAt === null ? "never" : new Date(client.lastSeenAt).toISOString();
			say(`${fingerprint(client.tokenHash)}  ${state.padEnd(8)} ${client.label}  scope=${client.agentId}  (last used ${seen})  id=${client.clientId}`);
		}
		return;
	}
	if (action === "revoke") {
		const target = args.positional[2];
		if (target === void 0) fail("usage: client revoke <clientId|fingerprint>");
		say(store.revokeClient(target) ? `Revoked ${target}. Any live session ends on its next request.` : `No active credential matching ${target}.`);
		return;
	}
	fail("usage: client <add|list|revoke>");
}
/** Entry point. */
async function main() {
	const args = parseArgs(process.argv.slice(2));
	const command = args.positional[0];
	if (command === void 0 || args.booleans.has("help") || command === "help") {
		say(USAGE);
		return;
	}
	switch (command) {
		case "setup":
			commandSetup(args);
			return;
		case "status":
			commandStatus(args);
			return;
		case "enable":
			commandToggle(true, args);
			return;
		case "disable":
			commandToggle(false, args);
			return;
		case "invite":
			commandInvite(args);
			return;
		case "show-config":
			commandShowConfig(args);
			return;
		case "relay":
			await commandRelay(args);
			return;
		case "agent":
			commandAgent(args);
			return;
		case "client":
			commandClient(args);
			return;
		default: fail(`unknown command "${command}". Run with --help for usage.`);
	}
}
process.stdout.on("error", (error) => {
	if (error.code === "EPIPE") process.exit(0);
	throw error;
});
main().catch((error) => {
	fail(error instanceof Error ? error.message : String(error));
});

//#endregion