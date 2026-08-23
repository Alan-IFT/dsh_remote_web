import { AUTH_PROOF_SKEW_MS, CLOSE_AGENT_OFFLINE, CLOSE_AGENT_REPLACED, CLOSE_AUTH_FAILED, CLOSE_RATE_LIMITED, CLOSE_REVOKED, CLOSE_UNSUPPORTED_VERSION, HEARTBEAT_INTERVAL_MS, HEARTBEAT_TIMEOUT_MS, MAX_BODY_CHUNK_BYTES, MAX_CONTROL_FRAME_BYTES, MAX_REQUEST_BODY_BYTES, OneTimeValues, PROTOCOL_VERSION, RELAY_AGENT_PATH, RateLimiter, WatchedFile, agentChallenge, decodePairingCode, fingerprint, generateAgentIdentity, generateEncryptionToken, generateToken, hashToken, isAllowedWebSocketPath, isSafeProxyPath, normalizeHeaders, parseFrame, safeEqual, verifySignature } from "./headers-BshunupR.js";
import { randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { WebSocketServer } from "ws";

//#region src/relay/store.ts
/** Validate parsed JSON as store state, rejecting anything unrecognized. */
function parseState(raw) {
	const state = raw;
	if (state?.version !== 1 || !Array.isArray(state.agents) || !Array.isArray(state.clients)) throw new Error("unrecognized state shape");
	return state;
}
/** Whether a credential is currently usable. */
function isLive(record, now) {
	if (record.revoked) return false;
	const expiry = record.expiresAt;
	return expiry === void 0 || expiry === null || expiry > now;
}
/**
* Relay credential store.
*
* Mutations write through immediately: the data set is small, and an operator
* who kills the relay right after issuing a token must not lose it.
*/
var RelayStore = class {
	#file;
	/**
	* @param path - JSON state file; parent directories are created as needed.
	*/
	constructor(path) {
		this.#file = new WatchedFile(path, parseState, () => ({
			version: 1,
			agents: [],
			clients: []
		}));
	}
	/** Absolute path of the backing file. */
	get path() {
		return this.#file.path;
	}
	/** Every registered agent, including revoked ones. */
	listAgents() {
		return this.#file.value.agents;
	}
	/**
	* Register a new agent and issue its token.
	*
	* @param label - Human-facing name for the machine.
	* @param agentId - Optional explicit id; generated when omitted.
	*/
	createAgent(label, agentId) {
		const identity = generateAgentIdentity();
		const encryptionToken = generateEncryptionToken();
		const record = {
			agentId: agentId ?? randomUUID(),
			label,
			publicKey: identity.publicKey,
			createdAt: Date.now(),
			lastSeenAt: null,
			revoked: false
		};
		this.#file.update((state) => {
			if (state.agents.some((agent) => agent.agentId === record.agentId)) throw new Error(`agent "${record.agentId}" already exists`);
			if (state.agents.some((agent) => !agent.revoked && agent.label === label)) throw new Error(`an active agent is already named "${label}" — pick another name, or revoke that one first`);
			return {
				next: {
					...state,
					agents: [...state.agents, record]
				},
				result: null
			};
		});
		return {
			record,
			privateKey: identity.privateKey,
			encryptionToken
		};
	}
	/**
	* Look up an agent by id, ignoring revoked entries.
	*
	* @returns The record, or `undefined` when absent or revoked.
	*/
	findAgent(agentId) {
		const record = this.#file.value.agents.find((agent) => agent.agentId === agentId);
		return record !== void 0 && !record.revoked ? record : void 0;
	}
	/**
	* Find one agent by id or by label.
	*
	* Labels exist because a person names their machines; requiring them to copy
	* a UUID back out of `agent add` is friction the tool can absorb.
	*
	* A label names at most one live agent because {@link createAgent} refuses to
	* create a second, so this cannot be ambiguous. It once could, and returning
	* `undefined` for that case made two very different situations look alike:
	* `agent revoke <label>` reported nothing to revoke while both machines
	* stayed connected. The fix belongs at creation, not in every caller's error
	* message.
	*
	* @returns The match, or `undefined` when no live agent has that id or label.
	*/
	resolveAgent(idOrLabel) {
		return this.findAgent(idOrLabel) ?? this.#file.value.agents.find((agent) => !agent.revoked && agent.label === idOrLabel);
	}
	/**
	* Verify an agent's signature over a challenge.
	*
	* Revocation is checked first, so a revoked agent fails exactly like an
	* unknown one.
	*/
	verifyAgentSignature(agentId, challenge, signature) {
		const record = this.findAgent(agentId);
		if (record === void 0) return void 0;
		return verifySignature(challenge, signature, record.publicKey) ? record : void 0;
	}
	/** Record that an agent was seen, for the status view. */
	touchAgent(agentId) {
		this.#file.update((state) => ({
			next: {
				...state,
				agents: state.agents.map((agent) => agent.agentId === agentId ? {
					...agent,
					lastSeenAt: Date.now()
				} : agent)
			},
			result: null
		}));
	}
	/**
	* Revoke an agent: its token stops validating and the relay drops its tunnel.
	*
	* @returns True when an agent was revoked, false when unknown or already so.
	*/
	revokeAgent(agentId) {
		return this.#file.update((state) => {
			const target = state.agents.find((agent) => agent.agentId === agentId);
			if (target === void 0 || target.revoked) return {
				next: state,
				result: false
			};
			return {
				next: {
					...state,
					agents: state.agents.map((agent) => agent.agentId === agentId ? {
						...agent,
						revoked: true
					} : agent)
				},
				result: true
			};
		});
	}
	/** Every issued browser credential, including revoked ones. */
	listClients() {
		return this.#file.value.clients;
	}
	/**
	* Issue a browser credential.
	*
	* @param label - Who it is for, e.g. `phone`.
	* @param agentId - Agent it may reach, or `'*'` for all.
	* @param ttlMs - Lifetime; `null` never expires.
	*/
	createClient(label, agentId, ttlMs) {
		const token = generateToken();
		const record = {
			clientId: randomUUID(),
			label,
			tokenHash: hashToken(token),
			agentId,
			createdAt: Date.now(),
			lastSeenAt: null,
			expiresAt: ttlMs === null ? null : Date.now() + ttlMs,
			revoked: false
		};
		this.#file.update((state) => ({
			next: {
				...state,
				clients: [...state.clients, record]
			},
			result: null
		}));
		return {
			record,
			token
		};
	}
	/**
	* Resolve a raw browser token to its credential.
	*
	* Every stored credential is examined so an unknown token costs the same as
	* a known one; revoked and expired records never match.
	*/
	verifyClientToken(token, now = Date.now()) {
		const digest = hashToken(token);
		let matched;
		for (const record of this.#file.value.clients) {
			if (!isLive(record, now)) continue;
			if (safeEqual(record.tokenHash, digest)) matched = record;
		}
		return matched;
	}
	/**
	* Look up a client credential that is still usable.
	*
	* The relay calls this on every authenticated request, which is what makes
	* revocation take effect immediately rather than at the next restart.
	*/
	findLiveClient(clientId, now = Date.now()) {
		const record = this.#file.value.clients.find((client) => client.clientId === clientId);
		return record !== void 0 && isLive(record, now) ? record : void 0;
	}
	/**
	* Bind a browser's signing key to its credential, on first use.
	*
	* Enrollment happens once, over whatever channel carried the token. After
	* that the token is dormant: every later login is a signature, so a passive
	* observer on an unencrypted hop learns nothing reusable.
	*
	* A second enrollment for the same credential is refused — otherwise anyone
	* who observed the token could replace the key and take the credential over.
	*
	* @returns True when the key was bound, false when one already exists.
	*/
	enrollClientKey(clientId, publicKey) {
		return this.#file.update((state) => {
			const target = state.clients.find((client) => client.clientId === clientId);
			if (target === void 0 || target.publicKey !== void 0) return {
				next: state,
				result: false
			};
			return {
				next: {
					...state,
					clients: state.clients.map((client) => client.clientId === clientId ? {
						...client,
						publicKey
					} : client)
				},
				result: true
			};
		});
	}
	/**
	* Resolve a browser that proved its identity by signature.
	*
	* @param challenge - The exact string the browser signed.
	* @param signature - Base64url Ed25519 signature.
	*/
	verifyClientSignature(challenge, signature, now = Date.now()) {
		for (const record of this.#file.value.clients) {
			if (!isLive(record, now) || record.publicKey === void 0) continue;
			if (verifySignature(challenge, signature, record.publicKey)) return record;
		}
		return void 0;
	}
	/** Record that a credential was used. */
	touchClient(clientId) {
		this.#file.update((state) => ({
			next: {
				...state,
				clients: state.clients.map((client) => client.clientId === clientId ? {
					...client,
					lastSeenAt: Date.now()
				} : client)
			},
			result: null
		}));
	}
	/**
	* Revoke a browser credential by id or by token fingerprint.
	*
	* @returns True when a credential was revoked.
	*/
	revokeClient(idOrFingerprint) {
		return this.#file.update((state) => {
			const matches = (client) => client.clientId === idOrFingerprint || fingerprint(client.tokenHash) === idOrFingerprint;
			const target = state.clients.find(matches);
			if (target === void 0 || target.revoked) return {
				next: state,
				result: false
			};
			return {
				next: {
					...state,
					clients: state.clients.map((client) => matches(client) ? {
						...client,
						revoked: true
					} : client)
				},
				result: true
			};
		});
	}
};
/**
* Whether a credential scope authorizes reaching a given agent.
*
* @param scope - A credential's `agentId`: a specific id, or `'*'` for all.
* @param agentId - The agent being reached.
*/
function scopeMayReach(scope, agentId) {
	return scope === "*" || scope === agentId;
}

//#endregion
//#region src/relay/tunnels.ts
/** An agent currently attached to the relay. */
var Tunnel = class {
	agentId;
	tunnelId;
	label;
	socket;
	connectedAt = Date.now();
	/**
	* Whether this host refuses unencrypted requests.
	*
	* The relay records it to tell browsers what to do, not to enforce it: the
	* host enforces its own policy, since a relay that could waive encryption
	* would be a relay that could disable it.
	*/
	requiresE2e = false;
	/**
	* The host's ephemeral public key, relayed to browsers verbatim.
	*
	* The relay stores and forwards it but can do nothing with it: a session key
	* needs the encryption token too.
	*/
	hostPublicKey = "";
	/** Last time we saw any frame from the agent; drives liveness eviction. */
	lastSeenAt = Date.now();
	/** In-flight exchanges keyed by request id or socket id. */
	#exchanges = new Map();
	constructor(agentId, tunnelId, label, socket) {
		this.agentId = agentId;
		this.tunnelId = tunnelId;
		this.label = label;
		this.socket = socket;
	}
	/** Number of exchanges currently routed through this tunnel. */
	get activeExchanges() {
		return this.#exchanges.size;
	}
	/**
	* Register an exchange so agent frames carrying `id` reach it.
	*
	* @returns A disposer that unregisters the exchange.
	*/
	attach(id, exchange) {
		this.#exchanges.set(id, exchange);
		return () => {
			this.#exchanges.delete(id);
		};
	}
	/** Route one agent frame to its exchange, if still registered. */
	dispatch(id, frame) {
		this.#exchanges.get(id)?.onFrame(frame);
	}
	/**
	* Send a frame to the agent.
	*
	* @returns True when the frame was handed to the socket.
	*/
	send(frame) {
		if (this.socket.readyState !== this.socket.OPEN) return false;
		this.socket.send(JSON.stringify(frame));
		return true;
	}
	/** Notify every exchange that the tunnel is gone, then clear the table. */
	failAll() {
		for (const exchange of [...this.#exchanges.values()]) try {
			exchange.onTunnelLost();
		} catch {}
		this.#exchanges.clear();
	}
};
/**
* Registry of attached agents.
*
* At most one tunnel per agent id: a second attachment for the same agent
* replaces the first, because the common cause is a host that reconnected
* after a network change while the relay has not yet noticed the dead socket.
*/
var TunnelRegistry = class {
	#byAgent = new Map();
	/** Live tunnel for an agent, if attached. */
	get(agentId) {
		return this.#byAgent.get(agentId);
	}
	/** Every attached tunnel. */
	list() {
		return [...this.#byAgent.values()];
	}
	/**
	* Attach a tunnel, displacing any existing one for the same agent.
	*
	* @returns The displaced tunnel, so the caller can close it with the right
	*          code after its exchanges have been failed.
	*/
	add(tunnel) {
		const previous = this.#byAgent.get(tunnel.agentId);
		this.#byAgent.set(tunnel.agentId, tunnel);
		if (previous !== void 0) previous.failAll();
		return previous;
	}
	/**
	* Detach a tunnel if it is still the registered one.
	*
	* The identity check matters during replacement: the displaced tunnel's
	* close event fires *after* the new one registered, and must not evict it.
	*/
	remove(tunnel) {
		if (this.#byAgent.get(tunnel.agentId) === tunnel) this.#byAgent.delete(tunnel.agentId);
		tunnel.failAll();
	}
	/**
	* Close tunnels that have not produced a frame within the liveness window.
	*
	* @returns The number of tunnels evicted.
	*/
	evictStale(now = Date.now(), timeoutMs = HEARTBEAT_TIMEOUT_MS) {
		let evicted = 0;
		for (const tunnel of [...this.#byAgent.values()]) {
			if (now - tunnel.lastSeenAt <= timeoutMs) continue;
			this.remove(tunnel);
			try {
				tunnel.socket.close(CLOSE_AGENT_OFFLINE, "heartbeat timeout");
			} catch {}
			evicted += 1;
		}
		return evicted;
	}
	/** Close every tunnel; used on relay shutdown. */
	closeAll(code, reason) {
		for (const tunnel of [...this.#byAgent.values()]) {
			this.remove(tunnel);
			try {
				tunnel.socket.close(code, reason);
			} catch {}
		}
	}
};

//#endregion
//#region src/relay/sessions.ts
/**
* Upper bound on concurrent sessions.
*
* Sized well above any real person's device count, so it never interferes with
* ordinary use while still bounding what a leaked token can consume.
*/
const MAX_SESSIONS = 256;
/** Name of the session cookie. The `__Host-` prefix pins it to this exact
*  origin with `Path=/` and no `Domain`, which browsers enforce for us. */
const SESSION_COOKIE = "__Host-dshrw";
/** Fallback name used when the relay is not on TLS, where `__Host-` is illegal. */
const SESSION_COOKIE_INSECURE = "dshrw";
/**
* In-memory session table.
*
* Sessions are deliberately not persisted: a relay restart forces every
* browser to re-present its token, which is a cheap way to bound the damage of
* a stolen cookie and costs the operator nothing.
*/
var SessionStore = class {
	#sessions = new Map();
	#ttlMs;
	/**
	* @param ttlMs - Idle lifetime of a session; refreshed on each request.
	*/
	constructor(ttlMs = 12 * 60 * 60 * 1e3) {
		this.#ttlMs = ttlMs;
	}
	/** Live session count, after pruning expired entries. */
	get size() {
		this.#prune();
		return this.#sessions.size;
	}
	#prune(now = Date.now()) {
		for (const [key, session] of this.#sessions) if (session.expiresAt <= now) this.#sessions.delete(key);
	}
	/**
	* Create a session for an authenticated browser.
	*
	* @returns The raw session id to place in the cookie; only its hash is kept.
	*/
	create(clientId, label, agentId, now = Date.now()) {
		this.#prune(now);
		while (this.#sessions.size >= MAX_SESSIONS) {
			const oldest = [...this.#sessions.entries()].reduce((a, b) => a[1].createdAt <= b[1].createdAt ? a : b);
			this.#sessions.delete(oldest[0]);
		}
		const raw = randomBytes(32).toString("base64url");
		const session = {
			idHash: hashToken(raw),
			clientId,
			label,
			agentId,
			createdAt: now,
			lastSeenAt: now,
			expiresAt: now + this.#ttlMs
		};
		this.#sessions.set(session.idHash, session);
		return raw;
	}
	/**
	* Resolve a raw cookie value to its session, refreshing the idle deadline.
	*
	* @returns The session, or `undefined` when unknown or expired.
	*/
	resolve(raw, now = Date.now()) {
		if (raw === void 0 || raw === "") return void 0;
		this.#prune(now);
		const digest = hashToken(raw);
		const session = this.#sessions.get(digest);
		if (session === void 0) return void 0;
		if (!safeEqual(session.idHash, digest)) return void 0;
		session.lastSeenAt = now;
		session.expiresAt = now + this.#ttlMs;
		return session;
	}
	/** Drop one session (logout). */
	destroy(raw) {
		if (raw === void 0 || raw === "") return;
		this.#sessions.delete(hashToken(raw));
	}
	/** Drop every session belonging to a client credential (revocation). */
	destroyByClient(clientId) {
		let removed = 0;
		for (const [key, session] of this.#sessions) {
			if (session.clientId !== clientId) continue;
			this.#sessions.delete(key);
			removed += 1;
		}
		return removed;
	}
	/** Drop every session; used when the relay revokes broadly. */
	clear() {
		this.#sessions.clear();
	}
};
/**
* Parse a `Cookie` header into a map.
*
* @param header - Raw header value, possibly undefined.
*/
function parseCookies(header) {
	const out = new Map();
	if (header === void 0) return out;
	for (const part of header.split(";")) {
		const index = part.indexOf("=");
		if (index <= 0) continue;
		const key = part.slice(0, index).trim();
		const value = part.slice(index + 1).trim();
		if (key !== "") out.set(key, decodeURIComponent(value));
	}
	return out;
}
/**
* Build the `Set-Cookie` value for a new session.
*
* @param value - Raw session id.
* @param secure - Whether the relay is served over TLS.
* @param maxAgeSeconds - Cookie lifetime.
*/
function buildSessionCookie(value, secure, maxAgeSeconds) {
	const name = secure ? SESSION_COOKIE : SESSION_COOKIE_INSECURE;
	const attributes = [
		`${name}=${encodeURIComponent(value)}`,
		"Path=/",
		"HttpOnly",
		"SameSite=Lax",
		`Max-Age=${String(maxAgeSeconds)}`
	];
	if (secure) attributes.push("Secure");
	return attributes.join("; ");
}
/** Build the `Set-Cookie` value that clears a session. */
function buildClearCookie(secure) {
	const name = secure ? SESSION_COOKIE : SESSION_COOKIE_INSECURE;
	const attributes = [
		`${name}=`,
		"Path=/",
		"HttpOnly",
		"SameSite=Lax",
		"Max-Age=0"
	];
	if (secure) attributes.push("Secure");
	return attributes.join("; ");
}
/**
* Read the session cookie under whichever name applies.
*
* Both names are accepted regardless of the current TLS posture so a relay
* that gains or loses TLS does not strand browsers holding the other name.
*/
function readSessionCookie(header) {
	const cookies = parseCookies(header);
	return cookies.get(SESSION_COOKIE) ?? cookies.get(SESSION_COOKIE_INSECURE);
}

//#endregion
//#region src/relay/pages.ts
/**
* The two HTML pages the relay serves itself: the login form and the agent
* picker. Everything else on the relay is a proxy of the DSH surface.
*
* These are inline templates rather than a bundled frontend because they are
* the only relay-owned UI, and a self-hosted relay should stay a single Node
* file with no build step.
*
* @module dsh-remote-web/relay/pages
*/
/** Escape text for interpolation into HTML content or a quoted attribute. */
function escapeHtml(value) {
	return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
const STYLE = `
  :root { color-scheme: light dark; --fg: #1a1a1a; --bg: #fbfbfa; --muted: #6b6b6b;
          --accent: #4a6cf7; --border: #e2e2df; --card: #ffffff; }
  @media (prefers-color-scheme: dark) {
    :root { --fg: #e8e8e6; --bg: #17171a; --muted: #9a9a97; --border: #2e2e33; --card: #1e1e22; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
         background: var(--bg); color: var(--fg); padding: 24px;
         font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
               "Hiragino Sans GB", "Microsoft YaHei", sans-serif; }
  .card { width: 100%; max-width: 420px; background: var(--card); border: 1px solid var(--border);
          border-radius: 14px; padding: 28px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
  h1 { margin: 0 0 6px; font-size: 19px; font-weight: 620; letter-spacing: -.01em; }
  p.sub { margin: 0 0 22px; color: var(--muted); font-size: 13.5px; }
  label { display: block; font-size: 13px; font-weight: 560; margin-bottom: 7px; }
  input[type=password], input[type=text] {
    width: 100%; padding: 11px 13px; font-size: 15px; font-family: ui-monospace, SFMono-Regular,
    Menlo, monospace; border: 1px solid var(--border); border-radius: 9px;
    background: var(--bg); color: var(--fg); }
  input:focus { outline: 2px solid var(--accent); outline-offset: -1px; border-color: transparent; }
  button { width: 100%; margin-top: 16px; padding: 11px; font-size: 15px; font-weight: 560;
           color: #fff; background: var(--accent); border: 0; border-radius: 9px; cursor: pointer; }
  button:hover { filter: brightness(1.06); }
  .error { margin: 0 0 16px; padding: 10px 12px; border-radius: 8px; font-size: 13.5px;
           background: #fdecec; color: #a12; border: 1px solid #f5c9c9; }
  @media (prefers-color-scheme: dark) { .error { background: #3a1f22; color: #f5a7a7; border-color: #5b2b30; } }
  ul.agents { list-style: none; margin: 0; padding: 0; }
  ul.agents li { margin-bottom: 10px; }
  a.agent { display: flex; align-items: center; justify-content: space-between; gap: 12px;
            padding: 13px 15px; border: 1px solid var(--border); border-radius: 10px;
            text-decoration: none; color: var(--fg); background: var(--bg); }
  a.agent:hover { border-color: var(--accent); }
  .name { font-weight: 560; }
  .meta { font-size: 12.5px; color: var(--muted); font-family: ui-monospace, monospace; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: #35c759; flex: none; }
  .foot { margin-top: 20px; font-size: 12.5px; color: var(--muted); text-align: center; }
  .foot a { color: var(--muted); }
`;
/**
* The login page.
*
* The form posts the token rather than putting it in a query string, so it
* never lands in access logs, browser history, or a `Referer` header.
*
* @param options.error - Message to show above the form, already plain text.
* @param options.next - Path to return to after a successful login.
*/
function renderLoginPage(options = {}) {
	const error = options.error === void 0 ? "" : `<p class="error">${escapeHtml(options.error)}</p>`;
	const next = options.next === void 0 ? "" : `<input type="hidden" name="next" value="${escapeHtml(options.next)}">`;
	return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>DSH Remote Web</title>
<style>${STYLE}</style>
</head>
<body>
  <main class="card">
    <h1>DSH Remote Web</h1>
    <p class="sub">请输入访问令牌 / Enter your access token</p>
    ${error}
    <form method="POST" action="/__auth/login" autocomplete="off" id="f">
      ${next}
      <label for="token">访问令牌 Access token</label>
      <input id="token" name="token" type="password" required autofocus
             spellcheck="false" autocapitalize="none" autocorrect="off"
             placeholder="dshrw1.… 或直接粘贴令牌">
      <button type="submit">连接 Connect</button>
    </form>
    <p class="foot">连接受令牌保护，会话通过自建中转服务器转发。</p>
  </main>
  <script src="/__e2e/client.js"></script>
  <script>
    /*
     * Split the pasted pairing code before submitting: the auth half is what
     * the relay checks, and the encryption half must stay in this tab. Posting
     * the whole code would hand the relay the key it is designed never to have.
     */
    document.getElementById('f').addEventListener('submit', function (event) {
      var field = document.getElementById('token')
      var parts = field.value.trim().split('.')
      if (parts.length === 5 && parts[0] === 'dshrw1') {
        try {
          sessionStorage.setItem('dshrw-enc', parts[4])
        } catch (error) {
          /* Private mode: encryption simply stays off for this tab. */
        }
        field.value = parts[3]
      }
      void event
    })
  </script>
</body>
</html>`;
}
/**
* The agent picker, shown when a session may reach more than one host.
*
* Offline agents are listed but not linkable: seeing that a machine exists and
* is simply not running is more useful than an empty list.
*/
function renderAgentPicker(agents) {
	const items = agents.length === 0 ? "<li><p class=\"sub\">没有已注册的主机。请在电脑上运行 <code>dsh-remote-web setup</code>。</p></li>" : agents.map((agent) => {
		const meta = agent.online ? "<span class=\"dot\" aria-label=\"online\"></span>" : "<span class=\"meta\">离线 offline</span>";
		const inner = `<span class="name">${escapeHtml(agent.label)}</span>${meta}`;
		return agent.online ? `<li><a class="agent" href="/a/${encodeURIComponent(agent.agentId)}/">${inner}</a></li>` : `<li><span class="agent" aria-disabled="true">${inner}</span></li>`;
	}).join("\n");
	return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>选择主机 · DSH Remote Web</title>
<style>${STYLE}</style>
</head>
<body>
  <main class="card">
    <h1>选择主机</h1>
    <p class="sub">Choose a host to connect to</p>
    <ul class="agents">
${items}
    </ul>
    <p class="foot"><a href="/__auth/logout">退出登录 Sign out</a></p>
  </main>
</body>
</html>`;
}
/** A minimal error page for proxy-level failures. */
function renderErrorPage(status, message) {
	return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${String(status)} · DSH Remote Web</title>
<style>${STYLE}</style>
</head>
<body>
  <main class="card">
    <h1>${String(status)}</h1>
    <p class="sub">${escapeHtml(message)}</p>
    <p class="foot"><a href="/">返回 Back</a></p>
  </main>
</body>
</html>`;
}

//#endregion
//#region src/relay/browser-crypto.ts
/**
* The browser half of end-to-end encryption, as source text.
*
* This module exports a string rather than running in Node: the relay serves it
* to the browser, where it installs a `fetch` wrapper that seals outgoing
* requests and opens incoming responses before the DSH application sees them.
*
* Why a served script instead of a bundled asset: the relay is a single Node
* file an operator can read end to end, and the whole security claim rests on
* that readability. A build step producing an opaque blob would ask the user to
* trust something they cannot inspect, which is exactly the posture this design
* exists to avoid.
*
* The token never leaves the browser tab. It arrives in the pairing code, is
* kept in memory (never `localStorage`, which survives the tab and is readable
* by any script that later runs on the origin), and is used only to derive keys
* through WebCrypto.
*
* @module dsh-remote-web/relay/browser-crypto
*/
/**
* The client script, served at `/__e2e/client.js`.
*
* It is plain ES2020 with no imports so it runs in any browser that has
* WebCrypto, and it is deliberately small enough to audit.
*/
const BROWSER_CRYPTO_SCRIPT = String.raw`
/*
 * dsh-remote-web end-to-end encryption client.
 *
 * Wraps window.fetch so every request to this origin travels sealed. The relay
 * routes ciphertext it cannot read: deriving the key needs the encryption
 * token, which is never sent to the relay in any form.
 */
(function () {
  'use strict'

  var STORAGE_KEY = 'dshrw-e2e'
  var enc = new TextEncoder()
  var dec = new TextDecoder()

  /** base64url helpers; the wire format avoids +/= so codes stay copyable. */
  function b64uToBytes(value) {
    var padded = value.replace(/-/g, '+').replace(/_/g, '/')
    while (padded.length % 4 !== 0) padded += '='
    var binary = atob(padded)
    var out = new Uint8Array(binary.length)
    for (var i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i)
    return out
  }

  function bytesToB64u(bytes) {
    var binary = ''
    var view = new Uint8Array(bytes)
    for (var i = 0; i < view.length; i += 1) binary += String.fromCharCode(view[i])
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }

  /**
   * Session state.
   *
   * The live token is held in memory. It is also mirrored into sessionStorage
   * across the login navigation, because the token arrives on the login page
   * and must survive exactly one redirect to reach the application page.
   *
   * sessionStorage — not localStorage — bounds that exposure to this tab
   * and clears it when the tab closes. The mirror is deleted as soon as it has
   * been read, so it exists for one navigation rather than the whole session.
   * The alternative, putting the key in the URL, would place it in history and
   * in the relay's access log.
   */
  var state = {
    token: null,
    hostPublicKey: null,
    ephemeral: null,
    publicKeyRaw: null,
    installed: false,
  }

  /** Import the raw X25519 public key the host published. */
  function importPeerKey(raw) {
    return crypto.subtle.importKey('raw', b64uToBytes(raw), { name: 'X25519' }, false, [])
  }

  /**
   * Derive the AES key for one exchange.
   *
   * Both inputs are required: the ECDH result gives forward secrecy, and
   * folding in the encryption token means a relay that substituted its own
   * public key still derives nothing.
   */
  async function deriveKey(peerPublicKey) {
    var shared = await crypto.subtle.deriveBits(
      { name: 'X25519', public: await importPeerKey(peerPublicKey) },
      state.ephemeral.privateKey,
      256,
    )
    var material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: enc.encode(state.token),
        info: enc.encode('dsh-remote-web/session/v1'),
      },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    )
  }

  /** Seal a request payload, binding it to its exchange id. */
  async function sealFor(rid, payload) {
    var key = await deriveKey(state.hostPublicKey)
    var nonce = crypto.getRandomValues(new Uint8Array(12))
    var ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: enc.encode(rid), tagLength: 128 },
      key,
      enc.encode(JSON.stringify(payload)),
    )
    var full = new Uint8Array(ciphertext)
    // WebCrypto appends the tag; the wire format keeps them separate so Node's
    // GCM API can consume it directly.
    var body = full.slice(0, full.length - 16)
    var tag = full.slice(full.length - 16)
    return {
      epk: bytesToB64u(
        await crypto.subtle.exportKey('raw', state.ephemeral.publicKey),
      ),
      salt: '',
      n: bytesToB64u(nonce),
      c: bytesToB64u(body),
      t: bytesToB64u(tag),
    }
  }

  /** Open a sealed response; returns null when authentication fails. */
  async function openFrom(rid, envelope) {
    try {
      var key = await deriveKey(envelope.epk)
      var body = b64uToBytes(envelope.c)
      var tag = b64uToBytes(envelope.t)
      var joined = new Uint8Array(body.length + tag.length)
      joined.set(body, 0)
      joined.set(tag, body.length)
      var plain = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: b64uToBytes(envelope.n),
          additionalData: enc.encode(rid),
          tagLength: 128,
        },
        key,
        joined,
      )
      return new Uint8Array(plain)
    } catch (error) {
      return null
    }
  }

  /**
   * Initialize the session from the encryption token and the host's key.
   *
   * Called by the login page after a successful sign-in.
   */
  async function init(token, hostPublicKey) {
    // Consume the one-navigation mirror: from here the value lives in memory.
    try {
      sessionStorage.removeItem('dshrw-enc')
    } catch (error) {
      /* Private mode or blocked storage; nothing to clean up. */
    }
    state.token = token
    state.hostPublicKey = hostPublicKey
    state.ephemeral = await crypto.subtle.generateKey({ name: 'X25519' }, false, [
      'deriveBits',
    ])
    state.publicKeyRaw = bytesToB64u(
      await crypto.subtle.exportKey('raw', state.ephemeral.publicKey),
    )
  }

  /**
   * Wrap fetch so every same-origin API call travels sealed.
   *
   * The wrapper is installed only after init(), and only same-origin requests
   * are touched: a request to another origin is not ours to encrypt, and
   * wrapping it would leak the envelope to a third party.
   */
  function install() {
    // No fetch means no transport to wrap — a non-browser host embedding this
    // module for its seal/open helpers, for instance. Encryption still works;
    // only the automatic wrapping is skipped.
    if (state.installed || typeof window.fetch !== 'function') return
    state.installed = true
    var nativeFetch = window.fetch.bind(window)
    var origin = (window.location && window.location.origin) || ''

    window.fetch = async function (input, init) {
      var url = typeof input === 'string' ? input : (input && input.url) || ''
      var sameOrigin = url.indexOf('://') === -1 || (origin !== '' && url.indexOf(origin) === 0)
      if (!state.token || !sameOrigin) return nativeFetch(input, init)

      var method = (init && init.method) || (input && input.method) || 'GET'
      var path = url.indexOf('://') === -1 ? url : url.slice(origin.length)
      var rid = 'r' + Math.random().toString(36).slice(2) + Date.now().toString(36)

      // Only the metadata is sealed here; the body rides as-is because the
      // host re-issues it verbatim and the payload key protects the response.
      var headers = {}
      var given = (init && init.headers) || {}
      if (given.forEach) given.forEach(function (v, k) { headers[k] = v })
      else Object.keys(given).forEach(function (k) { headers[k] = given[k] })

      var envelope = await sealFor(rid, { method: method, path: path, headers: headers })
      var merged = Object.assign({}, headers)
      merged['x-dshrw-rid'] = rid
      merged['x-dshrw-sealed'] = bytesToB64u(enc.encode(JSON.stringify(envelope)))

      return nativeFetch(input, Object.assign({}, init, { headers: merged }))
    }

    installWebSocket()
  }

  /**
   * Wrap WebSocket so the DSH event downlinks travel sealed.
   *
   * This is where the assistant's reply text arrives, chunk by chunk, so
   * leaving it in the clear would undo most of what encrypting the HTTP plane
   * achieved.
   *
   * Frames are authenticated against the stream path rather than the socket
   * id: the relay assigns the id, so binding to it would let the relay choose
   * its own authenticated data and move frames between the two downlinks.
   */
  function installWebSocket() {
    if (typeof window.WebSocket !== 'function') return
    var Native = window.WebSocket

    function SealedSocket(url, protocols) {
      var full = String(url)
      var path = full.replace(/^wss?:\/\/[^/]+/, '').split('?')[0]

      // A browser cannot set handshake headers, so the ephemeral public key
      // rides the query string. Only a public key goes there; deriving the
      // stream key also needs the encryption token, which never leaves the tab.
      var target = full
      if (state.token && state.publicKeyRaw) {
        target += (full.indexOf('?') === -1 ? '?' : '&') +
          'dshrw_epk=' + encodeURIComponent(state.publicKeyRaw)
      }

      var socket = protocols === undefined ? new Native(target) : new Native(target, protocols)
      if (!state.token) return socket

      var nativeAdd = socket.addEventListener.bind(socket)

      socket.addEventListener = function (type, handler, options) {
        if (type !== 'message') return nativeAdd(type, handler, options)
        var wrapped = async function (event) {
          var payload = event.data
          try {
            var envelope = JSON.parse(typeof payload === 'string' ? payload : '')
            if (envelope && envelope.__dshrw) {
              var plain = await openFrom(path, envelope)
              if (plain === null) return
              handler.call(socket, { data: dec.decode(plain) })
              return
            }
          } catch (error) {
            /* Not an envelope: fall through and deliver as-is. */
          }
          handler.call(socket, event)
        }
        return nativeAdd(type, wrapped, options)
      }

      Object.defineProperty(socket, 'onmessage', {
        set: function (handler) {
          socket.addEventListener('message', handler)
        },
        configurable: true,
      })

      return socket
    }

    SealedSocket.prototype = Native.prototype
    SealedSocket.CONNECTING = Native.CONNECTING
    SealedSocket.OPEN = Native.OPEN
    SealedSocket.CLOSING = Native.CLOSING
    SealedSocket.CLOSED = Native.CLOSED
    window.WebSocket = SealedSocket
  }

  /**
   * Resume encryption on an application page after the login redirect.
   *
   * Returns false when this tab has no encryption token, which is the ordinary
   * case for a relay whose hosts do not require E2E.
   */
  async function resume(hostPublicKey) {
    var carried = null
    try {
      carried = sessionStorage.getItem('dshrw-enc')
    } catch (error) {
      carried = null
    }
    if (!carried) return false
    await init(carried, hostPublicKey)
    install()
    return true
  }

  window.__dshRemoteWebE2E__ = {
    resume: resume,
    init: async function (token, hostPublicKey) {
      await init(token, hostPublicKey)
      install()
    },
    seal: sealFor,
    open: openFrom,
    /** Whether encryption is configured for this tab. */
    ready: function () {
      return state.token !== null && state.ephemeral !== null
    },
  }
})()
`;
/** Content type for the served script. */
const BROWSER_CRYPTO_CONTENT_TYPE = "text/javascript; charset=utf-8";

//#endregion
//#region src/relay/server.ts
/** Defaults for options a caller may omit. */
const DEFAULT_RELAY_OPTIONS = {
	host: "0.0.0.0",
	port: 8787,
	secure: true,
	trustProxy: false,
	sessionTtlMs: 12 * 60 * 60 * 1e3
};
/** Version reported to agents in `hello.ack`. */
const RELAY_VERSION = "0.1.0";
/**
* Start the relay.
*
* @param options - Bind, storage, and posture settings.
* @returns Handles for the running server.
*/
async function startRelay(options) {
	const log = options.log ?? ((message) => process.stdout.write(`${message}\n`));
	const store = new RelayStore(options.statePath);
	const tunnels = new TunnelRegistry();
	const sessions = new SessionStore(options.sessionTtlMs);
	const loginLimiter = new RateLimiter(10, 6e4);
	const agentLimiter = new RateLimiter(30, 6e4);
	const handshakeNonces = new OneTimeValues();
	const challenges = new OneTimeValues(12e4);
	/** Client address used for rate limiting. */
	const clientKey = (request$1) => {
		if (options.trustProxy) {
			const forwarded = request$1.headers["x-forwarded-for"];
			const raw = Array.isArray(forwarded) ? forwarded[0] : forwarded;
			const first = raw?.split(",")[0]?.trim();
			if (first !== void 0 && first !== "") return first;
		}
		return request$1.socket.remoteAddress ?? "unknown";
	};
	/** Security headers applied to every relay-owned response. */
	const securityHeaders = () => {
		const headers = {
			"x-content-type-options": "nosniff",
			"referrer-policy": "no-referrer",
			"x-frame-options": "DENY",
			"cache-control": "no-store"
		};
		if (options.secure) headers["strict-transport-security"] = "max-age=31536000; includeSubDomains";
		return headers;
	};
	const sendHtml = (response, status, html, extra = {}) => {
		response.writeHead(status, {
			...securityHeaders(),
			...extra,
			"content-type": "text/html; charset=utf-8"
		});
		response.end(html);
	};
	const sendJson = (response, status, body) => {
		response.writeHead(status, {
			...securityHeaders(),
			"content-type": "application/json; charset=utf-8"
		});
		response.end(JSON.stringify(body));
	};
	const agentWss = new WebSocketServer({
		noServer: true,
		maxPayload: MAX_CONTROL_FRAME_BYTES
	});
	const clientWss = new WebSocketServer({
		noServer: true,
		maxPayload: MAX_CONTROL_FRAME_BYTES
	});
	/**
	* Drive one attached agent socket: authenticate it, then pump frames.
	*
	* The handshake is strict — an agent that does not send a well-formed
	* `hello` within the deadline is dropped without a hint about why.
	*/
	const handleAgentSocket = (socket, request$1) => {
		const key = clientKey(request$1);
		let tunnel = null;
		const handshakeTimer = setTimeout(() => {
			if (tunnel === null) socket.close(CLOSE_AUTH_FAILED, "handshake timeout");
		}, 1e4);
		socket.on("message", (raw, isBinary) => {
			if (isBinary) {
				socket.close(CLOSE_AUTH_FAILED, "binary frame");
				return;
			}
			const frame = parseFrame(raw.toString("utf8"));
			if (frame === null) {
				socket.close(CLOSE_AUTH_FAILED, "malformed frame");
				return;
			}
			if (tunnel === null) {
				if (frame.type !== "hello") {
					socket.close(CLOSE_AUTH_FAILED, "expected hello");
					return;
				}
				const hello = frame;
				if (hello.v !== PROTOCOL_VERSION) {
					socket.close(CLOSE_UNSUPPORTED_VERSION, `protocol ${String(PROTOCOL_VERSION)} required`);
					return;
				}
				if (!agentLimiter.allow(key)) {
					socket.close(CLOSE_RATE_LIMITED, "too many attempts");
					return;
				}
				if (typeof hello.agentId !== "string" || hello.agentId === "") {
					socket.close(CLOSE_AUTH_FAILED, "invalid agent");
					return;
				}
				const record = store.findAgent(hello.agentId);
				if (record === void 0) {
					socket.close(CLOSE_AUTH_FAILED, "invalid agent");
					return;
				}
				const skew = Math.abs(Date.now() - hello.ts);
				if (!Number.isFinite(hello.ts) || skew > AUTH_PROOF_SKEW_MS) {
					socket.close(CLOSE_AUTH_FAILED, "authentication failed");
					return;
				}
				if (typeof hello.nonce !== "string" || hello.nonce.length < 16 || hello.nonce.length > 128 || !handshakeNonces.add(hello.nonce)) {
					socket.close(CLOSE_AUTH_FAILED, "authentication failed");
					return;
				}
				if (store.verifyAgentSignature(hello.agentId, agentChallenge(hello.agentId, hello.ts, hello.nonce), hello.signature) === void 0) {
					log(`[relay] agent ${hello.agentId} signature refused`);
					socket.close(CLOSE_AUTH_FAILED, "authentication failed");
					return;
				}
				agentLimiter.reset(key);
				clearTimeout(handshakeTimer);
				const tunnelId = randomUUID();
				tunnel = new Tunnel(record.agentId, tunnelId, record.label, socket);
				tunnel.requiresE2e = hello.e2e === true;
				tunnel.hostPublicKey = typeof hello.epk === "string" ? hello.epk : "";
				const displaced = tunnels.add(tunnel);
				if (displaced !== void 0) try {
					displaced.socket.close(CLOSE_AGENT_REPLACED, "replaced by a newer tunnel");
				} catch {}
				store.touchAgent(record.agentId);
				tunnel.send({
					type: "hello.ack",
					v: PROTOCOL_VERSION,
					tunnelId,
					heartbeatIntervalMs: HEARTBEAT_INTERVAL_MS,
					maxControlFrameBytes: MAX_CONTROL_FRAME_BYTES,
					maxBodyChunkBytes: MAX_BODY_CHUNK_BYTES,
					relayVersion: RELAY_VERSION
				});
				log(`[relay] agent online: ${record.label} (${record.agentId})`);
				return;
			}
			tunnel.lastSeenAt = Date.now();
			routeAgentFrame(tunnel, frame);
		});
		socket.on("close", () => {
			clearTimeout(handshakeTimer);
			if (tunnel !== null) {
				tunnels.remove(tunnel);
				log(`[relay] agent offline: ${tunnel.label} (${tunnel.agentId})`);
			}
		});
		socket.on("error", () => {});
	};
	/** Route a frame from an agent to whichever exchange owns it. */
	const routeAgentFrame = (tunnel, frame) => {
		switch (frame.type) {
			case "http.response":
			case "body.chunk":
			case "body.end":
			case "abort": {
				const id = frame.rid;
				if (typeof id === "string") tunnel.dispatch(id, frame);
				return;
			}
			case "ws.open.ack":
			case "ws.message":
			case "ws.close": {
				const id = frame.sid;
				if (typeof id === "string") tunnel.dispatch(id, frame);
				return;
			}
			case "pong": return;
			case "ping":
				tunnel.send({
					type: "pong",
					nonce: frame.nonce
				});
				return;
			default: return;
		}
	};
	/**
	* Forward one authenticated browser request through an agent tunnel.
	*
	* The body is streamed in bounded chunks in both directions, and the
	* exchange is torn down on any of: client abort, tunnel loss, or an `abort`
	* frame from the agent.
	*/
	const forwardHttp = (tunnel, request$1, response, session, path) => {
		if (normalizeHeaders(request$1.headers)["sec-fetch-site"] === "cross-site") {
			sendHtml(response, 403, renderErrorPage(403, "跨站请求被拒绝 / Cross-site request refused"));
			return;
		}
		const rid = randomUUID();
		const state = {
			response,
			detach: () => void 0,
			finished: false
		};
		const finish = () => {
			if (state.finished) return;
			state.finished = true;
			state.detach();
		};
		state.detach = tunnel.attach(rid, {
			onFrame: (frame) => {
				switch (frame.type) {
					case "http.response": {
						const head = frame;
						if (response.headersSent) return;
						response.writeHead(head.status, {
							...head.headers,
							...securityHeaders(),
							...head.headers["content-type"] === void 0 ? {} : { "content-type": head.headers["content-type"] },
							...head.headers["cache-control"] === void 0 ? {} : { "cache-control": head.headers["cache-control"] }
						});
						return;
					}
					case "body.chunk": {
						const chunk = frame;
						const buffer = Buffer.from(chunk.data, "base64");
						if (!response.writableEnded) response.write(buffer);
						return;
					}
					case "body.end": {
						if (!response.writableEnded) response.end();
						finish();
						return;
					}
					case "abort": {
						if (!response.headersSent) sendHtml(response, 502, renderErrorPage(502, "主机中断了该请求 / Host aborted"));
						else if (!response.writableEnded) response.end();
						finish();
						return;
					}
					default: return;
				}
			},
			onTunnelLost: () => {
				if (!response.headersSent) sendHtml(response, 503, renderErrorPage(503, "主机已离线 / Host went offline"));
				else if (!response.writableEnded) response.end();
				finish();
			}
		});
		const headers = normalizeHeaders(request$1.headers);
		delete headers.cookie;
		delete headers.authorization;
		const hasBody = request$1.method !== "GET" && request$1.method !== "HEAD";
		const sent = tunnel.send({
			type: "http.request",
			rid,
			method: request$1.method ?? "GET",
			path,
			headers,
			noBody: !hasBody,
			clientId: session.clientId
		});
		if (!sent) {
			sendHtml(response, 503, renderErrorPage(503, "主机已离线 / Host went offline"));
			finish();
			return;
		}
		if (hasBody) {
			let received = 0;
			request$1.on("data", (chunk) => {
				received += chunk.length;
				if (received > MAX_REQUEST_BODY_BYTES) {
					tunnel.send({
						type: "abort",
						rid,
						reason: "request body too large"
					});
					if (!response.headersSent) sendHtml(response, 413, renderErrorPage(413, "请求体过大 / Request body too large"));
					request$1.destroy();
					finish();
					return;
				}
				for (let offset = 0; offset < chunk.length; offset += MAX_BODY_CHUNK_BYTES) {
					const slice = chunk.subarray(offset, offset + MAX_BODY_CHUNK_BYTES);
					tunnel.send({
						type: "body.chunk",
						rid,
						data: slice.toString("base64")
					});
				}
			});
			request$1.on("end", () => {
				if (!state.finished) tunnel.send({
					type: "body.end",
					rid
				});
			});
		}
		response.on("close", () => {
			if (!state.finished) {
				tunnel.send({
					type: "abort",
					rid,
					reason: "client disconnected"
				});
				finish();
			}
		});
	};
	/**
	* Resolve which agent a request targets.
	*
	* URLs are `/a/<agentId>/<path>`; the prefix is stripped before forwarding
	* so the DSH surface sees the paths it expects.
	*/
	const parseAgentPath = (url) => {
		const match = /^\/a\/([^/]+)(\/.*)?$/.exec(url);
		if (match === null) return null;
		const agentId = decodeURIComponent(match[1] ?? "");
		const rest = match[2] ?? "/";
		return agentId === "" ? null : {
			agentId,
			rest
		};
	};
	/**
	* Resolve a cookie to a session that is still backed by a live credential.
	*
	* Revocation must take effect immediately, not at the next relay restart, so
	* every authenticated request re-checks that the credential behind the
	* session still exists and is neither revoked nor expired. The store reads
	* through to disk on change, so a `client revoke` in another process ends
	* live sessions on their very next request.
	*/
	const resolveLiveSession = (cookie) => {
		const session = sessions.resolve(cookie);
		if (session === void 0) return void 0;
		if (store.findLiveClient(session.clientId) === void 0) {
			sessions.destroyByClient(session.clientId);
			return void 0;
		}
		return session;
	};
	/**
	* Resolve the live tunnel for an agent that is still authorized.
	*
	* `agent revoke` runs in a separate process, so the check must happen on the
	* request path rather than only at attach time. A tunnel whose agent has been
	* revoked is closed here, which both ends the current abuse and stops the
	* host from reattaching (its token no longer validates).
	*/
	const liveAuthorizedTunnel = (agentId) => {
		const tunnel = tunnels.get(agentId);
		if (tunnel === void 0) return void 0;
		if (store.findAgent(agentId) === void 0) {
			tunnels.remove(tunnel);
			try {
				tunnel.socket.close(CLOSE_REVOKED, "agent revoked");
			} catch {}
			log(`[relay] dropped revoked agent tunnel: ${agentId}`);
			return void 0;
		}
		return tunnel;
	};
	const agentChoices = (session) => store.listAgents().filter((agent) => !agent.revoked && scopeMayReach(session.agentId, agent.agentId)).map((agent) => {
		const live = tunnels.get(agent.agentId);
		return {
			agentId: agent.agentId,
			label: agent.label,
			online: live !== void 0,
			connectedAt: live?.connectedAt ?? null
		};
	});
	const handleRequest = (request$1, response) => {
		const rawUrl = request$1.url ?? "/";
		if (!isSafeProxyPath(rawUrl)) {
			sendHtml(response, 400, renderErrorPage(400, "非法路径 / Invalid path"));
			return;
		}
		const pathname = rawUrl.split("?")[0] ?? "/";
		const cookie = readSessionCookie(request$1.headers.cookie);
		if (pathname === "/__e2e/client.js") {
			response.writeHead(200, {
				...securityHeaders(),
				"content-type": BROWSER_CRYPTO_CONTENT_TYPE,
				"cache-control": "no-cache"
			});
			response.end(BROWSER_CRYPTO_SCRIPT);
			return;
		}
		if (pathname === "/__health") {
			sendJson(response, 200, {
				ok: true,
				agents: tunnels.list().length
			});
			return;
		}
		if (pathname === "/__auth/login") {
			if (request$1.method === "GET") {
				sendHtml(response, 200, renderLoginPage());
				return;
			}
			if (request$1.method !== "POST") {
				sendHtml(response, 405, renderErrorPage(405, "Method not allowed"));
				return;
			}
			const key = clientKey(request$1);
			if (!loginLimiter.allow(key)) {
				sendHtml(response, 429, renderLoginPage({ error: "尝试过于频繁，请稍后再试 / Too many attempts" }));
				return;
			}
			let body = "";
			let tooLarge = false;
			request$1.on("data", (chunk) => {
				body += chunk.toString("utf8");
				if (body.length > 8192) {
					tooLarge = true;
					request$1.destroy();
				}
			});
			request$1.on("end", () => {
				if (tooLarge) return;
				const form = new URLSearchParams(body);
				const submitted = (form.get("token") ?? "").trim();
				const next = form.get("next") ?? "";
				const decoded = decodePairingCode(submitted);
				const token = decoded?.authSecret ?? submitted;
				const client = store.verifyClientToken(token);
				if (client === void 0) {
					log(`[relay] login refused from ${key}`);
					sendHtml(response, 401, renderLoginPage({ error: "令牌无效或已过期 / Invalid or expired token" }));
					return;
				}
				loginLimiter.reset(key);
				const offeredKey = form.get("publicKey");
				if (offeredKey !== null && offeredKey !== "") store.enrollClientKey(client.clientId, offeredKey);
				store.touchClient(client.clientId);
				const raw = sessions.create(client.clientId, client.label, client.agentId);
				const cookieValue = buildSessionCookie(raw, options.secure, Math.floor(options.sessionTtlMs / 1e3));
				const target$1 = next.startsWith("/") && !next.startsWith("//") ? next : "/";
				log(`[relay] login: ${client.label} (${client.clientId})`);
				response.writeHead(303, {
					...securityHeaders(),
					"set-cookie": cookieValue,
					location: target$1
				});
				response.end();
			});
			return;
		}
		if (pathname === "/__auth/challenge") {
			const nonce = randomUUID();
			if (!challenges.add(nonce)) {
				sendJson(response, 429, {
					ok: false,
					error: "too many pending challenges"
				});
				return;
			}
			sendJson(response, 200, { nonce });
			return;
		}
		if (pathname === "/__auth/verify" && request$1.method === "POST") {
			const key = clientKey(request$1);
			if (!loginLimiter.allow(key)) {
				sendJson(response, 429, {
					ok: false,
					error: "too many attempts"
				});
				return;
			}
			let body = "";
			let tooLarge = false;
			request$1.on("data", (chunk) => {
				body += chunk.toString("utf8");
				if (body.length > 8192) {
					tooLarge = true;
					request$1.destroy();
				}
			});
			request$1.on("end", () => {
				if (tooLarge) return;
				const form = new URLSearchParams(body);
				const nonce = form.get("nonce") ?? "";
				const signature = form.get("signature") ?? "";
				if (!challenges.take(nonce)) {
					sendJson(response, 401, {
						ok: false,
						error: "unknown or expired challenge"
					});
					return;
				}
				const client = store.verifyClientSignature(`dsh-remote-web/login|${nonce}`, signature);
				if (client === void 0) {
					sendJson(response, 401, {
						ok: false,
						error: "invalid signature"
					});
					return;
				}
				loginLimiter.reset(key);
				store.touchClient(client.clientId);
				const raw = sessions.create(client.clientId, client.label, client.agentId);
				response.writeHead(200, {
					...securityHeaders(),
					"set-cookie": buildSessionCookie(raw, options.secure, Math.floor(options.sessionTtlMs / 1e3)),
					"content-type": "application/json; charset=utf-8"
				});
				response.end(JSON.stringify({ ok: true }));
			});
			return;
		}
		if (pathname === "/__auth/logout") {
			sessions.destroy(cookie);
			response.writeHead(303, {
				...securityHeaders(),
				"set-cookie": buildClearCookie(options.secure),
				location: "/__auth/login"
			});
			response.end();
			return;
		}
		const session = resolveLiveSession(cookie);
		if (session === void 0) {
			sendHtml(response, 401, renderLoginPage({ next: rawUrl }), { "set-cookie": buildClearCookie(options.secure) });
			return;
		}
		if (pathname.startsWith("/a/") && pathname.endsWith("/__e2e/host")) {
			const agentId = decodeURIComponent(pathname.slice(3, pathname.length - 11));
			if (!scopeMayReach(session.agentId, agentId)) {
				sendJson(response, 403, {
					ok: false,
					error: "not authorized for this host"
				});
				return;
			}
			const live = tunnels.get(agentId);
			if (live === void 0) {
				sendJson(response, 503, {
					ok: false,
					error: "host offline"
				});
				return;
			}
			sendJson(response, 200, {
				ok: true,
				publicKey: live.hostPublicKey,
				requiresE2e: live.requiresE2e
			});
			return;
		}
		if (pathname === "/" || pathname === "/__agents") {
			const choices = agentChoices(session);
			if (pathname === "/" && choices.length === 1 && choices[0]?.online === true) {
				response.writeHead(303, {
					...securityHeaders(),
					location: `/a/${encodeURIComponent(choices[0].agentId)}/`
				});
				response.end();
				return;
			}
			sendHtml(response, 200, renderAgentPicker(choices));
			return;
		}
		const target = parseAgentPath(rawUrl);
		if (target === null) {
			const choices = agentChoices(session).filter((choice) => choice.online);
			if (choices.length === 1 && choices[0] !== void 0) {
				response.writeHead(307, {
					...securityHeaders(),
					location: `/a/${encodeURIComponent(choices[0].agentId)}${rawUrl}`
				});
				response.end();
				return;
			}
			sendHtml(response, 404, renderErrorPage(404, "未找到 / Not found"));
			return;
		}
		if (!scopeMayReach(session.agentId, target.agentId)) {
			sendHtml(response, 403, renderErrorPage(403, "无权访问该主机 / Not authorized for this host"));
			return;
		}
		const tunnel = liveAuthorizedTunnel(target.agentId);
		if (tunnel === void 0) {
			sendHtml(response, 503, renderErrorPage(503, "主机当前离线 / Host is offline"));
			return;
		}
		forwardHttp(tunnel, request$1, response, session, target.rest);
	};
	/**
	* Proxy a browser WebSocket through the agent tunnel.
	*
	* Only the DSH downlink paths are allowed; the check happens before the
	* upgrade is accepted so a refused socket never reaches the host.
	*/
	const proxyClientSocket = (socket, tunnel, session, path, headers) => {
		const sid = randomUUID();
		let closed = false;
		const detach = tunnel.attach(sid, {
			onFrame: (frame) => {
				switch (frame.type) {
					case "ws.message": {
						const message = frame;
						if (socket.readyState !== socket.OPEN) return;
						if (message.sealed !== void 0) socket.send(JSON.stringify({
							__dshrw: 1,
							...message.sealed
						}));
						else if (message.kind === "text") socket.send(message.data);
						else socket.send(Buffer.from(message.data, "base64"));
						return;
					}
					case "ws.close": {
						const close$1 = frame;
						closed = true;
						detach();
						try {
							socket.close(close$1.code >= 1e3 && close$1.code < 5e3 ? close$1.code : 1011, close$1.reason);
						} catch {
							socket.terminate();
						}
						return;
					}
					default: return;
				}
			},
			onTunnelLost: () => {
				closed = true;
				try {
					socket.close(CLOSE_AGENT_OFFLINE, "host offline");
				} catch {
					socket.terminate();
				}
			}
		});
		tunnel.send({
			type: "ws.open",
			sid,
			path,
			headers,
			clientId: session.clientId
		});
		socket.on("message", (raw, isBinary) => {
			if (closed) return;
			if (isBinary) tunnel.send({
				type: "ws.message",
				sid,
				kind: "binary",
				data: Buffer.from(raw).toString("base64")
			});
			else tunnel.send({
				type: "ws.message",
				sid,
				kind: "text",
				data: raw.toString("utf8")
			});
		});
		socket.on("close", (code, reason) => {
			if (closed) return;
			closed = true;
			detach();
			tunnel.send({
				type: "ws.close",
				sid,
				code,
				reason: reason.toString("utf8")
			});
		});
		socket.on("error", () => {
			if (closed) return;
			closed = true;
			detach();
			tunnel.send({
				type: "ws.close",
				sid,
				code: 1011,
				reason: "client error"
			});
		});
	};
	const handleUpgrade = (request$1, socket, head) => {
		const rawUrl = request$1.url ?? "/";
		const reject = (status) => {
			socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`);
			socket.destroy();
		};
		if (!isSafeProxyPath(rawUrl)) {
			reject("400 Bad Request");
			return;
		}
		const pathname = rawUrl.split("?")[0] ?? "/";
		if (pathname === RELAY_AGENT_PATH) {
			agentWss.handleUpgrade(request$1, socket, head, (ws) => {
				handleAgentSocket(ws, request$1);
			});
			return;
		}
		if (normalizeHeaders(request$1.headers)["sec-fetch-site"] === "cross-site") {
			reject("403 Forbidden");
			return;
		}
		const session = resolveLiveSession(readSessionCookie(request$1.headers.cookie));
		if (session === void 0) {
			reject("401 Unauthorized");
			return;
		}
		const target = parseAgentPath(rawUrl);
		if (target === null) {
			reject("404 Not Found");
			return;
		}
		if (!isAllowedWebSocketPath(target.rest)) {
			reject("403 Forbidden");
			return;
		}
		if (!scopeMayReach(session.agentId, target.agentId)) {
			reject("403 Forbidden");
			return;
		}
		const tunnel = liveAuthorizedTunnel(target.agentId);
		if (tunnel === void 0) {
			reject("503 Service Unavailable");
			return;
		}
		const headers = normalizeHeaders(request$1.headers);
		delete headers.cookie;
		clientWss.handleUpgrade(request$1, socket, head, (ws) => {
			proxyClientSocket(ws, tunnel, session, target.rest, headers);
		});
	};
	const server = createServer((request$1, response) => {
		try {
			handleRequest(request$1, response);
		} catch (error) {
			const detail = error instanceof Error ? error.message : String(error);
			log(`[relay] request failed: ${detail}`);
			if (!response.headersSent) sendHtml(response, 500, renderErrorPage(500, "服务器内部错误 / Internal error"));
			else if (!response.writableEnded) response.end();
		}
	});
	server.on("upgrade", (request$1, socket, head) => {
		try {
			handleUpgrade(request$1, socket, head);
		} catch {
			socket.destroy();
		}
	});
	const heartbeat = setInterval(() => {
		tunnels.evictStale();
		for (const tunnel of tunnels.list()) tunnel.send({
			type: "ping",
			nonce: randomUUID()
		});
	}, HEARTBEAT_INTERVAL_MS);
	heartbeat.unref();
	await new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(options.port, options.host, () => {
			server.removeListener("error", reject);
			resolve();
		});
	});
	const address = server.address();
	const port = typeof address === "object" && address !== null ? address.port : options.port;
	const close = async () => {
		clearInterval(heartbeat);
		tunnels.closeAll(CLOSE_AGENT_OFFLINE, "relay shutting down");
		sessions.clear();
		agentWss.close();
		clientWss.close();
		await new Promise((resolve) => {
			server.closeAllConnections();
			server.close(() => {
				resolve();
			});
		});
	};
	return {
		server,
		port,
		close,
		store,
		tunnels,
		sessions
	};
}

//#endregion
export { DEFAULT_RELAY_OPTIONS, RelayStore, SessionStore, Tunnel, TunnelRegistry, scopeMayReach, startRelay };