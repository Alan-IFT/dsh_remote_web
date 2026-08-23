import { CLOSE_AUTH_FAILED, CLOSE_E2E_REQUIRED, CLOSE_REVOKED, CLOSE_UNSUPPORTED_VERSION, E2E_ENVELOPE_HEADER, E2E_ID_HEADER, E2E_KEY_PARAM, HEARTBEAT_TIMEOUT_MS, MAX_BODY_CHUNK_BYTES, MAX_CONTROL_FRAME_BYTES, MAX_REQUEST_BODY_BYTES, MAX_WS_MESSAGE_BYTES, PROTOCOL_VERSION, RELAY_AGENT_PATH, agentChallenge, deriveSessionKey, fingerprint, generateEphemeralKeyPair, hashToken, isAllowedWebSocketPath, isSafeProxyPath, open, parseFrame, readEnvelopeHeader, rewriteRequestHeaders, rewriteResponseHeaders, seal, signMessage } from "./headers-B1leP-qx.js";
import { defaultCredentialPath, dshHome, openCredentials, openStatus, resolvePluginConfig, stateDir, statusPath } from "./config-LzdmX5ds.js";
import Schema from "@deepseek-ai/schemastery";
import { randomBytes } from "node:crypto";
import { request } from "node:http";
import WebSocket from "ws";

//#region src/plugin/tunnel.ts
/** Close codes after which retrying is pointless until the operator acts. */
const TERMINAL_CLOSE_CODES = new Set([
	CLOSE_AUTH_FAILED,
	CLOSE_UNSUPPORTED_VERSION,
	CLOSE_E2E_REQUIRED,
	CLOSE_REVOKED
]);
/**
* Manages one outbound tunnel, including reconnection.
*
* Lifecycle: {@link start} begins dialing and keeps redialing with exponential
* backoff until {@link stop}, or until the relay refuses us in a way that
* cannot be fixed by retrying (bad token, revoked agent, protocol mismatch).
*/
var TunnelClient = class {
	#credentials;
	#config;
	#log;
	#socket = null;
	#state = "disabled";
	#stopped = true;
	#retryDelay;
	#retryTimer = null;
	#livenessTimer = null;
	#connectedAt = null;
	#lastError = null;
	/**
	* In-flight loopback requests, keyed by the relay's request id.
	*
	* The received-byte count lives on the entry rather than in a parallel map:
	* the two share a key and a lifetime, and keeping them apart meant every
	* cleanup path had to remember to delete twice — five such pairs, where one
	* missed line would have leaked.
	*/
	#requests = new Map();
	/** Proxied sockets to the local DSH server, keyed by the relay's socket id. */
	#sockets = new Map();
	/**
	* Session key per exchange, present only for end-to-end encrypted requests.
	*
	* Derived from the browser's ephemeral public key and this machine's
	* encryption token, so the relay — which has neither — cannot reconstruct it
	* even though it carried the handshake.
	*/
	/**
	* Encryption state per encrypted context, keyed by exchange id or socket id.
	*
	* One table serves both planes because they need the same two things: the
	* session key, and the value that key's payloads are authenticated against.
	* Only the AAD differs — an HTTP exchange binds to its request id, a stream
	* binds to its path — and that difference is data, not structure.
	*/
	#contexts = new Map();
	/**
	* This host's ephemeral X25519 keypair for the lifetime of the client.
	*
	* Browsers combine their own ephemeral key with this one and the shared
	* encryption token, so the relay carrying both public keys still derives
	* nothing.
	*/
	#ephemeral = generateEphemeralKeyPair();
	constructor(credentials, config, log) {
		this.#credentials = credentials;
		this.#config = config;
		this.#log = log;
		this.#retryDelay = config.initialRetryMs;
	}
	/**
	* This host's ephemeral public key.
	*
	* A browser needs it to derive the session key. It is public by design: on
	* its own it yields nothing, because deriving the key also requires the
	* encryption token, which the relay never receives.
	*/
	get publicKey() {
		return this.#ephemeral.publicKey;
	}
	/**
	* Serve one sealed exchange directly, bypassing the relay socket.
	*
	* Exposed so tests can drive the real decrypt → proxy → encrypt path against
	* a live local server without standing up a browser. It uses exactly the
	* production code path; nothing here is a test-only shortcut.
	*/
	async handleSealedRequestForTest(rid, envelope) {
		return await this.#captureExchange(rid, () => {
			this.#openLocalRequest({
				type: "http.request",
				rid,
				method: "GET",
				path: "/",
				headers: {
					[E2E_ID_HEADER]: rid,
					[E2E_ENVELOPE_HEADER]: Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url")
				},
				noBody: true,
				clientId: "test"
			});
		});
	}
	/** Serve one unencrypted exchange directly; see {@link handleSealedRequestForTest}. */
	async handlePlainRequestForTest(rid, path) {
		const captured = await this.#captureExchange(rid, () => {
			this.#openLocalRequest({
				type: "http.request",
				rid,
				method: "GET",
				path,
				headers: {},
				noBody: true,
				clientId: "test"
			});
		});
		return {
			status: captured.status,
			body: captured.plainBody
		};
	}
	/**
	* Intercept the frames one exchange would have sent to the relay.
	*
	* The interception point is `#send`, so the frames observed are byte-for-byte
	* the ones a relay would receive — which is what makes the confidentiality
	* assertions meaningful.
	*/
	async #captureExchange(rid, start) {
		const original = this.#testSink;
		return await new Promise((resolve) => {
			let status = 0;
			let bodyEnvelope = {
				epk: "",
				salt: "",
				n: "",
				c: "",
				t: ""
			};
			let plainBody = "";
			this.#testSink = (frame) => {
				if (frame.type === "http.response" && frame.rid === rid) status = frame.status;
				if (frame.type === "body.chunk" && frame.rid === rid) if (frame.sealed !== void 0) bodyEnvelope = frame.sealed;
				else plainBody += Buffer.from(frame.data, "base64").toString("utf8");
				if (frame.type === "body.end" && frame.rid === rid) {
					this.#testSink = original;
					resolve({
						status,
						bodyEnvelope,
						plainBody
					});
				}
			};
			start();
		});
	}
	/** Optional frame interceptor used by the test seams above. */
	#testSink = null;
	/** Current status snapshot. */
	status() {
		return {
			state: this.#state,
			relayUrl: this.#credentials.relayUrl,
			agentId: this.#credentials.agentId,
			label: this.#credentials.label,
			tokenFingerprint: fingerprint(hashToken(this.#credentials.encryptionToken)),
			lastError: this.#lastError,
			connectedAt: this.#connectedAt,
			activeRequests: this.#requests.size,
			activeSockets: this.#sockets.size
		};
	}
	/** Begin connecting and keep the tunnel up until {@link stop}. */
	start() {
		if (!this.#stopped) return;
		this.#stopped = false;
		this.#lastError = null;
		this.#connect();
	}
	/** Tear the tunnel down and cancel any pending reconnect. */
	stop() {
		this.#stopped = true;
		this.#state = "disabled";
		if (this.#retryTimer !== null) {
			clearTimeout(this.#retryTimer);
			this.#retryTimer = null;
		}
		if (this.#livenessTimer !== null) {
			clearInterval(this.#livenessTimer);
			this.#livenessTimer = null;
		}
		this.#teardownExchanges();
		const socket = this.#socket;
		this.#socket = null;
		if (socket !== null) try {
			socket.close(1e3, "plugin shutting down");
		} catch {
			socket.terminate();
		}
	}
	/** Abort every in-flight exchange; used on disconnect and shutdown. */
	#teardownExchanges() {
		for (const entry of this.#requests.values()) entry.upstream.destroy();
		this.#requests.clear();
		this.#contexts.clear();
		for (const socket of this.#sockets.values()) try {
			socket.close(1001, "tunnel closed");
		} catch {
			socket.terminate();
		}
		this.#sockets.clear();
	}
	/** Absolute WebSocket URL of the relay's agent endpoint. */
	#relayWsUrl() {
		const url = new URL(this.#credentials.relayUrl);
		url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
		url.pathname = `${url.pathname.replace(/\/$/, "")}${RELAY_AGENT_PATH}`;
		url.search = "";
		return url.toString();
	}
	#scheduleRetry() {
		if (this.#stopped) return;
		this.#state = "retrying";
		const jitter = Math.floor(Math.random() * 500);
		const delay = Math.min(this.#retryDelay, this.#config.maxRetryMs) + jitter;
		this.#retryTimer = setTimeout(() => {
			this.#retryTimer = null;
			this.#connect();
		}, delay);
		this.#retryTimer.unref?.();
		this.#retryDelay = Math.min(this.#retryDelay * 2, this.#config.maxRetryMs);
	}
	#connect() {
		if (this.#stopped) return;
		this.#state = "connecting";
		let socket;
		try {
			socket = new WebSocket(this.#relayWsUrl(), {
				maxPayload: MAX_CONTROL_FRAME_BYTES,
				handshakeTimeout: 15e3
			});
		} catch (error) {
			this.#lastError = error instanceof Error ? error.message : String(error);
			this.#scheduleRetry();
			return;
		}
		this.#socket = socket;
		socket.on("open", () => {
			const ts = Date.now();
			const nonce = randomBytes(16).toString("hex");
			socket.send(JSON.stringify({
				type: "hello",
				v: PROTOCOL_VERSION,
				agentId: this.#credentials.agentId,
				ts,
				nonce,
				signature: signMessage(agentChallenge(this.#credentials.agentId, ts, nonce), this.#credentials.privateKey),
				label: this.#credentials.label,
				agentVersion: "0.1.0",
				e2e: this.#credentials.requireE2e,
				epk: this.#ephemeral.publicKey
			}));
		});
		let lastFrameAt = Date.now();
		this.#livenessTimer = setInterval(() => {
			if (Date.now() - lastFrameAt > HEARTBEAT_TIMEOUT_MS) {
				this.#log.warn("[dsh-remote-web] relay went quiet; reconnecting");
				try {
					socket.close(1001, "heartbeat timeout");
				} catch {
					socket.terminate();
				}
			}
		}, 15e3);
		this.#livenessTimer.unref?.();
		socket.on("message", (raw, isBinary) => {
			if (isBinary) return;
			lastFrameAt = Date.now();
			const frame = parseFrame(raw.toString("utf8"));
			if (frame === null) return;
			this.#handleFrame(socket, frame);
		});
		socket.on("close", (code, reason) => {
			if (this.#livenessTimer !== null) {
				clearInterval(this.#livenessTimer);
				this.#livenessTimer = null;
			}
			this.#teardownExchanges();
			this.#connectedAt = null;
			if (this.#socket === socket) this.#socket = null;
			if (this.#stopped) return;
			const detail = reason.toString("utf8");
			if (TERMINAL_CLOSE_CODES.has(code)) {
				this.#state = "refused";
				this.#lastError = detail === "" ? `relay refused the tunnel (code ${String(code)})` : detail;
				this.#log.warn(`[dsh-remote-web] relay refused this host: ${this.#lastError}. Run \`dsh-remote-web setup\` again to re-pair.`);
				return;
			}
			this.#lastError = detail === "" ? `disconnected (code ${String(code)})` : detail;
			this.#scheduleRetry();
		});
		socket.on("error", (error) => {
			this.#lastError = error.message;
		});
	}
	#send(frame) {
		if (this.#testSink !== null) {
			this.#testSink(frame);
			return;
		}
		const socket = this.#socket;
		if (socket === null || socket.readyState !== WebSocket.OPEN) return;
		socket.send(JSON.stringify(frame));
	}
	#handleFrame(socket, frame) {
		switch (frame.type) {
			case "hello.ack": {
				this.#state = "online";
				this.#connectedAt = Date.now();
				this.#retryDelay = this.#config.initialRetryMs;
				this.#lastError = null;
				this.#log.info(`[dsh-remote-web] tunnel online at ${this.#credentials.relayUrl} as "${this.#credentials.label}"`);
				return;
			}
			case "ping": {
				this.#send({
					type: "pong",
					nonce: frame.nonce
				});
				return;
			}
			case "error": {
				this.#lastError = frame.message;
				if (frame.fatal) {
					this.#state = "refused";
					this.#log.warn(`[dsh-remote-web] relay error: ${frame.message}`);
					try {
						socket.close(1e3, "fatal relay error");
					} catch {
						socket.terminate();
					}
				}
				return;
			}
			case "http.request":
				this.#openLocalRequest(frame);
				return;
			case "body.chunk": {
				const entry = this.#requests.get(frame.rid);
				if (entry === void 0) return;
				const buffer = Buffer.from(frame.data, "base64");
				entry.received += buffer.length;
				if (entry.received > MAX_REQUEST_BODY_BYTES) {
					this.#send({
						type: "abort",
						rid: frame.rid,
						reason: "request body too large"
					});
					entry.upstream.destroy();
					this.#requests.delete(frame.rid);
					return;
				}
				entry.upstream.write(buffer);
				return;
			}
			case "body.end": {
				this.#requests.get(frame.rid)?.upstream.end();
				return;
			}
			case "abort": {
				const entry = this.#requests.get(frame.rid);
				if (entry !== void 0) {
					entry.upstream.destroy();
					this.#requests.delete(frame.rid);
				}
				return;
			}
			case "ws.open":
				this.#openLocalSocket(frame);
				return;
			case "ws.message": {
				const socketToLocal = this.#sockets.get(frame.sid);
				if (socketToLocal === void 0 || socketToLocal.readyState !== WebSocket.OPEN) return;
				if (frame.sealed !== void 0) {
					const opened = this.#openFor(frame.sid, frame.sealed);
					if (opened === null) return;
					socketToLocal.send(opened);
					return;
				}
				if (frame.kind === "text") socketToLocal.send(frame.data);
				else socketToLocal.send(Buffer.from(frame.data, "base64"));
				return;
			}
			case "ws.close": {
				const socketToLocal = this.#sockets.get(frame.sid);
				this.#sockets.delete(frame.sid);
				this.#contexts.delete(frame.sid);
				if (socketToLocal === void 0) return;
				try {
					socketToLocal.close(frame.code >= 1e3 && frame.code < 5e3 ? frame.code : 1001, frame.reason);
				} catch {
					socketToLocal.terminate();
				}
				return;
			}
			default: return;
		}
	}
	/**
	* Establish an encryption context from a peer's envelope, and open it.
	*
	* The counterpart to {@link #openFor}, which uses a context already
	* established. HTTP establishes one per request because each request carries
	* its own ephemeral key; a stream establishes one at open and reuses it. The
	* two planes differ in when this runs, not in what it does.
	*
	* @returns Plaintext, or `null` when authentication fails — covering a
	*          tampered payload, a wrong token, and a misdirected one alike.
	*/
	#establishContext(envelope, id) {
		try {
			const key = deriveSessionKey(this.#ephemeral.privateKey, envelope.epk, this.#credentials.encryptionToken);
			const plaintext = open({
				n: envelope.n,
				c: envelope.c,
				t: envelope.t
			}, key, id);
			if (plaintext !== null) this.#contexts.set(id, {
				key,
				aad: id
			});
			return plaintext;
		} catch {
			return null;
		}
	}
	/**
	* Seal an outbound payload for whichever peer owns this context.
	*
	* @param id - Exchange id for an HTTP response, socket id for a stream frame.
	* @returns The envelope, or `null` when that context is not encrypted, which
	*          is how the plaintext path stays a single branch at each call site.
	*/
	#sealFor(id, plaintext) {
		const context = this.#contexts.get(id);
		if (context === void 0) return null;
		const sealed = seal(plaintext, context.key, context.aad);
		return {
			epk: this.#ephemeral.publicKey,
			salt: "",
			n: sealed.n,
			c: sealed.c,
			t: sealed.t
		};
	}
	/**
	* Open an inbound payload on an established context.
	*
	* @returns Plaintext, or `null` when authentication fails — covering a
	*          tampered frame, a wrong token, and a frame moved to another
	*          context alike.
	*/
	#openFor(id, envelope) {
		const context = this.#contexts.get(id);
		if (context === void 0) return null;
		return open({
			n: envelope.n,
			c: envelope.c,
			t: envelope.t
		}, context.key, context.aad);
	}
	/** Answer an exchange with a plain status and no upstream call. */
	#refuse(rid, status, reason) {
		this.#send({
			type: "http.response",
			rid,
			status,
			headers: { "content-type": "text/plain; charset=utf-8" }
		});
		this.#send({
			type: "body.chunk",
			rid,
			data: Buffer.from(reason, "utf8").toString("base64")
		});
		this.#send({
			type: "body.end",
			rid
		});
		this.#contexts.delete(rid);
	}
	/**
	* Re-issue a forwarded request against the local DSH server.
	*
	* The request is rebuilt rather than replayed: headers are rewritten so DSH
	* sees a loopback, same-origin request (see `shared/headers.ts` for why that
	* is safe), and the response is streamed back in bounded chunks.
	*/
	#openLocalRequest(frame) {
		if (!isSafeProxyPath(frame.path)) {
			this.#send({
				type: "abort",
				rid: frame.rid,
				reason: "invalid path"
			});
			return;
		}
		const sealed = readEnvelopeHeader(frame.headers);
		const rid = frame.headers[E2E_ID_HEADER] ?? frame.rid;
		let request$1;
		if (sealed !== void 0) {
			const opened = this.#establishContext(sealed, rid);
			if (opened === null) {
				this.#refuse(frame.rid, 403, "end-to-end decryption failed");
				return;
			}
			try {
				request$1 = JSON.parse(opened.toString("utf8"));
			} catch {
				this.#refuse(frame.rid, 400, "malformed encrypted request");
				return;
			}
			if (!isSafeProxyPath(request$1.path)) {
				this.#refuse(frame.rid, 400, "invalid path");
				return;
			}
			const opened2 = this.#contexts.get(rid);
			if (opened2 !== void 0) this.#contexts.set(frame.rid, opened2);
		} else if (this.#credentials.requireE2e) {
			this.#refuse(frame.rid, 403, "this host requires end-to-end encryption");
			return;
		} else request$1 = {
			method: frame.method,
			path: frame.path,
			headers: frame.headers
		};
		const headers = rewriteRequestHeaders(request$1.headers);
		const upstream = request({
			host: this.#config.localHost,
			port: this.#config.localPort,
			method: request$1.method,
			path: request$1.path,
			headers
		}, (response) => {
			const responseHeaders = rewriteResponseHeaders(response.headers);
			const sealedHead = this.#sealFor(frame.rid, Buffer.from(JSON.stringify(responseHeaders), "utf8"));
			this.#send({
				type: "http.response",
				rid: frame.rid,
				status: response.statusCode ?? 502,
				headers: sealedHead === null ? responseHeaders : {},
				...sealedHead === null ? {} : { sealed: sealedHead }
			});
			const isHtml = (responseHeaders["content-type"] ?? "").includes("text/html");
			response.on("data", (rawChunk) => {
				const chunk = isHtml && this.#contexts.has(frame.rid) ? Buffer.from(rawChunk.toString("utf8").replace("<head>", `<head><script src="/__e2e/client.js"></script><script>window.__dshRemoteWebE2E__&&window.__dshRemoteWebE2E__.resume(${JSON.stringify(this.#ephemeral.publicKey)});</script>`), "utf8") : rawChunk;
				for (let offset = 0; offset < chunk.length; offset += MAX_BODY_CHUNK_BYTES) {
					const slice = chunk.subarray(offset, offset + MAX_BODY_CHUNK_BYTES);
					const sealed$1 = this.#sealFor(frame.rid, slice);
					this.#send(sealed$1 === null ? {
						type: "body.chunk",
						rid: frame.rid,
						data: slice.toString("base64")
					} : {
						type: "body.chunk",
						rid: frame.rid,
						data: "",
						sealed: sealed$1
					});
				}
			});
			response.on("end", () => {
				this.#send({
					type: "body.end",
					rid: frame.rid
				});
				this.#requests.delete(frame.rid);
				this.#contexts.delete(frame.rid);
			});
			response.on("error", () => {
				this.#send({
					type: "abort",
					rid: frame.rid,
					reason: "upstream read failed"
				});
				this.#requests.delete(frame.rid);
			});
		});
		upstream.on("error", (error) => {
			this.#send({
				type: "abort",
				rid: frame.rid,
				reason: error.message
			});
			this.#requests.delete(frame.rid);
		});
		this.#requests.set(frame.rid, {
			upstream,
			received: 0
		});
		if (frame.noBody) upstream.end();
	}
	/**
	* Open a WebSocket against the local DSH server for a proxied browser socket.
	*
	* The path allowlist is enforced here as well as on the relay: the host must
	* not depend on a remote party's checks for what it exposes locally.
	*/
	#openLocalSocket(frame) {
		if (!isAllowedWebSocketPath(frame.path)) {
			this.#send({
				type: "ws.close",
				sid: frame.sid,
				code: 1008,
				reason: "path not allowed"
			});
			return;
		}
		const [streamPath = frame.path, query = ""] = frame.path.split("?");
		const browserKey = new URLSearchParams(query).get(E2E_KEY_PARAM);
		if (browserKey !== null && browserKey !== "") try {
			this.#contexts.set(frame.sid, {
				key: deriveSessionKey(this.#ephemeral.privateKey, browserKey, this.#credentials.encryptionToken),
				aad: streamPath
			});
		} catch {
			this.#send({
				type: "ws.close",
				sid: frame.sid,
				code: 1008,
				reason: "bad key exchange"
			});
			return;
		}
		else if (this.#credentials.requireE2e) {
			this.#send({
				type: "ws.close",
				sid: frame.sid,
				code: CLOSE_E2E_REQUIRED,
				reason: "this host requires end-to-end encryption"
			});
			return;
		}
		const authority = `${this.#config.localHost}:${String(this.#config.localPort)}`;
		const headers = rewriteRequestHeaders(frame.headers);
		delete headers.connection;
		delete headers.upgrade;
		let local;
		try {
			local = new WebSocket(`ws://${authority}${frame.path}`, {
				headers,
				maxPayload: MAX_WS_MESSAGE_BYTES,
				handshakeTimeout: 15e3
			});
		} catch (error) {
			const detail = error instanceof Error ? error.message : String(error);
			this.#send({
				type: "ws.close",
				sid: frame.sid,
				code: 1011,
				reason: detail
			});
			return;
		}
		this.#sockets.set(frame.sid, local);
		local.on("open", () => {
			this.#send({
				type: "ws.open.ack",
				sid: frame.sid
			});
		});
		local.on("message", (raw, isBinary) => {
			const kind = isBinary ? "binary" : "text";
			const bytes = isBinary ? Buffer.from(raw) : Buffer.from(raw.toString("utf8"), "utf8");
			const sealed = this.#sealFor(frame.sid, bytes);
			this.#send(sealed === null ? {
				type: "ws.message",
				sid: frame.sid,
				kind,
				data: bytes.toString(isBinary ? "base64" : "utf8")
			} : {
				type: "ws.message",
				sid: frame.sid,
				kind,
				data: "",
				sealed
			});
		});
		local.on("close", (code, reason) => {
			this.#sockets.delete(frame.sid);
			this.#contexts.delete(frame.sid);
			this.#send({
				type: "ws.close",
				sid: frame.sid,
				code,
				reason: reason.toString("utf8")
			});
		});
		local.on("error", (error) => {
			this.#sockets.delete(frame.sid);
			this.#contexts.delete(frame.sid);
			this.#send({
				type: "ws.close",
				sid: frame.sid,
				code: 1011,
				reason: error.message
			});
		});
	}
};

//#endregion
//#region src/index.ts
/** Plugin name as it appears in the loader tree. */
const name = "dsh-remote-web";
/**
* Services required before this plugin mounts.
*
* `webServer` is injected only to learn the port DSH actually bound — the one
* value that stays correct under `--port`, port `0`, or a second DSH on the
* same machine. No route is registered on it.
*/
const inject = ["webServer"];
/** Configuration schema surfaced to the loader and the settings UI. */
const Config = Schema.object({
	enabled: Schema.boolean().default(true).description("Whether the outbound tunnel may connect at all."),
	credentialPath: Schema.string().default("").description("Path to agent.json; empty uses $DSH_HOME/remote-web/agent.json."),
	localHost: Schema.string().default("").description("Local DSH host to proxy; empty uses the bound host."),
	localPort: Schema.number().default(0).description("Local DSH port to proxy; 0 uses the bound port."),
	initialRetryMs: Schema.number().default(1e3).description("Initial reconnect delay."),
	maxRetryMs: Schema.number().default(6e4).description("Maximum reconnect delay.")
});
/** How often the plugin re-reads the credential file and publishes status. */
const POLL_INTERVAL_MS = 2e3;
/**
* Mount the plugin.
*
* @param ctx - The cordis context, carrying `webServer` and effect ownership.
* @param input - Loader-provided configuration.
*/
function apply(ctx, input = {}) {
	const bound = ctx.webServer;
	const boundPort = typeof bound.port === "number" && bound.port > 0 ? bound.port : void 0;
	const boundHost = bound.host === void 0 || bound.host === "0.0.0.0" ? void 0 : bound.host;
	const config = resolvePluginConfig({
		...input,
		localHost: input.localHost === void 0 || input.localHost === "" ? boundHost : input.localHost,
		localPort: input.localPort === void 0 || input.localPort === 0 ? boundPort : input.localPort
	});
	const log = {
		info: (message) => ctx.logger?.info(message),
		warn: (message) => ctx.logger?.warn(message)
	};
	ctx.effect(() => {
		const credentials = openCredentials(config.credentialPath);
		const status = openStatus(statusPath(config.credentialPath));
		const target = `${config.localHost}:${String(config.localPort)}`;
		let client = null;
		let signature = "";
		let announcedUnconfigured = false;
		/** Values whose change requires rebuilding the tunnel. */
		const signatureOf = (current) => current === null || !current.enabled ? "" : [
			current.relayUrl,
			current.agentId,
			current.privateKey,
			current.encryptionToken,
			String(current.requireE2e)
		].join("|");
		/**
		* Reconcile the running tunnel with the credential file.
		*
		* Polling the file is what replaces an IPC channel: `setup`, `enable`, and
		* `disable` simply write, and the next tick adopts the change.
		*/
		const sync = () => {
			let current;
			try {
				current = credentials.value;
			} catch (error) {
				log.warn(error instanceof Error ? error.message : String(error));
				return;
			}
			if (current === null && !announcedUnconfigured) {
				announcedUnconfigured = true;
				log.info("[dsh-remote-web] not configured. Run `dsh-remote-web setup` on this machine.");
			}
			if (current !== null) announcedUnconfigured = false;
			const next = config.enabled ? signatureOf(current) : "";
			if (next !== signature) {
				signature = next;
				client?.stop();
				client = null;
				if (next !== "" && current !== null) {
					client = new TunnelClient(current, config, log);
					client.start();
				} else if (current !== null && !current.enabled) log.info("[dsh-remote-web] remote access is turned off");
			}
			const snapshot = client?.status();
			status.write({
				version: 1,
				state: snapshot?.state ?? (current === null ? "unconfigured" : "disabled"),
				relayUrl: current?.relayUrl ?? null,
				label: current?.label ?? null,
				localTarget: target,
				tokenFingerprint: snapshot?.tokenFingerprint ?? null,
				lastError: snapshot?.lastError ?? null,
				connectedAt: snapshot?.connectedAt ?? null,
				activeRequests: snapshot?.activeRequests ?? 0,
				activeSockets: snapshot?.activeSockets ?? 0,
				updatedAt: Date.now(),
				pid: process.pid
			});
		};
		sync();
		const timer = setInterval(sync, POLL_INTERVAL_MS);
		timer.unref?.();
		return () => {
			clearInterval(timer);
			client?.stop();
			client = null;
		};
	}, "dsh-remote-web: outbound tunnel");
}

//#endregion
export { Config, TunnelClient, apply, defaultCredentialPath, dshHome, inject, name, openCredentials, openStatus, resolvePluginConfig, stateDir, statusPath };