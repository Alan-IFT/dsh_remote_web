import { dirname, join } from "node:path";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, randomUUID, sign, timingSafeEqual, verify } from "node:crypto";

//#region src/shared/watched-file.ts
/**
* Owner-only JSON file whose in-memory value tracks the file on disk.
*
* @typeParam T - Shape stored in the file.
*/
var WatchedFile = class {
	#path;
	#parse;
	#fallback;
	#stamp = "";
	#value = null;
	/**
	* @param path - File location; parent directories are created on write.
	* @param parse - Validates and normalizes parsed JSON. Throw to reject a
	*                file whose shape is not understood; callers see the throw
	*                rather than a silently empty value.
	* @param fallback - Value used when the file does not exist yet.
	*/
	constructor(path, parse, fallback) {
		this.#path = path;
		this.#parse = parse;
		this.#fallback = fallback;
	}
	/** Absolute path of the backing file. */
	get path() {
		return this.#path;
	}
	/**
	* Identity of the file's current contents.
	*
	* Size joins mtime because two writes can land in the same millisecond here:
	* a CLI command and the relay may both write within one clock tick.
	*/
	#currentStamp() {
		try {
			const stats = statSync(this.#path);
			return `${String(stats.mtimeMs)}:${String(stats.size)}`;
		} catch {
			return "";
		}
	}
	/**
	* The current value, re-read when the file changed since the last access.
	*
	* Cost in the steady state is one `stat`; a parse happens only when the
	* stamp actually moved.
	*/
	get value() {
		const stamp = this.#currentStamp();
		if (stamp !== this.#stamp || this.#value === null) {
			this.#stamp = stamp;
			this.#value = this.#read();
		}
		return this.#value;
	}
	#read() {
		if (!existsSync(this.#path)) return this.#fallback();
		let parsed;
		try {
			parsed = JSON.parse(readFileSync(this.#path, "utf8"));
		} catch (error) {
			const detail = error instanceof Error ? error.message : String(error);
			throw new Error(`dsh-remote-web: ${this.#path} is unreadable (${detail}). Fix or remove the file before continuing.`);
		}
		return this.#parse(parsed);
	}
	/**
	* Replace the file's contents atomically with mode `0600`.
	*
	* Temp-file-plus-rename means a crash mid-write cannot leave a truncated
	* file, which for a credential store would lock the operator out.
	*/
	write(value) {
		const dir = dirname(this.#path);
		mkdirSync(dir, {
			recursive: true,
			mode: 448
		});
		const tmp = join(dir, `.${randomUUID()}.tmp`);
		writeFileSync(tmp, JSON.stringify(value, null, 2), { mode: 384 });
		renameSync(tmp, this.#path);
		try {
			chmodSync(this.#path, 384);
		} catch {}
		this.#value = value;
		this.#stamp = this.#currentStamp();
	}
	/**
	* Apply a mutation to the current value and persist the result.
	*
	* The read is deliberately inside this method: mutating a value fetched
	* earlier would reintroduce the lost-update bug this class exists to
	* prevent.
	*
	* @param mutate - Receives current state; return value is persisted.
	* @returns Whatever `mutate` reports, for callers that need a result.
	*/
	update(mutate) {
		const { next, result } = mutate(this.value);
		this.write(next);
		return result;
	}
	/** Whether the file exists on disk. */
	get exists() {
		return existsSync(this.#path);
	}
};

//#endregion
//#region src/shared/protocol.ts
/**
* Wire protocol between the DSH host plugin (agent), the relay server, and
* remote browsers.
*
* Design constraints that shape every frame below:
*
* - The host makes **outbound connections only**. It dials the relay over
*   WebSocket and never listens on a public port, so the frames must be able
*   to carry a full request/response cycle in the reverse direction.
* - The relay is a **dumb pipe with an auth gate**. It matches a browser
*   session to an agent tunnel and forwards bytes; it never interprets DSH
*   API payloads.
* - Everything is length-bounded. A remote peer must not be able to make the
*   host or the relay allocate without limit.
*
* Frames are JSON text messages except HTTP/WebSocket payload bodies, which
* ride as base64 inside the JSON envelope. Keeping one encoding avoids a
* second framing layer over the WebSocket the relay already gives us.
*
* @module dsh-remote-web/shared/protocol
*/
/**
* Headers a browser uses to carry an end-to-end encrypted request.
*
* The envelope rides as headers rather than as a new frame kind so the relay
* needs no knowledge of encryption at all: it already forwards headers
* verbatim, so "the relay cannot read this" requires no relay code and no
* second code path that could diverge from the plaintext one.
*/
const E2E_ID_HEADER = "x-dshrw-rid";
const E2E_ENVELOPE_HEADER = "x-dshrw-sealed";
/**
* Query parameter carrying a browser's ephemeral public key when it opens an
* encrypted WebSocket.
*
* A browser cannot attach headers to a WebSocket handshake, so this is the one
* channel available. It holds only a public key — useless without the
* encryption token — so a URL is an acceptable place for it.
*/
const E2E_KEY_PARAM = "dshrw_epk";
/** Protocol version; a mismatch is refused at handshake time. */
const PROTOCOL_VERSION = 1;
/** Largest control frame accepted on either side (256 KiB). */
const MAX_CONTROL_FRAME_BYTES = 256 * 1024;
/** Largest single HTTP body chunk carried in one frame (512 KiB pre-base64). */
const MAX_BODY_CHUNK_BYTES = 512 * 1024;
/**
* Largest aggregate request body the host will reassemble (160 MiB), matching
* the DSH `/api` bridge bound so image prompts behave the same remotely.
*/
const MAX_REQUEST_BODY_BYTES = 160 * 1024 * 1024;
/** Largest WebSocket message proxied in either direction (8 MiB). */
const MAX_WS_MESSAGE_BYTES = 8 * 1024 * 1024;
/** Heartbeat interval and liveness deadline for the agent tunnel. */
const HEARTBEAT_INTERVAL_MS = 25e3;
const HEARTBEAT_TIMEOUT_MS = 75e3;
/** WebSocket close codes with agreed meaning across the three parties. */
const CLOSE_AUTH_FAILED = 4001;
const CLOSE_AGENT_REPLACED = 4002;
const CLOSE_AGENT_OFFLINE = 4003;
const CLOSE_UNSUPPORTED_VERSION = 4004;
const CLOSE_RATE_LIMITED = 4005;
const CLOSE_REVOKED = 4006;
/** The peer required end-to-end encryption the other side did not provide. */
const CLOSE_E2E_REQUIRED = 4007;
/** Path on the relay where an agent (DSH host plugin) dials in. */
const RELAY_AGENT_PATH = "/tunnel/v1/agent";
/**
* The exact string an agent signs to prove its identity.
*
* Every field that scopes the proof is inside it: the purpose (so an agent
* signature is useless elsewhere), the agent id (so it speaks for one machine),
* and the freshness pair (so a captured signature expires and cannot repeat).
*/
function agentChallenge(agentId, ts, nonce) {
	return `${AGENT_AUTH_PURPOSE}|${agentId}|${String(ts)}|${nonce}`;
}
/**
* Domain-separation label folded into an agent's signed challenge, so a
* signature made here can never validate in another context.
*/
const AGENT_AUTH_PURPOSE = "dsh-remote-web/agent";
/** Maximum clock skew tolerated when verifying a proof (±2 minutes). */
const AUTH_PROOF_SKEW_MS = 2 * 60 * 1e3;
/** Narrow untrusted JSON to a tunnel frame with a `type` string. */
function isTunnelFrame(value) {
	return typeof value === "object" && value !== null && typeof value.type === "string";
}
/**
* Parse a text frame, enforcing the size bound before `JSON.parse` so a hostile
* peer cannot force a large allocation.
*
* @returns The decoded frame, or `null` when oversized or malformed.
*/
function parseFrame(raw) {
	if (raw.length > MAX_CONTROL_FRAME_BYTES) return null;
	let parsed;
	try {
		parsed = JSON.parse(raw);
	} catch {
		return null;
	}
	return isTunnelFrame(parsed) ? parsed : null;
}

//#endregion
//#region src/shared/auth.ts
/** Bytes of entropy in a generated token. */
const TOKEN_BYTES = 32;
/**
* Generate a fresh token with 256 bits of entropy.
*
* The alphabet is base64url so the value survives QR codes, URLs, shell
* arguments, and environment variables without escaping.
*
* @returns A raw token; the caller must show it once and store only its digest.
*/
function generateToken() {
	return randomBytes(TOKEN_BYTES).toString("base64url");
}
/**
* Hash a token for storage or comparison.
*
* @param token - The raw token.
* @returns Lowercase hex SHA-256 digest.
*/
function hashToken(token) {
	return createHash("sha256").update(token, "utf8").digest("hex");
}
/**
* Compare two strings without leaking their contents through timing.
*
* Lengths are compared first through the digest trick: both sides are hashed
* so unequal lengths cannot short-circuit the comparison itself.
*
* @returns True when the inputs are byte-identical.
*/
function safeEqual(a, b) {
	const left = createHash("sha256").update(a, "utf8").digest();
	const right = createHash("sha256").update(b, "utf8").digest();
	return timingSafeEqual(left, right);
}
/**
* A short, human-readable fingerprint of a token digest, safe to display and
* to log. It identifies which credential is in play without revealing it.
*
* @param digest - Hex digest from {@link hashToken}.
* @returns Twelve hex characters in three dash-separated groups.
*/
function fingerprint(digest) {
	const head = digest.slice(0, 12);
	return `${head.slice(0, 4)}-${head.slice(4, 8)}-${head.slice(8, 12)}`;
}
/**
* A set of one-time values that expire.
*
* Two things need exactly this: an agent's handshake nonce (accept once, within
* a clock window) and a browser's login challenge (issue, then redeem once).
* They were separate implementations until the second one needed the same
* bounds the first already had, which is the signal that one primitive was
* enough.
*
* Both bounds matter and neither is optional: entries expire so a long-running
* relay does not accumulate them, and the count is capped because these values
* are accepted before authentication — an unbounded set would be a free memory
* sink for any unauthenticated caller.
*/
var OneTimeValues = class {
	#seen = new Map();
	#windowMs;
	#limit;
	/**
	* @param windowMs - How long a value stays remembered.
	* @param limit - Maximum retained values; further additions are refused.
	*/
	constructor(windowMs = AUTH_PROOF_SKEW_MS * 2, limit = 1e3) {
		this.#windowMs = windowMs;
		this.#limit = limit;
	}
	#prune(now) {
		for (const [value, at] of this.#seen) if (now - at > this.#windowMs) this.#seen.delete(value);
	}
	/**
	* Record a value, rejecting a repeat.
	*
	* @returns True when the value is new and was retained.
	*/
	add(value, now = Date.now()) {
		this.#prune(now);
		if (this.#seen.has(value) || this.#seen.size >= this.#limit) return false;
		this.#seen.set(value, now);
		return true;
	}
	/**
	* Consume a previously added value.
	*
	* @returns True when the value was present and unexpired; it is removed, so
	*          a second attempt with the same value fails.
	*/
	take(value, now = Date.now()) {
		this.#prune(now);
		const present = this.#seen.delete(value);
		return present;
	}
	/** Retained value count; for tests and diagnostics. */
	get size() {
		return this.#seen.size;
	}
};
/**
* Fixed-window rate limiter for authentication attempts.
*
* Brute-forcing a 256-bit token is infeasible, but the limiter still matters:
* it caps the cost of a flood of forged proofs, each of which would otherwise
* force an HMAC computation.
*/
var RateLimiter = class {
	#hits = new Map();
	#limit;
	#windowMs;
	/**
	* @param limit - Attempts allowed per key within one window.
	* @param windowMs - Window length in milliseconds.
	*/
	constructor(limit = 20, windowMs = 6e4) {
		this.#limit = limit;
		this.#windowMs = windowMs;
	}
	/**
	* Consume one attempt for `key`.
	*
	* @returns True when the attempt is allowed, false when the key is throttled.
	*/
	allow(key, now = Date.now()) {
		for (const [existing, state] of this.#hits) if (state.resetAt <= now) this.#hits.delete(existing);
		const current = this.#hits.get(key);
		if (current === void 0 || current.resetAt <= now) {
			this.#hits.set(key, {
				count: 1,
				resetAt: now + this.#windowMs
			});
			return true;
		}
		if (current.count >= this.#limit) return false;
		current.count += 1;
		return true;
	}
	/** Forget a key, e.g. after a successful authentication. */
	reset(key) {
		this.#hits.delete(key);
	}
};
/** Encode a pairing code. */
function encodePairingCode(code) {
	const url = Buffer.from(code.relayUrl, "utf8").toString("base64url");
	const subject = code.subject === null ? "" : Buffer.from(code.subject, "utf8").toString("base64url");
	const base = `dshrw1.${url}.${subject}.${code.authSecret}.${code.encryptionToken}`;
	return code.browserToken === void 0 ? base : `${base}.${code.browserToken}`;
}
/**
* Parse a pairing code.
*
* @returns The decoded code, or `null` when the string is not well-formed.
*/
function decodePairingCode(input) {
	const parts = input.trim().split(".");
	if (parts.length !== 5 && parts.length !== 6 || parts[0] !== "dshrw1") return null;
	const [, encodedUrl, encodedSubject, authSecret, encryptionToken, browserToken] = parts;
	if (encodedUrl === void 0 || encodedUrl === "" || authSecret === void 0 || authSecret === "" || encryptionToken === void 0 || encryptionToken === "") return null;
	let relayUrl;
	try {
		relayUrl = Buffer.from(encodedUrl, "base64url").toString("utf8");
		new URL(relayUrl);
	} catch {
		return null;
	}
	return {
		relayUrl,
		subject: encodedSubject === void 0 || encodedSubject === "" ? null : Buffer.from(encodedSubject, "base64url").toString("utf8"),
		authSecret,
		encryptionToken,
		...browserToken === void 0 || browserToken === "" ? {} : { browserToken }
	};
}

//#endregion
//#region src/shared/crypto.ts
/** DER prefixes for raw Ed25519/X25519 key material (RFC 8410). */
const ED25519_PRIVATE_DER = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_PUBLIC_DER = Buffer.from("302a300506032b6570032100", "hex");
const X25519_PRIVATE_DER = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_PUBLIC_DER = Buffer.from("302a300506032b656e032100", "hex");
/** Wrap raw key bytes in the DER envelope `node:crypto` expects. */
function rawToKey(raw, prefix) {
	return Buffer.concat([prefix, raw]);
}
/** Extract the raw 32 bytes from a DER-encoded key. */
function keyToRaw(der, prefixLength) {
	return der.subarray(prefixLength);
}
/**
* Generate a fresh agent signing identity.
*
* @returns Base64url private and public keys.
*/
function generateAgentIdentity() {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const rawPrivate = keyToRaw(privateKey.export({
		type: "pkcs8",
		format: "der"
	}), ED25519_PRIVATE_DER.length);
	const rawPublic = keyToRaw(publicKey.export({
		type: "spki",
		format: "der"
	}), ED25519_PUBLIC_DER.length);
	return {
		privateKey: rawPrivate.toString("base64url"),
		publicKey: rawPublic.toString("base64url")
	};
}
/**
* Sign a challenge with an agent's private key.
*
* @param message - Bytes to sign; callers bind context into this.
* @param privateKey - Base64url raw private key.
* @returns Base64url signature.
*/
function signMessage(message, privateKey) {
	const key = createPrivateKey({
		key: rawToKey(Buffer.from(privateKey, "base64url"), ED25519_PRIVATE_DER),
		format: "der",
		type: "pkcs8"
	});
	return sign(null, Buffer.from(message, "utf8"), key).toString("base64url");
}
/**
* Verify a signature against an agent's public key.
*
* Returns false rather than throwing on malformed input: a hostile peer must
* not be able to crash the relay with a bad key.
*/
function verifySignature(message, signature, publicKey) {
	try {
		const key = createPublicKey({
			key: rawToKey(Buffer.from(publicKey, "base64url"), ED25519_PUBLIC_DER),
			format: "der",
			type: "spki"
		});
		return verify(null, Buffer.from(message, "utf8"), key, Buffer.from(signature, "base64url"));
	} catch {
		return false;
	}
}
/** Bytes in an encryption token. */
const ENCRYPTION_TOKEN_BYTES = 32;
/**
* Generate an encryption token.
*
* This value is shared **only** between the DSH machine and the browsers its
* operator authorizes. It is never sent to the relay, in any form.
*/
function generateEncryptionToken() {
	return randomBytes(ENCRYPTION_TOKEN_BYTES).toString("base64url");
}
/**
* Encrypt and authenticate a payload.
*
* AES-256-GCM is used with a random 96-bit nonce. GCM's tag is what makes the
* relay unable to tamper: a modified byte fails authentication rather than
* decrypting to something else.
*
* @param plaintext - Bytes to protect.
* @param key - Key from {@link deriveSessionKey}.
* @param aad - Additional authenticated data bound to this payload but not
*              encrypted, e.g. the exchange id, so a valid payload cannot be
*              replayed onto a different exchange.
*/
function seal(plaintext, key, aad) {
	const nonce = randomBytes(12);
	const cipher = createCipheriv("aes-256-gcm", key, nonce);
	if (aad !== void 0) cipher.setAAD(Buffer.from(aad, "utf8"));
	const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	return {
		n: nonce.toString("base64url"),
		c: ciphertext.toString("base64url"),
		t: cipher.getAuthTag().toString("base64url")
	};
}
/**
* Decrypt and verify a payload.
*
* @returns The plaintext, or `null` when authentication fails — which covers
*          tampering, the wrong key, and a replay onto another exchange alike.
*          Callers must treat `null` as hostile, not as an empty body.
*/
function open(sealed, key, aad) {
	try {
		const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(sealed.n, "base64url"));
		if (aad !== void 0) decipher.setAAD(Buffer.from(aad, "utf8"));
		decipher.setAuthTag(Buffer.from(sealed.t, "base64url"));
		return Buffer.concat([decipher.update(Buffer.from(sealed.c, "base64url")), decipher.final()]);
	} catch {
		return null;
	}
}
/** Generate an ephemeral X25519 keypair. */
function generateEphemeralKeyPair() {
	const { privateKey, publicKey } = generateKeyPairSync("x25519");
	return {
		privateKey: keyToRaw(privateKey.export({
			type: "pkcs8",
			format: "der"
		}), X25519_PRIVATE_DER.length).toString("base64url"),
		publicKey: keyToRaw(publicKey.export({
			type: "spki",
			format: "der"
		}), X25519_PUBLIC_DER.length).toString("base64url")
	};
}
/**
* Complete an X25519 exchange and mix the result with the encryption token.
*
* Both inputs are required, which is the point: the ephemeral exchange gives
* forward secrecy, while folding in the encryption token means a relay that
* substituted its own public key still cannot derive the key. Neither secret
* alone is sufficient.
*
* @param privateKey - Our ephemeral private key.
* @param peerPublicKey - The peer's ephemeral public key.
* @param token - The shared encryption token.
* @returns 32-byte session key.
*/
function deriveSessionKey(privateKey, peerPublicKey, token) {
	const shared = diffieHellman({
		privateKey: createPrivateKey({
			key: rawToKey(Buffer.from(privateKey, "base64url"), X25519_PRIVATE_DER),
			format: "der",
			type: "pkcs8"
		}),
		publicKey: createPublicKey({
			key: rawToKey(Buffer.from(peerPublicKey, "base64url"), X25519_PUBLIC_DER),
			format: "der",
			type: "spki"
		})
	});
	return Buffer.from(hkdfSync("sha256", shared, Buffer.from(token, "utf8"), "dsh-remote-web/session/v1", 32));
}

//#endregion
//#region src/shared/headers.ts
/**
* Headers never forwarded from the browser to the local DSH server.
*
* Three groups, all removed for the same reason — the receiving side must see
* a request that this host originated, not one a remote party shaped:
*
* - **Trust markers** (`host`, `origin`, `referer`, `sec-fetch-*`) are
*   re-derived below; a forwarded value would either fail the fence or, worse,
*   pass it while describing a different origin.
* - **Forwarding claims** (`x-forwarded-*`, `forwarded`, `via`) are dropped so
*   a remote peer cannot forge a chain that a future middlebox might believe.
* - **Hop-by-hop plumbing** (`connection`, `upgrade`, `te`, encodings) belongs
*   to the browser↔relay hop and is meaningless on this one.
*/
const STRIPPED_REQUEST_HEADERS = new Set([
	"host",
	"origin",
	"referer",
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"via",
	"forwarded",
	"x-forwarded-for",
	"x-forwarded-host",
	"x-forwarded-proto",
	"x-forwarded-port",
	"x-real-ip",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-dest",
	"sec-fetch-user",
	"sec-websocket-key",
	"sec-websocket-version",
	"sec-websocket-extensions",
	"sec-websocket-protocol",
	"accept-encoding"
]);
/**
* Response headers dropped on the way back to the browser: hop-by-hop
* plumbing plus lengths that no longer describe the re-chunked body.
*/
const STRIPPED_RESPONSE_HEADERS = new Set([
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"content-encoding",
	"content-length"
]);
/** Maximum number of headers accepted from a remote peer. */
const MAX_HEADER_COUNT = 100;
/** Maximum size of a single header value accepted from a remote peer. */
const MAX_HEADER_VALUE_BYTES = 8 * 1024;
/**
* Normalize raw incoming headers into a flat, bounded, lowercase map.
*
* Array values (repeated headers) are joined with `, ` except `set-cookie`,
* which is dropped: DSH's API does not rely on it and merging it would corrupt
* multiple cookies into one malformed value.
*
* @param headers - Node-style incoming headers.
* @returns A flat map safe to serialize into a protocol frame.
*/
function normalizeHeaders(headers) {
	const out = {};
	let count = 0;
	for (const [rawKey, value] of Object.entries(headers)) {
		if (count >= MAX_HEADER_COUNT) break;
		if (value === void 0) continue;
		const key = rawKey.toLowerCase();
		if (key === "set-cookie") continue;
		const joined = Array.isArray(value) ? value.join(", ") : value;
		if (Buffer.byteLength(joined, "utf8") > MAX_HEADER_VALUE_BYTES) continue;
		out[key] = joined;
		count += 1;
	}
	return out;
}
/**
* The authority a proxied request claims to come from.
*
* Deliberately **not** a loopback address. DSH's `/api` fence recognizes two
* kinds of caller: a loopback one, which may reach the privileged plane
* (credentials, settings, `host.openPath`, and the rest of `PRIVILEGED_METHODS`),
* and a declared `trustedHosts` authority, which passes the ordinary fence but
* is refused those methods.
*
* A remote browser belongs in the second category, so the tunnel presents
* itself as this named authority instead of impersonating loopback. DSH then
* enforces the privileged boundary itself, using its own list, which stays
* correct as that list grows.
*
* The alternative — claiming loopback and re-implementing the exclusions here —
* was tried and rejected: it silently missed `llm.discoverModels`, and every
* future DSH release would risk another silent gap.
*/
const REMOTE_AUTHORITY = "dsh-remote-web.internal";
/**
* Rewrite browser request headers so the local DSH server sees a request this
* host originated on behalf of a remote, non-privileged caller.
*
* @param headers - Normalized headers from the remote browser.
* @returns Headers to send on the local request.
*/
function rewriteRequestHeaders(headers) {
	const out = {};
	for (const [key, value] of Object.entries(headers)) {
		if (STRIPPED_REQUEST_HEADERS.has(key.toLowerCase())) continue;
		out[key.toLowerCase()] = value;
	}
	out.host = REMOTE_AUTHORITY;
	out.origin = `http://${REMOTE_AUTHORITY}`;
	out["sec-fetch-site"] = "same-origin";
	out["accept-encoding"] = "identity";
	return out;
}
/**
* Filter response headers for the trip back to the browser.
*
* @param headers - Headers from the local DSH server.
* @returns Headers safe to replay to the remote browser.
*/
function rewriteResponseHeaders(headers) {
	const normalized = normalizeHeaders(headers);
	const out = {};
	for (const [key, value] of Object.entries(normalized)) {
		if (STRIPPED_RESPONSE_HEADERS.has(key)) continue;
		out[key] = value;
	}
	return out;
}
/**
* Paths the tunnel is willing to proxy.
*
* This is an allowlist by prefix rather than a denylist because the DSH web
* surface is a single-page app: anything outside these prefixes is either a
* static asset (served through the SPA fallback, which the last entry covers)
* or something the remote surface has no business reaching.
*/
const ALLOWED_WS_PATHS = new Set(["/api/events.mux", "/api/events.host"]);
/**
* Decide whether a proxied WebSocket upgrade may proceed.
*
* Only the two DSH downlink streams are permitted. Any other upgrade — a
* plugin's own socket, a terminal, an unknown future route — is refused,
* because a shell-bearing socket reached through a remote browser would defeat
* the point of proxying only the conversation surface.
*
* @param path - Request path including query string.
*/
function isAllowedWebSocketPath(path) {
	const pathname = path.split("?")[0] ?? "";
	return ALLOWED_WS_PATHS.has(pathname);
}
/**
* Read an end-to-end envelope from a browser's request headers.
*
* The header form exists so the relay can stay ignorant of encryption: it
* forwards headers verbatim already, so no relay code — and no second relay
* code path — is needed for ciphertext to cross it.
*
* @param headers - Normalized request headers.
* @returns The envelope, or `undefined` when absent or malformed. A malformed
*          envelope is treated as absent, so the host's `requireE2e` decides
*          the outcome rather than this parser.
*/
function readEnvelopeHeader(headers) {
	const raw = headers[E2E_ENVELOPE_HEADER];
	if (raw === void 0) return void 0;
	let parsed;
	try {
		parsed = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
	} catch {
		return void 0;
	}
	const envelope = parsed;
	if (typeof envelope?.epk !== "string" || typeof envelope.n !== "string" || typeof envelope.c !== "string" || typeof envelope.t !== "string") return void 0;
	return envelope;
}
/**
* Reject paths that try to escape the proxied surface.
*
* Traversal is checked on the raw and the percent-decoded form, since the
* receiving server decodes before routing.
*
* @returns True when the path is a plain, root-relative request path.
*/
function isSafeProxyPath(path) {
	if (!path.startsWith("/") || path.startsWith("//")) return false;
	if (path.includes("\\") || path.includes("\0")) return false;
	let decoded;
	try {
		decoded = decodeURIComponent(path);
	} catch {
		return false;
	}
	if (decoded.includes("..") || decoded.includes("\0")) return false;
	return true;
}

//#endregion
export { AUTH_PROOF_SKEW_MS, CLOSE_AGENT_OFFLINE, CLOSE_AGENT_REPLACED, CLOSE_AUTH_FAILED, CLOSE_E2E_REQUIRED, CLOSE_RATE_LIMITED, CLOSE_REVOKED, CLOSE_UNSUPPORTED_VERSION, E2E_ENVELOPE_HEADER, E2E_ID_HEADER, E2E_KEY_PARAM, HEARTBEAT_INTERVAL_MS, HEARTBEAT_TIMEOUT_MS, MAX_BODY_CHUNK_BYTES, MAX_CONTROL_FRAME_BYTES, MAX_REQUEST_BODY_BYTES, MAX_WS_MESSAGE_BYTES, OneTimeValues, PROTOCOL_VERSION, RELAY_AGENT_PATH, RateLimiter, WatchedFile, agentChallenge, decodePairingCode, deriveSessionKey, encodePairingCode, fingerprint, generateAgentIdentity, generateEncryptionToken, generateEphemeralKeyPair, generateToken, hashToken, isAllowedWebSocketPath, isSafeProxyPath, normalizeHeaders, open, parseFrame, readEnvelopeHeader, rewriteRequestHeaders, rewriteResponseHeaders, safeEqual, seal, signMessage, verifySignature };