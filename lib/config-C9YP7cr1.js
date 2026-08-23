import { WatchedFile } from "./headers-BZAfeW6Z.js";
import { homedir } from "node:os";
import { join } from "node:path";

//#region src/plugin/config.ts
/** Resolve `$DSH_HOME`, falling back to the documented default. */
function dshHome() {
	return process.env.DSH_HOME ?? join(homedir(), ".dsh");
}
/** Directory holding this plugin's state. */
function stateDir() {
	return join(dshHome(), "remote-web");
}
/** Default path of the agent credential file. */
function defaultCredentialPath() {
	return join(stateDir(), "agent.json");
}
/** Path of the status file the running plugin publishes. */
function statusPath(credentialPath) {
	return credentialPath.replace(/agent\.json$/, "status.json");
}
/** Validate parsed JSON as credentials. */
function parseCredentials(raw) {
	const value = raw;
	if (value?.version !== 1 || typeof value.relayUrl !== "string" || typeof value.agentId !== "string" || typeof value.privateKey !== "string" || typeof value.encryptionToken !== "string") throw new Error("unrecognized credential shape");
	return {
		version: 1,
		relayUrl: value.relayUrl,
		agentId: value.agentId,
		privateKey: value.privateKey,
		encryptionToken: value.encryptionToken,
		label: typeof value.label === "string" ? value.label : value.agentId,
		enabled: value.enabled !== false,
		requireE2e: value.requireE2e === true
	};
}
/**
* Open the credential file.
*
* The returned handle re-reads on change, which is what lets `setup`,
* `enable`, and `disable` take effect in a running DSH without an IPC channel.
*/
function openCredentials(path) {
	return new WatchedFile(path, (raw) => parseCredentials(raw), () => null);
}
/** Open the status file for reading or publishing. */
function openStatus(path) {
	return new WatchedFile(path, (raw) => raw, () => null);
}
/**
* Apply defaults to loader-supplied config.
*
* `0` and `''` are the schema's "unset" sentinels and are treated exactly like
* an absent key, so a caller can pass the schema's own defaults through.
*/
function resolvePluginConfig(input = {}) {
	let inferredPort = 3080;
	let inferredHost = "127.0.0.1";
	const webUrl = process.env.DSH_WEB_URL;
	if (webUrl !== void 0) try {
		const parsed = new URL(webUrl);
		if (parsed.port !== "") inferredPort = Number.parseInt(parsed.port, 10);
		if (parsed.hostname !== "") inferredHost = parsed.hostname;
	} catch {}
	const path = input.credentialPath;
	const host = input.localHost;
	const port = input.localPort;
	return {
		credentialPath: path === void 0 || path === "" ? defaultCredentialPath() : path,
		enabled: input.enabled !== false,
		localHost: host === void 0 || host === "" ? inferredHost : host,
		localPort: port === void 0 || port === 0 ? inferredPort : port,
		initialRetryMs: input.initialRetryMs ?? 1e3,
		maxRetryMs: input.maxRetryMs ?? 6e4
	};
}

//#endregion
export { defaultCredentialPath, dshHome, openCredentials, openStatus, resolvePluginConfig, stateDir, statusPath };