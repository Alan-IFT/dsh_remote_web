/**
 * The two independent secrets this system is built on, and the primitives that
 * back them.
 *
 * ## Why two tokens
 *
 * A single shared token would let the relay mint a working browser credential
 * by itself, because it would hold everything such a credential contains. So
 * the credential is split, and no one party holds both halves:
 *
 * - **Auth token** — proves identity to the relay. The relay stores only a
 *   verifier (an Ed25519 public key for agents, a digest for browsers) and can
 *   check a proof without being able to forge one.
 * - **Encryption token** — minted by the relay at `agent add`, handed to the
 *   machine, and never kept. It becomes the machine's half of every browser
 *   pairing code, so a complete code can only be assembled on the machine
 *   (`invite`). A relay that later goes rogue can still issue auth tokens, but
 *   it cannot produce a code the operator's own machine would recognize.
 *
 * ## What this does *not* claim
 *
 * It does not hide traffic from the relay. The relay terminates the browser's
 * TLS and forwards plaintext frames; treating it as untrusted for
 * confidentiality would require the browser to run code the relay does not
 * serve, and the relay serves the entire page. An earlier version of this
 * module derived per-session keys for exactly that purpose and was removed
 * rather than left to imply a property it could not deliver. Run the relay on
 * infrastructure you control; see SECURITY.md.
 *
 * ## Why Ed25519 for agents rather than a shared digest
 *
 * The earlier design proved possession with an HMAC keyed by the *stored
 * digest*, which made that digest a bearer credential: anyone who read the
 * relay's state file could impersonate any agent, defeating the point of
 * storing "only a hash". A signature keypair removes the symmetry — the relay
 * holds a public key that verifies proofs and forges none.
 *
 * @module dsh-remote-web/shared/crypto
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as edSign,
  verify as edVerify,
} from 'node:crypto'

/* ───────────────────────────── agent identity ────────────────────────────── */

/** An agent's signing identity. The private half never leaves its machine. */
export interface AgentIdentity {
  /** Ed25519 private key, base64url of the raw 32-byte seed. */
  privateKey: string
  /** Ed25519 public key, base64url of the raw 32 bytes. */
  publicKey: string
}

/** DER prefixes for raw Ed25519 key material (RFC 8410). */
const ED25519_PRIVATE_DER = Buffer.from('302e020100300506032b657004220420', 'hex')
const ED25519_PUBLIC_DER = Buffer.from('302a300506032b6570032100', 'hex')

/** Wrap raw key bytes in the DER envelope `node:crypto` expects. */
function rawToKey(raw: Buffer, prefix: Buffer): Buffer {
  return Buffer.concat([prefix, raw])
}

/** Extract the raw 32 bytes from a DER-encoded key. */
function keyToRaw(der: Buffer, prefixLength: number): Buffer {
  return der.subarray(prefixLength)
}

/**
 * Generate a fresh agent signing identity.
 *
 * @returns Base64url private and public keys.
 */
export function generateAgentIdentity(): AgentIdentity {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const rawPrivate = keyToRaw(
    privateKey.export({ type: 'pkcs8', format: 'der' }),
    ED25519_PRIVATE_DER.length,
  )
  const rawPublic = keyToRaw(
    publicKey.export({ type: 'spki', format: 'der' }),
    ED25519_PUBLIC_DER.length,
  )
  return {
    privateKey: rawPrivate.toString('base64url'),
    publicKey: rawPublic.toString('base64url'),
  }
}

/**
 * Sign a challenge with an agent's private key.
 *
 * @param message - Bytes to sign; callers bind context into this.
 * @param privateKey - Base64url raw private key.
 * @returns Base64url signature.
 */
export function signMessage(message: string, privateKey: string): string {
  const key = createPrivateKey({
    key: rawToKey(Buffer.from(privateKey, 'base64url'), ED25519_PRIVATE_DER),
    format: 'der',
    type: 'pkcs8',
  })
  return edSign(null, Buffer.from(message, 'utf8'), key).toString('base64url')
}

/**
 * Verify a signature against an agent's public key.
 *
 * Returns false rather than throwing on malformed input: a hostile peer must
 * not be able to crash the relay with a bad key.
 */
export function verifySignature(
  message: string,
  signature: string,
  publicKey: string,
): boolean {
  try {
    const key = createPublicKey({
      key: rawToKey(Buffer.from(publicKey, 'base64url'), ED25519_PUBLIC_DER),
      format: 'der',
      type: 'spki',
    })
    return edVerify(null, Buffer.from(message, 'utf8'), key, Buffer.from(signature, 'base64url'))
  } catch {
    return false
  }
}

/* ───────────────────────────── pairing material ──────────────────────────── */

/** Bytes in an encryption token. */
const ENCRYPTION_TOKEN_BYTES = 32

/**
 * Generate an encryption token: a machine's half of every browser pairing code
 * it hands out.
 *
 * The relay mints one at `agent add`, gives it to the machine, and keeps no
 * copy. That is what makes a browser code un-mintable by the relay alone: the
 * relay can issue the auth half, but only the machine can join it to this
 * value.
 *
 * The name is historical — it once keyed payload encryption. It no longer
 * encrypts anything; it binds a credential to a machine.
 */
export function generateEncryptionToken(): string {
  return randomBytes(ENCRYPTION_TOKEN_BYTES).toString('base64url')
}
