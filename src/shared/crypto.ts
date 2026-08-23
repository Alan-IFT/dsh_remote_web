/**
 * The two independent secrets this system is built on, and the primitives that
 * back them.
 *
 * ## Why two tokens
 *
 * A single shared token conflates two different questions:
 *
 *   1. *May this party connect?* — the relay must answer this, so it needs
 *      whatever the answer depends on.
 *   2. *May this party read the session?* — the relay must NOT be able to
 *      answer this, or "self-hosted relay" is the only thing standing between
 *      an attacker and the plaintext.
 *
 * Keying both from one secret means the relay holds everything needed to read
 * traffic. So the credential is split:
 *
 * - **Auth token** — proves identity to the relay. The relay stores only a
 *   verifier (an Ed25519 public key for agents, a digest for browsers) and can
 *   check a proof without being able to forge one.
 * - **Encryption token** — never given to the relay in any form. It derives
 *   the key that protects payloads end to end. The relay forwards ciphertext
 *   it cannot read.
 *
 * Both must check out: the relay refuses a bad auth proof, and the peer
 * refuses a payload it cannot authenticate. Compromising the relay yields
 * neither.
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
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
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

/** DER prefixes for raw Ed25519/X25519 key material (RFC 8410). */
const ED25519_PRIVATE_DER = Buffer.from('302e020100300506032b657004220420', 'hex')
const ED25519_PUBLIC_DER = Buffer.from('302a300506032b6570032100', 'hex')
const X25519_PRIVATE_DER = Buffer.from('302e020100300506032b656e04220420', 'hex')
const X25519_PUBLIC_DER = Buffer.from('302a300506032b656e032100', 'hex')

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

/* ──────────────────────────── payload encryption ─────────────────────────── */

/** Bytes in an encryption token. */
const ENCRYPTION_TOKEN_BYTES = 32

/**
 * Generate an encryption token.
 *
 * This value is shared **only** between the DSH machine and the browsers its
 * operator authorizes. It is never sent to the relay, in any form.
 */
export function generateEncryptionToken(): string {
  return randomBytes(ENCRYPTION_TOKEN_BYTES).toString('base64url')
}

/** An encrypted payload: nonce, ciphertext, and authentication tag. */
export interface SealedPayload {
  /** base64url 12-byte GCM nonce. */
  n: string
  /** base64url ciphertext. */
  c: string
  /** base64url 16-byte GCM tag. */
  t: string
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
export function seal(plaintext: Buffer, key: Buffer, aad?: string): SealedPayload {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  if (aad !== undefined) cipher.setAAD(Buffer.from(aad, 'utf8'))
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return {
    n: nonce.toString('base64url'),
    c: ciphertext.toString('base64url'),
    t: cipher.getAuthTag().toString('base64url'),
  }
}

/**
 * Decrypt and verify a payload.
 *
 * @returns The plaintext, or `null` when authentication fails — which covers
 *          tampering, the wrong key, and a replay onto another exchange alike.
 *          Callers must treat `null` as hostile, not as an empty body.
 */
export function open(sealed: SealedPayload, key: Buffer, aad?: string): Buffer | null {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.n, 'base64url'))
    if (aad !== undefined) decipher.setAAD(Buffer.from(aad, 'utf8'))
    decipher.setAuthTag(Buffer.from(sealed.t, 'base64url'))
    return Buffer.concat([decipher.update(Buffer.from(sealed.c, 'base64url')), decipher.final()])
  } catch {
    return null
  }
}

/* ─────────────────────────── ephemeral key exchange ──────────────────────── */

/**
 * An ephemeral X25519 keypair, used to give each browser session a key the
 * relay never sees even though the relay carries the messages.
 */
export interface EphemeralKeyPair {
  privateKey: string
  publicKey: string
}

/** Generate an ephemeral X25519 keypair. */
export function generateEphemeralKeyPair(): EphemeralKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('x25519')
  return {
    privateKey: keyToRaw(
      privateKey.export({ type: 'pkcs8', format: 'der' }),
      X25519_PRIVATE_DER.length,
    ).toString('base64url'),
    publicKey: keyToRaw(
      publicKey.export({ type: 'spki', format: 'der' }),
      X25519_PUBLIC_DER.length,
    ).toString('base64url'),
  }
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
export function deriveSessionKey(
  privateKey: string,
  peerPublicKey: string,
  token: string,
): Buffer {
  const shared = diffieHellman({
    privateKey: createPrivateKey({
      key: rawToKey(Buffer.from(privateKey, 'base64url'), X25519_PRIVATE_DER),
      format: 'der',
      type: 'pkcs8',
    }),
    publicKey: createPublicKey({
      key: rawToKey(Buffer.from(peerPublicKey, 'base64url'), X25519_PUBLIC_DER),
      format: 'der',
      type: 'spki',
    }),
  })
  return Buffer.from(
    hkdfSync('sha256', shared, Buffer.from(token, 'utf8'), 'dsh-remote-web/session/v1', 32),
  )
}
