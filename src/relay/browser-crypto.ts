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
export const BROWSER_CRYPTO_SCRIPT = String.raw`
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
`

/** Content type for the served script. */
export const BROWSER_CRYPTO_CONTENT_TYPE = 'text/javascript; charset=utf-8'
