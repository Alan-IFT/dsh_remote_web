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
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
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
`

/**
 * The login page.
 *
 * The form posts the token rather than putting it in a query string, so it
 * never lands in access logs, browser history, or a `Referer` header.
 *
 * @param options.error - Message to show above the form, already plain text.
 * @param options.next - Path to return to after a successful login.
 */
export function renderLoginPage(options: { error?: string; next?: string } = {}): string {
  const error =
    options.error === undefined
      ? ''
      : `<p class="error">${escapeHtml(options.error)}</p>`
  const next =
    options.next === undefined
      ? ''
      : `<input type="hidden" name="next" value="${escapeHtml(options.next)}">`
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
  <script>
    /*
     * Trim the pasted pairing code to its auth half before submitting.
     *
     * The relay only needs that half, and the encryption half is what binds a
     * browser credential to one machine — a relay that learned it could mint a
     * complete code on its own. Dropping it here keeps that out of the request
     * entirely. The server tolerates a whole code as a fallback for a browser
     * without scripting, so this is a narrowing, not a requirement.
     */
    document.getElementById('f').addEventListener('submit', function (event) {
      var field = document.getElementById('token')
      var parts = field.value.trim().split('.')
      if (parts.length === 5 && parts[0] === 'dshrw1') field.value = parts[3]
      void event
    })

    /*
     * Enrol a signing key on first login, then log in by signature.
     *
     * Why: the access token is a reusable credential, and sending it on every
     * login is the difference between an observer learning "one spent
     * signature" and learning "a key to the account". The relay half of this
     * already existed — enrolment, a single-use challenge, and refusal of a
     * second enrolment — with no browser that used it. This is that browser.
     *
     * The key is generated non-extractable and kept in IndexedDB, so script on
     * this page cannot read it either: even an XSS steals the use of the key,
     * not the key. This is not end-to-end encryption; the relay terminates TLS
     * and still sees the session.
     *
     * Every step degrades to ordinary token login: no WebCrypto (which needs a
     * secure context, so plain HTTP has none), no IndexedDB, private mode, or
     * an older browser all fall through to the form above. Login is the only
     * door into this tool, so the fallback matters as much as the feature.
     */
    // Leading semicolon on purpose: without it ASI joins this to the statement
    // above, which parses as calling its result and throws before any handler
    // is registered.
    ;(function () {
      var KEY_ID = 'login-key'
      var sub = window.crypto && window.crypto.subtle
      if (!sub || !window.indexedDB) return

      function store(mode, run) {
        return new Promise(function (resolve) {
          var open = indexedDB.open('dshrw', 1)
          open.onupgradeneeded = function () { open.result.createObjectStore('keys') }
          open.onerror = function () { resolve(null) }
          open.onsuccess = function () {
            var db = open.result
            var request = run(db.transaction('keys', mode).objectStore('keys'))
            request.onsuccess = function () { resolve(request.result === undefined ? true : request.result) }
            request.onerror = function () { resolve(null) }
          }
        })
      }

      function b64u(buffer) {
        var binary = String.fromCharCode.apply(null, new Uint8Array(buffer))
        return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '')
      }

      // Signature login, attempted before the page is shown. A failure here is
      // never fatal: it just leaves the token form in place.
      store('readonly', function (s) { return s.get(KEY_ID) }).then(function (pair) {
        if (!pair || !pair.privateKey) return
        return fetch('/__auth/challenge')
          .then(function (r) { return r.ok ? r.json() : null })
          .then(function (challenge) {
            if (!challenge || !challenge.nonce) return
            var message = new TextEncoder().encode('dsh-remote-web/login|' + challenge.nonce)
            return sub.sign('Ed25519', pair.privateKey, message).then(function (signature) {
              return fetch('/__auth/verify', {
                method: 'POST',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ nonce: challenge.nonce, signature: b64u(signature) }),
              })
            })
          })
          .then(function (verified) {
            if (!verified || !verified.ok) return
            // Go to the destination, not back to this page: reloading the login
            // page would sign in again and loop forever. Same local-path test
            // the server applies, rather than trusting a value read from the DOM.
            var field = document.querySelector('[name=next]')
            var to = field ? field.value : ''
            window.location.href =
              to.charAt(0) === '/' && to.charAt(1) !== '/' ? to : '/'
          })
          .catch(function () { /* fall through to the token form */ })
      })

      // First login: attach a fresh public key so the token is not needed next
      // time. The private half never leaves the browser.
      document.getElementById('f').addEventListener('submit', function (event) {
        var form = event.target
        if (form.dataset.enrolling) return
        event.preventDefault()
        form.dataset.enrolling = '1'
        sub.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])
          .then(function (pair) {
            return sub.exportKey('raw', pair.publicKey).then(function (raw) {
              return store('readwrite', function (s) { return s.put(pair, KEY_ID) }).then(function () {
                var field = document.createElement('input')
                field.type = 'hidden'
                field.name = 'publicKey'
                field.value = b64u(raw)
                form.appendChild(field)
              })
            })
          })
          .catch(function () { /* submit without a key; the token still works */ })
          .then(function () { form.submit() })
      })
    })()
  </script>
</body>
</html>`
}

/** One row in the agent picker. */
export interface AgentChoice {
  agentId: string
  label: string
  online: boolean
  connectedAt: number | null
}

/**
 * The agent picker, shown when a session may reach more than one host.
 *
 * Offline agents are listed but not linkable: seeing that a machine exists and
 * is simply not running is more useful than an empty list.
 */
export function renderAgentPicker(agents: readonly AgentChoice[]): string {
  const items =
    agents.length === 0
      ? '<li><p class="sub">没有已注册的主机。请在电脑上运行 <code>dsh-remote-web setup</code>。</p></li>'
      : agents
          .map((agent) => {
            const meta = agent.online
              ? '<span class="dot" aria-label="online"></span>'
              : '<span class="meta">离线 offline</span>'
            const inner = `<span class="name">${escapeHtml(agent.label)}</span>${meta}`
            return agent.online
              ? `<li><a class="agent" href="/a/${encodeURIComponent(agent.agentId)}/">${inner}</a></li>`
              : `<li><span class="agent" aria-disabled="true">${inner}</span></li>`
          })
          .join('\n')
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
</html>`
}

/** A minimal error page for proxy-level failures. */
export function renderErrorPage(status: number, message: string): string {
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
</html>`
}
