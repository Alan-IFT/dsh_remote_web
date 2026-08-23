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
