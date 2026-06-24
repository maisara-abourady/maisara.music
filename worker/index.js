// Cloudflare Worker entry for maisara.music.
// Handles the /learn auth + data API; everything else is served from static assets.
//
// Bindings (see wrangler.jsonc):
//   ASSETS              - static assets (the site, including /learn)
//   DB                  - D1 database (users, sessions, progress)
//   GOOGLE_CLIENT_ID    - var (non-secret)
//   GOOGLE_CLIENT_SECRET- secret

export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    const { pathname } = url

    if (pathname.startsWith('/learn/api/')) {
      try {
        return await handleApi(request, env, url)
      } catch (err) {
        return json({ error: 'server_error', detail: String(err) }, 500)
      }
    }

    // Not an API route — serve the static site.
    return env.ASSETS.fetch(request)
  },
}

async function handleApi(request, env, url) {
  const { pathname } = url
  const method = request.method

  if (pathname === '/learn/api/me' && method === 'GET') {
    const user = await getSessionUser(request, env)
    return json({ user })
  }

  if (pathname === '/learn/api/auth/login' && method === 'GET') {
    return authLogin(env, url)
  }

  if (pathname === '/learn/api/auth/callback' && method === 'GET') {
    return authCallback(request, env, url)
  }

  if (pathname === '/learn/api/auth/logout' && method === 'POST') {
    return authLogout(request, env)
  }

  if (pathname === '/learn/api/progress') {
    if (method === 'GET') return progressGet(request, env)
    if (method === 'PUT') return progressPut(request, env)
  }

  return json({ error: 'not_found' }, 404)
}

// ---- Route handlers --------------------------------------------------------

function authLogin(env, url) {
  const redirectUri = `${url.origin}/learn/api/auth/callback`
  const state = randomToken()
  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    access_type: 'online',
    prompt: 'select_account',
  })
  const headers = new Headers({
    Location: `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`,
  })
  headers.append(
    'Set-Cookie',
    setCookie('learn_oauth_state', state, { maxAge: 600, path: '/learn', httpOnly: true, secure: true, sameSite: 'Lax' })
  )
  return new Response(null, { status: 302, headers })
}

async function authCallback(request, env, url) {
  const code = url.searchParams.get('code')
  const state = url.searchParams.get('state')
  const cookieState = getCookie(request, 'learn_oauth_state')
  if (!code || !state || !cookieState || state !== cookieState) {
    return new Response('Invalid OAuth state', { status: 400 })
  }

  const redirectUri = `${url.origin}/learn/api/auth/callback`
  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }),
  })
  if (!tokenRes.ok) {
    const detail = await tokenRes.text()
    return new Response(`Token exchange failed (${tokenRes.status}): ${detail}`, { status: 502 })
  }

  const tokens = await tokenRes.json()
  const claims = decodeJwtPayload(tokens.id_token)
  const sub = claims.sub
  if (!sub) return new Response('No subject in token', { status: 502 })

  const now = nowSec()
  // Role is derived from the ADMIN_EMAILS allowlist on every login, so promotion
  // or demotion takes effect the next time the user signs in.
  const role = isAdminEmail(claims.email, env) ? 'admin' : 'user'
  const existing = await env.DB.prepare('SELECT id FROM users WHERE google_sub = ?').bind(sub).first()
  let userId
  if (existing) {
    userId = existing.id
    await env.DB.prepare('UPDATE users SET email = ?, name = ?, picture = ?, role = ? WHERE id = ?')
      .bind(claims.email || null, claims.name || null, claims.picture || null, role, userId)
      .run()
  } else {
    userId = crypto.randomUUID()
    await env.DB.prepare(
      'INSERT INTO users (id, google_sub, email, name, picture, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    )
      .bind(userId, sub, claims.email || null, claims.name || null, claims.picture || null, role, now)
      .run()
  }

  const sid = randomToken()
  const expires = now + 60 * 60 * 24 * 30 // 30 days
  await env.DB.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').bind(sid, userId, expires).run()

  const headers = new Headers({ Location: `${url.origin}/learn/` })
  headers.append(
    'Set-Cookie',
    setCookie('learn_session', sid, { maxAge: 60 * 60 * 24 * 30, path: '/learn', httpOnly: true, secure: true, sameSite: 'Lax' })
  )
  headers.append('Set-Cookie', clearCookie('learn_oauth_state', '/learn'))
  return new Response(null, { status: 302, headers })
}

async function authLogout(request, env) {
  const sid = getCookie(request, 'learn_session')
  if (sid) await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sid).run()
  const headers = new Headers({ 'content-type': 'application/json' })
  headers.append('Set-Cookie', clearCookie('learn_session', '/learn'))
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers })
}

async function progressGet(request, env) {
  const user = await getSessionUser(request, env)
  if (!user) return json({ error: 'unauthorized' }, 401)
  const row = await env.DB.prepare('SELECT data FROM progress WHERE user_id = ?').bind(user.id).first()
  return json({ data: row ? JSON.parse(row.data) : null })
}

async function progressPut(request, env) {
  const user = await getSessionUser(request, env)
  if (!user) return json({ error: 'unauthorized' }, 401)
  let body
  try {
    body = await request.json()
  } catch {
    return json({ error: 'bad_json' }, 400)
  }
  await env.DB.prepare(
    `INSERT INTO progress (user_id, data, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`
  )
    .bind(user.id, JSON.stringify(body), nowSec())
    .run()
  return json({ ok: true })
}

// ---- Helpers ---------------------------------------------------------------

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } })
}

function getCookie(request, name) {
  const header = request.headers.get('Cookie') || ''
  for (const part of header.split(/; */)) {
    const idx = part.indexOf('=')
    if (idx === -1) continue
    if (part.slice(0, idx) === name) return decodeURIComponent(part.slice(idx + 1))
  }
  return null
}

function setCookie(name, value, opts = {}) {
  const p = [`${name}=${value}`]
  if (opts.maxAge != null) p.push(`Max-Age=${opts.maxAge}`)
  p.push(`Path=${opts.path || '/'}`)
  if (opts.httpOnly) p.push('HttpOnly')
  if (opts.secure) p.push('Secure')
  p.push(`SameSite=${opts.sameSite || 'Lax'}`)
  return p.join('; ')
}

function clearCookie(name, path = '/') {
  return `${name}=; Max-Age=0; Path=${path}; SameSite=Lax`
}

function randomToken() {
  const a = new Uint8Array(32)
  crypto.getRandomValues(a)
  return [...a].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function decodeJwtPayload(token) {
  const part = token.split('.')[1]
  const b64 = part.replace(/-/g, '+').replace(/_/g, '/')
  const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : ''
  const bin = atob(b64 + pad)
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
  return JSON.parse(new TextDecoder().decode(bytes))
}

function nowSec() {
  return Math.floor(Date.now() / 1000)
}

function isAdminEmail(email, env) {
  if (!email || !env.ADMIN_EMAILS) return false
  const target = email.trim().toLowerCase()
  return env.ADMIN_EMAILS.split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean)
    .includes(target)
}

async function getSessionUser(request, env) {
  const sid = getCookie(request, 'learn_session')
  if (!sid) return null
  const row = await env.DB.prepare(
    `SELECT u.id AS id, u.email AS email, u.name AS name, u.picture AS picture, u.role AS role, s.expires_at AS expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.id = ?`
  )
    .bind(sid)
    .first()
  if (!row) return null
  if (row.expires_at < nowSec()) {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sid).run()
    return null
  }
  return { id: row.id, email: row.email, name: row.name, picture: row.picture, role: row.role || 'user' }
}
