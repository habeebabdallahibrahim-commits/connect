// Connect API as a Netlify Function (v2). Storage: Netlify Blobs.
import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

export const config = { path: '/api/*' };

const MAX_USERS = 2;
const SESSION_MS = 1000 * 60 * 60 * 24 * 30;

const store = () => getStore({ name: 'connect', consistency: 'strong' });

const send = (code, obj, headers = {}) =>
  new Response(JSON.stringify(obj), {
    status: code,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers },
  });

const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const cookie = (token, maxAge) =>
  `sid=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
const getToken = req => (/(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.get('cookie') || '') || [])[1];

async function currentUser(db, req) {
  const token = getToken(req);
  if (!token) return null;
  const s = await db.get('sess/' + token, { type: 'json' });
  if (!s) return null;
  if (s.exp < Date.now()) { await db.delete('sess/' + token); return null; }
  return s.user;
}

// 10 attempts / 5 min per IP, kept in storage so it works across function instances
async function limited(db, ip) {
  const key = 'rl/' + crypto.createHash('sha256').update(String(ip)).digest('hex').slice(0, 24);
  const now = Date.now();
  const list = ((await db.get(key, { type: 'json' })) || []).filter(t => now - t < 300000);
  list.push(now);
  await db.setJSON(key, list);
  return list.length > 10;
}

export default async (req, context) => {
  const db = store();
  const url = new URL(req.url);
  const route = url.pathname.replace(/\/$/, '');

  try {
    // ----- signup / login -----
    if (req.method === 'POST' && (route === '/api/signup' || route === '/api/login')) {
      if (await limited(db, context?.ip || req.headers.get('x-nf-client-connection-ip')))
        return send(429, { error: 'Too many attempts. Try again in a few minutes.' });
      let body;
      try { body = await req.json(); } catch { return send(400, { error: 'Bad request' }); }
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      const name = username.toLowerCase();

      if (route === '/api/signup') {
        if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
          return send(400, { error: 'Username must be 3–20 letters, numbers or underscores.' });
        if (password.length < 6 || password.length > 200)
          return send(400, { error: 'Password must be at least 6 characters.' });
        if (await db.get('user/' + name, { type: 'json' }))
          return send(409, { error: 'That username is taken.' });
        const { blobs } = await db.list({ prefix: 'user/' });
        if (blobs.length >= MAX_USERS)
          return send(403, { error: 'Connect already has its two users.' });
        const salt = crypto.randomBytes(16).toString('hex');
        await db.setJSON('user/' + name, { display: username, salt, hash: hashPw(password, salt) });
      } else {
        const u = await db.get('user/' + name, { type: 'json' });
        const ok = u && crypto.timingSafeEqual(
          Buffer.from(hashPw(password, u.salt), 'hex'), Buffer.from(u.hash, 'hex'));
        if (!ok) return send(401, { error: 'Wrong username or password.' });
      }
      const u = await db.get('user/' + name, { type: 'json' });
      const token = crypto.randomBytes(32).toString('hex');
      await db.setJSON('sess/' + token, { user: name, exp: Date.now() + SESSION_MS });
      return send(200, { username: u.display, key: name },
        { 'Set-Cookie': cookie(token, SESSION_MS / 1000) });
    }

    if (req.method === 'POST' && route === '/api/logout') {
      const token = getToken(req);
      if (token) await db.delete('sess/' + token);
      return send(200, { ok: true }, { 'Set-Cookie': cookie('', 0) });
    }

    // ----- everything below needs a login -----
    const me = await currentUser(db, req);
    if (!me) return send(401, { error: 'Not signed in' });
    const meRec = await db.get('user/' + me, { type: 'json' });

    if (req.method === 'GET' && route === '/api/me')
      return send(200, { username: meRec.display, key: me });

    if (req.method === 'GET' && route === '/api/messages') {
      const after = url.searchParams.get('after') || '';
      const { blobs } = await db.list({ prefix: 'msg/' });
      let keys = blobs.map(b => b.key).sort();
      keys = after ? keys.filter(k => k > after) : keys.slice(-100);
      const messages = (await Promise.all(keys.map(async k => {
        const m = await db.get(k, { type: 'json' });
        return m && { id: k, ...m };
      }))).filter(Boolean);
      return send(200, { messages });
    }

    if (req.method === 'POST' && route === '/api/messages') {
      let body;
      try { body = await req.json(); } catch { return send(400, { error: 'Bad request' }); }
      const text = String(body.text || '').trim().slice(0, 2000);
      if (!text) return send(400, { error: 'Empty message' });
      const ts = Date.now();
      const id = `msg/${String(ts).padStart(15, '0')}-${crypto.randomBytes(4).toString('hex')}`;
      const msg = { from: me, name: meRec.display, text, ts };
      await db.setJSON(id, msg);
      return send(200, { id, ...msg });
    }

    return send(404, { error: 'Not found' });
  } catch (e) {
    console.error(e);
    return send(500, { error: 'Server error' });
  }
};
