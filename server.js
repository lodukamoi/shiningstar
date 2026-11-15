const express = require('express'), http = require('http'), path = require('path'), crypto = require('crypto');
const { Pool } = require('pg'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const webpush = require('web-push');

const env = process.env;
const SECRET = env.JWT_SECRET || 'dev-only-change-me';
if (!env.JWT_SECRET) console.warn('Set JWT_SECRET in production!');
if (!env.DATABASE_URL) { console.error('DATABASE_URL is not set (see README).'); process.exit(1); }
const SMS = !!(env.TWILIO_SID && env.TWILIO_TOKEN && env.TWILIO_FROM);
const OWNERS = new Set((env.ADMIN_EMAILS || '').toLowerCase().split(',').map(x => x.trim()).filter(Boolean)); // always admins; can't be changed from the dashboard
const escRe = x => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const ICE = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }]; // add a TURN server for reliable calls (see README)
if (env.TURN_URLS) ICE.push({ urls: env.TURN_URLS.split(',').map(x => x.trim()), username: env.TURN_USERNAME || '', credential: env.TURN_CREDENTIAL || '' });
const app = express(), server = http.createServer(app), io = new Server(server);
app.set('trust proxy', 1);
const pool = new Pool({ connectionString: env.DATABASE_URL, ssl: env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false }, max: 5 });
const q = (sql, p = []) => pool.query(sql, p).then(r => r.rows);
const one = (sql, p) => q(sql, p).then(r => r[0]);
const fail = (status, message) => Object.assign(new Error(message), { status });
const wrap = fn => (req, res) => fn(req, res).catch(e => {
  if (e.status) return res.status(e.status).json({ error: e.message });
  console.error(e); res.status(500).json({ error: 'Server error. Please try again.' });
});

async function init() {
  await q(`CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    join_year INT, join_class TEXT, left_year INT, left_class TEXT, status TEXT, detail TEXT, contact TEXT, created_at TIMESTAMPTZ DEFAULT now())`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS verified BOOLEAN`);
  await q(`UPDATE users SET verified=true WHERE verified IS NULL`); // accounts made before verification existed
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user'`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended BOOLEAN DEFAULT false`);
  await q(`CREATE TABLE IF NOT EXISTS posts(id SERIAL PRIMARY KEY, user_id INT NOT NULL, body TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ DEFAULT now())`);
  await q(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS pinned BOOLEAN DEFAULT false`);
  await q(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS media_url TEXT`);
  await q(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS media_type TEXT`);
  await q(`CREATE TABLE IF NOT EXISTS likes(post_id INT NOT NULL, user_id INT NOT NULL, PRIMARY KEY(post_id,user_id))`);
  await q(`CREATE TABLE IF NOT EXISTS comments(id SERIAL PRIMARY KEY, post_id INT NOT NULL, user_id INT NOT NULL, body TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())`);
  await q(`CREATE TABLE IF NOT EXISTS messages(id SERIAL PRIMARY KEY, from_id INT NOT NULL, to_id INT NOT NULL, body TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())`);
  await q(`CREATE TABLE IF NOT EXISTS codes(id SERIAL PRIMARY KEY, user_id INT NOT NULL, purpose TEXT NOT NULL, code_hash TEXT NOT NULL, attempts INT DEFAULT 0, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ DEFAULT now())`);
  await q(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted BOOLEAN DEFAULT false`);
  for (const c of ['att_url TEXT', 'att_type TEXT', 'att_name TEXT', 'att_size INT']) await q(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS ${c}`);
  await q(`CREATE TABLE IF NOT EXISTS push_subs(id SERIAL PRIMARY KEY, user_id INT NOT NULL, endpoint TEXT NOT NULL, p256dh TEXT NOT NULL, auth TEXT NOT NULL)`);
  await q(`CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL)`);
  await q(`CREATE INDEX IF NOT EXISTS idx_msg ON messages(from_id,to_id)`);
  await syncAdmins();
}
async function syncAdmins() { for (const e of OWNERS) await q(`UPDATE users SET role='admin' WHERE email=$1 AND verified`, [e]); }

const PUB = 'id,name,email,avatar_url,role,join_year,join_class,left_year,left_class,status,detail,contact,created_at';
const online = new Map();
const sign = u => jwt.sign({ id: u.id }, SECRET, { expiresIn: '30d' });
const clean = (v, max = 200) => String(v ?? '').trim().slice(0, max);
const withOnline = u => ({ ...u, online: online.has(u.id) });
const mediaOk = (url, kinds) => new RegExp(`^https://res\\.cloudinary\\.com/${env.CLOUDINARY_CLOUD_NAME ? escRe(env.CLOUDINARY_CLOUD_NAME) : '[\\w-]+'}/(${kinds})/upload/`).test(url || '');

// ---------- verification / recovery codes ----------
const hash = c => crypto.createHash('sha256').update(c + SECRET).digest('hex');
async function deliver(user, channel, code, purpose) {
  const text = `Your Shining Star ${purpose === 'verify' ? 'verification' : 'password reset'} code is ${code}. It expires in 10 hours.`;
  if (channel === 'phone' && SMS) {
    const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_SID}/Messages.json`, { method: 'POST',
      headers: { Authorization: 'Basic ' + Buffer.from(env.TWILIO_SID + ':' + env.TWILIO_TOKEN).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ To: user.contact, From: env.TWILIO_FROM, Body: text }) });
    if (!r.ok) throw fail(502, 'We couldn’t send the SMS. Check the phone number or use email.');
  } else if (env.BREVO_API_KEY && env.MAIL_FROM) {
    const r = await fetch('https://api.brevo.com/v3/smtp/email', { method: 'POST', headers: { 'api-key': env.BREVO_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender: { name: 'Shining Star Reunion', email: env.MAIL_FROM }, to: [{ email: user.email, name: user.name }],
        subject: purpose === 'verify' ? 'Confirm your Shining Star account' : 'Reset your Shining Star password',
        htmlContent: `<div style="font-family:sans-serif"><p>Hi ${user.name.replace(/[<>&]/g, '')},</p><p>${text.replace(code, `<b style="font-size:22px;letter-spacing:4px">${code}</b>`)}</p><p>If this wasn’t you, ignore this email.</p></div>` }) });
    if (!r.ok) { console.error('Brevo error', r.status, await r.text()); throw fail(502, 'We couldn’t send the email. Check the address and try again.'); }
  } else console.log(`[DEV – no email provider set] ${purpose} code for ${user.email}: ${code}`);
}
async function issueCode(u, purpose, channel) {
  const last = await one(`SELECT (created_at > now() - interval '45 seconds') AS recent FROM codes WHERE user_id=$1 AND purpose=$2`, [u.id, purpose]);
  if (last && last.recent) throw fail(429, 'Please wait a minute before asking for another code.');
  const code = String(crypto.randomInt(100000, 1000000));
  await q('DELETE FROM codes WHERE user_id=$1 AND purpose=$2', [u.id, purpose]);
  await q(`INSERT INTO codes(user_id,purpose,code_hash,expires_at) VALUES($1,$2,$3,now()+interval '10 hours')`, [u.id, purpose, hash(code)]);
  await deliver(u, channel, code, purpose);
}
// returns null when the code is right, otherwise a message that says what went wrong
async function checkCode(u, purpose, code) {
  const generic = 'That code is wrong or has expired. Request a new one.';
  if (!u) return generic;
  const c = await one('SELECT *, (expires_at < now()) AS expired FROM codes WHERE user_id=$1 AND purpose=$2', [u.id, purpose]);
  let why = !c ? 'none' : c.expired ? 'expired' : c.attempts >= 5 ? 'locked' : c.code_hash !== hash(clean(code, 10)) ? 'wrong' : 'ok';
  console.log(`[code check] ${purpose} for ${u.email}: ${why}`);
  if (why === 'ok') { await q('DELETE FROM codes WHERE id=$1', [c.id]); return null; }
  if (why === 'wrong') await q('UPDATE codes SET attempts=attempts+1 WHERE id=$1', [c.id]);
  return { none: 'No active code. Request a new one.', expired: 'That code has expired. Request a new one.',
    locked: 'Too many wrong tries. Request a new code.', wrong: 'That code isn’t correct. Use the newest code we sent you.' }[why];
}

app.use(express.json({ limit: '20kb' }));
const ICONS = require('./icons.js'); // app icons are served from memory so only text files need uploading
app.get('/icons/:name', (req, res) => {
  const b = ICONS[req.params.name];
  if (!b) return res.status(404).end();
  res.set({ 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=604800' }).send(Buffer.from(b, 'base64'));
});
app.use(express.static(path.join(__dirname, 'public')));
app.get('/health', (req, res) => res.send('ok'));
app.get('/api/config', (req, res) => res.json({ cloud: env.CLOUDINARY_CLOUD_NAME || null, preset: env.CLOUDINARY_UPLOAD_PRESET || null, sms: SMS, vapid: VAPID || null }));

const hits = new Map();
const limit = (req, res, next) => {
  const k = req.ip, now = Date.now(), arr = (hits.get(k) || []).filter(t => now - t < 60000);
  arr.push(now); hits.set(k, arr);
  arr.length > 20 ? res.status(429).json({ error: 'Too many attempts. Try again in a minute.' }) : next();
};
const auth = async (req, res, next) => {
  let id; try { id = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET).id; } catch { return res.status(401).json({ error: 'Please log in again.' }); }
  try {
    const u = await one('SELECT id,role,suspended FROM users WHERE id=$1', [id]);
    if (!u) return res.status(401).json({ error: 'Please log in again.' });
    if (u.suspended) return res.status(401).json({ error: 'Your account has been suspended. Please contact an administrator.', suspended: true });
    req.uid = u.id; req.role = u.role || 'user'; next();
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
};
const admin = (req, res, next) => (req.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only.' }));
const byEmail = e => one('SELECT * FROM users WHERE email=$1', [clean(e, 120).toLowerCase()]);
const channelOf = c => (c === 'phone' && SMS ? 'phone' : 'email');

app.post('/api/register', limit, wrap(async (req, res) => {
  const b = req.body, y = n => parseInt(n, 10);
  const d = { name: clean(b.name, 80), email: clean(b.email, 120).toLowerCase(), joinYear: y(b.joinYear), joinClass: clean(b.joinClass, 40),
    leftYear: y(b.leftYear), leftClass: clean(b.leftClass, 40), status: b.status === 'occupation' ? 'occupation' : 'university',
    detail: clean(b.detail, 150), contact: clean(b.contact, 30).replace(/[\s-]/g, '') };
  if (!d.name || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(d.email)) return res.status(400).json({ error: 'Enter your name and a valid email address.' });
  if (String(b.password || '').length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (!(d.joinYear >= 1950 && d.joinYear <= 2100 && d.leftYear >= d.joinYear && d.leftYear <= 2100) || !d.joinClass || !d.leftClass)
    return res.status(400).json({ error: 'Check the years and classes: you can’t leave before you joined.' });
  if (!/^\+[1-9]\d{7,14}$/.test(d.contact)) return res.status(400).json({ error: 'Enter a valid phone number with country code, like +250788123456.' });
  if (!d.detail) return res.status(400).json({ error: 'Tell us what you study or do now.' });
  const old = await byEmail(d.email);
  if (old && old.verified) return res.status(409).json({ error: 'That email is already registered. Try logging in.' });
  const pw = bcrypt.hashSync(b.password, 10);
  const user = old
    ? await one(`UPDATE users SET name=$1,password=$2,join_year=$3,join_class=$4,left_year=$5,left_class=$6,status=$7,detail=$8,contact=$9 WHERE id=$10 RETURNING *`,
        [d.name, pw, d.joinYear, d.joinClass, d.leftYear, d.leftClass, d.status, d.detail, d.contact, old.id])
    : await one(`INSERT INTO users(name,email,password,join_year,join_class,left_year,left_class,status,detail,contact,verified) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,false) RETURNING *`,
        [d.name, d.email, pw, d.joinYear, d.joinClass, d.leftYear, d.leftClass, d.status, d.detail, d.contact]);
  const channel = channelOf(b.channel);
  await issueCode(user, 'verify', channel);
  res.json({ needsVerify: true, email: d.email, channel });
}));

app.post('/api/verify', limit, wrap(async (req, res) => {
  const u = await byEmail(req.body.email);
  const bad = u && !u.verified ? await checkCode(u, 'verify', req.body.code) : 'That code is wrong or has expired. Request a new one.';
  if (bad) return res.status(400).json({ error: bad });
  await q('UPDATE users SET verified=true WHERE id=$1', [u.id]); await syncAdmins();
  const user = await one(`SELECT ${PUB} FROM users WHERE id=$1`, [u.id]);
  res.json({ token: sign(user), user });
}));

app.post('/api/send-code', limit, wrap(async (req, res) => { // resend verification, or start password recovery
  const purpose = req.body.purpose === 'reset' ? 'reset' : 'verify', u = await byEmail(req.body.email);
  if (u && (purpose === 'reset' ? u.verified : !u.verified)) await issueCode(u, purpose, channelOf(req.body.channel));
  res.json({ ok: true }); // same answer whether or not the account exists
}));

app.post('/api/reset', limit, wrap(async (req, res) => {
  if (String(req.body.password || '').length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const u = await byEmail(req.body.email);
  const bad = u && u.verified ? await checkCode(u, 'reset', req.body.code) : 'That code is wrong or has expired. Request a new one.';
  if (bad) return res.status(400).json({ error: bad });
  await q('UPDATE users SET password=$1 WHERE id=$2', [bcrypt.hashSync(req.body.password, 10), u.id]);
  res.json({ ok: true });
}));

app.post('/api/login', limit, wrap(async (req, res) => {
  const u = await byEmail(req.body.email);
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.password)) return res.status(401).json({ error: 'Email or password is incorrect.' });
  if (u.suspended) return res.status(403).json({ error: 'Your account has been suspended. Please contact an administrator.' });
  if (!u.verified) {
    await issueCode(u, 'verify', 'email').catch(() => {});
    return res.status(403).json({ error: 'Please confirm your account first.', needsVerify: true, email: u.email });
  }
  await syncAdmins();
  const user = await one(`SELECT ${PUB} FROM users WHERE id=$1`, [u.id]);
  res.json({ token: sign(user), user });
}));

app.get('/api/me', auth, wrap(async (req, res) => {
  const u = await one(`SELECT ${PUB} FROM users WHERE id=$1 AND verified`, [req.uid]);
  u ? res.json(u) : res.status(401).json({ error: 'Account not found.' });
}));
app.put('/api/me/avatar', auth, wrap(async (req, res) => {
  if (!mediaOk(req.body.url, 'image')) return res.status(400).json({ error: 'Invalid photo.' });
  res.json(await one(`UPDATE users SET avatar_url=$1 WHERE id=$2 RETURNING ${PUB}`, [req.body.url, req.uid]));
}));
app.get('/api/users', auth, wrap(async (req, res) =>
  res.json((await q(`SELECT ${PUB} FROM users WHERE id<>$1 AND verified AND NOT COALESCE(suspended,false) ORDER BY name`, [req.uid])).map(withOnline))));
app.get('/api/users/:id', auth, wrap(async (req, res) => {
  const id = parseInt(req.params.id, 10), u = id && await one(`SELECT ${PUB} FROM users WHERE id=$1 AND verified`, [id]);
  u ? res.json(withOnline(u)) : res.status(404).json({ error: 'Student not found.' });
}));

// ---------- posts, likes, comments ----------
const POST_Q = `SELECT p.id,p.body,p.media_url,p.media_type,p.created_at,u.id user_id,u.name,u.avatar_url,u.role,p.pinned,u.join_year,u.left_year FROM posts p JOIN users u ON u.id=p.user_id`;
async function decorate(rows, uid) { // add like/comment counts
  if (!rows.length) return rows;
  const ids = rows.map(r => r.id).join(',');
  const L = await q(`SELECT post_id,count(*)::int n FROM likes WHERE post_id IN (${ids}) GROUP BY post_id`);
  const M = await q(`SELECT post_id FROM likes WHERE user_id=$1 AND post_id IN (${ids})`, [uid]);
  const C = await q(`SELECT post_id,count(*)::int n FROM comments WHERE post_id IN (${ids}) GROUP BY post_id`);
  return rows.map(r => ({ ...r, like_count: L.find(x => x.post_id === r.id)?.n || 0, liked: M.some(x => x.post_id === r.id), comment_count: C.find(x => x.post_id === r.id)?.n || 0 }));
}
app.get('/api/posts', auth, wrap(async (req, res) => res.json(await decorate(await q(`${POST_Q} ORDER BY COALESCE(p.pinned,false) DESC, p.id DESC LIMIT 100`), req.uid))));
app.post('/api/posts', auth, wrap(async (req, res) => {
  const body = clean(req.body.body, 1000), type = req.body.media_type === 'video' ? 'video' : 'image';
  const url = req.body.media_url ? (mediaOk(req.body.media_url, type) ? req.body.media_url : null) : undefined;
  if (url === null) return res.status(400).json({ error: 'Invalid photo or video.' });
  if (!body && !url) return res.status(400).json({ error: 'Write something or add a photo or video.' });
  const pin = req.role === 'admin' && !!req.body.announce; // admins can pin a post as an announcement
  const { id } = await one('INSERT INTO posts(user_id,body,media_url,media_type,pinned) VALUES($1,$2,$3,$4,$5) RETURNING id', [req.uid, body, url || null, url ? type : null, pin]);
  const post = { ...(await one(`${POST_Q} WHERE p.id=$1`, [id])), like_count: 0, liked: false, comment_count: 0 };
  io.emit('post', post); res.json(post);
  if (pin) q('SELECT id FROM users WHERE verified AND id<>$1', [req.uid]).then(r => pushTo(r.map(x => x.id),
    { title: '📢 Announcement from ' + post.name, body: (body || 'New announcement').slice(0, 140), url: '/', tag: 'announce', kind: 'message' })).catch(() => {});
}));
app.delete('/api/posts/:id', auth, wrap(async (req, res) => {
  const pid = parseInt(req.params.id, 10) || 0;
  const gone = req.role === 'admin' ? await one('DELETE FROM posts WHERE id=$1 RETURNING id', [pid]) : await one('DELETE FROM posts WHERE id=$1 AND user_id=$2 RETURNING id', [pid, req.uid]);
  if (!gone) return res.status(404).json({ error: 'Post not found, or it isn’t yours.' });
  await q('DELETE FROM likes WHERE post_id=$1', [pid]); await q('DELETE FROM comments WHERE post_id=$1', [pid]);
  io.emit('post-deleted', { id: pid }); res.json({ ok: true });
}));
app.post('/api/posts/:id/like', auth, wrap(async (req, res) => {
  const pid = parseInt(req.params.id, 10);
  if (!pid || !(await one('SELECT 1 FROM posts WHERE id=$1', [pid]))) return res.status(404).json({ error: 'Post not found.' });
  const had = await one('DELETE FROM likes WHERE post_id=$1 AND user_id=$2 RETURNING 1', [pid, req.uid]);
  if (!had) await q('INSERT INTO likes(post_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING', [pid, req.uid]);
  const { n } = await one('SELECT count(*)::int n FROM likes WHERE post_id=$1', [pid]);
  io.emit('like', { post_id: pid, count: n }); res.json({ liked: !had, count: n });
}));
const CM_Q = `SELECT c.id,c.post_id,c.body,c.created_at,u.id user_id,u.name,u.avatar_url FROM comments c JOIN users u ON u.id=c.user_id`;
app.get('/api/posts/:id/comments', auth, wrap(async (req, res) =>
  res.json(await q(`${CM_Q} WHERE c.post_id=$1 ORDER BY c.id LIMIT 200`, [parseInt(req.params.id, 10) || 0]))));
app.post('/api/posts/:id/comments', auth, wrap(async (req, res) => {
  const pid = parseInt(req.params.id, 10), body = clean(req.body.body, 500);
  if (!body) return res.status(400).json({ error: 'Write a comment first.' });
  if (!pid || !(await one('SELECT 1 FROM posts WHERE id=$1', [pid]))) return res.status(404).json({ error: 'Post not found.' });
  const { id } = await one('INSERT INTO comments(post_id,user_id,body) VALUES($1,$2,$3) RETURNING id', [pid, req.uid, body]);
  const comment = await one(`${CM_Q} WHERE c.id=$1`, [id]), { n } = await one('SELECT count(*)::int n FROM comments WHERE post_id=$1', [pid]);
  io.emit('comment', { post_id: pid, count: n, comment }); res.json(comment);
}));
// to_id = 0 is the "Everyone" group chat
const MSG_Q = `SELECT m.id,m.from_id,m.to_id,m.body,m.deleted,m.att_url,m.att_type,m.att_name,m.att_size,m.created_at,u.name,u.avatar_url FROM messages m JOIN users u ON u.id=m.from_id`;
app.get('/api/messages/:id', auth, wrap(async (req, res) => {
  const o = parseInt(req.params.id, 10) || 0;
  const rows = o === 0 ? await q(`${MSG_Q} WHERE m.to_id=0 ORDER BY m.id DESC LIMIT 200`)
    : await q(`${MSG_Q} WHERE (m.from_id=$1 AND m.to_id=$2) OR (m.from_id=$2 AND m.to_id=$1) ORDER BY m.id DESC LIMIT 200`, [req.uid, o]);
  res.json(rows.reverse());
}));

app.delete('/api/comments/:id', auth, wrap(async (req, res) => {
  const c = await one('SELECT id,post_id,user_id FROM comments WHERE id=$1', [parseInt(req.params.id, 10) || 0]);
  if (!c || (c.user_id !== req.uid && req.role !== 'admin')) return res.status(404).json({ error: 'Comment not found, or it isn’t yours.' });
  await q('DELETE FROM comments WHERE id=$1', [c.id]);
  const { n } = await one('SELECT count(*)::int n FROM comments WHERE post_id=$1', [c.post_id]);
  io.emit('comment-deleted', { id: c.id, post_id: c.post_id, count: n }); res.json({ ok: true });
}));
app.delete('/api/messages/:id', auth, wrap(async (req, res) => {
  const wipe = `UPDATE messages SET body='',att_url=NULL,att_type=NULL,att_name=NULL,att_size=NULL,deleted=true WHERE id=$1 AND NOT COALESCE(deleted,false)`;
  const id = parseInt(req.params.id, 10) || 0;
  const m = (await one(`${wipe} AND from_id=$2 RETURNING id,from_id,to_id`, [id, req.uid]))
    || (req.role === 'admin' ? await one(`${wipe} AND to_id=0 RETURNING id,from_id,to_id`, [id]) : null);
  if (!m) return res.status(404).json({ error: 'Message not found, or it isn’t yours.' });
  (m.to_id === 0 ? io : io.to('u' + m.to_id).to('u' + m.from_id)).emit('message-deleted', { id: m.id });
  res.json({ ok: true });
}));

// ---------- push notifications (work even when the app is closed) ----------
let VAPID = null;
async function initPush() {
  let pub = env.VAPID_PUBLIC_KEY, priv = env.VAPID_PRIVATE_KEY;
  if (!pub || !priv) { // generate once and keep in the database so it survives restarts
    if (!(await one(`SELECT v FROM settings WHERE k='vapid'`))) {
      const k = webpush.generateVAPIDKeys();
      await q(`INSERT INTO settings(k,v) VALUES('vapid',$1)`, [JSON.stringify({ pub: k.publicKey, priv: k.privateKey })]).catch(() => {});
    }
    ({ pub, priv } = JSON.parse((await one(`SELECT v FROM settings WHERE k='vapid'`)).v));
  }
  webpush.setVapidDetails('mailto:' + (env.MAIL_FROM || 'admin@example.com'), pub, priv);
  VAPID = pub;
}
async function pushTo(ids, payload, opts = {}) {
  ids = [...new Set(ids.map(Number).filter(Boolean))];
  if (!VAPID || !ids.length) return;
  const subs = await q(`SELECT * FROM push_subs WHERE user_id IN (${ids.join(',')})`), data = JSON.stringify(payload);
  await Promise.all(subs.map(x => webpush.sendNotification({ endpoint: x.endpoint, keys: { p256dh: x.p256dh, auth: x.auth } }, data,
    { TTL: opts.ttl || 3600, urgency: opts.urgency || 'normal' }).catch(e => {
      if (e.statusCode === 404 || e.statusCode === 410) return q('DELETE FROM push_subs WHERE id=$1', [x.id]);
      console.error('push failed', e.statusCode || e.message);
    })));
}
app.post('/api/push/subscribe', auth, wrap(async (req, res) => {
  const { endpoint, keys } = req.body || {};
  if (typeof endpoint !== 'string' || !/^https:\/\//.test(endpoint) || !keys?.p256dh || !keys?.auth) return res.status(400).json({ error: 'Invalid subscription.' });
  await q('DELETE FROM push_subs WHERE endpoint=$1', [endpoint]);
  await q('INSERT INTO push_subs(user_id,endpoint,p256dh,auth) VALUES($1,$2,$3,$4)', [req.uid, endpoint, String(keys.p256dh), String(keys.auth)]);
  res.json({ ok: true });
}));
app.post('/api/push/unsubscribe', auth, wrap(async (req, res) => {
  await q('DELETE FROM push_subs WHERE endpoint=$1 AND user_id=$2', [String(req.body?.endpoint || ''), req.uid]); res.json({ ok: true });
}));
app.get('/api/call-config', auth, (req, res) => res.json({ iceServers: ICE }));

// ---------- real-time chat + presence ----------
// ---------- admin dashboard ----------
async function target(req, res) { // the member an admin wants to change, or null (after sending the error)
  const id = parseInt(req.params.id, 10) || 0, u = await one('SELECT id,name,email,role,verified FROM users WHERE id=$1', [id]);
  if (!u) { res.status(404).json({ error: 'Member not found.' }); return null; }
  if (id === req.uid) { res.status(400).json({ error: 'You can’t do that to your own account.' }); return null; }
  if (OWNERS.has(u.email)) { res.status(403).json({ error: 'This is an owner account and can’t be changed.' }); return null; }
  return u;
}
app.get('/api/admin/stats', auth, admin, wrap(async (req, res) => {
  const n = async sql => (await one(sql)).n;
  const [users, verified, suspended, admins, posts, comments, dms, room, newUsers, newPosts] = await Promise.all([
    n('SELECT count(*)::int n FROM users'), n('SELECT count(*)::int n FROM users WHERE verified'), n('SELECT count(*)::int n FROM users WHERE suspended'),
    n(`SELECT count(*)::int n FROM users WHERE role='admin'`), n('SELECT count(*)::int n FROM posts'), n('SELECT count(*)::int n FROM comments'),
    n('SELECT count(*)::int n FROM messages WHERE to_id<>0'), n('SELECT count(*)::int n FROM messages WHERE to_id=0'),
    n(`SELECT count(*)::int n FROM users WHERE verified AND created_at > now() - interval '7 days'`), n(`SELECT count(*)::int n FROM posts WHERE created_at > now() - interval '7 days'`)]);
  res.json({ users: verified, pending: users - verified, suspended, admins, online: online.size, posts, comments, dms, room, newUsers, newPosts, groupCall: gstate() });
}));
app.get('/api/admin/users', auth, admin, wrap(async (req, res) => res.json((await q(
  `SELECT id,name,email,contact,avatar_url,join_year,join_class,left_year,left_class,status,detail,role,verified,suspended,created_at FROM users ORDER BY id DESC LIMIT 2000`))
  .map(u => ({ ...u, suspended: !!u.suspended, role: u.role || 'user', online: online.has(u.id), owner: OWNERS.has(u.email) })))));
app.post('/api/admin/users/:id/suspend', auth, admin, wrap(async (req, res) => {
  const u = await target(req, res); if (!u) return;
  if (u.role === 'admin') return res.status(403).json({ error: 'Remove admin rights first.' });
  const on = !!req.body.suspended;
  await q('UPDATE users SET suspended=$1 WHERE id=$2', [on, u.id]);
  if (on) { await q('DELETE FROM push_subs WHERE user_id=$1', [u.id]); leaveGroup(u.id); io.in('u' + u.id).disconnectSockets(true); }
  res.json({ ok: true });
}));
app.post('/api/admin/users/:id/role', auth, admin, wrap(async (req, res) => {
  const u = await target(req, res); if (!u) return;
  if (!u.verified) return res.status(400).json({ error: 'Verify this member first.' });
  await q('UPDATE users SET role=$1 WHERE id=$2', [req.body.role === 'admin' ? 'admin' : 'user', u.id]); res.json({ ok: true });
}));
app.post('/api/admin/users/:id/verify', auth, admin, wrap(async (req, res) => {
  const u = await target(req, res); if (!u) return;
  await q('UPDATE users SET verified=true WHERE id=$1', [u.id]); await q('DELETE FROM codes WHERE user_id=$1', [u.id]); res.json({ ok: true });
}));
app.delete('/api/admin/users/:id', auth, admin, wrap(async (req, res) => {
  const u = await target(req, res); if (!u) return;
  if (u.role === 'admin') return res.status(403).json({ error: 'Remove admin rights first.' });
  const pids = (await q('SELECT id FROM posts WHERE user_id=$1', [u.id])).map(r => r.id);
  if (pids.length) { const l = pids.join(','); await q(`DELETE FROM likes WHERE post_id IN (${l})`); await q(`DELETE FROM comments WHERE post_id IN (${l})`); await q('DELETE FROM posts WHERE user_id=$1', [u.id]); }
  for (const t of ['likes WHERE user_id', 'comments WHERE user_id', 'push_subs WHERE user_id', 'codes WHERE user_id']) await q(`DELETE FROM ${t}=$1`, [u.id]);
  await q('DELETE FROM messages WHERE from_id=$1 OR to_id=$1', [u.id]); await q('DELETE FROM users WHERE id=$1', [u.id]);
  pids.forEach(id => io.emit('post-deleted', { id })); leaveGroup(u.id); io.in('u' + u.id).disconnectSockets(true); io.emit('user-removed', { id: u.id });
  res.json({ ok: true });
}));
app.post('/api/admin/end-call', auth, admin, wrap(async (req, res) => {
  gcall.parts.clear(); gcall.by = null; gcall.startedAt = 0; io.emit('gcall:state', null); res.json({ ok: true });
}));
app.post('/api/posts/:id/pin', auth, admin, wrap(async (req, res) => {
  const r = await one('UPDATE posts SET pinned=$1 WHERE id=$2 RETURNING id', [!!req.body.pinned, parseInt(req.params.id, 10) || 0]);
  if (!r) return res.status(404).json({ error: 'Post not found.' });
  io.emit('post-updated', {}); res.json({ ok: true });
}));
app.get('/api/admin/export.csv', auth, admin, wrap(async (req, res) => {
  const rows = await q('SELECT name,email,contact,join_year,join_class,left_year,left_class,status,detail,verified,suspended,role,created_at FROM users ORDER BY name');
  const cell = v => { let t = v == null ? '' : v instanceof Date ? v.toISOString() : String(v); if (/^(=|@|\t|\r|[+-](?!\d))/.test(t)) t = "'" + t; return '"' + t.replace(/"/g, '""') + '"'; }; // stops spreadsheet formula tricks
  const head = ['Name', 'Email', 'Phone', 'Joined year', 'Joined class', 'Left year', 'Left class', 'Now', 'Course / occupation', 'Verified', 'Suspended', 'Role', 'Registered'];
  const csv = [head.map(cell).join(',')].concat(rows.map(r => [r.name, r.email, r.contact, r.join_year, r.join_class, r.left_year, r.left_class,
    r.status === 'occupation' ? 'Working' : 'Studying', r.detail, r.verified ? 'yes' : 'no', r.suspended ? 'yes' : 'no', r.role || 'user', r.created_at].map(cell).join(','))).join('\r\n');
  res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="shining-star-members.csv"' }).send('\ufeff' + csv);
}));

io.use(async (s, next) => {
  try {
    const id = jwt.verify(s.handshake.auth.token, SECRET).id, u = await one('SELECT id,suspended FROM users WHERE id=$1', [id]);
    if (!u || u.suspended) return next(new Error('auth'));
    s.uid = id; next();
  } catch { next(new Error('auth')); }
});

// ---- voice / group calls (signalling only; audio flows directly between phones) ----
const ringing = new Map(); // callee id -> { from, name, avatar_url, ts }
const inCall = new Map();  // user id -> partner id
const gcall = { parts: new Map(), by: null, startedAt: 0 }; // Chat Room group call, max 8 people
const gstate = () => (gcall.parts.size ? { by: gcall.by, startedAt: gcall.startedAt, parts: [...gcall.parts].map(([id, name]) => ({ id, name })) } : null);
const who = id => one('SELECT id,name,avatar_url FROM users WHERE id=$1', [id]);
function leaveGroup(uid) {
  if (!gcall.parts.delete(uid)) return;
  gcall.parts.forEach((n, id) => io.to('u' + id).emit('gcall:left', { id: uid }));
  if (!gcall.parts.size) { gcall.by = null; gcall.startedAt = 0; }
  io.emit('gcall:state', gstate());
}

io.on('connection', s => {
  s.join('u' + s.uid);
  const wasOnline = online.has(s.uid);
  online.set(s.uid, (online.get(s.uid) || 0) + 1);
  if (!wasOnline) io.emit('presence', { id: s.uid, online: true });
  s.emit('online-list', [...online.keys()]);
  s.emit('gcall:state', gstate());
  const r = ringing.get(s.uid); // someone is calling and this user just opened the app (e.g. from the notification)
  if (r && Date.now() - r.ts < 44000) s.emit('call:incoming', { from: r.from, name: r.name, avatar_url: r.avatar_url });

  s.on('send', async ({ to, body, att } = {}, ack) => {
    try {
      body = clean(body, 2000); to = parseInt(to, 10) || 0; // to = 0 means the Chat Room
      const a = att && typeof att.url === 'string' && mediaOk(att.url, 'image|video|raw') && ['audio', 'file', 'image'].includes(att.type)
        ? { url: att.url, type: att.type, name: clean(att.name || 'File', 120), size: Math.max(0, parseInt(att.size, 10) || 0) } : null;
      if ((!body && !a) || (to !== 0 && !(await one('SELECT 1 FROM users WHERE id=$1 AND verified', [to])))) return ack && ack({ error: true });
      const { id } = await one('INSERT INTO messages(from_id,to_id,body,att_url,att_type,att_name,att_size) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',
        [s.uid, to, body, a?.url || null, a?.type || null, a?.name || null, a?.size ?? null]);
      const m = await one(`${MSG_Q} WHERE m.id=$1`, [id]);
      (to === 0 ? io : io.to('u' + to).to('u' + s.uid)).emit('message', m);
      ack && ack({ ok: true });
      const preview = body || (a?.type === 'audio' ? '🎤 Voice message' : a?.type === 'image' ? '📷 Photo' : a ? '📎 ' + a.name : '');
      const ids = to === 0 ? (await q('SELECT id FROM users WHERE verified AND id<>$1', [s.uid])).map(x => x.id) : [to];
      pushTo(ids, { title: to === 0 ? 'Chat Room' : m.name, body: (to === 0 ? m.name + ': ' : '') + preview.slice(0, 140),
        url: to === 0 ? '/#room' : '/#chat-' + s.uid, tag: to === 0 ? 'room' : 'chat-' + s.uid, kind: 'message' }).catch(() => {});
    } catch (e) { console.error(e); ack && ack({ error: true }); }
  });
  s.on('typing', ({ to } = {}) => io.to('u' + parseInt(to, 10)).emit('typing', { from: s.uid }));

  // 1-to-1 calls
  s.on('call:invite', async ({ to } = {}, ack) => {
    try {
      to = parseInt(to, 10);
      if (!to || to === s.uid || inCall.has(s.uid)) return ack && ack({ error: true });
      if (inCall.has(to)) return ack && ack({ busy: true });
      const me = await who(s.uid); if (!me) return ack && ack({ error: true });
      const ring = { from: s.uid, name: me.name, avatar_url: me.avatar_url, ts: Date.now() };
      ringing.set(to, ring);
      io.to('u' + to).emit('call:incoming', { from: s.uid, name: me.name, avatar_url: me.avatar_url });
      pushTo([to], { title: '📞 Incoming call', body: me.name + ' is calling you', url: '/#chat-' + s.uid, tag: 'call', kind: 'call', requireInteraction: true }, { urgency: 'high', ttl: 30 }).catch(() => {});
      setTimeout(() => { if (ringing.get(to) === ring) { ringing.delete(to); io.to('u' + s.uid).emit('call:missed', { to }); io.to('u' + to).emit('call:cancel', { from: s.uid }); } }, 45000);
      ack && ack({ ok: true, online: online.has(to) });
    } catch (e) { console.error(e); ack && ack({ error: true }); }
  });
  s.on('call:accept', ({ to } = {}) => {
    to = parseInt(to, 10); const r = ringing.get(s.uid);
    if (!r || r.from !== to) return;
    ringing.delete(s.uid); inCall.set(s.uid, to); inCall.set(to, s.uid);
    io.to('u' + s.uid).emit('call:handled', {}); io.to('u' + to).emit('call:accepted', { from: s.uid });
  });
  s.on('call:reject', ({ to } = {}) => {
    to = parseInt(to, 10); if (ringing.get(s.uid)?.from === to) ringing.delete(s.uid);
    io.to('u' + s.uid).emit('call:handled', {}); io.to('u' + to).emit('call:rejected', { from: s.uid });
  });
  s.on('call:cancel', ({ to } = {}) => { // caller hung up before an answer
    to = parseInt(to, 10); if (ringing.get(to)?.from === s.uid) ringing.delete(to);
    io.to('u' + to).emit('call:cancel', { from: s.uid });
  });
  s.on('call:signal', ({ to, data } = {}) => { to = parseInt(to, 10); if (inCall.get(s.uid) === to) io.to('u' + to).emit('call:signal', { from: s.uid, data }); });
  s.on('call:end', ({ to } = {}) => {
    to = parseInt(to, 10); if (inCall.get(s.uid) === to) { inCall.delete(s.uid); inCall.delete(to); }
    io.to('u' + to).emit('call:ended', { from: s.uid });
  });

  // Chat Room group call: everyone is alerted, people join by accepting
  s.on('gcall:start', async (_, ack) => {
    try {
      if (gcall.parts.size) return ack && ack({ exists: true });
      const me = await who(s.uid); if (!me) return ack && ack({ error: true });
      gcall.by = me.name; gcall.startedAt = Date.now(); gcall.parts.set(s.uid, me.name);
      io.emit('gcall:state', gstate());
      const ids = (await q('SELECT id FROM users WHERE verified AND id<>$1', [s.uid])).map(x => x.id);
      pushTo(ids, { title: '📞 Group call in Chat Room', body: me.name + ' started a group call. Tap to join.', url: '/#room', tag: 'gcall', kind: 'gcall', requireInteraction: true }, { urgency: 'high', ttl: 120 }).catch(() => {});
      ack && ack({ ok: true });
    } catch (e) { console.error(e); ack && ack({ error: true }); }
  });
  s.on('gcall:join', async (_, ack) => {
    try {
      if (!gcall.parts.size) return ack && ack({ error: 'ended' });
      if (gcall.parts.has(s.uid)) return ack && ack({ error: 'already' });
      if (gcall.parts.size >= 8) return ack && ack({ error: 'full' });
      const me = await who(s.uid), peers = [...gcall.parts].map(([id, name]) => ({ id, name }));
      gcall.parts.set(s.uid, me.name);
      peers.forEach(p => io.to('u' + p.id).emit('gcall:joined', { id: s.uid, name: me.name }));
      io.emit('gcall:state', gstate());
      ack && ack({ ok: true, peers });
    } catch (e) { console.error(e); ack && ack({ error: true }); }
  });
  s.on('gcall:signal', ({ to, data } = {}) => { to = parseInt(to, 10); if (gcall.parts.has(s.uid) && gcall.parts.has(to)) io.to('u' + to).emit('gcall:signal', { from: s.uid, data }); });
  s.on('gcall:leave', () => leaveGroup(s.uid));

  s.on('disconnect', () => {
    const n = (online.get(s.uid) || 1) - 1;
    if (n > 0) return online.set(s.uid, n);
    online.delete(s.uid); io.emit('presence', { id: s.uid, online: false });
    leaveGroup(s.uid);
    const partner = inCall.get(s.uid);
    if (partner) { inCall.delete(s.uid); inCall.delete(partner); io.to('u' + partner).emit('call:ended', { from: s.uid }); }
    ringing.forEach((r, callee) => { if (r.from === s.uid) { ringing.delete(callee); io.to('u' + callee).emit('call:cancel', { from: s.uid }); } });
    ringing.delete(s.uid);
  });
});

const PORT = env.PORT || 3000;
init().then(initPush).then(() => server.listen(PORT, () => console.log(`Shining Star Reunion running on port ${PORT}`)))
  .catch(e => { console.error('Database setup failed:', e.message); process.exit(1); });
