const express = require('express'), http = require('http'), path = require('path'), crypto = require('crypto');
const { Pool } = require('pg'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const env = process.env;
const SECRET = env.JWT_SECRET || 'dev-only-change-me';
if (!env.JWT_SECRET) console.warn('Set JWT_SECRET in production!');
if (!env.DATABASE_URL) { console.error('DATABASE_URL is not set (see README).'); process.exit(1); }
const SMS = !!(env.TWILIO_SID && env.TWILIO_TOKEN && env.TWILIO_FROM);
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
  await q(`CREATE TABLE IF NOT EXISTS posts(id SERIAL PRIMARY KEY, user_id INT NOT NULL, body TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ DEFAULT now())`);
  await q(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS media_url TEXT`);
  await q(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS media_type TEXT`);
  await q(`CREATE TABLE IF NOT EXISTS likes(post_id INT NOT NULL, user_id INT NOT NULL, PRIMARY KEY(post_id,user_id))`);
  await q(`CREATE TABLE IF NOT EXISTS comments(id SERIAL PRIMARY KEY, post_id INT NOT NULL, user_id INT NOT NULL, body TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())`);
  await q(`CREATE TABLE IF NOT EXISTS messages(id SERIAL PRIMARY KEY, from_id INT NOT NULL, to_id INT NOT NULL, body TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())`);
  await q(`CREATE TABLE IF NOT EXISTS codes(id SERIAL PRIMARY KEY, user_id INT NOT NULL, purpose TEXT NOT NULL, code_hash TEXT NOT NULL, attempts INT DEFAULT 0, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ DEFAULT now())`);
  await q(`CREATE INDEX IF NOT EXISTS idx_msg ON messages(from_id,to_id)`);
}

const PUB = 'id,name,email,avatar_url,join_year,join_class,left_year,left_class,status,detail,contact,created_at';
const online = new Map();
const sign = u => jwt.sign({ id: u.id }, SECRET, { expiresIn: '30d' });
const clean = (v, max = 200) => String(v ?? '').trim().slice(0, max);
const withOnline = u => ({ ...u, online: online.has(u.id) });
const mediaOk = (url, kinds) => new RegExp(`^https://res\\.cloudinary\\.com/[\\w-]+/(${kinds})/upload/`).test(url || '');

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
app.use(express.static(path.join(__dirname, 'public')));
app.get('/health', (req, res) => res.send('ok'));
app.get('/api/config', (req, res) => res.json({ cloud: env.CLOUDINARY_CLOUD_NAME || null, preset: env.CLOUDINARY_UPLOAD_PRESET || null, sms: SMS }));

const hits = new Map();
const limit = (req, res, next) => {
  const k = req.ip, now = Date.now(), arr = (hits.get(k) || []).filter(t => now - t < 60000);
  arr.push(now); hits.set(k, arr);
  arr.length > 20 ? res.status(429).json({ error: 'Too many attempts. Try again in a minute.' }) : next();
};
const auth = (req, res, next) => {
  try { req.uid = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET).id; next(); }
  catch { res.status(401).json({ error: 'Please log in again.' }); }
};
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
  const user = await one(`UPDATE users SET verified=true WHERE id=$1 RETURNING ${PUB}`, [u.id]);
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
  if (!u.verified) {
    await issueCode(u, 'verify', 'email').catch(() => {});
    return res.status(403).json({ error: 'Please confirm your account first.', needsVerify: true, email: u.email });
  }
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
  res.json((await q(`SELECT ${PUB} FROM users WHERE id<>$1 AND verified ORDER BY name`, [req.uid])).map(withOnline))));
app.get('/api/users/:id', auth, wrap(async (req, res) => {
  const id = parseInt(req.params.id, 10), u = id && await one(`SELECT ${PUB} FROM users WHERE id=$1 AND verified`, [id]);
  u ? res.json(withOnline(u)) : res.status(404).json({ error: 'Student not found.' });
}));

// ---------- posts, likes, comments ----------
const POST_Q = `SELECT p.id,p.body,p.media_url,p.media_type,p.created_at,u.id user_id,u.name,u.avatar_url,u.join_year,u.left_year FROM posts p JOIN users u ON u.id=p.user_id`;
async function decorate(rows, uid) { // add like/comment counts
  if (!rows.length) return rows;
  const ids = rows.map(r => r.id).join(',');
  const L = await q(`SELECT post_id,count(*)::int n FROM likes WHERE post_id IN (${ids}) GROUP BY post_id`);
  const M = await q(`SELECT post_id FROM likes WHERE user_id=$1 AND post_id IN (${ids})`, [uid]);
  const C = await q(`SELECT post_id,count(*)::int n FROM comments WHERE post_id IN (${ids}) GROUP BY post_id`);
  return rows.map(r => ({ ...r, like_count: L.find(x => x.post_id === r.id)?.n || 0, liked: M.some(x => x.post_id === r.id), comment_count: C.find(x => x.post_id === r.id)?.n || 0 }));
}
app.get('/api/posts', auth, wrap(async (req, res) => res.json(await decorate(await q(`${POST_Q} ORDER BY p.id DESC LIMIT 100`), req.uid))));
app.post('/api/posts', auth, wrap(async (req, res) => {
  const body = clean(req.body.body, 1000), type = req.body.media_type === 'video' ? 'video' : 'image';
  const url = req.body.media_url ? (mediaOk(req.body.media_url, type) ? req.body.media_url : null) : undefined;
  if (url === null) return res.status(400).json({ error: 'Invalid photo or video.' });
  if (!body && !url) return res.status(400).json({ error: 'Write something or add a photo or video.' });
  const { id } = await one('INSERT INTO posts(user_id,body,media_url,media_type) VALUES($1,$2,$3,$4) RETURNING id', [req.uid, body, url || null, url ? type : null]);
  const post = { ...(await one(`${POST_Q} WHERE p.id=$1`, [id])), like_count: 0, liked: false, comment_count: 0 };
  io.emit('post', post); res.json(post);
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
app.get('/api/messages/:id', auth, wrap(async (req, res) => {
  const o = parseInt(req.params.id, 10) || 0;
  res.json((await q(`SELECT * FROM messages WHERE (from_id=$1 AND to_id=$2) OR (from_id=$2 AND to_id=$1) ORDER BY id DESC LIMIT 200`, [req.uid, o])).reverse());
}));

// ---------- real-time chat + presence ----------
io.use((s, next) => {
  try { s.uid = jwt.verify(s.handshake.auth.token, SECRET).id; next(); } catch { next(new Error('auth')); }
});
io.on('connection', s => {
  s.join('u' + s.uid);
  const wasOnline = online.has(s.uid);
  online.set(s.uid, (online.get(s.uid) || 0) + 1);
  if (!wasOnline) io.emit('presence', { id: s.uid, online: true });
  s.emit('online-list', [...online.keys()]);
  s.on('send', async ({ to, body } = {}, ack) => {
    try {
      body = clean(body, 2000); to = parseInt(to, 10);
      if (!body || !to || !(await one('SELECT 1 FROM users WHERE id=$1', [to]))) return ack && ack({ error: true });
      const m = await one('INSERT INTO messages(from_id,to_id,body) VALUES($1,$2,$3) RETURNING *', [s.uid, to, body]);
      io.to('u' + to).to('u' + s.uid).emit('message', m);
      ack && ack({ ok: true });
    } catch (e) { console.error(e); ack && ack({ error: true }); }
  });
  s.on('typing', ({ to } = {}) => io.to('u' + parseInt(to, 10)).emit('typing', { from: s.uid }));
  s.on('disconnect', () => {
    const n = (online.get(s.uid) || 1) - 1;
    if (n <= 0) { online.delete(s.uid); io.emit('presence', { id: s.uid, online: false }); } else online.set(s.uid, n);
  });
});

const PORT = env.PORT || 3000;
init().then(() => server.listen(PORT, () => console.log(`Shining Star Reunion running on port ${PORT}`)))
  .catch(e => { console.error('Database setup failed:', e.message); process.exit(1); });
