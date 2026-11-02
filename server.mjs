// VGN Cinemas backend — zero npm dependencies (Node 22.13+).
// Uses built-in node:http, node:sqlite and node:crypto.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'vgn.db');
const PRICE = 15, SIGNUP_CREDITS = 1000, MAX_SEATS = 10;
const PUBLIC = path.join(__dirname, 'public');

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pass TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('audience','owner')),
  credits INTEGER NOT NULL DEFAULT 0 CHECK(credits>=0));
CREATE TABLE IF NOT EXISTS shows(
  id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, name TEXT NOT NULL, runtime INTEGER NOT NULL,
  cert TEXT NOT NULL, poster TEXT, times TEXT NOT NULL, screen TEXT NOT NULL, screen_name TEXT NOT NULL,
  release TEXT NOT NULL, open TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS bookings(
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, show_id TEXT, movie TEXT NOT NULL, poster TEXT,
  screen TEXT NOT NULL, screen_name TEXT NOT NULL, time TEXT NOT NULL, date TEXT NOT NULL,
  seats TEXT NOT NULL, total INTEGER NOT NULL, phone TEXT NOT NULL, email TEXT NOT NULL, booked TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS seats(
  show_id TEXT NOT NULL, date TEXT NOT NULL, time TEXT NOT NULL, seat TEXT NOT NULL, booking_id TEXT NOT NULL,
  UNIQUE(show_id,date,time,seat));
`);

// Signing secret: env var, else generated once and persisted.
let SECRET = process.env.SECRET;
if (!SECRET) {
  const r = db.prepare("SELECT v FROM meta WHERE k='secret'").get();
  if (r) SECRET = r.v;
  else { SECRET = crypto.randomBytes(32).toString('hex'); db.prepare("INSERT INTO meta VALUES('secret',?)").run(SECRET); }
}

/* ---------- helpers ---------- */
const b64 = b => Buffer.from(b).toString('base64url');
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const makeToken = uid => { const p = b64(JSON.stringify({ uid, exp: Date.now() + 7 * 864e5 })); return p + '.' + sign(p); };
function readToken(t) {
  if (!t) return null; const [p, s] = t.split('.');
  if (!p || !s) return null;
  const a = Buffer.from(sign(p)), b = Buffer.from(s);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url')); return o.exp > Date.now() ? o.uid : null; } catch { return null; }
}
const hashPw = pw => { const salt = crypto.randomBytes(16); return salt.toString('hex') + ':' + crypto.scryptSync(pw, salt, 64).toString('hex'); };
function checkPw(pw, stored) {
  const [s, h] = stored.split(':'); const x = crypto.scryptSync(pw, Buffer.from(s, 'hex'), 64);
  return crypto.timingSafeEqual(x, Buffer.from(h, 'hex'));
}
class HttpError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const bad = (m, c = 400) => { throw new HttpError(c, m); };
const today = tz => new Intl.DateTimeFormat('en-CA', { timeZone: tz }).format(new Date()); // YYYY-MM-DD
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/, TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;
const CERTS = ['U (All ages)', 'UA 7+', 'UA 13+', 'UA 16+', 'A (18+)'], SCREENS = ['Single', 'Multiplex', 'IMAX', 'PXL', 'EPIQ'];
const pubUser = u => ({ u: u.username, role: u.role, credits: u.credits });
const showOut = r => ({ id: r.id, name: r.name, runtime: r.runtime, cert: r.cert, poster: r.poster || '', times: JSON.parse(r.times),
  screen: r.screen, screenName: r.screen_name, release: r.release, open: r.open, owner: r.owner });
const bookingOut = r => ({ id: r.id, movie: r.movie, poster: r.poster || '', screen: r.screen_name, screenType: r.screen, time: r.time,
  date: r.date, seats: JSON.parse(r.seats), total: r.total, booked: r.booked });

const tx = fn => { db.exec('BEGIN IMMEDIATE'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } };

// naive in-memory rate limit for auth endpoints
const hits = new Map();
function limit(ip) {
  const now = Date.now(), a = (hits.get(ip) || []).filter(t => now - t < 60000); a.push(now); hits.set(ip, a);
  if (a.length > 20) bad('Too many attempts. Try again in a minute.', 429);
}
setInterval(() => hits.clear(), 600000).unref();

/* ---------- routes ---------- */
const routes = [];
const route = (method, pattern, fn, auth) => routes.push({ method, re: new RegExp('^' + pattern.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), fn, auth });

route('POST', '/api/signup', ({ body, ip }) => {
  limit(ip);
  const username = String(body.username || '').trim(), password = String(body.password || ''), role = body.role;
  if (!/^[A-Za-z0-9_.-]{3,30}$/.test(username)) bad('Username must be 3-30 chars (letters, numbers, _ . -).');
  if (password.length < 6 || password.length > 100) bad('Password must be at least 6 characters.');
  if (!['audience', 'owner'].includes(role)) bad('Invalid role.');
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(username)) bad('Username already taken.', 409);
  const r = db.prepare('INSERT INTO users(username,pass,role,credits) VALUES(?,?,?,?)').run(username, hashPw(password), role, role === 'audience' ? SIGNUP_CREDITS : 0);
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid);
  return { token: makeToken(u.id), user: pubUser(u) };
});

route('POST', '/api/login', ({ body, ip }) => {
  limit(ip);
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(body.username || '').trim());
  if (!u || !checkPw(String(body.password || ''), u.pass)) bad('Invalid username or password.', 401);
  if (body.role && u.role !== body.role) bad(`This account is registered as ${u.role === 'owner' ? 'Theater Owner' : 'Audience'}.`, 403);
  return { token: makeToken(u.id), user: pubUser(u) };
});

route('GET', '/api/me', ({ user }) => ({ user: pubUser(user) }), true);

route('GET', '/api/shows', () => db.prepare('SELECT s.*,u.username owner FROM shows s JOIN users u ON u.id=s.owner_id ORDER BY s.created').all().map(showOut));

route('POST', '/api/shows', ({ user, body: b }) => {
  if (user.role !== 'owner') bad('Only theater owners can add shows.', 403);
  const name = String(b.name || '').trim(), runtime = parseInt(b.runtime, 10);
  if (!name || name.length > 120) bad('Movie name is required (max 120 chars).');
  if (!(runtime > 0 && runtime < 600)) bad('Enter a valid runtime in minutes.');
  if (!CERTS.includes(b.cert)) bad('Invalid censor certificate.');
  if (!SCREENS.includes(b.screen)) bad('Invalid screen type.');
  if (!Array.isArray(b.times) || !b.times.length || b.times.length > 12 || !b.times.every(t => TIME_RE.test(t))) bad('Add at least one valid show time.');
  if (!DATE_RE.test(b.release) || !DATE_RE.test(b.open)) bad('Invalid dates.');
  if (b.open > b.release) bad('Booking open date must be on or before the premiere date.');
  let poster = b.poster || '';
  if (poster && (!/^data:image\/(jpeg|png|webp);base64,/.test(poster) || poster.length > 700000)) bad('Poster must be a small JPEG/PNG/WebP image.');
  const n = db.prepare('SELECT COUNT(*) c FROM shows WHERE owner_id=?').get(user.id).c;
  const id = 's' + crypto.randomBytes(6).toString('hex');
  db.prepare('INSERT INTO shows VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run(id, user.id, name, runtime, b.cert, poster, JSON.stringify([...new Set(b.times)].sort()), b.screen, 'Screen ' + (n + 1), b.release, b.open, new Date().toISOString());
  return showOut(db.prepare('SELECT s.*,u.username owner FROM shows s JOIN users u ON u.id=s.owner_id WHERE s.id=?').get(id));
}, true);

route('DELETE', '/api/shows/:id', ({ user, params }) => {
  const r = db.prepare('DELETE FROM shows WHERE id=? AND owner_id=?').run(params.id, user.id);
  if (!r.changesToRow && !r.changes) bad('Show not found.', 404);
  return { ok: true };
}, true);

// seats already booked for a given show/date/time
route('GET', '/api/shows/:id/taken', ({ params, query }) => {
  const rows = db.prepare('SELECT seat FROM seats WHERE show_id=? AND date=? AND time=?').all(params.id, String(query.date), String(query.time));
  return { seats: rows.map(r => r.seat) };
});

route('GET', '/api/bookings', ({ user }) =>
  db.prepare('SELECT * FROM bookings WHERE user_id=? ORDER BY booked DESC').all(user.id).map(bookingOut), true);

route('POST', '/api/bookings', ({ user, body: b }) => {
  if (user.role !== 'audience') bad('Only audience accounts can book tickets.', 403);
  const show = db.prepare('SELECT * FROM shows WHERE id=?').get(String(b.showId));
  if (!show) bad('Show no longer exists.', 404);
  if (!JSON.parse(show.times).includes(b.time)) bad('Invalid show time.');
  if (!DATE_RE.test(b.date)) bad('Invalid date.');
  const ist = today('Asia/Kolkata'), utc = today('UTC');
  if (ist < show.open) bad(`Bookings open on ${show.open}.`);
  if (b.date < show.release) bad(`This movie premieres on ${show.release}.`);
  if (b.date < (ist < utc ? ist : utc)) bad('Cannot book a past date.');
  const seats = [...new Set(Array.isArray(b.seats) ? b.seats : [])];
  if (!seats.length || seats.length > MAX_SEATS || !seats.every(s => /^[A-H](10|[1-9])$/.test(s))) bad(`Select 1-${MAX_SEATS} valid seats.`);
  if (!/^\d{10}$/.test(String(b.phone))) bad('Enter a valid 10-digit phone number.');
  if (!/^\S+@\S+\.\S+$/.test(String(b.email)) || b.email.length > 200) bad('Enter a valid email.');
  const total = seats.length * PRICE, id = 'VGN' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(2).toString('hex').toUpperCase();
  return tx(() => {
    const u = db.prepare('SELECT credits FROM users WHERE id=?').get(user.id);
    if (u.credits < total) bad('Not enough credits.', 402);
    const ins = db.prepare('INSERT INTO seats VALUES(?,?,?,?,?)');
    try { for (const s of seats) ins.run(show.id, b.date, b.time, s, id); }
    catch { bad('Some of those seats were just booked by someone else. Please pick again.', 409); }
    db.prepare('UPDATE users SET credits=credits-? WHERE id=?').run(total, user.id);
    const booked = new Date().toISOString(), sorted = seats.sort();
    db.prepare('INSERT INTO bookings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id, user.id, show.id, show.name, show.poster, show.screen, show.screen_name, b.time, b.date, JSON.stringify(sorted), total, b.phone, b.email, booked);
    return { booking: { id, movie: show.name, poster: show.poster || '', screen: show.screen_name, screenType: show.screen, time: b.time, date: b.date, seats: sorted, total, booked }, credits: u.credits - total };
  });
}, true);

/* ---------- server ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
const SEC = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'DENY' };

function readBody(req) {
  return new Promise((res, rej) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > 1.5e6) { rej(new HttpError(413, 'Request too large.')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { res(chunks.length ? JSON.parse(Buffer.concat(chunks)) : {}); } catch { rej(new HttpError(400, 'Invalid JSON.')); } });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...SEC }); res.end(JSON.stringify(obj)); };
  try {
    if (url.pathname.startsWith('/api/')) {
      if (url.pathname === '/api/health') return send(200, { ok: true });
      const r = routes.find(r => r.method === req.method && r.re.test(url.pathname));
      if (!r) return send(404, { error: 'Not found.' });
      const ctx = { params: r.re.exec(url.pathname).groups || {}, query: Object.fromEntries(url.searchParams), ip: (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim(), body: {} };
      if (r.auth) {
        const uid = readToken((req.headers.authorization || '').replace(/^Bearer /, ''));
        ctx.user = uid && db.prepare('SELECT * FROM users WHERE id=?').get(uid);
        if (!ctx.user) return send(401, { error: 'Please log in again.' });
      }
      if (['POST', 'PUT', 'PATCH'].includes(req.method)) ctx.body = await readBody(req);
      return send(200, r.fn(ctx));
    }
    // static files
    let p = path.normalize(decodeURIComponent(url.pathname)).replace(/^(\.\.[/\\])+/, '');
    if (p === '/' || p === '\\') p = '/index.html';
    const file = path.join(PUBLIC, p);
    if (!file.startsWith(PUBLIC) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404, SEC); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', ...SEC });
    fs.createReadStream(file).pipe(res);
  } catch (e) {
    if (e instanceof HttpError) return send(e.code, { error: e.message });
    console.error(e); send(500, { error: 'Server error.' });
  }
});
server.listen(PORT, () => console.log(`VGN Cinemas running on :${PORT}  (db: ${DB_PATH})`));
