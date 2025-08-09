import express from 'express';
import cors from 'cors';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';

const app = express();
const PORT = process.env.PORT || 3000;

// ---- Tiny rate-limit (هر دقیقه 120 درخواست به‌صورت پیش‌فرض)
const RATE = { windowMs: 60_000, limit: Number(process.env.RATE_LIMIT || 120) };
const hits = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [ip, arr] of hits) {
    const pruned = arr.filter(t => now - t < RATE.windowMs);
    if (pruned.length) hits.set(ip, pruned); else hits.delete(ip);
  }
}, 30_000);
app.use((req, res, next) => {
  const ip = (req.headers['x-forwarded-for']?.split(',')[0]?.trim()) || req.socket.remoteAddress || 'ip';
  const now = Date.now();
  const arr = hits.get(ip) || [];
  arr.push(now);
  hits.set(ip, arr);
  if (arr.filter(t => now - t < RATE.windowMs).length > RATE.limit) {
    return res.status(429).json({ error: 'Too many requests' });
  }
  next();
});

// ---- Security + CORS
const ORIGINS = (process.env.CORS_ORIGINS || '*').split(',').map(s => s.trim()).filter(Boolean);
app.use((req,res,next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});
app.use(cors({
  origin(origin, cb){
    if (!origin || ORIGINS.includes('*') || ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('CORS blocked'), false);
  }
}));
app.options('*', cors());
app.use(express.json({ limit: process.env.JSON_LIMIT || '2mb' }));

// ---- SQLite (فایل در همان دایرکتوری ساخته می‌شود)
const db = new Database('dreammatch.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  passhash TEXT NOT NULL,
  name TEXT DEFAULT '',
  bio TEXT DEFAULT '',
  avatar_url TEXT DEFAULT '',
  created_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS dreams (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT DEFAULT '',
  text TEXT NOT NULL,
  date TEXT DEFAULT '',
  mood TEXT DEFAULT '',
  tags TEXT DEFAULT '',
  visibility TEXT DEFAULT 'public',
  embedding TEXT DEFAULT NULL,
  created_at INTEGER DEFAULT (strftime('%s','now'))
);
`);

// ---- Helpers
function cleanStr(s, max=256){ s = String(s||'').trim(); if (s.length>max) s = s.slice(0,max); return s; }
function clampText(s, max=5000){ s = String(s||''); if (s.length > max) s = s.slice(0, max); return s; }
function tokenize(t){ return String(t||'').toLowerCase().replace(/[^آ-یa-z0-9]+/g,' ').trim().split(/\s+/).filter(Boolean); }
function tfVec(tokens){
  const m = new Map();
  for (const w of tokens) m.set(w, (m.get(w)||0)+1);
  let norm = 0; for (const v of m.values()) norm += v*v; norm = Math.sqrt(norm)||1;
  const obj = {}; for (const [k,v] of m) obj[k] = v/norm;
  return obj;
}
function cosine(a,b){
  let dot=0;
  for (const [k,v] of Object.entries(a)) if (k in b) dot += v * b[k];
  const na = Math.sqrt(Object.values(a).reduce((s,x)=>s+x*x,0))||1;
  const nb = Math.sqrt(Object.values(b).reduce((s,x)=>s+x*x,0))||1;
  return dot/(na*nb);
}
function makeToken(){ return crypto.randomBytes(32).toString('hex'); }
function auth(req,res,next){
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing token' });
  const row = db.prepare('SELECT user_id FROM sessions WHERE token=?').get(token);
  if (!row) return res.status(401).json({ error: 'invalid token' });
  req.user_id = row.user_id;
  next();
}

// ---- Health
app.get('/health', (req,res)=> res.json({ ok:true, version:'4.1.1', time: Date.now(), cors: ORIGINS }) );

// ---- Auth
app.post('/auth/signup', (req,res)=>{
  let { email, password, name='' } = req.body || {};
  email = cleanStr(email, 320).toLowerCase(); name = cleanStr(name, 120);
  if (!email || !password) return res.status(400).json({ error:'email and password required' });
  const passhash = bcrypt.hashSync(String(password), 10);
  try{
    const info = db.prepare('INSERT INTO users (email, passhash, name) VALUES (?,?,?)').run(email, passhash, name);
    const token = makeToken();
    db.prepare('INSERT INTO sessions (token, user_id) VALUES (?,?)').run(token, info.lastInsertRowid);
    res.json({ token, user: { id: info.lastInsertRowid, email, name } });
  } catch(e){
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error:'email already exists' });
    res.status(500).json({ error:'signup failed' });
  }
});

app.post('/auth/login', (req,res)=>{
  let { email, password } = req.body || {};
  email = cleanStr(email, 320).toLowerCase();
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u) return res.status(401).json({ error:'invalid credentials' });
  if (!bcrypt.compareSync(String(password||''), u.passhash)) return res.status(401).json({ error:'invalid credentials' });
  const token = makeToken();
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?,?)').run(token, u.id);
  res.json({ token, user: { id: u.id, email: u.email, name: u.name } });
});

app.post('/auth/logout', auth, (req,res)=>{
  const token = (req.headers.authorization || '').slice(7);
  db.prepare('DELETE FROM sessions WHERE token=?').run(token);
  res.json({ ok:true });
});

// ---- Me
app.get('/me', auth, (req,res)=>{
  const u = db.prepare('SELECT id,email,name,bio,avatar_url,created_at FROM users WHERE id=?').get(req.user_id);
  res.json(u||{});
});
app.put('/me', auth, (req,res)=>{
  let { name='', bio='', avatar_url='' } = req.body || {};
  name = cleanStr(name, 120); bio = cleanStr(bio, 500); avatar_url = cleanStr(avatar_url, 500);
  db.prepare('UPDATE users SET name=?, bio=?, avatar_url=? WHERE id=?').run(name, bio, avatar_url, req.user_id);
  res.json({ ok:true });
});

// ---- Dreams
app.post('/dreams', auth, (req,res)=>{
  let { title='', text, date='', mood='', tags='', visibility='public' } = req.body || {};
  title = cleanStr(title, 160); date = cleanStr(date, 32); mood = cleanStr(mood, 32); tags = cleanStr(tags, 512); text = clampText(text, 5000);
  if (!text) return res.status(400).json({ error:'text required' });
  const vec = tfVec(tokenize(text + ' ' + tags)); // embedding ساده
  const info = db.prepare(`INSERT INTO dreams (user_id,title,text,date,mood,tags,visibility,embedding) VALUES (?,?,?,?,?,?,?,?)`)
    .run(req.user_id, title, text, date, mood, tags, visibility==='private'?'private':'public', JSON.stringify(vec));
  res.json({ id: info.lastInsertRowid });
});

app.get('/dreams', (req,res)=>{
  const limit = Math.max(1, Math.min(200, Number(req.query.limit)||50));
  const offset = Math.max(0, Number(req.query.offset)||0);
  const mine = String(req.query.mine||'').toLowerCase() === 'true';
  if (mine){
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'missing token' });
    const row = db.prepare('SELECT user_id FROM sessions WHERE token=?').get(token);
    if (!row) return res.status(401).json({ error: 'invalid token' });
    const rows = db.prepare('SELECT * FROM dreams WHERE user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?').all(row.user_id, limit, offset);
    return res.json(rows);
  }
  const rows = db.prepare("SELECT * FROM dreams WHERE visibility='public' ORDER BY created_at DESC LIMIT ? OFFSET ?").all(limit, offset);
  res.json(rows);
});

app.delete('/dreams/:id', auth, (req,res)=>{
  const d = db.prepare('SELECT * FROM dreams WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).json({ error:'not found' });
  if (d.user_id !== req.user_id) return res.status(403).json({ error:'forbidden' });
  db.prepare('DELETE FROM dreams WHERE id=?').run(d.id);
  res.json({ ok:true });
});

// ---- Search (TF/cosine)
app.get('/dreams/search', (req,res)=>{
  const q = String(req.query.q||'').trim();
  if (!q) return res.status(400).json({ error:'q required' });
  let user_id = null;
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (token){
    const row = db.prepare('SELECT user_id FROM sessions WHERE token=?').get(token);
    if (row) user_id = row.user_id;
  }
  const rows = user_id
    ? db.prepare("SELECT * FROM dreams WHERE visibility='public' OR user_id=? ORDER BY created_at DESC LIMIT 5000").all(user_id)
    : db.prepare("SELECT * FROM dreams WHERE visibility='public' ORDER BY created_at DESC LIMIT 5000").all();
  if (rows.length === 0) return res.json([]);
  const qVec = tfVec(tokenize(q));
  const items = rows.map(r => {
    let vec = null;
    try { vec = r.embedding ? JSON.parse(r.embedding) : null; } catch(e){ vec = null; }
    if (!vec){
      vec = tfVec(tokenize(r.text + ' ' + (r.tags||'')));
      db.prepare('UPDATE dreams SET embedding=? WHERE id=?').run(JSON.stringify(vec), r.id);
    }
    return { ref: r, score: cosine(qVec, vec) };
  }).sort((a,b)=> b.score - a.score).slice(0, 20);
  res.json(items);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('DreamMatch API listening on :' + PORT);
});
