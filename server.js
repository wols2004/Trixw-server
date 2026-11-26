// Shati chat server - plain Node.js, zero dependencies.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
fs.mkdirSync(DATA_DIR, { recursive: true });

let db = { users: {}, tokens: {}, messages: [], nextId: 1 };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) {}
let saveTimer = null;
function save() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, DB_FILE);
  }, 200);
}

function hashPw(pw, salt) {
  return crypto.scryptSync(pw, salt, 32).toString('hex');
}
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 1.5e6) { reject(new Error('big')); req.destroy(); } });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); } });
  });
}
function authUser(req) {
  const h = req.headers['authorization'] || '';
  const t = h.replace('Bearer ', '');
  return db.tokens[t] || null;
}
function newToken(username) {
  const t = crypto.randomBytes(24).toString('hex');
  db.tokens[t] = username;
  return t;
}

function pub(u) {
  const r = db.users[u] || {};
  return { username: u, name: r.name || u, bio: r.bio || '', hasAvatar: !!r.avatar, av: r.avatarV || 0 };
}
function visible(m, me) { return (m.from === me || m.to === me); }
function msgOut(m) {
  return { id: m.id, from: m.from, to: m.to, text: m.deleted ? '' : m.text, time: m.time, read: m.read,
    replyTo: m.replyTo || 0, reactions: m.reactions || {}, edited: !!m.edited, deleted: !!m.deleted };
}
const EDIT_WINDOW = 2 * 60 * 60 * 1000;

const routes = {
  'POST /api/register': async (req, res) => {
    const { username, password, name } = await readBody(req);
    const u = (username || '').trim().toLowerCase();
    if (!/^[a-z0-9_]{3,20}$/.test(u)) return send(res, 400, { error: 'اليوزر لازم 3 إلى 20 حرف إنجليزي أو أرقام' });
    if (!password || password.length < 4) return send(res, 400, { error: 'كلمة السر قصيرة (4 على الأقل)' });
    if (db.users[u]) return send(res, 409, { error: 'اليوزر ده موجود قبل كده' });
    const salt = crypto.randomBytes(16).toString('hex');
    db.users[u] = { salt, hash: hashPw(password, salt), created: Date.now(), name: (name || u).toString().slice(0, 40), bio: '', pins: [] };
    save();
    send(res, 200, { token: newToken(u), username: u });
  },
  'POST /api/login': async (req, res) => {
    const { username, password } = await readBody(req);
    const u = (username || '').trim().toLowerCase();
    const rec = db.users[u];
    if (!rec || hashPw(password || '', rec.salt) !== rec.hash)
      return send(res, 401, { error: 'اسم المستخدم أو كلمة السر غلط' });
    send(res, 200, { token: newToken(u), username: u });
  },
  'GET /api/me': async (req, res, me) => send(res, 200, pub(me)),
  'GET /api/profile': async (req, res, me, url) => {
    const u = (url.searchParams.get('u') || '').toLowerCase();
    if (!db.users[u]) return send(res, 404, { error: 'المستخدم مش موجود' });
    send(res, 200, pub(u));
  },
  'POST /api/profile': async (req, res, me) => {
    const b = await readBody(req);
    const r = db.users[me];
    if (typeof b.name === 'string') r.name = b.name.trim().slice(0, 40) || me;
    if (typeof b.bio === 'string') r.bio = b.bio.slice(0, 160);
    if (typeof b.avatar === 'string' && b.avatar.length < 400000) {
      r.avatar = b.avatar || null; r.avatarV = (r.avatarV || 0) + 1;
    }
    save();
    send(res, 200, pub(me));
  },
  'POST /api/password': async (req, res, me) => {
    const { oldPassword, newPassword } = await readBody(req);
    const r = db.users[me];
    if (hashPw(oldPassword || '', r.salt) !== r.hash) return send(res, 403, { error: 'كلمة السر القديمة غلط' });
    if (!newPassword || newPassword.length < 4) return send(res, 400, { error: 'كلمة السر الجديدة قصيرة' });
    r.salt = crypto.randomBytes(16).toString('hex'); r.hash = hashPw(newPassword, r.salt);
    save();
    send(res, 200, { ok: true });
  },
  'GET /api/chats': async (req, res, me) => {
    const last = {}, unread = {};
    for (const m of db.messages) {
      if (!visible(m, me)) continue;
      const other = m.from === me ? m.to : m.from;
      last[other] = m;
      if (m.to === me && !m.read) unread[other] = (unread[other] || 0) + 1;
    }
    const pins = db.users[me].pins || [];
    const chats = Object.keys(last).map(o => ({
      with: o, name: pub(o).name, hasAvatar: pub(o).hasAvatar, av: pub(o).av,
      last: last[o].deleted ? 'تم حذف الرسالة' : last[o].text, time: last[o].time,
      mine: last[o].from === me, read: last[o].read, unread: unread[o] || 0, pinned: pins.includes(o)
    })).sort((a, b) => (b.pinned - a.pinned) || (b.time - a.time));
    send(res, 200, { chats });
  },
  'GET /api/messages': async (req, res, me, url) => {
    const other = (url.searchParams.get('with') || '').toLowerCase();
    let changed = false;
    const all = [];
    for (const m of db.messages) {
      if (!((m.from === me && m.to === other) || (m.from === other && m.to === me))) continue;
      if (m.to === me && !m.read) { m.read = true; changed = true; }
      all.push(msgOut(m));
    }
    if (changed) save();
    send(res, 200, { messages: all.slice(-300), user: pub(other) });
  },
  'POST /api/send': async (req, res, me) => {
    const { to, text, replyTo } = await readBody(req);
    const t = (to || '').toLowerCase();
    const body = (text || '').toString().trim().slice(0, 4000);
    if (!db.users[t]) return send(res, 404, { error: 'المستخدم ده مش موجود' });
    if (t === me) return send(res, 400, { error: 'مينفعش تبعت لنفسك' });
    if (!body) return send(res, 400, { error: 'الرسالة فاضية' });
    const m = { id: db.nextId++, from: me, to: t, text: body, time: Date.now(), read: false, replyTo: replyTo || 0, reactions: {} };
    db.messages.push(m);
    save();
    send(res, 200, { message: msgOut(m) });
  },
  'POST /api/react': async (req, res, me) => {
    const { id, emoji } = await readBody(req);
    const m = db.messages.find(x => x.id === id);
    if (!m || !visible(m, me)) return send(res, 404, { error: 'مش لاقي الرسالة' });
    m.reactions = m.reactions || {};
    if (!emoji || m.reactions[me] === emoji) delete m.reactions[me]; else m.reactions[me] = String(emoji).slice(0, 16);
    save();
    send(res, 200, { message: msgOut(m) });
  },
  'POST /api/edit': async (req, res, me) => {
    const { id, text } = await readBody(req);
    const m = db.messages.find(x => x.id === id);
    if (!m || m.from !== me || m.deleted) return send(res, 403, { error: 'مينفعش تعدل الرسالة دي' });
    if (Date.now() - m.time > EDIT_WINDOW) return send(res, 403, { error: 'عدّت ساعتين، مينفعش تعدل' });
    const t = (text || '').toString().trim().slice(0, 4000);
    if (!t) return send(res, 400, { error: 'الرسالة فاضية' });
    m.text = t; m.edited = true; save();
    send(res, 200, { message: msgOut(m) });
  },
  'POST /api/delete': async (req, res, me) => {
    const { id } = await readBody(req);
    const m = db.messages.find(x => x.id === id);
    if (!m || m.from !== me) return send(res, 403, { error: 'مينفعش تمسح الرسالة دي' });
    m.deleted = true; m.text = ''; m.reactions = {}; save();
    send(res, 200, { ok: true });
  },
  'POST /api/pin': async (req, res, me) => {
    const { with: w } = await readBody(req);
    const r = db.users[me]; r.pins = r.pins || [];
    const i = r.pins.indexOf(w);
    if (i >= 0) r.pins.splice(i, 1); else r.pins.push(w);
    save();
    send(res, 200, { pinned: i < 0 });
  },
  'GET /api/users': async (req, res, me, url) => {
    const q = (url.searchParams.get('q') || '').toLowerCase();
    const users = Object.keys(db.users).filter(u => u !== me && (u.includes(q) || (db.users[u].name || '').toLowerCase().includes(q))).slice(0, 50).map(pub);
    send(res, 200, { users });
  },
};
const open = new Set(['POST /api/register', 'POST /api/login']);

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const key = req.method + ' ' + url.pathname;
  try {
    if (key === 'GET /' || key === 'GET /health') {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Shati server is running');
    }
    if (key === 'GET /api/avatar') {
      const r = db.users[(url.searchParams.get('u') || '').toLowerCase()];
      if (!r || !r.avatar) { res.writeHead(404); return res.end(); }
      const buf = Buffer.from(r.avatar.replace(/^data:image\/\w+;base64,/, ''), 'base64');
      res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Cache-Control': 'public, max-age=3600' });
      return res.end(buf);
    }
    const h = routes[key];
    if (!h) return send(res, 404, { error: 'not found' });
    let me = null;
    if (!open.has(key)) {
      me = authUser(req);
      if (!me) return send(res, 401, { error: 'سجل دخول الأول' });
    }
    await h(req, res, me, url);
  } catch (e) {
    send(res, 400, { error: 'bad request' });
  }
}).listen(PORT, () => console.log('Shati server on ' + PORT));
