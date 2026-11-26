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
db.rooms = db.rooms || {}; db.nextRoom = db.nextRoom || 1;
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
  const u = db.tokens[t] || null;
  if (u && db.users[u]) { const r = db.users[u]; const now = Date.now(); const prev = r.lastSeen || 0; r.lastSeen = now; if (now - prev > 60000) save(); }
  return u;
}
function newToken(username) {
  const t = crypto.randomBytes(24).toString('hex');
  db.tokens[t] = username;
  return t;
}

function pub(u) {
  const r = db.users[u] || {};
  return { username: u, name: r.name || u, bio: r.bio || '', hasAvatar: !!r.avatar, av: r.avatarV || 0, photos: (r.photos || []).slice(), online: (Date.now() - (r.lastSeen || 0)) < 40000, seenAgo: r.lastSeen ? Math.round((Date.now() - r.lastSeen) / 1000) : -1 };
}
let callSeq = 0; const callSigs = [];
function isRoom(x) { return typeof x === 'string' && x[0] === '#'; }
function roomOf(id) { return db.rooms[id]; }
function canView(r, me) { return !!(r && (r.members[me] || r.username)); }
function visible(m, me) { if (isRoom(m.to)) return canView(roomOf(m.to), me); return (m.from === me || m.to === me); }
function canPostIn(r, me) { const mm = r && r.members[me]; return !!mm && (mm.role === 'owner' || !!mm.canPost); }
function roomInfo(r, me) {
  const mem = r.members[me];
  const o = { id: r.id, type: r.type, name: r.name, bio: r.bio || '', username: r.username || '', owner: r.owner, count: Object.keys(r.members).length,
    hasAvatar: !!r.avatar, av: r.avV || 0, isMember: !!mem, role: mem ? mem.role : '', canPost: canPostIn(r, me), muted: !!(mem && mem.muted), maxReact: r.maxReact || 0 };
  if (mem) o.members = Object.keys(r.members).map(u => { const p = pub(u); const m2 = r.members[u];
    return { username: u, name: p.name, hasAvatar: p.hasAvatar, av: p.av, online: p.online, seenAgo: p.seenAgo, role: m2.role, canPost: m2.role === 'owner' || !!m2.canPost }; });
  return o;
}
function nameTaken(u, exceptRoom) {
  return !!db.users[u] || Object.values(db.rooms).some(r => r.username === u && r.id !== exceptRoom);
}
function msgOut(m) {
  return { id: m.id, from: m.from, to: m.to, text: m.deleted ? '' : m.text, time: m.time, read: m.read,
    replyTo: m.replyTo || 0, reactions: m.reactions || {}, edited: !!m.edited, deleted: !!m.deleted,
    views: Object.keys(m.views || {}).length, fromName: (db.users[m.from] || {}).name || m.from,
    fid: m.deleted ? '' : (m.fid || ''), fname: m.fname || '', fmime: m.fmime || '', fsize: m.fsize || 0 };
}
const EDIT_WINDOW = 2 * 60 * 60 * 1000;

const routes = {
  'POST /api/register': async (req, res) => {
    const { username, password, name } = await readBody(req);
    const u = (username || '').trim().toLowerCase();
    if (!/^[a-z0-9_]{3,20}$/.test(u)) return send(res, 400, { error: 'اليوزر لازم 3 إلى 20 حرف إنجليزي أو أرقام' });
    if (!password || password.length < 4) return send(res, 400, { error: 'كلمة السر قصيرة (4 على الأقل)' });
    if (nameTaken(u)) return send(res, 409, { error: 'اليوزر ده موجود قبل كده' });
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
  'POST /api/ping': async (req, res, me) => send(res, 200, { ok: true }),
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
  'POST /api/photos/add': async (req, res, me) => {
    const b = await readBody(req); const r = db.users[me];
    if (!b.fid || !(db.files || {})[b.fid] || db.files[b.fid].owner !== me) return send(res, 400, { error: 'الصورة مش موجودة' });
    r.photos = r.photos || []; r.photos.unshift(b.fid); r.photos = r.photos.slice(0, 10);
    save(); send(res, 200, pub(me));
  },
  'POST /api/photos/remove': async (req, res, me) => {
    const b = await readBody(req); const r = db.users[me];
    r.photos = (r.photos || []).filter(x => x !== b.fid);
    save(); send(res, 200, pub(me));
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
      if (isRoom(m.to)) {
        const r = roomOf(m.to); if (!r || !r.members[me]) continue;
        last[m.to] = m;
        if (m.from !== me && !(m.views && m.views[me])) unread[m.to] = (unread[m.to] || 0) + 1;
        continue;
      }
      if (!visible(m, me)) continue;
      const other = m.from === me ? m.to : m.from;
      last[other] = m;
      if (m.to === me && !m.read) unread[other] = (unread[other] || 0) + 1;
    }
    for (const id of Object.keys(db.rooms)) if (db.rooms[id].members[me] && !last[id]) last[id] = null;
    const pins = db.users[me].pins || [];
    const prevOf = (m) => m.deleted ? 'تم حذف الرسالة' : (m.text || (m.fid ? (String(m.fmime || '').startsWith('image/') ? 'صورة' : (String(m.fmime || '').startsWith('audio/') ? 'رسالة صوتية' : 'ملف')) : ''));
    const chats = Object.keys(last).map(o => {
      const m = last[o];
      if (isRoom(o)) {
        const r = roomOf(o); const mm = r.members[me];
        let pv = m ? prevOf(m) : (r.type === 'channel' ? 'تم إنشاء القناة' : 'تم إنشاء المجموعة');
        if (m && r.type === 'group' && m.from !== me) pv = ((db.users[m.from] || {}).name || m.from) + ': ' + pv;
        return { with: o, name: r.name, hasAvatar: !!r.avatar, av: r.avV || 0, online: false, seenAgo: -1, isRoom: true, rtype: r.type, muted: !!mm.muted,
          last: pv, time: m ? m.time : r.created, mine: false, read: true, unread: unread[o] || 0, pinned: pins.includes(o) };
      }
      return { with: o, name: pub(o).name, hasAvatar: pub(o).hasAvatar, av: pub(o).av, online: pub(o).online, seenAgo: pub(o).seenAgo,
        last: prevOf(m), time: m.time, mine: m.from === me, read: m.read, unread: unread[o] || 0, pinned: pins.includes(o) };
    }).sort((a, b) => (b.pinned - a.pinned) || (b.time - a.time));
    send(res, 200, { chats });
  },
  'GET /api/messages': async (req, res, me, url) => {
    const other = (url.searchParams.get('with') || '').toLowerCase();
    if (isRoom(other)) {
      const r = roomOf(other);
      if (!canView(r, me)) return send(res, 403, { error: 'القناة دي خاصة' });
      const all2 = []; let ch = false;
      for (const m of db.messages) {
        if (m.to !== other) continue;
        if (r.members[me] && m.from !== me) { m.views = m.views || {}; if (!m.views[me]) { m.views[me] = 1; ch = true; } }
        all2.push(msgOut(m));
      }
      if (ch) save();
      return send(res, 200, { messages: all2.slice(-300), user: { username: r.id, name: r.name, hasAvatar: !!r.avatar, av: r.avV || 0 }, room: roomInfo(r, me) });
    }
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
    const { to, text, replyTo, fid, fname, fmime, fsize } = await readBody(req);
    const t = (to || '').toLowerCase();
    const body = (text || '').toString().trim().slice(0, 4000);
    if (isRoom(t)) {
      const r = roomOf(t);
      if (!r || !r.members[me]) return send(res, 403, { error: 'لازم تشترك الأول' });
      if (!canPostIn(r, me)) return send(res, 403, { error: 'مفيش عندك صلاحية الإرسال هنا' });
    } else {
    if (!db.users[t]) return send(res, 404, { error: 'المستخدم ده مش موجود' });
    if (t === me) return send(res, 400, { error: 'مينفعش تبعت لنفسك' });
    }
    if (!body && !fid) return send(res, 400, { error: 'الرسالة فاضية' });
    const m = { id: db.nextId++, from: me, to: t, text: body, time: Date.now(), read: false, replyTo: replyTo || 0, reactions: {} };
    if (fid) {
      const f = (db.files || {})[fid];
      if (!f || !(f.owner === me || db.messages.some(x => x.fid === fid && visible(x, me)))) return send(res, 400, { error: 'الملف مش موجود' });
      m.fid = fid; m.fname = f.name; m.fmime = f.mime; m.fsize = f.size;
    }
    db.messages.push(m);
    save();
    send(res, 200, { message: msgOut(m) });
  },
  'POST /api/react': async (req, res, me) => {
    const { id, emoji } = await readBody(req);
    const m = db.messages.find(x => x.id === id);
    if (!m || !visible(m, me)) return send(res, 404, { error: 'مش لاقي الرسالة' });
    m.reactions = m.reactions || {};
    if (isRoom(m.to) && !(roomOf(m.to) && roomOf(m.to).members[me])) return send(res, 403, { error: 'لازم تشترك الأول' });
    if (isRoom(m.to) && emoji && !m.reactions[me]) {
      const rr = roomOf(m.to);
      if (rr && rr.maxReact > 0 && Object.keys(m.reactions).length >= rr.maxReact) return send(res, 403, { error: 'وصل الحد الأقصى للتفاعل على المنشور ده' });
    }
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
    const rd = m && isRoom(m.to) ? roomOf(m.to) : null;
    if (!m || (m.from !== me && !(rd && rd.owner === me))) return send(res, 403, { error: 'مينفعش تمسح الرسالة دي' });
    if (rd) { db.messages = db.messages.filter(x => x.id !== m.id); db.messages.forEach(x => { if (x.replyTo === m.id) x.replyTo = 0; }); }
    else { m.deleted = true; m.text = ''; m.reactions = {}; }
    save();
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
    const rooms = Object.values(db.rooms).filter(r => r.username && (q === '' ? false : (r.username.includes(q) || r.name.toLowerCase().includes(q)))).slice(0, 20)
      .map(r => ({ id: r.id, type: r.type, name: r.name, username: r.username, hasAvatar: !!r.avatar, av: r.avV || 0, count: Object.keys(r.members).length }));
    send(res, 200, { users, rooms });
  },
  'GET /api/events': async (req, res, me, url) => {
    const since = parseInt(url.searchParams.get('since') || '-1', 10);
    const last = db.nextId - 1;
    const events = [];
    if (since >= 0) {
      for (const m of db.messages) {
        if (m.id <= since || m.from === me || m.deleted) continue;
        let title, isR = false, chat;
        const sname = (db.users[m.from] || {}).name || m.from;
        if (isRoom(m.to)) {
          const r = roomOf(m.to); if (!r || !r.members[me] || r.members[me].muted) continue;
          title = r.name; isR = true; chat = m.to;
        } else { if (m.to !== me) continue; title = sname; chat = m.from; }
        const mime = String(m.fmime || '');
        const text = m.text || (m.fid ? (mime.startsWith('image/') ? 'صورة' : mime.startsWith('audio/') ? 'رسالة صوتية' : mime.startsWith('video/') ? 'فيديو' : 'ملف') : '');
        events.push({ id: m.id, from: m.from, chat, title, sender: sname, text, isRoom: isR, time: m.time });
      }
    }
    send(res, 200, { events: events.slice(-30), last });
  },
  'POST /api/call/sig': async (req, res, me) => {
    const b = await readBody(req); const to = String(b.to || '').toLowerCase();
    if (!db.users[to] || to === me) return send(res, 404, { error: 'المستخدم مش موجود' });
    const id = ++callSeq; const now = Date.now();
    callSigs.push({ id, from: me, to, type: String(b.type || ''), video: !!b.video, data: typeof b.data === 'string' ? b.data.slice(0, 20000) : '', t: now });
    while (callSigs.length && now - callSigs[0].t > 120000) callSigs.shift();
    send(res, 200, { id });
  },
  'GET /api/call/poll': async (req, res, me, url) => {
    const since = parseInt(url.searchParams.get('since') || '-1', 10); const now = Date.now();
    const sigs = since < 0 ? [] : callSigs.filter(x => x.to === me && x.id > since && now - x.t < 120000);
    send(res, 200, { signals: sigs, last: callSeq, now });
  },
  'GET /api/call/config': async (req, res, me) => {
    const ice = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }];
    if (process.env.TURN_URL) ice.push({ urls: process.env.TURN_URL.split(','), username: process.env.TURN_USER || '', credential: process.env.TURN_PASS || '' });
    else ice.push({ urls: ['turn:openrelay.metered.ca:80', 'turn:openrelay.metered.ca:443', 'turn:openrelay.metered.ca:443?transport=tcp'], username: 'openrelayproject', credential: 'openrelayproject' });
    send(res, 200, { iceServers: ice });
  },
  'GET /api/handle': async (req, res, me, url) => {
    const u = (url.searchParams.get('u') || '').toLowerCase().replace('@', '');
    const r = Object.values(db.rooms).find(x => x.username === u);
    if (r) return send(res, 200, { type: 'room', id: r.id });
    if (db.users[u]) return send(res, 200, { type: 'user', id: u });
    send(res, 404, { error: 'مش لاقي حاجة بالاسم ده' });
  },
  'POST /api/rooms/create': async (req, res, me) => {
    const b = await readBody(req);
    const type = b.type === 'group' ? 'group' : 'channel';
    const name = (b.name || '').toString().trim().slice(0, 50);
    if (!name) return send(res, 400, { error: 'اكتب الاسم الأول' });
    let un = (b.username || '').toString().trim().toLowerCase().replace('@', '');
    if (un) {
      if (!/^[a-z0-9_]{4,20}$/.test(un)) return send(res, 400, { error: 'اليوزر لازم 4 إلى 20 حرف إنجليزي أو أرقام' });
      if (nameTaken(un)) return send(res, 409, { error: 'اليوزر ده مستخدم قبل كده' });
    }
    const id = '#' + (db.nextRoom++);
    const r = { id, type, name, bio: (b.bio || '').toString().slice(0, 200), username: un, owner: me, created: Date.now(), maxReact: 0, members: {} };
    if (typeof b.avatar === 'string' && b.avatar.length < 400000 && b.avatar) { r.avatar = b.avatar; r.avV = 1; }
    r.members[me] = { role: 'owner', canPost: true, muted: false };
    for (const u of (Array.isArray(b.members) ? b.members : []).slice(0, 200)) {
      const uu = String(u).toLowerCase(); if (db.users[uu] && !r.members[uu]) r.members[uu] = { role: 'member', canPost: type === 'group', muted: false };
    }
    db.rooms[id] = r; save();
    send(res, 200, { room: roomInfo(r, me) });
  },
  'GET /api/room': async (req, res, me, url) => {
    const r = db.rooms[url.searchParams.get('id') || ''];
    if (!canView(r, me)) return send(res, 404, { error: 'مش لاقي القناة' });
    send(res, 200, { room: roomInfo(r, me) });
  },
  'POST /api/rooms/add': async (req, res, me) => {
    const b = await readBody(req); const r = db.rooms[b.id || ''];
    if (!r || !r.members[me]) return send(res, 404, { error: 'مش لاقي القناة' });
    if (r.type === 'channel' && r.owner !== me) return send(res, 403, { error: 'المالك بس يقدر يضيف' });
    let n = 0;
    for (const u of (Array.isArray(b.users) ? b.users : []).slice(0, 200)) {
      const uu = String(u).toLowerCase(); if (db.users[uu] && !r.members[uu]) { r.members[uu] = { role: 'member', canPost: r.type === 'group', muted: false }; n++; }
    }
    save(); send(res, 200, { added: n, room: roomInfo(r, me) });
  },
  'POST /api/rooms/join': async (req, res, me) => {
    const b = await readBody(req); const r = db.rooms[b.id || ''];
    if (!r || !(r.username || r.members[me])) return send(res, 404, { error: 'مش لاقي القناة' });
    if (!r.members[me]) r.members[me] = { role: 'member', canPost: r.type === 'group', muted: false };
    save(); send(res, 200, { room: roomInfo(r, me) });
  },
  'POST /api/rooms/leave': async (req, res, me) => {
    const b = await readBody(req); const r = db.rooms[b.id || ''];
    if (!r || !r.members[me]) return send(res, 404, { error: 'مش لاقي القناة' });
    if (r.owner === me) return send(res, 400, { error: 'إنت المالك، تقدر تحذفها بس' });
    delete r.members[me]; save(); send(res, 200, { ok: true });
  },
  'POST /api/rooms/delete': async (req, res, me) => {
    const b = await readBody(req); const r = db.rooms[b.id || ''];
    if (!r || r.owner !== me) return send(res, 403, { error: 'المالك بس يقدر يحذف' });
    delete db.rooms[r.id]; db.messages = db.messages.filter(m => m.to !== r.id); save(); send(res, 200, { ok: true });
  },
  'POST /api/rooms/mute': async (req, res, me) => {
    const b = await readBody(req); const r = db.rooms[b.id || ''];
    if (!r || !r.members[me]) return send(res, 404, { error: 'مش لاقي القناة' });
    r.members[me].muted = !r.members[me].muted; save(); send(res, 200, { muted: r.members[me].muted });
  },
  'POST /api/rooms/kick': async (req, res, me) => {
    const b = await readBody(req); const r = db.rooms[b.id || ''];
    if (!r || r.owner !== me) return send(res, 403, { error: 'المالك بس يقدر يشيل أعضاء' });
    const u = String(b.user || '').toLowerCase();
    if (u === me || !r.members[u]) return send(res, 400, { error: 'مينفعش' });
    delete r.members[u]; save(); send(res, 200, { room: roomInfo(r, me) });
  },
  'POST /api/rooms/perm': async (req, res, me) => {
    const b = await readBody(req); const r = db.rooms[b.id || ''];
    if (!r || r.owner !== me) return send(res, 403, { error: 'المالك بس يغير الصلاحيات' });
    const u = String(b.user || '').toLowerCase();
    if (u === me || !r.members[u]) return send(res, 400, { error: 'مينفعش' });
    r.members[u].canPost = typeof b.canPost === 'boolean' ? b.canPost : !r.members[u].canPost;
    save(); send(res, 200, { room: roomInfo(r, me) });
  },
  'POST /api/rooms/settings': async (req, res, me) => {
    const b = await readBody(req); const r = db.rooms[b.id || ''];
    if (!r || r.owner !== me) return send(res, 403, { error: 'المالك بس يعدل' });
    if (typeof b.name === 'string' && b.name.trim()) r.name = b.name.trim().slice(0, 50);
    if (typeof b.bio === 'string') r.bio = b.bio.slice(0, 200);
    if (typeof b.maxReact === 'number') r.maxReact = Math.max(0, Math.min(100000, Math.floor(b.maxReact)));
    if (typeof b.username === 'string') {
      const un = b.username.trim().toLowerCase().replace('@', '');
      if (un !== r.username) {
        if (un && !/^[a-z0-9_]{4,20}$/.test(un)) return send(res, 400, { error: 'اليوزر لازم 4 إلى 20 حرف إنجليزي أو أرقام' });
        if (un && nameTaken(un, r.id)) return send(res, 409, { error: 'اليوزر ده مستخدم قبل كده' });
        r.username = un;
      }
    }
    if (typeof b.avatar === 'string' && b.avatar.length < 400000 && b.avatar) { r.avatar = b.avatar; r.avV = (r.avV || 0) + 1; }
    save(); send(res, 200, { room: roomInfo(r, me) });
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
      const uq = (url.searchParams.get('u') || '').toLowerCase();
      const r = isRoom(uq) ? db.rooms[uq] : db.users[uq];
      if (!r || !r.avatar) { res.writeHead(404); return res.end(); }
      const buf = Buffer.from(r.avatar.replace(/^data:image\/\w+;base64,/, ''), 'base64');
      res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Cache-Control': 'public, max-age=3600' });
      return res.end(buf);
    }
    if (key === 'POST /api/upload') {
      const me = authUser(req);
      if (!me) return send(res, 401, { error: 'سجل دخول الأول' });
      const chunks = []; let size = 0; const LIM = 20 * 1024 * 1024;
      await new Promise((ok, no) => {
        req.on('data', c => { size += c.length; if (size > LIM) { no(new Error('big')); req.destroy(); } else chunks.push(c); });
        req.on('end', ok); req.on('error', no);
      });
      const id = crypto.randomBytes(12).toString('hex');
      fs.mkdirSync(path.join(DATA_DIR, 'files'), { recursive: true });
      fs.writeFileSync(path.join(DATA_DIR, 'files', id), Buffer.concat(chunks));
      db.files = db.files || {};
      db.files[id] = { owner: me, name: (url.searchParams.get('name') || 'file').slice(0, 120), mime: (url.searchParams.get('mime') || 'application/octet-stream').slice(0, 80), size };
      save();
      return send(res, 200, { fid: id });
    }
    if (key === 'GET /api/file') {
      const me = authUser(req);
      if (!me) return send(res, 401, { error: 'سجل دخول الأول' });
      const id = url.searchParams.get('id') || '';
      const f = (db.files || {})[id];
      const ok = f && (f.owner === me || db.messages.some(m => m.fid === id && visible(m, me)) || Object.values(db.users).some(u => (u.photos || []).includes(id)));
      if (!ok) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'Content-Type': f.mime, 'Content-Length': f.size, 'Cache-Control': 'private, max-age=86400' });
      return fs.createReadStream(path.join(DATA_DIR, 'files', id)).pipe(res);
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
