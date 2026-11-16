// POST /api/availability with a JSON body { action, name, token?, ... }:
//   login        { password? }                 -> { name, hasPassword, token? }
//   setPassword  { password }                  -> { name, hasPassword: true, token }   (only if the name has none yet)
//   list         {}                            -> groups you can see: { group: { members: [..], private, creator } }
//   open         { group, code? }              -> { exists, group, private, creator, members: { name: days } }
//   save         { group, days, private?, code? } -> saves (creating the group if new), returns the group
//   leave        { group }                     -> removes you from the group (an emptied group is deleted)
//   delete       { group }                     -> deletes the group, only if you created it
//
// Accounts: a name works with no password. Once a name has a password, every request as that name
// needs a session token (issued by login / setPassword). Creating a group requires a password account,
// so a group's creator is always a verified identity.
//
// Storage (Upstash Redis REST, no dependencies):
//   hash "users":         lowercased name -> { name, salt, pw (scrypt) }   (password accounts only)
//   hash "sessions":      token -> lowercased name
//   hash "groupmeta":     group -> { creator, private, code (sha256 of passcode) }
//   hash "group:<name>":  member -> { Monday: {from,to} | null, ... }
// Private groups are hidden from non-members and need the passcode to join.

const crypto = require('crypto');

const URL_ = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
const TIME = /^\d{2}:\d{2}$/;
const META = 'groupmeta', USERS = 'users', SESSIONS = 'sessions';
const MIN_PASSWORD = 6;

// Runs several commands in one round trip; returns their results in order.
async function redis(...commands) {
  const r = await fetch(URL_ + '/pipeline', {
    method: 'POST',
    headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(commands),
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || `Redis error ${r.status}`);
  return data.map(d => {
    if (d.error) throw new Error(d.error);
    return d.result;
  });
}

const clean = v => String(v || '').trim().slice(0, 40);
const key = group => 'group:' + group;
const same = (a, b) => a.toLowerCase() === b.toLowerCase();
const hash = code => crypto.createHash('sha256').update(String(code)).digest('hex');
const scrypt = (password, salt) => crypto.scryptSync(password, salt, 32).toString('hex');

// HGETALL comes back as [field, value, field, value, ...] with JSON values.
function parseHash(flat) {
  const out = {};
  for (let i = 0; i < (flat || []).length; i += 2) out[flat[i]] = JSON.parse(flat[i + 1]);
  return out;
}

class HttpError extends Error {
  constructor(status, message, extra) { super(message); this.status = status; this.extra = extra; }
}

// Public groups are open; private ones need membership or the passcode.
function checkAccess(info, isMember, code) {
  if (!info.private || isMember) return;
  if (!code) throw new HttpError(403, 'This group is private. Enter its passcode to join.', { needCode: true });
  if (hash(code) !== info.code) throw new HttpError(403, 'Wrong passcode.', { needCode: true });
}

async function newSession(lower) {
  const token = crypto.randomBytes(24).toString('hex');
  // ponytail: sessions never expire and aren't removed on sign-out; add a TTL if that matters.
  await redis(['HSET', SESSIONS, token, lower]);
  return token;
}

async function handle(req) {
  if (req.method !== 'POST') throw new HttpError(405, 'Method not allowed.');
  const input = req.body || {};
  const action = input.action;
  const typedName = clean(input.name);
  if (!typedName) throw new HttpError(400, 'Name is required.');
  const lower = typedName.toLowerCase();
  const token = String(input.token || '').slice(0, 64);
  const password = String(input.password || '').slice(0, 200);

  const [metaFlat, userRaw, sessionName] = await redis(
    ['HGETALL', META], ['HGET', USERS, lower], ['HGET', SESSIONS, token || '-']);
  const meta = parseHash(metaFlat);
  const user = userRaw ? JSON.parse(userRaw) : null;   // exists only for password accounts
  const verified = !!user && sessionName === lower;
  const name = user ? user.name : typedName;

  if (action === 'login') {
    if (!user) return { name, hasPassword: false };
    if (verified) return { name, hasPassword: true, token };
    if (!password) throw new HttpError(401, 'This name has a password. Enter it to continue.', { needPassword: true });
    const ok = crypto.timingSafeEqual(Buffer.from(scrypt(password, user.salt)), Buffer.from(user.pw));
    if (!ok) throw new HttpError(401, 'Wrong password.', { needPassword: true });
    return { name, hasPassword: true, token: await newSession(lower) };
  }

  if (action === 'setPassword') {
    if (user) throw new HttpError(409, 'This name already has a password.');
    if (password.length < MIN_PASSWORD) throw new HttpError(400, `Password must be at least ${MIN_PASSWORD} characters.`);
    const salt = crypto.randomBytes(16).toString('hex');
    await redis(['HSET', USERS, lower, JSON.stringify({ name, salt, pw: scrypt(password, salt) })]);
    return { name, hasPassword: true, token: await newSession(lower) };
  }

  // Everything below acts as `name`; a password-protected name must prove it.
  if (user && !verified) throw new HttpError(401, 'This name has a password. Enter it to continue.', { needPassword: true });

  // Group names match case-insensitively, so "poker" and "Poker" are the same group.
  const typedGroup = clean(input.group);
  const group = Object.keys(meta).find(g => same(g, typedGroup)) || typedGroup;
  const info = meta[group];

  if (action === 'list') {
    const groups = Object.keys(meta);
    const members = groups.length ? await redis(...groups.map(g => ['HKEYS', key(g)])) : [];
    const out = {};
    groups.forEach((g, i) => {
      if (meta[g].private && !members[i].some(m => same(m, name))) return;
      out[g] = { members: members[i], private: meta[g].private, creator: meta[g].creator };
    });
    return out;
  }

  if (!group) throw new HttpError(400, 'Group is required.');

  if (action === 'open') {
    if (!info) return { exists: false, group, members: {} };
    const members = parseHash((await redis(['HGETALL', key(group)]))[0]);
    checkAccess(info, Object.keys(members).some(m => same(m, name)), input.code);
    return { exists: true, group, private: info.private, creator: info.creator, members };
  }

  const [memberNames] = await redis(['HKEYS', key(group)]);
  const member = memberNames.find(m => same(m, name));

  if (action === 'leave') {
    if (member) await redis(['HDEL', key(group), member]);
    // Nobody left: remove the group so it doesn't linger with no one able to see it.
    if (member && memberNames.length === 1) await redis(['HDEL', META, group]);
    return { ok: true };
  }

  if (action === 'delete') {
    if (!info) throw new HttpError(404, 'That group no longer exists.');
    // Creators always have a password, so reaching here as the creator means they signed in.
    if (!verified || !same(info.creator, name)) throw new HttpError(403, 'Only the person who created this group can delete it.');
    await redis(['DEL', key(group)], ['HDEL', META, group]);
    return { ok: true };
  }

  if (action !== 'save') throw new HttpError(400, 'Unknown action.');

  const days = {};
  for (const day of DAYS) {
    const d = input.days && input.days[day];
    days[day] = d && TIME.test(d.from) && TIME.test(d.to) ? { from: d.from, to: d.to } : null;
  }
  const commands = [['HSET', key(group), member || name, JSON.stringify(days)]];
  let created = info;
  if (!info) {
    if (!verified) throw new HttpError(403, 'Set a password on your account to create groups.', { needAccount: true });
    const isPrivate = !!input.private;
    if (isPrivate && !clean(input.code)) throw new HttpError(400, 'Private groups need a passcode.');
    created = { creator: name, private: isPrivate, code: isPrivate ? hash(input.code) : null };
    commands.push(['HSET', META, group, JSON.stringify(created)]);
  } else {
    checkAccess(info, !!member, input.code);
  }
  await redis(...commands);
  const members = parseHash((await redis(['HGETALL', key(group)]))[0]);
  return { exists: true, group, private: created.private, creator: created.creator, members };
}

module.exports = async (req, res) => {
  if (!URL_ || !TOKEN) {
    return res.status(500).json({ error: 'No database connected. Add an Upstash Redis store to this Vercel project and redeploy.' });
  }
  res.setHeader('Cache-Control', 'no-store');
  try {
    return res.status(200).json(await handle(req));
  } catch (e) {
    return res.status(e.status || 500).json({ error: e.message, ...e.extra });
  }
};
