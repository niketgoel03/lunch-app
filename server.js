'use strict';

require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const db = require('./db');
const mailer = require('./mailer');
const push = require('./push');

const app = express();
app.set('trust proxy', 1); // behind Nginx/Cloudflare: trust X-Forwarded-* so Secure cookies work
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-insecure-secret';
const COOKIE_SECURE = String(process.env.COOKIE_SECURE).toLowerCase() === 'true';

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---------- Helpers ----------
function nowInTz(tz) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false,
  }).formatToParts(new Date());
  const g = (t) => parts.find((p) => p.type === t).value;
  let hour = g('hour'); if (hour === '24') hour = '00';
  return { date: `${g('year')}-${g('month')}-${g('day')}`, minutes: Number(hour) * 60 + Number(g('minute')) };
}
const hhmmToMinutes = (s) => { const [h, m] = String(s).split(':').map(Number); return h * 60 + m; };

function allowedDomains() {
  return (db.getSetting('allowed_domains') || '')
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
}
// null = no whitelist configured; true/false = whether the email's domain is allowed
function domainAllowed(email) {
  const list = allowedDomains();
  if (list.length === 0) return null;
  const dom = String(email).split('@')[1] || '';
  return list.includes(dom.toLowerCase());
}
function safeEqual(a, b) {
  const ab = Buffer.from(String(a)); const bb = Buffer.from(String(b));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

function orderingState() {
  const tz = db.getSetting('timezone');
  const { date, minutes } = nowInTz(tz);
  const cutoff = hhmmToMinutes(db.getSetting('cutoff_time'));
  const aggregate = hhmmToMinutes(db.getSetting('aggregate_time'));
  const manualOpen = db.getSetting('ordering_open') === '1';
  return {
    today: date, nowMinutes: minutes, cutoff, aggregate,
    isOpen: manualOpen && minutes < cutoff,
    afterAggregate: minutes >= aggregate,
    cutoffTime: db.getSetting('cutoff_time'),
    aggregateTime: db.getSetting('aggregate_time'),
    timezone: tz,
    currency: db.getSetting('currency'),
    allowCustomItems: db.getSetting('allow_custom_items') === '1',
    manualOpen,
  };
}

// ---------- Auth (session) ----------
function setSession(res, user) {
  const token = jwt.sign({ uid: user.id, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
  res.cookie('session', token, { httpOnly: true, sameSite: 'lax', secure: COOKIE_SECURE, maxAge: 12 * 3600 * 1000 });
}
const auth = wrap(async (req, res, next) => {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Session expired' }); }
  const user = await db.get('SELECT id, email, name, role, active FROM users WHERE id = $1', [payload.uid]);
  if (!user || !user.active) return res.status(401).json({ error: 'Account inactive' });
  req.user = user;
  next();
});
const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Forbidden' });

// ---------- Office-boy no-login auth (secret key + optional PIN) ----------
function boyAuth(req, res, next) {
  const key = req.get('x-boy-key') || req.query.key || (req.body && req.body.key);
  const real = db.getSetting('boy_access_key');
  if (!real || !key || !safeEqual(key, real)) return res.status(401).json({ error: 'Invalid access link' });
  const pinHash = db.getSetting('boy_pin_hash');
  if (pinHash) {
    const pin = req.get('x-boy-pin') || req.query.pin || (req.body && req.body.pin);
    if (!pin || !bcrypt.compareSync(String(pin), pinHash)) return res.status(401).json({ error: 'PIN required', pinRequired: true });
  }
  next();
}

// Limits are per client IP. Office staff often share one public IP (NAT), so keep
// these generous enough for a whole office while still curbing abuse.
const otpRequestLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
const otpVerifyLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });

// ---------- Auth routes ----------
app.post('/api/auth/request-otp', otpRequestLimiter, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Valid email required' });

  const user = await db.get('SELECT id, active FROM users WHERE email = $1', [email]);
  const allowed = domainAllowed(email); // null | true | false
  const isExisting = !!(user && user.active);
  const canOnboard = allowed === true; // whitelist configured and domain matches

  if (isExisting || canOnboard) {
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const codeHash = bcrypt.hashSync(code, 10);
    const expiresAt = Date.now() + 5 * 60 * 1000;
    await db.run('UPDATE otps SET consumed = 1 WHERE email = $1 AND consumed = 0', [email]);
    await db.run('INSERT INTO otps(email, code_hash, expires_at) VALUES ($1, $2, $3)', [email, codeHash, expiresAt]);
    try { await mailer.sendOtp(email, code); } catch (e) { console.error('Mail error:', e.message); }
    if (mailer.devMode) return res.json({ ok: true, devCode: code, newUser: !isExisting });
    return res.json({ ok: true, newUser: !isExisting });
  }
  // Unknown email and not eligible to onboard. Do not reveal which case it is.
  return res.json({ ok: true });
}));

app.post('/api/auth/verify-otp', otpVerifyLimiter, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const code = String(req.body.code || '').trim();
  const row = await db.get('SELECT * FROM otps WHERE email = $1 AND consumed = 0 ORDER BY id DESC LIMIT 1', [email]);
  if (!row) return res.status(400).json({ error: 'Request a new code' });
  if (Date.now() > Number(row.expires_at)) return res.status(400).json({ error: 'Code expired' });
  if (row.attempts >= 5) {
    await db.run('UPDATE otps SET consumed = 1 WHERE id = $1', [row.id]);
    return res.status(429).json({ error: 'Too many attempts, request a new code' });
  }
  if (!bcrypt.compareSync(code, row.code_hash)) {
    await db.run('UPDATE otps SET attempts = attempts + 1 WHERE id = $1', [row.id]);
    return res.status(400).json({ error: 'Incorrect code' });
  }
  await db.run('UPDATE otps SET consumed = 1 WHERE id = $1', [row.id]);

  let user = await db.get('SELECT id, email, name, role, active FROM users WHERE email = $1', [email]);
  if (!user) {
    // First-time onboarding: only for whitelisted domains.
    if (domainAllowed(email) !== true) return res.status(403).json({ error: 'This email domain is not allowed' });
    const name = email.split('@')[0].replace(/[._-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
    const r = await db.get('INSERT INTO users(email, name, role) VALUES ($1, $2, $3) RETURNING id, email, name, role, active', [email, name, 'staff']);
    user = r;
  }
  if (!user.active) return res.status(401).json({ error: 'Account inactive' });
  setSession(res, user);
  res.json({ ok: true, user: { email: user.email, name: user.name, role: user.role } });
}));

app.post('/api/auth/logout', (req, res) => { res.clearCookie('session'); res.json({ ok: true }); });

app.get('/api/me', auth, (req, res) => {
  res.json({ user: { email: req.user.email, name: req.user.name, role: req.user.role }, state: orderingState() });
});

// ---------- Web push ----------
app.get('/api/push/vapid', (req, res) => res.json({ publicKey: push.publicKey() }));

async function saveSubscription(userId, sub) {
  if (!sub || !sub.endpoint || !sub.keys) throw new Error('Invalid subscription');
  await db.run(
    `INSERT INTO push_subscriptions(user_id, endpoint, p256dh, auth) VALUES ($1,$2,$3,$4)
     ON CONFLICT(endpoint) DO UPDATE SET user_id = EXCLUDED.user_id, p256dh = EXCLUDED.p256dh, auth = EXCLUDED.auth`,
    [userId, sub.endpoint, sub.keys.p256dh, sub.keys.auth]);
}
app.post('/api/push/subscribe', auth, wrap(async (req, res) => {
  await saveSubscription(req.user.id, req.body.subscription);
  res.json({ ok: true });
}));
app.post('/api/boy/push/subscribe', boyAuth, wrap(async (req, res) => {
  const userId = Number(req.body.user_id);
  const u = await db.get("SELECT id FROM users WHERE id = $1 AND role = 'office_boy' AND active = 1", [userId]);
  if (!u) return res.status(400).json({ error: 'Select a valid office boy' });
  await saveSubscription(userId, req.body.subscription);
  res.json({ ok: true });
}));
app.get('/api/notifications/mine', auth, wrap(async (req, res) => {
  res.json(await db.all('SELECT id, title, body, url, category, created_at FROM notifications WHERE user_id = $1 ORDER BY id DESC LIMIT 30', [req.user.id]));
}));

// ---------- Menu ----------
app.get('/api/menu', auth, wrap(async (req, res) => {
  res.json(await db.all('SELECT id, name, price, available FROM menu_items ORDER BY name'));
}));

// ---------- Orders (staff) ----------
async function loadOrder(orderId) {
  const order = await db.get('SELECT * FROM orders WHERE id = $1', [orderId]);
  if (!order) return null;
  order.items = await db.all('SELECT name, qty, unit_price FROM order_items WHERE order_id = $1', [orderId]);
  order.payment = (await db.get('SELECT amount, paid FROM payments WHERE order_id = $1', [orderId])) || { amount: 0, paid: 0 };
  return order;
}

async function validateItems(items, allowCustom) {
  if (!Array.isArray(items) || items.length === 0) throw new Error('At least one item required');
  const clean = [];
  for (const it of items) {
    const qty = Math.max(1, Math.min(50, parseInt(it.qty, 10) || 1));
    if (it.menu_item_id) {
      const m = await db.get('SELECT id, name, price, available FROM menu_items WHERE id = $1', [it.menu_item_id]);
      if (!m || !m.available) throw new Error('Selected item not available');
      clean.push({ menu_item_id: m.id, name: m.name, qty, unit_price: m.price });
    } else {
      if (!allowCustom) throw new Error('Custom items are disabled');
      const name = String(it.name || '').trim().slice(0, 120);
      if (!name) throw new Error('Item name required');
      const price = Math.max(0, Number(it.price) || 0);
      clean.push({ menu_item_id: null, name, qty, unit_price: price });
    }
  }
  return clean;
}

app.get('/api/orders/mine', auth, wrap(async (req, res) => {
  const { today } = orderingState();
  const o = await db.get("SELECT id FROM orders WHERE user_id = $1 AND order_date = $2 AND status <> 'cancelled'", [req.user.id, today]);
  res.json({ order: o ? await loadOrder(o.id) : null, state: orderingState() });
}));

const placeOrUpdate = wrap(async (req, res) => {
  const st = orderingState();
  if (!st.isOpen) return res.status(403).json({ error: `Ordering is closed. Cutoff is ${st.cutoffTime} (${st.timezone}).` });

  let items;
  try { items = await validateItems(req.body.items, st.allowCustomItems); }
  catch (e) { return res.status(400).json({ error: e.message }); }
  const note = String(req.body.note || '').slice(0, 300);

  const result = await db.tx(async (c) => {
    const existing = await c.query('SELECT id FROM orders WHERE user_id = $1 AND order_date = $2', [req.user.id, st.today]);
    let id, isNew = false;
    if (existing.rows[0]) {
      id = existing.rows[0].id;
      await c.query("UPDATE orders SET status = 'placed', note = $1, updated_at = now() WHERE id = $2", [note, id]);
    } else {
      const r = await c.query('INSERT INTO orders(user_id, order_date, note) VALUES ($1, $2, $3) RETURNING id', [req.user.id, st.today, note]);
      id = r.rows[0].id; isNew = true;
    }
    await c.query('DELETE FROM order_items WHERE order_id = $1', [id]);
    let total = 0;
    for (const it of items) {
      await c.query('INSERT INTO order_items(order_id, menu_item_id, name, qty, unit_price) VALUES ($1,$2,$3,$4,$5)',
        [id, it.menu_item_id, it.name, it.qty, it.unit_price]);
      total += it.qty * it.unit_price;
    }
    await c.query('INSERT INTO payments(order_id, amount, paid) VALUES ($1, $2, 0) ON CONFLICT(order_id) DO UPDATE SET amount = EXCLUDED.amount', [id, total]);
    return { id, isNew };
  });

  if (result.isNew) {
    push.sendToRole('office_boy', { title: '🍱 New lunch order', body: `${req.user.name || req.user.email} placed a lunch order`, url: '/', category: 'order' });
  }
  res.json({ ok: true, order: await loadOrder(result.id), state: orderingState() });
});
app.post('/api/orders', auth, placeOrUpdate);
app.put('/api/orders/mine', auth, placeOrUpdate);

app.delete('/api/orders/mine', auth, wrap(async (req, res) => {
  const st = orderingState();
  if (!st.isOpen) return res.status(403).json({ error: `Cannot cancel after cutoff (${st.cutoffTime}).` });
  const o = await db.get("SELECT id FROM orders WHERE user_id = $1 AND order_date = $2 AND status <> 'cancelled'", [req.user.id, st.today]);
  if (o) await cancelOrder(o.id);
  res.json({ ok: true });
}));

// ---------- Aggregation (shared by session office_boy/admin and the no-login boy link) ----------
// Cancelled orders stay in the per-person list (with status) but are excluded from
// the shopping list and money totals.
async function aggregateData() {
  const st = orderingState();
  const orders = await db.all(`
    SELECT o.id, o.note, o.status, u.name, u.email
    FROM orders o JOIN users u ON u.id = o.user_id
    WHERE o.order_date = $1
    ORDER BY (o.status = 'cancelled'), u.name`, [st.today]);

  const perPerson = [];
  for (const o of orders) {
    const items = await db.all('SELECT name, qty, unit_price FROM order_items WHERE order_id = $1', [o.id]);
    const pay = (await db.get('SELECT amount, paid FROM payments WHERE order_id = $1', [o.id])) || { amount: 0, paid: 0 };
    perPerson.push({ ...o, items, amount: pay.amount, paid: !!pay.paid, cancelled: o.status === 'cancelled' });
  }

  const shoppingList = await db.all(`
    SELECT oi.name, SUM(oi.qty)::int AS qty, oi.unit_price
    FROM order_items oi JOIN orders o ON o.id = oi.order_id
    WHERE o.order_date = $1 AND o.status <> 'cancelled'
    GROUP BY oi.name, oi.unit_price ORDER BY oi.name`, [st.today]);

  const active = perPerson.filter((p) => !p.cancelled);
  const grandTotal = active.reduce((s, p) => s + p.amount, 0);
  const collected = active.filter((p) => p.paid).reduce((s, p) => s + p.amount, 0);
  return {
    state: st, perPerson, shoppingList, grandTotal, collected,
    activeCount: active.length, paidCount: active.filter((p) => p.paid).length,
    frozen: st.afterAggregate,
  };
}
async function orderPaid(orderId) {
  const p = await db.get('SELECT paid FROM payments WHERE order_id = $1', [orderId]);
  return !!(p && p.paid);
}
async function setPaid(orderId, paid, collectedBy) {
  await db.run('UPDATE payments SET paid = $1, paid_at = $2, collected_by = $3 WHERE order_id = $4',
    [paid ? 1 : 0, paid ? new Date().toISOString() : null, collectedBy, orderId]);
  if (paid) {
    await db.run("UPDATE orders SET status = 'delivered' WHERE id = $1", [orderId]);
    const o = await db.get('SELECT user_id FROM orders WHERE id = $1', [orderId]);
    if (o) push.sendToUsers([o.user_id], { title: '💰 Payment received', body: 'Your lunch payment has been recorded.', url: '/', category: 'payment' });
  }
}
async function cancelOrder(orderId) {
  const o = await db.get(
    'SELECT o.id, o.status, o.user_id, u.email, u.name FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = $1', [orderId]);
  if (!o || o.status === 'cancelled') return false;
  await db.run("UPDATE orders SET status = 'cancelled', updated_at = now() WHERE id = $1", [orderId]);
  // Notify the employee by email + push (fire-and-forget; never blocks the response).
  mailer.sendNotice(o.email, 'Your lunch order has been cancelled',
    `Hi ${o.name || ''},\n\nYour lunch order for today has been cancelled. If you did not expect this, please contact the office.\n\n— Office Lunch Orders`);
  push.sendToUsers([o.user_id], { title: '❌ Order cancelled', body: 'Your lunch order for today was cancelled.', url: '/', category: 'order' });
  return true;
}

app.get('/api/aggregate', auth, requireRole('office_boy', 'admin'), wrap(async (req, res) => res.json(await aggregateData())));
app.post('/api/payments/:orderId/paid', auth, requireRole('office_boy', 'admin'), wrap(async (req, res) => {
  const wantPaid = !!req.body.paid;
  // Paid is a final state: only an admin may reverse it.
  if (!wantPaid && req.user.role !== 'admin') return res.status(403).json({ error: 'Only an admin can reverse a paid order' });
  await setPaid(Number(req.params.orderId), wantPaid, req.user.id);
  res.json({ ok: true });
}));
app.post('/api/orders/:orderId/cancel', auth, requireRole('office_boy', 'admin'), wrap(async (req, res) => {
  const id = Number(req.params.orderId);
  if (await orderPaid(id) && req.user.role !== 'admin') return res.status(403).json({ error: 'Paid orders can only be cancelled by an admin' });
  await cancelOrder(id);
  res.json({ ok: true });
}));

// ---------- Office-boy no-login endpoints (key-authed) ----------
app.post('/api/boy/check', boyAuth, (req, res) => res.json({ ok: true }));
app.get('/api/boy/aggregate', boyAuth, wrap(async (req, res) => res.json(await aggregateData())));
app.post('/api/boy/payments/:orderId/paid', boyAuth, wrap(async (req, res) => {
  await setPaid(Number(req.params.orderId), true, null); // office boy can only mark paid, never undo
  res.json({ ok: true });
}));
app.post('/api/boy/orders/:orderId/cancel', boyAuth, wrap(async (req, res) => {
  const id = Number(req.params.orderId);
  if (await orderPaid(id)) return res.status(403).json({ error: 'A paid order cannot be cancelled here' });
  await cancelOrder(id);
  res.json({ ok: true });
}));

// ---------- Office-boy out/in (attendance & movement) ----------
function todayStr() { return nowInTz(db.getSetting('timezone')).date; }
function durationMin(outAt, backAt) {
  if (!outAt || !backAt) return null;
  return Math.max(0, Math.round((new Date(backAt) - new Date(outAt)) / 60000));
}
async function officeBoys() {
  return db.all("SELECT id, name, email FROM users WHERE role = 'office_boy' AND active = 1 ORDER BY name");
}
async function currentOuting(userId) {
  return db.get("SELECT * FROM outings WHERE user_id = $1 AND status = 'out' ORDER BY id DESC LIMIT 1", [userId]);
}
// Any 'out' record from a previous day = the boy never marked back in -> incomplete + penalty.
// Also pushes "missed return" alerts and "out too long" reminders.
async function sweepOutings() {
  const penalty = Math.max(0, Number(db.getSetting('penalty_amount') || 0));
  const today = todayStr();
  const currency = db.getSetting('currency');

  const stale = await db.all("SELECT id, user_id FROM outings WHERE status = 'out' AND out_date < $1", [today]);
  await db.run(
    "UPDATE outings SET status = 'incomplete', penalty_amount = CASE WHEN penalty_waived = 1 THEN 0 ELSE $1 END WHERE status = 'out' AND out_date < $2",
    [penalty, today]);
  for (const s of stale) {
    push.sendToUsers([s.user_id], { title: '⚠️ Missed return', body: `You didn't mark Back in Office. A penalty of ${currency} ${penalty} may apply.`, url: '/', category: 'attendance' });
  }

  const maxMin = Math.max(0, Number(db.getSetting('out_max_minutes') || 0));
  if (maxMin > 0) {
    const longs = await db.all("SELECT id, user_id, out_at FROM outings WHERE status = 'out' AND warned_long = 0 AND out_date = $1", [today]);
    for (const l of longs) {
      if ((Date.now() - new Date(l.out_at).getTime()) / 60000 >= maxMin) {
        await db.run('UPDATE outings SET warned_long = 1 WHERE id = $1', [l.id]);
        push.sendToUsers([l.user_id], { title: '⏳ Still out of office', body: `You've been out over ${maxMin} min. Please mark Back in Office when you return.`, url: '/', category: 'attendance' });
      }
    }
  }
}

app.get('/api/boy/outing/state', boyAuth, wrap(async (req, res) => {
  await sweepOutings();
  const boys = [];
  for (const b of await officeBoys()) {
    const cur = await currentOuting(b.id);
    boys.push({ id: b.id, name: b.name || b.email, current: cur ? { id: cur.id, out_at: cur.out_at, purpose: cur.purpose } : null });
  }
  const today = todayStr();
  const history = await db.all(
    "SELECT o.*, u.name FROM outings o JOIN users u ON u.id = o.user_id WHERE o.out_date = $1 AND u.role = 'office_boy' ORDER BY o.id DESC", [today]);
  res.json({
    boys, today, penalty: Number(db.getSetting('penalty_amount') || 0),
    history: history.map((h) => ({ id: h.id, name: h.name, purpose: h.purpose, out_at: h.out_at, back_at: h.back_at, status: h.status, duration_min: durationMin(h.out_at, h.back_at) })),
  });
}));
app.post('/api/boy/outing/out', boyAuth, wrap(async (req, res) => {
  const userId = Number(req.body.user_id);
  const u = await db.get("SELECT id FROM users WHERE id = $1 AND role = 'office_boy' AND active = 1", [userId]);
  if (!u) return res.status(400).json({ error: 'Select a valid office boy' });
  if (await currentOuting(userId)) return res.status(409).json({ error: 'Already marked out — mark Back in Office first' });
  const purpose = String(req.body.purpose || '').slice(0, 160);
  await db.run('INSERT INTO outings(user_id, out_date, purpose) VALUES ($1, $2, $3)', [userId, todayStr(), purpose]);
  res.json({ ok: true });
}));
app.post('/api/boy/outing/in', boyAuth, wrap(async (req, res) => {
  const userId = Number(req.body.user_id);
  const cur = await currentOuting(userId);
  if (!cur) return res.status(409).json({ error: 'No open outing to close' });
  await db.run("UPDATE outings SET back_at = now(), status = 'in' WHERE id = $1", [cur.id]);
  res.json({ ok: true });
}));

// ---------- Admin: settings, menu, users, boy access ----------
app.get('/api/settings', auth, requireRole('admin'), (req, res) => {
  res.json({
    cutoff_time: db.getSetting('cutoff_time'),
    aggregate_time: db.getSetting('aggregate_time'),
    timezone: db.getSetting('timezone'),
    currency: db.getSetting('currency'),
    allow_custom_items: db.getSetting('allow_custom_items') === '1',
    ordering_open: db.getSetting('ordering_open') === '1',
    allowed_domains: db.getSetting('allowed_domains') || '',
    boy_access_key: db.getSetting('boy_access_key') || '',
    boy_pin_set: !!db.getSetting('boy_pin_hash'),
    penalty_amount: Number(db.getSetting('penalty_amount') || 0),
  });
});
app.put('/api/settings', auth, requireRole('admin'), wrap(async (req, res) => {
  const b = req.body || {};
  const reTime = /^([01]\d|2[0-3]):[0-5]\d$/;
  if (b.cutoff_time && !reTime.test(b.cutoff_time)) return res.status(400).json({ error: 'cutoff_time must be HH:MM' });
  if (b.aggregate_time && !reTime.test(b.aggregate_time)) return res.status(400).json({ error: 'aggregate_time must be HH:MM' });
  if (b.cutoff_time) await db.setSetting('cutoff_time', b.cutoff_time);
  if (b.aggregate_time) await db.setSetting('aggregate_time', b.aggregate_time);
  if (b.timezone) await db.setSetting('timezone', String(b.timezone).slice(0, 64));
  if (b.currency) await db.setSetting('currency', String(b.currency).slice(0, 8));
  if (b.allow_custom_items !== undefined) await db.setSetting('allow_custom_items', b.allow_custom_items ? '1' : '0');
  if (b.ordering_open !== undefined) await db.setSetting('ordering_open', b.ordering_open ? '1' : '0');
  if (b.allowed_domains !== undefined) {
    const cleaned = String(b.allowed_domains).split(',')
      .map((s) => s.trim().toLowerCase().replace(/^@/, '')).filter(Boolean).join(',');
    await db.setSetting('allowed_domains', cleaned);
  }
  if (b.penalty_amount !== undefined) {
    const amt = Math.max(0, Number(b.penalty_amount) || 0);
    await db.setSetting('penalty_amount', String(amt));
  }
  res.json({ ok: true });
}));

// Office-boy access management
app.post('/api/admin/boy-key', auth, requireRole('admin'), wrap(async (req, res) => {
  const key = crypto.randomBytes(24).toString('hex');
  await db.setSetting('boy_access_key', key);
  res.json({ ok: true, boy_access_key: key });
}));
app.put('/api/admin/boy-pin', auth, requireRole('admin'), wrap(async (req, res) => {
  const pin = String(req.body.pin || '').trim();
  if (!pin) { await db.setSetting('boy_pin_hash', ''); return res.json({ ok: true, boy_pin_set: false }); }
  if (!/^\d{4,8}$/.test(pin)) return res.status(400).json({ error: 'PIN must be 4-8 digits' });
  await db.setSetting('boy_pin_hash', bcrypt.hashSync(pin, 10));
  res.json({ ok: true, boy_pin_set: true });
}));

// Admin: outing audit trail + penalty waive/override
app.get('/api/admin/outings', auth, requireRole('admin'), wrap(async (req, res) => {
  await sweepOutings();
  const cond = [], params = [];
  if (req.query.from) { params.push(req.query.from); cond.push(`o.out_date >= $${params.length}`); }
  if (req.query.to) { params.push(req.query.to); cond.push(`o.out_date <= $${params.length}`); }
  const where = cond.length ? 'WHERE ' + cond.join(' AND ') : '';
  const rows = await db.all(`SELECT o.*, u.name, u.email FROM outings o JOIN users u ON u.id = o.user_id ${where} ORDER BY o.out_date DESC, o.id DESC`, params);
  const outings = rows.map((r) => ({
    id: r.id, name: r.name || r.email, out_date: r.out_date, purpose: r.purpose,
    out_at: r.out_at, back_at: r.back_at, status: r.status,
    duration_min: durationMin(r.out_at, r.back_at),
    penalty_amount: r.penalty_amount, penalty_waived: !!r.penalty_waived,
    effective_penalty: r.penalty_waived ? 0 : r.penalty_amount,
  }));
  res.json({ outings, totalPenalty: outings.reduce((s, r) => s + (r.effective_penalty || 0), 0), penalty_default: Number(db.getSetting('penalty_amount') || 0) });
}));
app.put('/api/admin/outings/:id', auth, requireRole('admin'), wrap(async (req, res) => {
  const id = Number(req.params.id);
  const o = await db.get('SELECT * FROM outings WHERE id = $1', [id]);
  if (!o) return res.status(404).json({ error: 'Not found' });
  const purpose = req.body.purpose !== undefined ? String(req.body.purpose).slice(0, 160) : o.purpose;
  const waived = req.body.penalty_waived !== undefined ? (req.body.penalty_waived ? 1 : 0) : o.penalty_waived;
  const amount = req.body.penalty_amount !== undefined ? Math.max(0, Number(req.body.penalty_amount) || 0) : o.penalty_amount;
  await db.run('UPDATE outings SET purpose = $1, penalty_waived = $2, penalty_amount = $3 WHERE id = $4', [purpose, waived, amount, id]);
  res.json({ ok: true });
}));

// Admin notification center + history
app.post('/api/admin/notify', auth, requireRole('admin'), wrap(async (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 120);
  if (!title) return res.status(400).json({ error: 'Title required' });
  const body = String(req.body.body || '').slice(0, 300);
  const url = String(req.body.url || '/').slice(0, 200);
  const target = req.body.target;
  let userIds = [];
  if (Array.isArray(target)) userIds = target.map(Number).filter(Boolean);
  else if (target === 'all') userIds = (await db.all('SELECT id FROM users WHERE active = 1')).map((u) => u.id);
  else if (['staff', 'office_boy', 'admin'].includes(target)) userIds = (await db.all('SELECT id FROM users WHERE active = 1 AND role = $1', [target])).map((u) => u.id);
  else return res.status(400).json({ error: 'Invalid target' });
  await push.sendToUsers(userIds, { title, body, url, category: 'admin' }, req.user.id);
  res.json({ ok: true, recipients: userIds.length });
}));
app.get('/api/admin/notifications', auth, requireRole('admin'), wrap(async (req, res) => {
  res.json(await db.all(`
    SELECT n.id, n.title, n.body, n.category, n.delivered, n.error, n.created_at, u.name, u.email
    FROM notifications n LEFT JOIN users u ON u.id = n.user_id
    ORDER BY n.id DESC LIMIT 100`));
}));

app.post('/api/menu', auth, requireRole('admin'), wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 120);
  const price = Math.max(0, Number(req.body.price) || 0);
  if (!name) return res.status(400).json({ error: 'Name required' });
  const r = await db.get('INSERT INTO menu_items(name, price) VALUES ($1, $2) RETURNING id', [name, price]);
  res.json({ ok: true, id: r.id });
}));
app.put('/api/menu/:id', auth, requireRole('admin'), wrap(async (req, res) => {
  const id = Number(req.params.id);
  const m = await db.get('SELECT * FROM menu_items WHERE id = $1', [id]);
  if (!m) return res.status(404).json({ error: 'Not found' });
  const name = req.body.name !== undefined ? String(req.body.name).trim().slice(0, 120) : m.name;
  const price = req.body.price !== undefined ? Math.max(0, Number(req.body.price) || 0) : m.price;
  const available = req.body.available !== undefined ? (req.body.available ? 1 : 0) : m.available;
  await db.run('UPDATE menu_items SET name = $1, price = $2, available = $3 WHERE id = $4', [name, price, available, id]);
  res.json({ ok: true });
}));
app.delete('/api/menu/:id', auth, requireRole('admin'), wrap(async (req, res) => {
  await db.run('DELETE FROM menu_items WHERE id = $1', [Number(req.params.id)]);
  res.json({ ok: true });
}));

app.get('/api/users', auth, requireRole('admin'), wrap(async (req, res) => {
  res.json(await db.all('SELECT id, email, name, role, active FROM users ORDER BY name'));
}));
app.post('/api/users', auth, requireRole('admin'), wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const name = String(req.body.name || '').trim().slice(0, 120);
  const role = ['staff', 'office_boy', 'admin'].includes(req.body.role) ? req.body.role : 'staff';
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Valid email required' });
  const dup = await db.get('SELECT 1 FROM users WHERE email = $1', [email]);
  if (dup) return res.status(409).json({ error: 'Email already exists' });
  await db.run('INSERT INTO users(email, name, role) VALUES ($1, $2, $3)', [email, name, role]);
  res.json({ ok: true });
}));
app.put('/api/users/:id', auth, requireRole('admin'), wrap(async (req, res) => {
  const id = Number(req.params.id);
  const u = await db.get('SELECT * FROM users WHERE id = $1', [id]);
  if (!u) return res.status(404).json({ error: 'Not found' });
  const name = req.body.name !== undefined ? String(req.body.name).trim().slice(0, 120) : u.name;
  const role = ['staff', 'office_boy', 'admin'].includes(req.body.role) ? req.body.role : u.role;
  const active = req.body.active !== undefined ? (req.body.active ? 1 : 0) : u.active;
  await db.run('UPDATE users SET name = $1, role = $2, active = $3 WHERE id = $4', [name, role, active, id]);
  res.json({ ok: true });
}));

// ---------- Employee task assignment module ----------
const TASK_STATUSES = ['pending', 'in_progress', 'completed', 'cancelled'];
const TASK_SELECT = `
  SELECT t.id, t.title, t.details, t.status, t.remarks, t.category_id,
         c.name AS category_name, t.assignee_id, u.name AS assignee_name, u.email AS assignee_email,
         t.created_at, t.updated_at, t.completed_at
  FROM tasks t
  LEFT JOIN task_categories c ON c.id = t.category_id
  LEFT JOIN users u ON u.id = t.assignee_id`;
const TASK_ORDER = "ORDER BY (t.status IN ('completed','cancelled')), t.updated_at DESC";

async function updateTaskStatus(id, status, remarks) {
  const completedAt = status === 'completed' ? new Date().toISOString() : null;
  await db.run('UPDATE tasks SET status = $1, remarks = COALESCE($2, remarks), completed_at = $3, updated_at = now() WHERE id = $4',
    [status, remarks === undefined ? null : remarks, completedAt, id]);
}

// --- Admin: task categories + visibility ---
app.get('/api/admin/task-categories', auth, requireRole('admin'), wrap(async (req, res) => {
  const cats = await db.all('SELECT id, name, active FROM task_categories ORDER BY name');
  for (const c of cats) {
    c.visible_to = (await db.all('SELECT user_id FROM task_category_visibility WHERE category_id = $1', [c.id])).map((r) => r.user_id);
  }
  res.json(cats);
}));
app.post('/api/admin/task-categories', auth, requireRole('admin'), wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80);
  if (!name) return res.status(400).json({ error: 'Name required' });
  const r = await db.get('INSERT INTO task_categories(name) VALUES ($1) RETURNING id', [name]);
  res.json({ ok: true, id: r.id });
}));
app.put('/api/admin/task-categories/:id', auth, requireRole('admin'), wrap(async (req, res) => {
  const id = Number(req.params.id);
  const c = await db.get('SELECT * FROM task_categories WHERE id = $1', [id]);
  if (!c) return res.status(404).json({ error: 'Not found' });
  const name = req.body.name !== undefined ? String(req.body.name).trim().slice(0, 80) : c.name;
  const active = req.body.active !== undefined ? (req.body.active ? 1 : 0) : c.active;
  await db.run('UPDATE task_categories SET name = $1, active = $2 WHERE id = $3', [name, active, id]);
  res.json({ ok: true });
}));
app.delete('/api/admin/task-categories/:id', auth, requireRole('admin'), wrap(async (req, res) => {
  await db.run('DELETE FROM task_categories WHERE id = $1', [Number(req.params.id)]);
  res.json({ ok: true });
}));
app.put('/api/admin/task-categories/:id/visibility', auth, requireRole('admin'), wrap(async (req, res) => {
  const id = Number(req.params.id);
  const ids = Array.isArray(req.body.user_ids) ? req.body.user_ids.map(Number).filter(Boolean) : [];
  await db.tx(async (c) => {
    await c.query('DELETE FROM task_category_visibility WHERE category_id = $1', [id]);
    for (const uid of ids) {
      await c.query('INSERT INTO task_category_visibility(category_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [id, uid]);
    }
  });
  res.json({ ok: true });
}));

// --- Admin: tasks ---
app.get('/api/admin/tasks', auth, requireRole('admin'), wrap(async (req, res) => {
  res.json(await db.all(`${TASK_SELECT} ${TASK_ORDER}`));
}));
app.post('/api/admin/tasks', auth, requireRole('admin'), wrap(async (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 160);
  if (!title) return res.status(400).json({ error: 'Title required' });
  const details = String(req.body.details || '').slice(0, 1000);
  const categoryId = req.body.category_id ? Number(req.body.category_id) : null;
  const assigneeId = req.body.assignee_id ? Number(req.body.assignee_id) : null;
  if (assigneeId) {
    const u = await db.get('SELECT 1 FROM users WHERE id = $1 AND active = 1', [assigneeId]);
    if (!u) return res.status(400).json({ error: 'Assignee not found' });
  }
  const r = await db.get(
    'INSERT INTO tasks(category_id, title, details, assignee_id, created_by) VALUES ($1,$2,$3,$4,$5) RETURNING id',
    [categoryId, title, details, assigneeId, req.user.id]);
  if (assigneeId) push.sendToUsers([assigneeId], { title: '🗂️ New task assigned', body: title, url: '/', category: 'task' });
  res.json({ ok: true, id: r.id });
}));
app.put('/api/admin/tasks/:id', auth, requireRole('admin'), wrap(async (req, res) => {
  const id = Number(req.params.id);
  const t = await db.get('SELECT * FROM tasks WHERE id = $1', [id]);
  if (!t) return res.status(404).json({ error: 'Not found' });
  const b = req.body || {};
  const title = b.title !== undefined ? String(b.title).trim().slice(0, 160) : t.title;
  const details = b.details !== undefined ? String(b.details).slice(0, 1000) : t.details;
  const categoryId = b.category_id !== undefined ? (b.category_id ? Number(b.category_id) : null) : t.category_id;
  const assigneeId = b.assignee_id !== undefined ? (b.assignee_id ? Number(b.assignee_id) : null) : t.assignee_id;
  const status = b.status !== undefined && TASK_STATUSES.includes(b.status) ? b.status : t.status;
  const remarks = b.remarks !== undefined ? String(b.remarks).slice(0, 1000) : t.remarks;
  const completedAt = status === 'completed' ? (t.completed_at || new Date().toISOString()) : null;
  await db.run(
    'UPDATE tasks SET title=$1, details=$2, category_id=$3, assignee_id=$4, status=$5, remarks=$6, completed_at=$7, updated_at=now() WHERE id=$8',
    [title, details, categoryId, assigneeId, status, remarks, completedAt, id]);
  if (assigneeId && assigneeId !== t.assignee_id) push.sendToUsers([assigneeId], { title: '🗂️ New task assigned', body: title, url: '/', category: 'task' });
  res.json({ ok: true });
}));
app.delete('/api/admin/tasks/:id', auth, requireRole('admin'), wrap(async (req, res) => {
  await db.run('DELETE FROM tasks WHERE id = $1', [Number(req.params.id)]);
  res.json({ ok: true });
}));

// --- Employee (logged in): my tasks ---
app.get('/api/tasks/mine', auth, wrap(async (req, res) => {
  res.json(await db.all(`${TASK_SELECT} WHERE t.assignee_id = $1 ${TASK_ORDER}`, [req.user.id]));
}));
app.post('/api/tasks/:id/status', auth, wrap(async (req, res) => {
  const id = Number(req.params.id);
  const t = await db.get('SELECT assignee_id FROM tasks WHERE id = $1', [id]);
  if (!t || t.assignee_id !== req.user.id) return res.status(403).json({ error: 'Not your task' });
  const status = req.body.status;
  if (!TASK_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  await updateTaskStatus(id, status, req.body.remarks !== undefined ? String(req.body.remarks).slice(0, 1000) : undefined);
  res.json({ ok: true });
}));
// Categories visible to the current employee (empty visibility = visible to all).
app.get('/api/task-categories/mine', auth, wrap(async (req, res) => {
  res.json(await db.all(`
    SELECT c.id, c.name FROM task_categories c
    WHERE c.active = 1 AND (
      c.id NOT IN (SELECT category_id FROM task_category_visibility)
      OR c.id IN (SELECT category_id FROM task_category_visibility WHERE user_id = $1)
    ) ORDER BY c.name`, [req.user.id]));
}));

// --- Office boy (no login): tasks assigned to any office_boy user ---
app.get('/api/boy/tasks', boyAuth, wrap(async (req, res) => {
  res.json(await db.all(`${TASK_SELECT} WHERE u.role = 'office_boy' ${TASK_ORDER}`));
}));
app.post('/api/boy/tasks/:id/status', boyAuth, wrap(async (req, res) => {
  const id = Number(req.params.id);
  const t = await db.get("SELECT t.id FROM tasks t JOIN users u ON u.id = t.assignee_id WHERE t.id = $1 AND u.role = 'office_boy'", [id]);
  if (!t) return res.status(404).json({ error: 'Task not found' });
  const status = req.body.status;
  if (!TASK_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  await updateTaskStatus(id, status, req.body.remarks !== undefined ? String(req.body.remarks).slice(0, 1000) : undefined);
  res.json({ ok: true });
}));

// ---------- Static frontend + error handler ----------
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Server error' }); });

async function start() {
  await db.init();
  push.configure();
  await sweepOutings().catch((e) => console.error('Outing sweep failed:', e.message));
  // Re-run periodically so previous-day open outings get flagged incomplete + penalised.
  setInterval(() => sweepOutings().catch((e) => console.error('Outing sweep failed:', e.message)), 30 * 60 * 1000).unref();
  app.listen(PORT, () => {
    console.log(`Lunch order app running on http://localhost:${PORT}`);
    console.log(`DB: PostgreSQL | Mail transport: ${process.env.MAIL_TRANSPORT || 'console'} | Admin: ${process.env.ADMIN_EMAIL || 'admin@office.local'}`);
  });
}
if (require.main === module) start().catch((e) => { console.error('Startup failed:', e); process.exit(1); });

module.exports = { app, start };
