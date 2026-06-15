'use strict';

require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const db = require('./db');
const mailer = require('./mailer');

const app = express();
app.set('trust proxy', 1); // behind Nginx/Cloudflare: trust X-Forwarded-* so Secure cookies work
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-insecure-secret';
const COOKIE_SECURE = String(process.env.COOKIE_SECURE).toLowerCase() === 'true';

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

// Wrap async handlers so rejected promises become clean 500s instead of crashes.
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---------- Time helpers (configured timezone is source of truth) ----------
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

// Synchronous: reads from the in-memory settings cache populated at startup.
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

// ---------- Auth ----------
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

const otpRequestLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false });
const otpVerifyLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });

// ---------- Auth routes ----------
app.post('/api/auth/request-otp', otpRequestLimiter, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Valid email required' });

  const user = await db.get('SELECT id, active FROM users WHERE email = $1', [email]);
  if (user && user.active) {
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const codeHash = bcrypt.hashSync(code, 10);
    const expiresAt = Date.now() + 5 * 60 * 1000;
    await db.run('UPDATE otps SET consumed = 1 WHERE email = $1 AND consumed = 0', [email]);
    await db.run('INSERT INTO otps(email, code_hash, expires_at) VALUES ($1, $2, $3)', [email, codeHash, expiresAt]);
    try { await mailer.sendOtp(email, code); } catch (e) { console.error('Mail error:', e.message); }
    if (mailer.devMode) return res.json({ ok: true, devCode: code });
  }
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
  const user = await db.get('SELECT id, email, name, role, active FROM users WHERE email = $1', [email]);
  if (!user || !user.active) return res.status(401).json({ error: 'Account inactive' });
  setSession(res, user);
  res.json({ ok: true, user: { email: user.email, name: user.name, role: user.role } });
}));

app.post('/api/auth/logout', (req, res) => { res.clearCookie('session'); res.json({ ok: true }); });

app.get('/api/me', auth, (req, res) => {
  res.json({ user: { email: req.user.email, name: req.user.name, role: req.user.role }, state: orderingState() });
});

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

  const orderId = await db.tx(async (c) => {
    const existing = await c.query('SELECT id FROM orders WHERE user_id = $1 AND order_date = $2', [req.user.id, st.today]);
    let id;
    if (existing.rows[0]) {
      id = existing.rows[0].id;
      await c.query("UPDATE orders SET status = 'placed', note = $1, updated_at = now() WHERE id = $2", [note, id]);
    } else {
      const r = await c.query('INSERT INTO orders(user_id, order_date, note) VALUES ($1, $2, $3) RETURNING id', [req.user.id, st.today, note]);
      id = r.rows[0].id;
    }
    await c.query('DELETE FROM order_items WHERE order_id = $1', [id]);
    let total = 0;
    for (const it of items) {
      await c.query('INSERT INTO order_items(order_id, menu_item_id, name, qty, unit_price) VALUES ($1,$2,$3,$4,$5)',
        [id, it.menu_item_id, it.name, it.qty, it.unit_price]);
      total += it.qty * it.unit_price;
    }
    await c.query('INSERT INTO payments(order_id, amount, paid) VALUES ($1, $2, 0) ON CONFLICT(order_id) DO UPDATE SET amount = EXCLUDED.amount', [id, total]);
    return id;
  });

  res.json({ ok: true, order: await loadOrder(orderId), state: orderingState() });
});
app.post('/api/orders', auth, placeOrUpdate);
app.put('/api/orders/mine', auth, placeOrUpdate);

app.delete('/api/orders/mine', auth, wrap(async (req, res) => {
  const st = orderingState();
  if (!st.isOpen) return res.status(403).json({ error: `Cannot cancel after cutoff (${st.cutoffTime}).` });
  await db.run("UPDATE orders SET status = 'cancelled', updated_at = now() WHERE user_id = $1 AND order_date = $2", [req.user.id, st.today]);
  res.json({ ok: true });
}));

// ---------- Aggregation (office boy / admin) ----------
app.get('/api/aggregate', auth, requireRole('office_boy', 'admin'), wrap(async (req, res) => {
  const st = orderingState();
  const orders = await db.all(`
    SELECT o.id, o.note, o.status, u.name, u.email
    FROM orders o JOIN users u ON u.id = o.user_id
    WHERE o.order_date = $1 AND o.status <> 'cancelled'
    ORDER BY u.name`, [st.today]);

  const perPerson = [];
  for (const o of orders) {
    const items = await db.all('SELECT name, qty, unit_price FROM order_items WHERE order_id = $1', [o.id]);
    const pay = (await db.get('SELECT amount, paid FROM payments WHERE order_id = $1', [o.id])) || { amount: 0, paid: 0 };
    perPerson.push({ ...o, items, amount: pay.amount, paid: !!pay.paid });
  }

  const shoppingList = await db.all(`
    SELECT oi.name, SUM(oi.qty)::int AS qty, oi.unit_price
    FROM order_items oi JOIN orders o ON o.id = oi.order_id
    WHERE o.order_date = $1 AND o.status <> 'cancelled'
    GROUP BY oi.name, oi.unit_price ORDER BY oi.name`, [st.today]);

  const grandTotal = perPerson.reduce((s, p) => s + p.amount, 0);
  res.json({ state: st, perPerson, shoppingList, grandTotal, frozen: st.afterAggregate });
}));

app.post('/api/payments/:orderId/paid', auth, requireRole('office_boy', 'admin'), wrap(async (req, res) => {
  const paid = req.body.paid ? 1 : 0;
  await db.run('UPDATE payments SET paid = $1, paid_at = $2, collected_by = $3 WHERE order_id = $4',
    [paid, paid ? new Date().toISOString() : null, req.user.id, Number(req.params.orderId)]);
  if (paid) await db.run("UPDATE orders SET status = 'delivered' WHERE id = $1", [Number(req.params.orderId)]);
  res.json({ ok: true });
}));

// ---------- Admin: settings, menu, users ----------
app.get('/api/settings', auth, requireRole('admin'), (req, res) => {
  res.json({
    cutoff_time: db.getSetting('cutoff_time'),
    aggregate_time: db.getSetting('aggregate_time'),
    timezone: db.getSetting('timezone'),
    currency: db.getSetting('currency'),
    allow_custom_items: db.getSetting('allow_custom_items') === '1',
    ordering_open: db.getSetting('ordering_open') === '1',
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
  res.json({ ok: true });
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

// ---------- Static frontend + error handler ----------
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Server error' }); });

async function start() {
  await db.init();
  app.listen(PORT, () => {
    console.log(`Lunch order app running on http://localhost:${PORT}`);
    console.log(`DB: PostgreSQL | Mail transport: ${process.env.MAIL_TRANSPORT || 'console'} | Admin: ${process.env.ADMIN_EMAIL || 'admin@office.local'}`);
  });
}
if (require.main === module) start().catch((e) => { console.error('Startup failed:', e); process.exit(1); });

module.exports = { app, start };
