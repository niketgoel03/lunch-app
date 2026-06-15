'use strict';

const crypto = require('crypto');
const { Pool } = require('pg');

// Connection: prefer a single DATABASE_URL, else discrete PG* vars.
const pool = new Pool(
  process.env.DATABASE_URL
    ? { connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : undefined }
    : {
        host: process.env.PGHOST || 'localhost',
        port: Number(process.env.PGPORT || 5432),
        user: process.env.PGUSER,
        password: process.env.PGPASSWORD,
        database: process.env.PGDATABASE,
        ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : undefined,
      }
);

// ---- Query helpers ----
async function get(sql, params = []) { const r = await pool.query(sql, params); return r.rows[0] || null; }
async function all(sql, params = []) { const r = await pool.query(sql, params); return r.rows; }
async function run(sql, params = []) { return pool.query(sql, params); }

// Run fn inside a single transaction; fn receives a dedicated client.
async function tx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

// ---- Settings cache (read-mostly; keeps request-time access synchronous) ----
const settingsCache = {};
function getSetting(key) { return key in settingsCache ? settingsCache[key] : null; }
async function setSetting(key, value) {
  await run('INSERT INTO settings(key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value', [key, String(value)]);
  settingsCache[key] = String(value);
}
async function loadSettings() {
  const rows = await all('SELECT key, value FROM settings');
  for (const r of rows) settingsCache[r.key] = r.value;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id         SERIAL PRIMARY KEY,
  email      TEXT UNIQUE NOT NULL,
  name       TEXT NOT NULL DEFAULT '',
  role       TEXT NOT NULL DEFAULT 'staff',
  active      INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS otps (
  id         SERIAL PRIMARY KEY,
  email      TEXT NOT NULL,
  code_hash  TEXT NOT NULL,
  expires_at BIGINT NOT NULL,           -- epoch ms
  attempts   INTEGER NOT NULL DEFAULT 0,
  consumed   INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS menu_items (
  id        SERIAL PRIMARY KEY,
  name      TEXT NOT NULL,
  price     DOUBLE PRECISION NOT NULL DEFAULT 0,
  available INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS orders (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  order_date TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'placed',
  note       TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, order_date)
);

CREATE TABLE IF NOT EXISTS order_items (
  id           SERIAL PRIMARY KEY,
  order_id     INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  menu_item_id INTEGER,
  name         TEXT NOT NULL,
  qty          INTEGER NOT NULL DEFAULT 1,
  unit_price   DOUBLE PRECISION NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS payments (
  order_id     INTEGER PRIMARY KEY REFERENCES orders(id) ON DELETE CASCADE,
  amount       DOUBLE PRECISION NOT NULL DEFAULT 0,
  paid         INTEGER NOT NULL DEFAULT 0,
  paid_at      TIMESTAMPTZ,
  collected_by INTEGER
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- ===== Employee task assignment module =====
CREATE TABLE IF NOT EXISTS task_categories (
  id     SERIAL PRIMARY KEY,
  name   TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS tasks (
  id           SERIAL PRIMARY KEY,
  category_id  INTEGER REFERENCES task_categories(id) ON DELETE SET NULL,
  title        TEXT NOT NULL,
  details      TEXT NOT NULL DEFAULT '',
  assignee_id  INTEGER REFERENCES users(id),
  status       TEXT NOT NULL DEFAULT 'pending',   -- pending | in_progress | completed | cancelled
  remarks      TEXT NOT NULL DEFAULT '',
  created_by   INTEGER,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ
);

-- Which task categories are visible to which employees (empty for a category = all employees).
CREATE TABLE IF NOT EXISTS task_category_visibility (
  category_id INTEGER NOT NULL REFERENCES task_categories(id) ON DELETE CASCADE,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (category_id, user_id)
);

-- ===== Web push notifications =====
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  endpoint   TEXT UNIQUE NOT NULL,
  p256dh     TEXT NOT NULL,
  auth       TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS notifications (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
  title      TEXT NOT NULL,
  body       TEXT NOT NULL DEFAULT '',
  url        TEXT NOT NULL DEFAULT '/',
  category   TEXT NOT NULL DEFAULT 'general',
  delivered  INTEGER NOT NULL DEFAULT 0,   -- # of subscriptions the push reached
  error      TEXT,
  created_by INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===== Office-boy out/in (attendance & movement) tracking =====
CREATE TABLE IF NOT EXISTS outings (
  id             SERIAL PRIMARY KEY,
  user_id        INTEGER NOT NULL REFERENCES users(id),
  out_date       TEXT NOT NULL,                       -- YYYY-MM-DD in configured tz
  purpose        TEXT NOT NULL DEFAULT '',
  out_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  back_at        TIMESTAMPTZ,
  status         TEXT NOT NULL DEFAULT 'out',         -- out | in | incomplete
  penalty_amount DOUBLE PRECISION NOT NULL DEFAULT 0,
  penalty_waived INTEGER NOT NULL DEFAULT 0,
  warned_long    INTEGER NOT NULL DEFAULT 0,          -- 1 once an "out too long" alert was sent
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
`;

async function init() {
  await pool.query(SCHEMA);

  const seed = async (key, value) =>
    run('INSERT INTO settings(key, value) VALUES ($1, $2) ON CONFLICT(key) DO NOTHING', [key, String(value)]);
  await seed('cutoff_time', process.env.DEFAULT_CUTOFF_TIME || '13:00');
  await seed('aggregate_time', process.env.DEFAULT_AGGREGATE_TIME || '13:05');
  await seed('timezone', process.env.TIMEZONE || 'Asia/Kolkata');
  await seed('currency', process.env.CURRENCY || 'INR');
  await seed('allow_custom_items', '1');
  await seed('ordering_open', '1');
  await seed('allowed_domains', process.env.ALLOWED_DOMAINS || '');   // comma-separated; empty = no self-onboarding
  await seed('boy_access_key', crypto.randomBytes(24).toString('hex')); // secret for office-boy no-login link
  await seed('boy_pin_hash', '');                                      // optional bcrypt PIN; empty = link only
  await seed('penalty_amount', process.env.PENALTY_AMOUNT || '300');   // penalty for not checking back in (per day)
  await seed('out_max_minutes', process.env.OUT_MAX_MINUTES || '120'); // alert when office boy is out longer than this

  // VAPID keys for web push (generated once, then persisted).
  if (!(await get("SELECT 1 FROM settings WHERE key = 'vapid_public'"))) {
    try {
      const webpush = require('web-push');
      const keys = webpush.generateVAPIDKeys();
      await run('INSERT INTO settings(key, value) VALUES ($1, $2) ON CONFLICT(key) DO NOTHING', ['vapid_public', keys.publicKey]);
      await run('INSERT INTO settings(key, value) VALUES ($1, $2) ON CONFLICT(key) DO NOTHING', ['vapid_private', keys.privateKey]);
    } catch (e) { console.error('VAPID key generation skipped:', e.message); }
  }

  const adminEmail = (process.env.ADMIN_EMAIL || 'admin@office.local').toLowerCase();
  const adminName = process.env.ADMIN_NAME || 'Office Admin';
  const exists = await get('SELECT 1 FROM users WHERE email = $1', [adminEmail]);
  if (!exists) await run('INSERT INTO users(email, name, role) VALUES ($1, $2, $3)', [adminEmail, adminName, 'admin']);

  const c = await get('SELECT COUNT(*)::int AS c FROM menu_items');
  if (c.c === 0) {
    await run('INSERT INTO menu_items(name, price) VALUES ($1, $2)', ['Veg Thali', 80]);
    await run('INSERT INTO menu_items(name, price) VALUES ($1, $2)', ['Sandwich', 50]);
    await run('INSERT INTO menu_items(name, price) VALUES ($1, $2)', ['Tea', 10]);
  }

  const tc = await get('SELECT COUNT(*)::int AS c FROM task_categories');
  if (tc.c === 0) {
    for (const n of ['Shopping', 'Courier', 'Bank Work', 'Office Supplies', 'External Visits']) {
      await run('INSERT INTO task_categories(name) VALUES ($1)', [n]);
    }
  }

  await loadSettings();
}

module.exports = { pool, get, all, run, tx, getSetting, setSetting, loadSettings, init };
