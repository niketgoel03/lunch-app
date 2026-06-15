# Office Lunch Order App

A small internal web app where office staff place their lunch request before a daily cutoff (default **1:00 PM**). The office boy collects all requests after the aggregation time (default **1:05 PM**), buys the items, and collects payment per person. Login is by email + OTP. Cutoff, aggregation time, menu, and other rules are admin-configurable.

---

## 1. Architecture (Solution Architect view)

**Pattern:** Modular monolith — right size for a single-office internal tool. One Node process, clear module separation (auth, orders, config, admin), easy to split later if needed.

**Stack & why**

| Layer | Choice | Rationale |
|---|---|---|
| Runtime | Node.js + Express | Ubiquitous, huge community, easy onboarding, zero license cost |
| DB | PostgreSQL (`pg`, pooled) | Production-grade, concurrent-safe, ACID; pooled async access with explicit transactions |
| Auth | Email OTP + JWT (HttpOnly cookie) | No passwords to leak; short-lived OTP + signed session |
| Frontend | Single-file vanilla HTML/JS | No build step, trivial to host and audit |
| Email | Microsoft Graph (app-only) | Sends OTP via your Microsoft 365 tenant; SMTP and console transports available as fallback |

**Data access:** a thin async layer (`db.js`) exposes `get` / `all` / `run` / `tx` over a `pg` connection pool. Writes that span multiple rows (placing an order + its items + payment) run inside a single `tx()` transaction. Settings are cached in memory at startup and refreshed on change, so per-request cutoff checks stay fast and synchronous.

**Mail transports (`MAIL_TRANSPORT`):** `graph` (Microsoft Graph client-credentials → `/users/{sender}/sendMail`), `smtp` (nodemailer), or `console` (dev: prints OTP to log + UI). The Graph app registration needs the **application** permission `Mail.Send` with admin consent, plus `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET`, and a `GRAPH_SENDER` mailbox.

**Roles**
- `staff` — place / edit / cancel their own order until cutoff.
- `office_boy` — see the aggregated list + per-person payment after cutoff; mark paid/delivered.
- `admin` — manage settings, menu, and users.

## 2. Cutoff logic (the core rule)

- Server time is the single source of truth (never trust the browser clock).
- `POST /api/orders` and edits are **rejected after `cutoff_time`** with HTTP 403.
- Times are evaluated in the configured `timezone` (default `Asia/Kolkata`).
- The office-boy aggregation view is only meaningful at/after `aggregate_time`; it shows the frozen list of orders placed before cutoff.

## 3. Data model

```
users(id, email, name, role, active, created_at)
otps(id, email, code_hash, expires_at, attempts, consumed)
menu_items(id, name, price, available)
orders(id, user_id, order_date, status, note, created_at, updated_at)
order_items(id, order_id, menu_item_id, name, qty, unit_price)
payments(order_id, amount, paid, paid_at, collected_by)
settings(key, value)   -- cutoff_time, aggregate_time, timezone, currency, allow_custom_items, ordering_open
```

Configurable settings (admin UI): `cutoff_time`, `aggregate_time`, `timezone`, `currency`, `allow_custom_items`, `ordering_open` (manual kill-switch), and the menu list.

## 4. API surface

```
POST /api/auth/request-otp   { email }          -> sends 6-digit code
POST /api/auth/verify-otp    { email, code }     -> sets session cookie
POST /api/auth/logout
GET  /api/me

GET  /api/menu
GET  /api/orders/mine
POST /api/orders             { items[], note }   -> 403 after cutoff
PUT  /api/orders/mine        { items[], note }   -> 403 after cutoff
DELETE /api/orders/mine                          -> 403 after cutoff

GET  /api/aggregate          (office_boy/admin)  -> per-person + shopping totals
POST /api/payments/:orderId/paid (office_boy/admin)

GET  /api/settings           (admin)
PUT  /api/settings           (admin)
POST /api/menu  PUT /api/menu/:id  DELETE /api/menu/:id  (admin)
GET  /api/users  POST /api/users  (admin)
```

## 5. Security (baked in from day 1)

- **AuthN:** OTP is random 6 digits, hashed (bcrypt) at rest, 5-min expiry, max 5 attempts, single-use. No code is ever returned in the API response in prod.
- **AuthZ:** RBAC middleware per route; users can only touch their own order.
- **Sessions:** JWT in an HttpOnly, SameSite=Lax cookie; `Secure` when behind TLS.
- **Transport:** Run behind a TLS-terminating reverse proxy (nginx/Caddy) — TLS 1.2+.
- **Input:** All bodies validated and parameterized SQL (no string-built queries → no SQLi).
- **Abuse:** Rate limiting on OTP request/verify; helmet security headers.
- **Audit:** `created_at`/`updated_at`, payment `collected_by`, OTP attempt counts.
- **Dependencies:** run `npm audit` in CI; minimal dependency list.

> Per your standing rule, this codebase contains **no AI/assistant references** in code, comments, commit messages, or docs. Keep architecture/decision notes in your separate `/project-memory/` store.

## 6. Run it

```bash
cd lunch-order-app
npm install

# Provision a Postgres database, e.g.:
#   createdb lunchdb
#   psql -c "CREATE USER lunch WITH PASSWORD 'secret'; GRANT ALL ON DATABASE lunchdb TO lunch;"

cp .env.example .env        # set DATABASE_URL, JWT_SECRET, GRAPH_* (or SMTP)
npm start                   # http://localhost:3000  (schema auto-creates on first run)
```

For a quick local trial without Microsoft 365, set `MAIL_TRANSPORT=console`: the OTP prints to the server log and is surfaced in the UI so you can log in without a real mailbox. For production set `MAIL_TRANSPORT=graph` with the `GRAPH_*` values, or `smtp` with the `SMTP_*` values.

**First-run seed:** the email in `ADMIN_EMAIL` is created as the `admin`. Log in with it, then add staff/office-boy users and the menu from the Admin tab.

## 7. Files

```
lunch-order-app/
├── server.js          # app, auth, routes, cutoff enforcement (async pg)
├── db.js              # pg pool, async query/tx helpers, schema + seed, settings cache
├── mailer.js          # mail transports: graph | smtp | console
├── public/index.html  # single-page UI (login, order, office-boy, admin)
├── package.json
├── .env.example
├── ecosystem.config.js # PM2 process config for production
├── DEPLOYMENT.md       # manual VPS deploy guide (Ubuntu + PM2 + Nginx + HTTPS + Postgres)
└── test/              # dev-only end-to-end smoke test (uses pg-mem; not loaded by the app)
```

> Verified end-to-end (10/10 checks) against a Postgres-compatible backend: OTP login, RBAC, order placement and totals, payment collection, and cutoff enforcement (time-based + master switch).
