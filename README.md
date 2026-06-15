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
POST /api/auth/request-otp   { email }            -> sends 6-digit code
POST /api/auth/verify-otp    { email, code }       -> sets session cookie (+ auto-onboard)
POST /api/auth/login         { email, password }   -> PIN/password login (no OTP)
POST /api/auth/set-password  { password }          -> set/change PIN (logged in)
POST /api/auth/logout
GET  /api/me                                       -> includes hasPassword

GET  /api/menu
GET  /api/orders/mine
POST /api/orders             { items[], note }   -> 403 after cutoff
PUT  /api/orders/mine        { items[], note }   -> 403 after cutoff
DELETE /api/orders/mine                          -> 403 after cutoff

GET  /api/aggregate                  (office_boy/admin) -> per-person + shopping totals + stats
POST /api/payments/:orderId/paid     (office_boy/admin) -> paid=true; only admin may set paid=false
POST /api/orders/:orderId/cancel     (office_boy/admin) -> emails employee; paid orders admin-only

# Task assignment module
GET  /api/tasks/mine                          (any logged-in employee)
POST /api/tasks/:id/status                     {status, remarks}   (own tasks only)
GET  /api/task-categories/mine                 (categories visible to me)
GET/POST/PUT/DELETE /api/admin/task-categories[/:id]            (admin)
PUT  /api/admin/task-categories/:id/visibility {user_ids:[]}     (admin)
GET/POST/PUT/DELETE /api/admin/tasks[/:id]                       (admin: create/assign/track)
GET  /api/boy/tasks ; POST /api/boy/tasks/:id/status            (office boy, no login)

# Office-boy out/in (attendance & movement)
GET  /api/boy/outing/state                     (office boy: who's out + today history + penalty)
POST /api/boy/outing/out   {user_id, purpose}  (mark Going Out)
POST /api/boy/outing/in    {user_id}           (mark Back in Office)
GET  /api/admin/outings[?from&to]              (admin: full audit + total penalties)
PUT  /api/admin/outings/:id {penalty_waived, penalty_amount, purpose}  (admin: waive/override)

# Web push notifications (PWA + VAPID, self-hosted)
GET  /api/push/vapid                            (public VAPID key for the browser)
POST /api/push/subscribe        {subscription}  (logged-in user)
POST /api/boy/push/subscribe    {user_id, subscription}  (office boy, no login)
GET  /api/notifications/mine                     (my recent notifications)
POST /api/admin/notify    {title, body, url, target}     (admin broadcast: all|role|user_ids[])
GET  /api/admin/notifications                    (admin: history + delivery status)

# Office boy WITHOUT login (authenticated by secret key + optional PIN, sent as
# x-boy-key / x-boy-pin headers or ?key=&pin= query):
POST /api/boy/check
GET  /api/boy/aggregate
POST /api/boy/payments/:orderId/paid
POST /api/boy/orders/:orderId/cancel

GET  /api/settings           (admin)   -> includes allowed_domains, boy_access_key, boy_pin_set
PUT  /api/settings           (admin)   -> set cutoff/aggregate/tz/currency/allowed_domains/toggles
POST /api/admin/boy-key      (admin)   -> rotate the office-boy access link
PUT  /api/admin/boy-pin      (admin)   -> set/clear the office-boy PIN
POST /api/menu  PUT /api/menu/:id  DELETE /api/menu/:id  (admin)
GET  /api/users  POST /api/users  PUT /api/users/:id     (admin)
```

### Onboarding & access model

- **Domain whitelist** (`allowed_domains`, admin-configurable): when set, anyone with an email in those domains can self-onboard. When blank, only admin-added people can log in.
- **Auto-onboarding:** an unknown but whitelisted email receives an OTP; on successful verification the account is created automatically as `staff` (no admin step). Unknown off-domain emails get no code and cannot verify.
- **Login methods:** after first-time OTP verification the user is prompted to create a **PIN or password** (bcrypt-hashed). Subsequent logins use **email + PIN** (no OTP needed). The login screen always offers **"Login with OTP"** as a passwordless alternative and a forgot-PIN fallback. Both methods set the same session cookie; login errors are generic to avoid revealing whether an email exists.
- **Office boy without login:** the office boy has an admin-created account with a dummy email (e.g. `rahul@ayasya.com`). They use a private link `/boy.html?key=<secret>` (optionally PIN-protected) to view the collection list, mark payments paid, cancel orders, and see/update their assigned tasks — no OTP/mailbox needed. Admin can rotate the link or set/clear the PIN anytime.

### Orders: paid & cancelled are final states

- **Paid is final.** Once an order is marked paid, the office boy sees no Undo/Cancel — only an **admin** can reverse a payment or cancel a paid order (a deliberate, separate process).
- **Cancellation notifies the employee** by email and the order stays visible in the collection list with a **Cancelled** badge (and **Paid** too if payment was already recorded). Cancelled orders are excluded from the shopping list and money totals.

### Task assignment module

Admin creates **task categories** (Shopping, Courier, Bank Work, Office Supplies, External Visits seeded by default), assigns **tasks** to any employee with title/details/category, and configures **category visibility** per employee. Each task tracks status (Pending → In progress → Completed / Cancelled) with remarks and timestamps. Employees manage their tasks from the **My Tasks** tab; the office boy manages theirs from the no-login link.

### Office-boy out/in tracking (attendance)

From the no-login link the office boy marks **Going Out** (with optional purpose) and **Back in Office**. Every outing is logged with date, out time, back time, duration and name. If a return isn't marked before the day ends, the record is auto-flagged **Incomplete** and a configurable penalty (default ₹300, set in Admin → Daily rules) is applied. The admin sees the full **audit trail** with total penalties and can **waive or override** any penalty. The daily sweep runs on startup and every 30 minutes.

### Web push notifications (PWA)

Self-hosted Web Push via Service Worker + VAPID — no Firebase, no third-party service. Keys are auto-generated on first run and stored in the DB. Users tap 🔔 to enable notifications on a device (the office boy enables per-person from the attendance card). Notifications fire on: new lunch order (→ office boy), task assigned (→ assignee), order cancelled & payment received (→ employee), plus attendance reminders ("out too long" after `OUT_MAX_MINUTES`, and "missed return"). Admins also get a **Notification Center** to broadcast a custom message to everyone or a group, and every notification is stored with delivery status in the **history log**.

> Web Push and Service Workers require **HTTPS** (already in place via Nginx + Let's Encrypt). `localhost` also works for development.

## 5. Security (baked in from day 1)

- **AuthN:** OTP is random 6 digits, hashed (bcrypt) at rest, 5-min expiry, max 5 attempts, single-use. No code is ever returned in the API response in prod. Self-onboarding is gated to admin-whitelisted email domains.
- **AuthZ:** RBAC middleware per route; users can only touch their own order. The office-boy no-login link is a high-entropy secret (constant-time compared) with an optional bcrypt-hashed PIN, and is rotatable — treat it like a bearer token and prefer HTTPS-only sharing.
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
├── public/index.html  # single-page UI (login, order, collection, admin)
├── public/boy.html    # office-boy no-login collection page (secret link + PIN)
├── package.json
├── .env.example
├── ecosystem.config.js # PM2 process config for production
├── DEPLOYMENT.md       # manual VPS deploy guide (Ubuntu + PM2 + Nginx + HTTPS + Postgres)
└── test/              # dev-only end-to-end smoke test (uses pg-mem; not loaded by the app)
```

> Verified end-to-end (10/10 checks) against a Postgres-compatible backend: OTP login, RBAC, order placement and totals, payment collection, and cutoff enforcement (time-based + master switch).
