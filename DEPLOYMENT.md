# Manual VPS Deployment — Ubuntu/Debian + Nginx + Let's Encrypt + PostgreSQL

Target: Ubuntu 22.04/24.04 (or Debian 12) VPS. App served behind Nginx with HTTPS; PostgreSQL on the same server. Run commands as a sudo-capable user. Replace `lunch.yourcompany.com`, passwords, and secrets with your own values.

---

## 0. Before you start

You need:
- A VPS with a public IP and SSH access.
- A domain/subdomain (e.g. `lunch.yourcompany.com`) with an **A record** pointing to the VPS IP. Set this first — Let's Encrypt verification in step 8 needs DNS to resolve.
- Your Microsoft Graph values (`GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET`, `GRAPH_SENDER`) ready, with `Mail.Send` application permission granted + admin consent.

---

## 1. Update the system

```bash
sudo apt update && sudo apt upgrade -y
```

## 2. Create a dedicated app user (least privilege)

Never run the app as root.

```bash
sudo adduser --system --group --home /opt/lunch-app lunch
```

## 3. Install Node.js 20 LTS

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
node -v && npm -v
```

## 4. Install PostgreSQL and create the database

```bash
sudo apt install -y postgresql
sudo systemctl enable --now postgresql
```

Create a database and a least-privilege role (pick a strong password):

```bash
sudo -u postgres psql <<'SQL'
CREATE USER lunch WITH PASSWORD 'STRONG_DB_PASSWORD';
CREATE DATABASE lunchdb OWNER lunch;
GRANT ALL PRIVILEGES ON DATABASE lunchdb TO lunch;
SQL
```

The default install only listens on `localhost`, which is what we want (the app connects locally). Don't open 5432 to the internet.

## 5. Put the application on the server

From your machine, copy the project folder up (exclude `node_modules` — it gets built on the server):

```bash
rsync -av --exclude node_modules --exclude .env --exclude '*.log' \
  ./lunch-app/  YOUR_USER@VPS_IP:/tmp/lunch-app/
```

On the VPS, move it into place and hand ownership to the app user:

```bash
sudo mkdir -p /opt/lunch-app
sudo rsync -a /tmp/lunch-app/ /opt/lunch-app/
sudo chown -R lunch:lunch /opt/lunch-app
```

Install production dependencies only:

```bash
cd /opt/lunch-app
sudo -u lunch npm install --omit=dev
```

## 6. Configure environment (`.env`)

```bash
sudo -u lunch cp /opt/lunch-app/.env.example /opt/lunch-app/.env
sudo -u lunch nano /opt/lunch-app/.env
```

Set at minimum:

```ini
PORT=3000
JWT_SECRET=<run: openssl rand -hex 32>
ADMIN_EMAIL=admin@yourcompany.com
ADMIN_NAME=Office Admin

DEFAULT_CUTOFF_TIME=13:00
DEFAULT_AGGREGATE_TIME=13:05
TIMEZONE=Asia/Kolkata
CURRENCY=INR

DATABASE_URL=postgresql://lunch:STRONG_DB_PASSWORD@localhost:5432/lunchdb
PGSSL=false

MAIL_TRANSPORT=graph
MAIL_FROM=lunch@yourcompany.com
GRAPH_TENANT_ID=...
GRAPH_CLIENT_ID=...
GRAPH_CLIENT_SECRET=...
GRAPH_SENDER=lunch@yourcompany.com

COOKIE_SECURE=true
```

Generate the JWT secret:

```bash
openssl rand -hex 32
```

Lock down the file so only the app user can read it:

```bash
sudo chmod 600 /opt/lunch-app/.env
sudo chown lunch:lunch /opt/lunch-app/.env
```

The schema auto-creates and the admin user is seeded on first start.

## 7. Run with PM2 (auto-start, auto-restart)

PM2 is a Node process manager that keeps the app running, restarts it on crash, and brings it back after a reboot.

Install PM2 globally:

```bash
sudo npm install -g pm2
pm2 -v
```

The repo includes `ecosystem.config.js` (PM2 reads it from the app directory). The app loads `.env` itself via dotenv, so PM2 only needs the correct working directory. Start it **as the `lunch` user** so it never runs as root:

```bash
cd /opt/lunch-app
sudo -u lunch pm2 start ecosystem.config.js
sudo -u lunch pm2 status
```

Enable start-on-boot for the `lunch` user. The `pm2 startup` command prints a `sudo env ... systemctl enable` line — copy and run exactly what it outputs:

```bash
sudo -u lunch pm2 startup systemd -u lunch --hp /opt/lunch-app
# run the sudo command it prints, then save the current process list:
sudo -u lunch pm2 save
```

Check logs / confirm it bound to port 3000:

```bash
sudo -u lunch pm2 logs lunch-app --lines 50
curl -s http://localhost:3000/api/menu   # expect 401 (not logged in) -> service is up
```

Handy PM2 commands (always as the `lunch` user):

```bash
sudo -u lunch pm2 restart lunch-app    # restart
sudo -u lunch pm2 reload lunch-app     # zero-downtime reload
sudo -u lunch pm2 stop lunch-app       # stop
sudo -u lunch pm2 monit                # live dashboard
```

## 8. Nginx reverse proxy + HTTPS

```bash
sudo apt install -y nginx
```

Create `/etc/nginx/sites-available/lunch-app`:

```bash
sudo tee /etc/nginx/sites-available/lunch-app > /dev/null <<'NGINX'
server {
    listen 80;
    server_name lunch.yourcompany.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX

sudo ln -s /etc/nginx/sites-available/lunch-app /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

The app already calls `app.set('trust proxy', 1)`, so with `COOKIE_SECURE=true` the session cookie works correctly over HTTPS behind Nginx — no edit needed.

Obtain a free auto-renewing certificate:

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d lunch.yourcompany.com
```

Certbot rewrites the Nginx config for TLS and sets up renewal. Verify renewal works:

```bash
sudo certbot renew --dry-run
```

## 9. Firewall

```bash
sudo apt install -y ufw
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'   # 80 + 443
sudo ufw --force enable
sudo ufw status
```

Note: 3000 (the app) and 5432 (Postgres) are **not** opened — they stay local-only behind Nginx.

## 10. First login

Open `https://lunch.yourcompany.com`, enter the `ADMIN_EMAIL`, receive the OTP by email (Graph), and sign in. From the **Admin** tab add staff + the office boy, set the menu, and confirm the cutoff/aggregate times and timezone.

---

## Updating to a new version

```bash
# copy new files up (same rsync as step 5, into /tmp/lunch-app)
sudo rsync -a --exclude node_modules --exclude .env /tmp/lunch-app/ /opt/lunch-app/
sudo chown -R lunch:lunch /opt/lunch-app
cd /opt/lunch-app && sudo -u lunch npm install --omit=dev
sudo -u lunch pm2 reload lunch-app        # zero-downtime restart
sudo -u lunch pm2 logs lunch-app --lines 30 --nostream
```

## Database backups (cron)

```bash
sudo mkdir -p /var/backups/lunch
sudo tee /etc/cron.daily/lunch-db-backup > /dev/null <<'CRON'
#!/bin/sh
PGPASSWORD='STRONG_DB_PASSWORD' pg_dump -U lunch -h localhost lunchdb \
  | gzip > /var/backups/lunch/lunchdb-$(date +\%F).sql.gz
find /var/backups/lunch -name '*.sql.gz' -mtime +14 -delete
CRON
sudo chmod +x /etc/cron.daily/lunch-db-backup
```

Restore example:

```bash
gunzip -c /var/backups/lunch/lunchdb-YYYY-MM-DD.sql.gz | psql -U lunch -h localhost lunchdb
```

---

## Production checklist

- [ ] `JWT_SECRET` is a fresh 32-byte random value (not the example).
- [ ] `.env` is `chmod 600`, owned by `lunch`, and **never** committed to git.
- [ ] `COOKIE_SECURE=true` and the site is HTTPS-only (HTTP redirects to HTTPS via certbot).
- [ ] `app.set('trust proxy', 1)` is set so secure cookies work behind Nginx.
- [ ] Postgres role uses a strong password; 5432 is not internet-exposed.
- [ ] UFW enabled; only SSH + Nginx Full open.
- [ ] PM2 runs as the `lunch` user (not root); `pm2 save` done and `pm2 startup` enabled so it survives reboots.
- [ ] `certbot renew --dry-run` succeeds (auto-renewal works).
- [ ] Daily DB backup cron in place and tested with a restore.
- [ ] `npm audit --omit=dev` clean; SSH hardened (key-only, no root login).
- [ ] Server timezone or `TIMEZONE` env matches the office so the 1:00 PM cutoff is correct.
```
