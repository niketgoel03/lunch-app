'use strict';

// Mail transports:
//   graph   -> Microsoft Graph (app-only / client-credentials) via /users/{sender}/sendMail
//   smtp    -> classic SMTP via nodemailer
//   console -> development only: prints the OTP to the server log
const transport = (process.env.MAIL_TRANSPORT || 'console').toLowerCase();
const from = process.env.MAIL_FROM || process.env.GRAPH_SENDER || 'lunch@office.local';

// ---------- Microsoft Graph ----------
const GRAPH_SCOPE = 'https://graph.microsoft.com/.default';
let cachedToken = { value: null, exp: 0 };

async function graphToken() {
  const now = Date.now();
  if (cachedToken.value && now < cachedToken.exp - 60_000) return cachedToken.value;

  const tenant = process.env.GRAPH_TENANT_ID;
  const url = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    client_id: process.env.GRAPH_CLIENT_ID,
    client_secret: process.env.GRAPH_CLIENT_SECRET,
    scope: GRAPH_SCOPE,
    grant_type: 'client_credentials',
  });
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  const data = await res.json();
  if (!res.ok || !data.access_token) {
    throw new Error('Graph token request failed: ' + (data.error_description || res.status));
  }
  cachedToken = { value: data.access_token, exp: now + data.expires_in * 1000 };
  return cachedToken.value;
}

async function sendViaGraph(to, subject, text) {
  const token = await graphToken();
  const sender = process.env.GRAPH_SENDER; // UPN or object id of the sending mailbox
  const res = await fetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(sender)}/sendMail`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message: {
        subject,
        body: { contentType: 'Text', content: text },
        toRecipients: [{ emailAddress: { address: to } }],
      },
      saveToSentItems: false,
    }),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error('Graph sendMail failed: ' + res.status + ' ' + detail);
  }
}

// ---------- SMTP (lazy) ----------
let smtp = null;
function smtpClient() {
  if (!smtp) {
    const nodemailer = require('nodemailer');
    smtp = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE).toLowerCase() === 'true',
      auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
    });
  }
  return smtp;
}

// Returns true when delivered out-of-band (real email); false in console/dev mode.
async function sendOtp(email, code) {
  const subject = 'Your lunch order login code';
  const text = `Your one-time login code is ${code}. It expires in 5 minutes.`;

  if (transport === 'graph') { await sendViaGraph(email, subject, text); return true; }
  if (transport === 'smtp') { await smtpClient().sendMail({ from, to: email, subject, text }); return true; }

  console.log(`[OTP] ${email} -> ${code} (expires in 5 min)`);
  return false;
}

module.exports = { sendOtp, devMode: transport === 'console' };
