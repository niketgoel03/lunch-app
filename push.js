'use strict';

const webpush = require('web-push');
const db = require('./db');

let configured = false;
function configure() {
  const pub = db.getSetting('vapid_public');
  const priv = db.getSetting('vapid_private');
  if (pub && priv) {
    webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'mailto:admin@office.local', pub, priv);
    configured = true;
  }
  return configured;
}
function publicKey() { return db.getSetting('vapid_public') || ''; }

async function deliver(sub, payloadStr) {
  await webpush.sendNotification(
    { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } }, payloadStr);
}

// Send to a set of user ids. Records one notifications row per recipient (history + delivery log).
// Never throws — push must not break the request that triggered it.
async function sendToUsers(userIds, payload, createdBy = null) {
  try {
    if (!configured && !configure()) return;
    const ids = [...new Set((userIds || []).filter(Boolean))];
    const payloadStr = JSON.stringify({
      title: payload.title, body: payload.body || '', url: payload.url || '/', category: payload.category || 'general',
    });
    for (const uid of ids) {
      const subs = await db.all('SELECT * FROM push_subscriptions WHERE user_id = $1', [uid]);
      let delivered = 0, err = subs.length ? null : 'no subscription';
      for (const s of subs) {
        try { await deliver(s, payloadStr); delivered++; }
        catch (e) {
          err = e && e.statusCode ? ('HTTP ' + e.statusCode) : (e.message || 'send error');
          if (e && (e.statusCode === 404 || e.statusCode === 410)) {
            await db.run('DELETE FROM push_subscriptions WHERE id = $1', [s.id]).catch(() => {});
          }
        }
      }
      await db.run(
        'INSERT INTO notifications(user_id, title, body, url, category, delivered, error, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [uid, payload.title, payload.body || '', payload.url || '/', payload.category || 'general', delivered, delivered ? null : err, createdBy]);
    }
  } catch (e) { console.error('push.sendToUsers error:', e.message); }
}

async function sendToRole(role, payload, createdBy = null) {
  const us = await db.all('SELECT id FROM users WHERE role = $1 AND active = 1', [role]);
  await sendToUsers(us.map((u) => u.id), payload, createdBy);
}

module.exports = { configure, publicKey, sendToUsers, sendToRole };
