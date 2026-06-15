'use strict';
// End-to-end smoke test against a running server. Uses global fetch (Node 18+).
const BASE = process.env.BASE || 'http://localhost:3100';
let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  PASS', m)) : (fail++, console.log('  FAIL', m)); };

function jar() { return { cookie: '' }; }
async function call(j, method, path, body, extraHeaders) {
  const r = await fetch(BASE + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...(j && j.cookie ? { Cookie: j.cookie } : {}), ...(extraHeaders || {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const sc = r.headers.get('set-cookie');
  if (j && sc) j.cookie = sc.split(';')[0];
  let data = null; try { data = await r.json(); } catch {}
  return { status: r.status, data };
}
async function loginAs(email) {
  const j = jar();
  const r1 = await call(j, 'POST', '/api/auth/request-otp', { email });
  const code = r1.data.devCode;
  if (!code) throw new Error('no devCode for ' + email + ': ' + JSON.stringify(r1.data));
  const r2 = await call(j, 'POST', '/api/auth/verify-otp', { email, code });
  if (r2.status !== 200) throw new Error('login failed for ' + email + ': ' + JSON.stringify(r2.data));
  return j;
}

(async () => {
  console.log('Admin login + bootstrap');
  const admin = await loginAs('admin@office.local');
  const me = await call(admin, 'GET', '/api/me');
  ok(me.data.user.role === 'admin', 'admin session established');

  await call(admin, 'PUT', '/api/settings', { cutoff_time: '23:59', aggregate_time: '23:59', ordering_open: true });
  const m = await call(admin, 'POST', '/api/menu', { name: 'Test Biryani', price: 120 });
  ok(m.status === 200, 'admin added menu item');
  // Office boy with a dummy email + a normal staff member.
  await call(admin, 'POST', '/api/users', { name: 'Rahul', email: 'rahul@ayasya.com', role: 'office_boy' });
  await call(admin, 'POST', '/api/users', { name: 'Staff One', email: 'staff1@office.local', role: 'staff' });

  console.log('Email domain whitelist');
  await call(admin, 'PUT', '/api/settings', { allowed_domains: 'ayasya.com' });
  const sset = await call(admin, 'GET', '/api/settings');
  ok(sset.data.allowed_domains === 'ayasya.com', 'whitelist saved');
  const off = await call(jar(), 'POST', '/api/auth/request-otp', { email: 'stranger@gmail.com' });
  ok(off.status === 200 && !off.data.devCode, 'off-domain unknown email gets no code');
  const ondom = await call(jar(), 'POST', '/api/auth/request-otp', { email: 'newbie@ayasya.com' });
  ok(ondom.status === 200 && !!ondom.data.devCode && ondom.data.newUser === true, 'whitelisted new email gets code + newUser flag');

  console.log('Auto-onboarding on first verify');
  const nb = jar();
  const req = await call(nb, 'POST', '/api/auth/request-otp', { email: 'newbie@ayasya.com' });
  const ver = await call(nb, 'POST', '/api/auth/verify-otp', { email: 'newbie@ayasya.com', code: req.data.devCode });
  ok(ver.status === 200 && ver.data.user.role === 'staff', 'new whitelisted user auto-created as staff');
  const users = await call(admin, 'GET', '/api/users');
  ok(users.data.some(u => u.email === 'newbie@ayasya.com'), 'auto-created user appears in People list');

  console.log('Off-domain stranger cannot verify (no account, blocked)');
  const sver = await call(jar(), 'POST', '/api/auth/verify-otp', { email: 'stranger@gmail.com', code: '000000' });
  ok(sver.status === 400, 'stranger has no pending code -> cannot onboard');

  console.log('Existing staff (off-domain, admin-added) can still log in');
  const staff = await loginAs('staff1@office.local');
  const place = await call(staff, 'POST', '/api/orders', { items: [{ menu_item_id: m.data.id, qty: 2 }], note: 'no onion' });
  ok(place.status === 200 && place.data.order.payment.amount === 240, 'existing staff places order = 240');

  console.log('Office-boy no-login access (secret key)');
  const skey = (await call(admin, 'GET', '/api/settings')).data.boy_access_key;
  ok(!!skey && skey.length >= 32, 'admin can read boy access key');
  const badKey = await call(null, 'GET', '/api/boy/aggregate', null, { 'x-boy-key': 'wrong' });
  ok(badKey.status === 401, 'wrong key rejected');
  const bagg = await call(null, 'GET', '/api/boy/aggregate', null, { 'x-boy-key': skey });
  ok(bagg.status === 200 && bagg.data.grandTotal === 240, 'valid key sees aggregate (total 240)');
  const oid = bagg.data.perPerson[0].id;
  await call(null, 'POST', '/api/boy/payments/' + oid + '/paid', { paid: true }, { 'x-boy-key': skey });
  const bagg2 = await call(null, 'GET', '/api/boy/aggregate', null, { 'x-boy-key': skey });
  ok(bagg2.data.perPerson[0].paid === true, 'boy marked payment paid (no login)');

  console.log('Office-boy PIN gate');
  await call(admin, 'PUT', '/api/admin/boy-pin', { pin: '4321' });
  const noPin = await call(null, 'GET', '/api/boy/aggregate', null, { 'x-boy-key': skey });
  ok(noPin.status === 401 && noPin.data.pinRequired === true, 'key without PIN rejected when PIN set');
  const withPin = await call(null, 'GET', '/api/boy/aggregate', null, { 'x-boy-key': skey, 'x-boy-pin': '4321' });
  ok(withPin.status === 200, 'key + correct PIN accepted');
  await call(admin, 'PUT', '/api/admin/boy-pin', { pin: '' }); // clear

  console.log('Office-boy cancels an order (no login)');
  await call(null, 'POST', '/api/boy/orders/' + oid + '/cancel', {}, { 'x-boy-key': skey });
  const bagg3 = await call(null, 'GET', '/api/boy/aggregate', null, { 'x-boy-key': skey });
  ok(bagg3.data.perPerson.length === 0, 'cancelled order removed from collection');

  console.log('Key rotation invalidates old key');
  const rot = await call(admin, 'POST', '/api/admin/boy-key');
  ok(rot.data.boy_access_key && rot.data.boy_access_key !== skey, 'admin rotated key');
  const oldKey = await call(null, 'GET', '/api/boy/aggregate', null, { 'x-boy-key': skey });
  ok(oldKey.status === 401, 'old key no longer works after rotation');

  console.log('Cutoff still enforced');
  await call(admin, 'PUT', '/api/settings', { cutoff_time: '00:00' });
  const late = await call(staff, 'POST', '/api/orders', { items: [{ menu_item_id: m.data.id, qty: 1 }] });
  ok(late.status === 403, 'order rejected after cutoff (403)');

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('ERROR', e); process.exit(1); });
