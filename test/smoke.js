'use strict';
// End-to-end smoke test against a running server. Uses global fetch (Node 18+).
const BASE = process.env.BASE || 'http://localhost:3100';
let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log('  PASS', m)) : (fail++, console.log('  FAIL', m)); };

function jar() { return { cookie: '' }; }
async function call(j, method, path, body) {
  const r = await fetch(BASE + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...(j.cookie ? { Cookie: j.cookie } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const sc = r.headers.get('set-cookie');
  if (sc) j.cookie = sc.split(';')[0];
  let data = null; try { data = await r.json(); } catch {}
  return { status: r.status, data };
}
async function loginAs(email) {
  const j = jar();
  const r1 = await call(j, 'POST', '/api/auth/request-otp', { email });
  const code = r1.data.devCode;
  const r2 = await call(j, 'POST', '/api/auth/verify-otp', { email, code });
  if (r2.status !== 200) throw new Error('login failed for ' + email + ': ' + JSON.stringify(r2.data));
  return j;
}

(async () => {
  console.log('Admin login + bootstrap');
  const admin = await loginAs('admin@office.local');
  const me = await call(admin, 'GET', '/api/me');
  ok(me.data.user.role === 'admin', 'admin session established');

  // Open ordering with a late cutoff.
  await call(admin, 'PUT', '/api/settings', { cutoff_time: '23:59', aggregate_time: '23:59', ordering_open: true });
  // Add a menu item.
  const m = await call(admin, 'POST', '/api/menu', { name: 'Test Biryani', price: 120 });
  ok(m.status === 200, 'admin added menu item');
  // Add staff + office boy.
  await call(admin, 'POST', '/api/users', { name: 'Staff One', email: 'staff1@office.local', role: 'staff' });
  await call(admin, 'POST', '/api/users', { name: 'Boy', email: 'boy@office.local', role: 'office_boy' });

  console.log('Unregistered email gets no devCode');
  const stray = await call(jar(), 'POST', '/api/auth/request-otp', { email: 'nobody@office.local' });
  ok(stray.status === 200 && !stray.data.devCode, 'unknown email is not issued a code');

  console.log('Staff places an order before cutoff');
  const staff = await loginAs('staff1@office.local');
  const place = await call(staff, 'POST', '/api/orders', { items: [{ menu_item_id: m.data.id, qty: 2 }], note: 'no onion' });
  ok(place.status === 200 && place.data.order.payment.amount === 240, 'order placed, amount = 2 x 120 = 240');

  console.log('Staff cannot access admin or aggregate');
  const forbid = await call(staff, 'GET', '/api/aggregate');
  ok(forbid.status === 403, 'staff blocked from /api/aggregate (RBAC)');

  console.log('Office boy sees aggregation + collects payment');
  const boy = await loginAs('boy@office.local');
  const agg = await call(boy, 'GET', '/api/aggregate');
  ok(agg.data.perPerson.length === 1 && agg.data.grandTotal === 240, 'aggregate shows 1 order, total 240');
  await call(boy, 'POST', '/api/payments/' + agg.data.perPerson[0].id + '/paid', { paid: true });
  const agg2 = await call(boy, 'GET', '/api/aggregate');
  ok(agg2.data.perPerson[0].paid === true, 'payment marked paid');

  console.log('Cutoff enforcement');
  await call(admin, 'PUT', '/api/settings', { cutoff_time: '00:00' }); // now is after 00:00 -> closed
  const late = await call(staff, 'POST', '/api/orders', { items: [{ menu_item_id: m.data.id, qty: 1 }] });
  ok(late.status === 403, 'order rejected after cutoff (403)');
  const mine = await call(staff, 'GET', '/api/orders/mine');
  ok(mine.data.state.isOpen === false, 'state reports ordering closed');

  console.log('Master switch closes ordering even before cutoff');
  await call(admin, 'PUT', '/api/settings', { cutoff_time: '23:59', ordering_open: false });
  const off = await call(staff, 'POST', '/api/orders', { items: [{ menu_item_id: m.data.id, qty: 1 }] });
  ok(off.status === 403, 'order rejected when master switch off');

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('ERROR', e); process.exit(1); });
