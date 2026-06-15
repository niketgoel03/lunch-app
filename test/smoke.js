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
  const code = r1.data && r1.data.devCode;
  if (!code) throw new Error('no devCode for ' + email + ': ' + JSON.stringify(r1.data) + ' (status ' + r1.status + ')');
  const r2 = await call(j, 'POST', '/api/auth/verify-otp', { email, code });
  if (r2.status !== 200) throw new Error('login failed for ' + email + ': ' + JSON.stringify(r2.data));
  return j;
}
const boyKey = () => null; // marker; key passed via header
const H = (key, pin) => pin ? { 'x-boy-key': key, 'x-boy-pin': pin } : { 'x-boy-key': key };
const findP = (d, email) => d.perPerson.find(p => p.email === email);

(async () => {
  console.log('Admin bootstrap');
  const admin = await loginAs('admin@office.local');
  ok((await call(admin, 'GET', '/api/me')).data.user.role === 'admin', 'admin session established');
  await call(admin, 'PUT', '/api/settings', { cutoff_time: '23:59', aggregate_time: '23:59', ordering_open: true, allowed_domains: 'ayasya.com' });
  const m = await call(admin, 'POST', '/api/menu', { name: 'Test Biryani', price: 120 });
  ok(m.status === 200, 'admin added menu item');
  await call(admin, 'POST', '/api/users', { name: 'Rahul', email: 'rahul@ayasya.com', role: 'office_boy' });
  await call(admin, 'POST', '/api/users', { name: 'Staff One', email: 'staff1@office.local', role: 'staff' });
  await call(admin, 'POST', '/api/users', { name: 'Staff Two', email: 'staff2@office.local', role: 'staff' });
  const key = (await call(admin, 'GET', '/api/settings')).data.boy_access_key;
  ok(!!key && key.length >= 32, 'admin can read office-boy access key');

  console.log('Whitelist + first-time onboarding');
  ok(!(await call(jar(), 'POST', '/api/auth/request-otp', { email: 'stranger@gmail.com' })).data.devCode, 'off-domain unknown email gets no code');
  const nb = jar();
  const nbReq = await call(nb, 'POST', '/api/auth/request-otp', { email: 'newbie@ayasya.com' });
  ok(nbReq.data.devCode && nbReq.data.newUser === true, 'whitelisted new email gets code + newUser flag');
  const nbVer = await call(nb, 'POST', '/api/auth/verify-otp', { email: 'newbie@ayasya.com', code: nbReq.data.devCode });
  ok(nbVer.status === 200 && nbVer.data.user.role === 'staff', 'first-time user auto-created as staff after OTP');
  ok((await call(admin, 'GET', '/api/users')).data.some(u => u.email === 'newbie@ayasya.com'), 'auto-created user in People list');
  ok((await call(jar(), 'POST', '/api/auth/verify-otp', { email: 'stranger@gmail.com', code: '000000' })).status === 400, 'off-domain stranger cannot verify');

  console.log('Orders + office-boy no-login link');
  const staff1 = await loginAs('staff1@office.local');
  const o1 = await call(staff1, 'POST', '/api/orders', { items: [{ menu_item_id: m.data.id, qty: 2 }], note: 'no onion' });
  ok(o1.status === 200 && o1.data.order.payment.amount === 240, 'staff1 order placed = 240');
  ok((await call(null, 'GET', '/api/boy/aggregate', null, H('wrong'))).status === 401, 'wrong key rejected');
  const agg1 = await call(null, 'GET', '/api/boy/aggregate', null, H(key));
  ok(agg1.status === 200 && agg1.data.grandTotal === 240, 'valid key sees aggregate (total 240)');

  console.log('Office boy cancels an UNPAID order (stays listed)');
  const oid1 = findP(agg1.data, 'staff1@office.local').id;
  await call(null, 'POST', '/api/boy/orders/' + oid1 + '/cancel', {}, H(key));
  const agg2 = await call(null, 'GET', '/api/boy/aggregate', null, H(key));
  const c1 = agg2.data.perPerson.find(p => p.id === oid1);
  ok(c1 && c1.cancelled === true, 'cancelled order stays listed with cancelled=true');
  ok(agg2.data.activeCount === 0, 'cancelled order excluded from active count/total');

  console.log('Paid = final state');
  const staff2 = await loginAs('staff2@office.local');
  await call(staff2, 'POST', '/api/orders', { items: [{ menu_item_id: m.data.id, qty: 1 }] });
  const oid2 = findP((await call(null, 'GET', '/api/boy/aggregate', null, H(key))).data, 'staff2@office.local').id;
  await call(null, 'POST', '/api/boy/payments/' + oid2 + '/paid', { paid: true }, H(key));
  ok((await call(null, 'POST', '/api/boy/orders/' + oid2 + '/cancel', {}, H(key))).status === 403, 'office boy cannot cancel a PAID order');
  const rahul = await loginAs('rahul@ayasya.com');
  ok((await call(rahul, 'POST', '/api/payments/' + oid2 + '/paid', { paid: false })).status === 403, 'office_boy role cannot reverse a paid order');
  ok((await call(admin, 'POST', '/api/payments/' + oid2 + '/paid', { paid: false })).status === 200, 'admin CAN reverse a paid order');

  console.log('PIN gate + key rotation');
  await call(admin, 'PUT', '/api/admin/boy-pin', { pin: '4321' });
  const noPin = await call(null, 'GET', '/api/boy/aggregate', null, H(key));
  ok(noPin.status === 401 && noPin.data.pinRequired === true, 'key without PIN rejected when PIN set');
  ok((await call(null, 'GET', '/api/boy/aggregate', null, H(key, '4321'))).status === 200, 'key + correct PIN accepted');
  await call(admin, 'PUT', '/api/admin/boy-pin', { pin: '' });
  const rot = await call(admin, 'POST', '/api/admin/boy-key');
  ok(rot.data.boy_access_key && rot.data.boy_access_key !== key, 'admin rotated key');
  ok((await call(null, 'GET', '/api/boy/aggregate', null, H(key))).status === 401, 'old key no longer works');
  const key2 = rot.data.boy_access_key;

  console.log('Task assignment module');
  const cat = await call(admin, 'POST', '/api/admin/task-categories', { name: 'Bank Work X' });
  ok(cat.status === 200, 'admin created a task category');
  const users = (await call(admin, 'GET', '/api/users')).data;
  const rahulU = users.find(u => u.email === 'rahul@ayasya.com');
  const staff2U = users.find(u => u.email === 'staff2@office.local');
  const tk1 = await call(admin, 'POST', '/api/admin/tasks', { title: 'Deposit cheque', category_id: cat.data.id, assignee_id: rahulU.id, details: 'HDFC branch' });
  const tk2 = await call(admin, 'POST', '/api/admin/tasks', { title: 'Buy markers', assignee_id: staff2U.id });
  ok(tk1.status === 200 && tk2.status === 200, 'admin created & assigned two tasks');
  const mine = await call(staff2, 'GET', '/api/tasks/mine');
  ok(mine.data.length === 1 && mine.data[0].title === 'Buy markers', 'employee sees only their task');
  ok((await call(staff2, 'POST', '/api/tasks/' + mine.data[0].id + '/status', { status: 'in_progress', remarks: 'on it' })).status === 200, 'employee updates own task');
  ok((await call(staff2, 'POST', '/api/tasks/' + tk1.data.id + '/status', { status: 'completed' })).status === 403, 'employee cannot update another user task');
  const bt = await call(null, 'GET', '/api/boy/tasks', null, H(key2));
  ok(bt.data.some(t => t.id === tk1.data.id), 'office boy sees their task via no-login link');
  await call(null, 'POST', '/api/boy/tasks/' + tk1.data.id + '/status', { status: 'completed', remarks: 'done' }, H(key2));
  ok((await call(null, 'GET', '/api/boy/tasks', null, H(key2))).data.find(t => t.id === tk1.data.id).status === 'completed', 'office boy completed task via link');
  await call(admin, 'PUT', '/api/admin/task-categories/' + cat.data.id + '/visibility', { user_ids: [staff2U.id] });
  ok((await call(staff2, 'GET', '/api/task-categories/mine')).data.some(c => c.id === cat.data.id), 'category visibility grants employee access');

  console.log('Cutoff still enforced');
  await call(admin, 'PUT', '/api/settings', { cutoff_time: '00:00' });
  ok((await call(staff1, 'POST', '/api/orders', { items: [{ menu_item_id: m.data.id, qty: 1 }] })).status === 403, 'order rejected after cutoff (403)');

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('ERROR', e); process.exit(1); });
