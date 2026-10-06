const express = require('express');
const crypto = require('crypto');
const { promisify } = require('util');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 10000;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || '';
const SESSION_SECRET = process.env.AUTH_SESSION_SECRET || '';
const PAYSTACK_FEE_RATE = 0.0195;
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const BREVO_API_KEY = process.env.BREVO_API_KEY || '';
const EMAIL_FROM = process.env.EMAIL_FROM || '';
const EMAIL_FROM_NAME = process.env.EMAIL_FROM_NAME || 'PureGlow Solutions';
const BUSINESS_EMAIL = process.env.BUSINESS_EMAIL || 'Pureglowsoltions25@gmail.com';
const BUSINESS_PHONE = '0597601733';
const scryptAsync = promisify(crypto.scrypt);

const PRODUCTS = {
  'viora-dish-450-yellow': { name: 'Viora Dishwashing Liquid Soap', variant: '450ml', colorLabel: 'Yellow', price: 13 },
  'viora-dish-450-green': { name: 'Viora Dishwashing Liquid Soap', variant: '450ml', colorLabel: 'Green', price: 13 },
  'viora-dish-450-orange': { name: 'Viora Dishwashing Liquid Soap', variant: '450ml', colorLabel: 'Orange', price: 13 },
  'viora-dish-5l': { name: 'Viora Dishwashing Liquid Soap', variant: '5 Litres', price: 65 },
  'viora-fabric-500-blue': { name: 'Viora Fabric Softener', variant: '500ml', colorLabel: 'Blue', price: 20 },
  'viora-fabric-500-pink': { name: 'Viora Fabric Softener', variant: '500ml', colorLabel: 'Pink', price: 20 },
  'viora-bleach-1l': { name: 'Viora Thick Perfumed Bleach', variant: '1 Litre', price: 20 },
  'viora-floor-5l': { name: 'Viora Floor Cleaner', variant: '5 Litres', price: 75 }
};

const db = (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } })
  : null;

app.use(express.json({ limit: '1mb', verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(express.static(__dirname));

function jsonError(res, status, message) { return res.status(status).json({ error: message }); }
function normalizeEmail(v) { return String(v || '').trim().toLowerCase(); }
function validEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function money(n) { return `GHS ${Number(n || 0).toFixed(2)}`; }
function paystackGross(net) { return net <= 0 ? 0 : Math.round(((net / (1 - PAYSTACK_FEE_RATE)) + 0.01) * 100) / 100; }

async function requireDb(res) {
  if (!db) { jsonError(res, 503, 'Customer accounts and order records need SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY to be configured in Render.'); return false; }
  return true;
}

async function initDb() {
  if (!db) { console.warn('Supabase is not configured. Accounts/order storage and order emails are disabled.'); return; }
  const { error } = await db.from('orders').select('reference', { head: true, count: 'exact' }).limit(1);
  if (error) console.error('Supabase check failed — have you run supabase/schema.sql in the SQL editor?', error.message);
  else console.log('Supabase connected; tables found.');
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = await scryptAsync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt}$${Buffer.from(derived).toString('hex')}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const expected = Buffer.from(parts[2], 'hex');
  const derived = Buffer.from(await scryptAsync(password, parts[1], expected.length, { N: 16384, r: 8, p: 1 }));
  return expected.length === derived.length && crypto.timingSafeEqual(expected, derived);
}

function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}
function createSession(user) {
  const payload = { uid: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + 30 * 86400 };
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${encoded}.${sign(encoded)}`;
}
function parseCookies(header) {
  return String(header || '').split(';').reduce((out, part) => {
    const i = part.indexOf('='); if (i < 0) return out;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); return out;
  }, {});
}
function readSession(req) {
  if (!SESSION_SECRET) return null;
  const token = parseCookies(req.headers.cookie).pureglow_session;
  if (!token) return null;
  const dot = token.lastIndexOf('.'); if (dot <= 0) return null;
  const encoded = token.slice(0, dot), signature = token.slice(dot + 1);
  const expected = sign(encoded);
  try {
    if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    return payload.exp > Math.floor(Date.now() / 1000) ? payload : null;
  } catch { return null; }
}
function setSession(res, token) {
  res.setHeader('Set-Cookie', `pureglow_session=${encodeURIComponent(token)}; Path=/; Max-Age=${30 * 86400}; HttpOnly; Secure; SameSite=Lax`);
}
function clearSession(res) {
  res.setHeader('Set-Cookie', 'pureglow_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
}
function publicUser(u) { return { id: u.id, name: u.name, email: u.email, phone: u.phone }; }

app.get('/health', (_req, res) => res.json({ ok: true, service: 'PureGlow Solutions', database: Boolean(db), paystack: Boolean(PAYSTACK_SECRET_KEY), email: Boolean(BREVO_API_KEY && EMAIL_FROM) }));

app.get('/api/auth', async (req, res) => {
  if (!(await requireDb(res))) return;
  if (req.query.action !== 'me') return jsonError(res, 405, 'Method not allowed.');
  const session = readSession(req);
  if (!session) return res.status(401).json({ authenticated: false });
  const { data, error } = await db.from('customers').select('id,name,email,phone').eq('id', session.uid).maybeSingle();
  if (error || !data) return res.status(401).json({ authenticated: false });
  return res.json({ authenticated: true, user: publicUser(data) });
});

app.post('/api/auth', async (req, res) => {
  if (!(await requireDb(res))) return;
  if (!SESSION_SECRET) return jsonError(res, 503, 'AUTH_SESSION_SECRET is not configured in Render.');
  const action = req.query.action;
  const body = req.body || {};

  if (action === 'logout') { clearSession(res); return res.json({ ok: true }); }

  if (action === 'signup') {
    const name = String(body.name || '').trim();
    const email = normalizeEmail(body.email);
    const phone = String(body.phone || '').trim();
    const password = String(body.password || '');
    if (name.length < 2) return jsonError(res, 400, 'Please enter your full name.');
    if (!validEmail(email)) return jsonError(res, 400, 'Please enter a valid email address.');
    if (phone.length < 7) return jsonError(res, 400, 'Please enter a valid phone number.');
    if (password.length < 8) return jsonError(res, 400, 'Password must be at least 8 characters.');
    const exists = await db.from('customers').select('id').eq('email', email).maybeSingle();
    if (exists.data) return jsonError(res, 409, 'An account with that email already exists. Please log in.');
    const id = 'CUS-' + crypto.randomBytes(8).toString('hex').toUpperCase();
    const password_hash = await hashPassword(password);
    const ins = await db.from('customers').insert({ id, name, email, phone, password_hash }).select('id,name,email,phone').single();
    if (ins.error) { console.error(ins.error); return jsonError(res, 500, 'Could not create your account. Please try again.'); }
    setSession(res, createSession(ins.data));
    return res.status(201).json({ ok: true, user: publicUser(ins.data) });
  }

  if (action === 'login') {
    const email = normalizeEmail(body.email), password = String(body.password || '');
    if (!validEmail(email) || !password) return jsonError(res, 400, 'Enter your email and password.');
    const { data } = await db.from('customers').select('id,name,email,phone,password_hash').eq('email', email).maybeSingle();
    if (!data || !(await verifyPassword(password, data.password_hash))) return jsonError(res, 401, 'Incorrect email or password.');
    setSession(res, createSession(data));
    return res.json({ ok: true, user: publicUser(data) });
  }
  return jsonError(res, 405, 'Method not allowed.');
});

app.post('/api/payments/initialize', async (req, res) => {
  if (!PAYSTACK_SECRET_KEY) return jsonError(res, 503, 'Paystack is not configured. Add PAYSTACK_SECRET_KEY to Render environment variables.');
  const { name, email, phone, items, delivery } = req.body || {};
  if (!String(name || '').trim()) return jsonError(res, 400, 'Full name is required.');
  if (!validEmail(normalizeEmail(email))) return jsonError(res, 400, 'A valid email is required.');
  if (!String(phone || '').trim()) return jsonError(res, 400, 'WhatsApp/phone number is required.');
  if (!Array.isArray(items) || !items.length) return jsonError(res, 400, 'Your cart is empty.');
  const method = delivery?.method === 'cape-coast-delivery' ? 'Cape Coast delivery' : 'Collection — PureGlow Solutions, Kakumdo, Cape Coast';
  if (method === 'Cape Coast delivery' && (!String(delivery?.area || '').trim() || !String(delivery?.address || '').trim())) return jsonError(res, 400, 'Please provide your delivery area and address.');

  let subtotal = 0;
  const lineItems = [];
  for (const raw of items) {
    const product = PRODUCTS[raw?.id];
    const qty = Math.max(1, Math.min(999, parseInt(raw?.quantity, 10) || 0));
    if (!product || !qty) return jsonError(res, 400, `Product ${raw?.id || ''} is not available.`);
    const lineTotal = Math.round(product.price * qty * 100) / 100;
    subtotal += lineTotal;
    lineItems.push({ id: raw.id, name: product.name, variant: product.variant, colorLabel: product.colorLabel || '', qty, unitPrice: product.price, lineTotal });
  }
  subtotal = Math.round(subtotal * 100) / 100;
  const total = paystackGross(subtotal);
  const fee = Math.round((total - subtotal) * 100) / 100;
  const reference = 'PGS-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase();
  const session = readSession(req);
  const metadata = {
    customer_name: String(name).trim(), customer_phone: String(phone).trim(), fulfilment_method: method,
    delivery_area: String(delivery?.area || '').trim(), delivery_address: String(delivery?.address || '').trim(), delivery_landmark: String(delivery?.landmark || '').trim(),
    delivery_map_link: String(delivery?.mapLink || '').trim(),
    items: lineItems, subtotal, fee, total, customer_id: session?.uid || ''
  };

  try {
    const ps = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST', headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: normalizeEmail(email), amount: Math.round(total * 100), currency: 'GHS', reference, metadata, channels: ['card','mobile_money','bank','ussd','qr','bank_transfer'] })
    });
    const data = await ps.json();
    if (!ps.ok || !data.status) return jsonError(res, 502, data.message || 'Paystack could not start this payment.');
    return res.json({ access_code: data.data.access_code, reference: data.data.reference, authorization_url: data.data.authorization_url });
  } catch (err) {
    console.error(err); return jsonError(res, 502, 'Could not reach Paystack right now. Please try again.');
  }
});

// ---------- Order emails ----------
function esc(v) { return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

function itemLabel(i) { return `${i.name} ${i.variant || ''}${i.colorLabel ? ' (' + i.colorLabel + ')' : ''}`.trim(); }

function buildEmail(order, audience) {
  const items = Array.isArray(order.items) ? order.items : [];
  const delivery = /delivery/i.test(order.fulfilment_method);
  const rows = items.map(i => `<tr><td style="padding:8px 0;border-bottom:1px solid #e6eef0">${esc(itemLabel(i))}</td><td style="padding:8px 0;border-bottom:1px solid #e6eef0;text-align:center">${esc(i.qty)}</td><td style="padding:8px 0;border-bottom:1px solid #e6eef0;text-align:right">${money(i.lineTotal)}</td></tr>`).join('');
  const where = delivery
    ? `<p style="margin:0 0 4px"><b>Delivery in Cape Coast</b></p><p style="margin:0">${esc(order.delivery_area)}<br>${esc(order.delivery_address)}${order.delivery_landmark ? '<br>Landmark: ' + esc(order.delivery_landmark) : ''}${order.delivery_map_link ? `<br><a href="${esc(order.delivery_map_link)}">Open in Google Maps</a>` : ''}</p>`
    : `<p style="margin:0 0 4px"><b>Pickup</b></p><p style="margin:0">PureGlow Solutions, Kakumdo, Cape Coast</p>`;
  const heading = audience === 'customer' ? 'Thank you for your order!' : 'New paid order received';
  const intro = audience === 'customer'
    ? `Hi ${esc(order.customer_name)}, your payment was received and your order is confirmed. Here are the details:`
    : `<b>${esc(order.customer_name)}</b> has paid for an order. Phone: <b>${esc(order.customer_phone)}</b> · Email: ${esc(order.customer_email)}`;
  const footer = audience === 'customer'
    ? `<p style="color:#5b6b70;font-size:13px">Questions? Call or WhatsApp ${BUSINESS_PHONE}, or reply to this email.</p>`
    : '';
  const html = `<div style="font-family:Arial,Helvetica,sans-serif;background:#f3fafb;padding:24px"><div style="max-width:560px;margin:auto;background:#fff;border-radius:14px;overflow:hidden;border:1px solid #d7e9ec"><div style="background:#0aa6b7;color:#fff;padding:20px 24px"><div style="font-size:13px;letter-spacing:1px;opacity:.9">PUREGLOW SOLUTIONS</div><div style="font-size:22px;font-weight:bold;margin-top:4px">${heading}</div></div><div style="padding:24px;color:#173238;font-size:15px;line-height:1.5"><p style="margin-top:0">${intro}</p><p style="margin:0 0 12px;color:#5b6b70">Order reference: <b style="color:#173238">${esc(order.reference)}</b></p><table style="width:100%;border-collapse:collapse;font-size:14px"><thead><tr style="text-align:left;color:#5b6b70"><th style="padding-bottom:6px">Item</th><th style="padding-bottom:6px;text-align:center">Qty</th><th style="padding-bottom:6px;text-align:right">Amount</th></tr></thead><tbody>${rows}</tbody></table><table style="width:100%;margin-top:12px;font-size:14px"><tr><td>Subtotal</td><td style="text-align:right">${money(order.subtotal)}</td></tr><tr><td>Payment processing fee</td><td style="text-align:right">${money(order.fee)}</td></tr><tr><td style="padding-top:6px"><b>Total paid</b></td><td style="padding-top:6px;text-align:right;color:#f57c00;font-size:17px"><b>${money(order.total)}</b></td></tr></table><div style="background:#f3fafb;border-radius:10px;padding:14px;margin-top:18px">${where}</div>${footer}</div></div></div>`;
  const text = [heading, `Ref: ${order.reference}`, '', ...items.map(i => `- ${itemLabel(i)} x${i.qty} — ${money(i.lineTotal)}`), '', `Subtotal: ${money(order.subtotal)}`, `Fee: ${money(order.fee)}`, `Total paid: ${money(order.total)}`, '', delivery ? `Delivery: ${order.delivery_area}, ${order.delivery_address}` : 'Pickup: PureGlow Solutions, Kakumdo, Cape Coast', ...(audience === 'business' ? [`Customer: ${order.customer_name} / ${order.customer_phone} / ${order.customer_email}`] : [])].join('\n');
  return { html, text, subject: audience === 'customer' ? `Your PureGlow order ${order.reference} is confirmed` : `New paid order ${order.reference} — ${money(order.total)}` };
}

async function sendMail({ to, toName, subject, html, text, replyTo }) {
  if (!BREVO_API_KEY || !EMAIL_FROM) throw new Error('Email is not configured (BREVO_API_KEY / EMAIL_FROM).');
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': BREVO_API_KEY, 'Content-Type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ sender: { name: EMAIL_FROM_NAME, email: EMAIL_FROM }, to: [{ email: to, name: toName || undefined }], subject, htmlContent: html, textContent: text, ...(replyTo ? { replyTo: { email: replyTo } } : {}) })
  });
  if (!r.ok) throw new Error(`Brevo ${r.status}: ${(await r.text()).slice(0, 300)}`);
}

// Sends the customer confirmation (+ a copy to the business) exactly once per order.
async function sendOrderEmails(reference, { force = false } = {}) {
  if (!db) return 'unavailable';
  const { data: current } = await db.from('orders').select('email_status,email_sent_at').eq('reference', reference).maybeSingle();
  if (!current) return 'unavailable';
  if (current.email_status === 'sent' && !force) return 'sent';
  if (force && current.email_sent_at && Date.now() - new Date(current.email_sent_at).getTime() < 60000) return 'sent';
  // atomic claim so the browser poll and the webhook can never both send
  const allowed = force ? ['pending', 'failed', 'sent'] : ['pending', 'failed'];
  const claim = await db.from('orders').update({ email_status: 'sending' }).eq('reference', reference).in('email_status', allowed).select('*');
  if (claim.error || !claim.data?.length) return current.email_status;
  const order = claim.data[0];
  try {
    const c = buildEmail(order, 'customer');
    await sendMail({ to: order.customer_email, toName: order.customer_name, subject: c.subject, html: c.html, text: c.text, replyTo: BUSINESS_EMAIL });
    await db.from('orders').update({ email_status: 'sent', email_sent_at: new Date().toISOString(), email_error: null }).eq('reference', reference);
    if (!force) {
      try { const b = buildEmail(order, 'business'); await sendMail({ to: BUSINESS_EMAIL, subject: b.subject, html: b.html, text: b.text, replyTo: order.customer_email }); }
      catch (e) { console.error('Business copy failed:', e.message); }
    }
    return 'sent';
  } catch (e) {
    console.error('Order email failed:', e.message);
    await db.from('orders').update({ email_status: 'failed', email_error: String(e.message).slice(0, 500) }).eq('reference', reference);
    return 'failed';
  }
}

// Stores a verified paid transaction (idempotent) and triggers the emails.
async function recordPaidOrder(tx) {
  if (!db) return 'unavailable';
  const md = tx.metadata || {};
  const reference = tx.reference;
  const row = {
    reference, customer_id: md.customer_id || null, customer_name: md.customer_name || '', customer_email: tx.customer?.email || '',
    customer_phone: md.customer_phone || '', fulfilment_method: md.fulfilment_method || '', delivery_area: md.delivery_area || '',
    delivery_address: md.delivery_address || '', delivery_landmark: md.delivery_landmark || '', delivery_map_link: md.delivery_map_link || '',
    items: md.items || [], subtotal: Number(md.subtotal || 0), fee: Number(md.fee || 0), total: Number(tx.amount || 0) / 100,
    paid_at: tx.paid_at || new Date().toISOString()
  };
  const ins = await db.from('orders').upsert(row, { onConflict: 'reference', ignoreDuplicates: true });
  if (ins.error) { console.error('Order save failed:', ins.error.message); return 'unavailable'; }
  return sendOrderEmails(reference);
}

app.get('/api/payments/verify', async (req, res) => {
  if (!PAYSTACK_SECRET_KEY) return jsonError(res, 503, 'Paystack is not configured.');
  const reference = String(req.query.reference || '').trim();
  if (!reference) return jsonError(res, 400, 'Missing payment reference.');
  try {
    const ps = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } });
    const data = await ps.json();
    if (!ps.ok || !data.data) return res.json({ status: 'pending', reference });
    const tx = data.data;
    let emailStatus = null;
    if (tx.status === 'success') emailStatus = await recordPaidOrder(tx);
    return res.json({ status: tx.status, reference, amount: tx.amount, email: tx.customer?.email || '', emailStatus });
  } catch (err) {
    console.error(err); return res.json({ status: 'pending', reference });
  }
});

// Paystack webhook — set this URL in Paystack Dashboard > Settings > API Keys & Webhooks
app.post('/api/payments/webhook', async (req, res) => {
  const sig = req.headers['x-paystack-signature'];
  const expected = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY).update(req.rawBody || Buffer.from('')).digest('hex');
  if (!PAYSTACK_SECRET_KEY || !sig || sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return res.sendStatus(401);
  res.sendStatus(200);
  try { if (req.body?.event === 'charge.success' && req.body.data?.status === 'success') await recordPaidOrder(req.body.data); }
  catch (e) { console.error('Webhook error:', e); }
});

app.post('/api/orders/resend-email', async (req, res) => {
  if (!(await requireDb(res))) return;
  const reference = String(req.body?.reference || '').trim();
  if (!reference) return jsonError(res, 400, 'Missing reference.');
  const status = await sendOrderEmails(reference, { force: true });
  return res.json({ ok: status === 'sent', emailStatus: status });
});

app.get('*', (_req, res) => res.sendFile(require('path').join(__dirname, 'index.html')));

initDb().catch(err => console.error('Supabase init error:', err)).finally(() => app.listen(PORT, () => console.log(`PureGlow running on port ${PORT}`)));
