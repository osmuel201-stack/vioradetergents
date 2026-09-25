const express = require('express');
const crypto = require('crypto');
const { promisify } = require('util');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 10000;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || '';
const SESSION_SECRET = process.env.AUTH_SESSION_SECRET || '';
const PAYSTACK_FEE_RATE = 0.0195;
const WHATSAPP_NUMBER = process.env.PUREGLOW_WHATSAPP || '233597601733';
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

const pool = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false }
}) : null;

app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));

function jsonError(res, status, message) { return res.status(status).json({ error: message }); }
function normalizeEmail(v) { return String(v || '').trim().toLowerCase(); }
function validEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function money(n) { return `GHS ${Number(n || 0).toFixed(2)}`; }
function paystackGross(net) { return net <= 0 ? 0 : Math.round(((net / (1 - PAYSTACK_FEE_RATE)) + 0.01) * 100) / 100; }

async function requireDb(res) {
  if (!pool) { jsonError(res, 503, 'Customer accounts and order records need DATABASE_URL to be configured in Render.'); return false; }
  return true;
}

async function initDb() {
  if (!pool) {
    console.warn('DATABASE_URL is not configured. Authentication/order storage is disabled until a PostgreSQL database is connected.');
    return;
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS orders (
      reference TEXT PRIMARY KEY,
      customer_id TEXT REFERENCES customers(id) ON DELETE SET NULL,
      customer_name TEXT NOT NULL,
      customer_email TEXT NOT NULL,
      customer_phone TEXT NOT NULL,
      fulfilment_method TEXT NOT NULL,
      delivery_area TEXT,
      delivery_address TEXT,
      delivery_landmark TEXT,
      delivery_map_link TEXT,
      items JSONB NOT NULL,
      subtotal NUMERIC(12,2) NOT NULL,
      fee NUMERIC(12,2) NOT NULL,
      total NUMERIC(12,2) NOT NULL,
      paid_at TIMESTAMPTZ,
      whatsapp_sent BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  console.log('PureGlow PostgreSQL tables are ready.');
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

app.get('/health', (_req, res) => res.json({ ok: true, service: 'PureGlow Solutions', database: Boolean(pool), paystack: Boolean(PAYSTACK_SECRET_KEY) }));

app.get('/api/auth', async (req, res) => {
  if (!(await requireDb(res))) return;
  const action = req.query.action;
  if (action !== 'me') return jsonError(res, 405, 'Method not allowed.');
  const session = readSession(req);
  if (!session) return res.status(401).json({ authenticated: false });
  const result = await pool.query('SELECT id,name,email,phone FROM customers WHERE id=$1', [session.uid]);
  if (!result.rowCount) return res.status(401).json({ authenticated: false });
  return res.json({ authenticated: true, user: publicUser(result.rows[0]) });
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
    if (phone.length < 7) return jsonError(res, 400, 'Please enter a valid WhatsApp/phone number.');
    if (password.length < 8) return jsonError(res, 400, 'Password must be at least 8 characters.');
    const exists = await pool.query('SELECT id FROM customers WHERE email=$1', [email]);
    if (exists.rowCount) return jsonError(res, 409, 'An account with that email already exists. Please log in.');
    const id = 'CUS-' + crypto.randomBytes(8).toString('hex').toUpperCase();
    const passwordHash = await hashPassword(password);
    const result = await pool.query('INSERT INTO customers (id,name,email,phone,password_hash) VALUES ($1,$2,$3,$4,$5) RETURNING id,name,email,phone', [id,name,email,phone,passwordHash]);
    setSession(res, createSession(result.rows[0]));
    return res.status(201).json({ ok: true, user: publicUser(result.rows[0]) });
  }

  if (action === 'login') {
    const email = normalizeEmail(body.email), password = String(body.password || '');
    if (!validEmail(email) || !password) return jsonError(res, 400, 'Enter your email and password.');
    const result = await pool.query('SELECT id,name,email,phone,password_hash FROM customers WHERE email=$1', [email]);
    if (!result.rowCount || !(await verifyPassword(password, result.rows[0].password_hash))) return jsonError(res, 401, 'Incorrect email or password.');
    setSession(res, createSession(result.rows[0]));
    return res.json({ ok: true, user: publicUser(result.rows[0]) });
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

app.get('/api/payments/verify', async (req, res) => {
  if (!PAYSTACK_SECRET_KEY) return jsonError(res, 503, 'Paystack is not configured.');
  const reference = String(req.query.reference || '').trim();
  if (!reference) return jsonError(res, 400, 'Missing payment reference.');
  try {
    const ps = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } });
    const data = await ps.json();
    if (!ps.ok || !data.data) return res.json({ status: 'pending', reference });
    const tx = data.data;
    if (tx.status === 'success' && pool) {
      const md = tx.metadata || {};
      const existing = await pool.query('SELECT reference FROM orders WHERE reference=$1', [reference]);
      if (!existing.rowCount) {
        await pool.query(`INSERT INTO orders (reference,customer_id,customer_name,customer_email,customer_phone,fulfilment_method,delivery_area,delivery_address,delivery_landmark,delivery_map_link,items,subtotal,fee,total,paid_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, [
          reference, md.customer_id || null, md.customer_name || '', tx.customer?.email || '', md.customer_phone || '', md.fulfilment_method || '', md.delivery_area || '', md.delivery_address || '', md.delivery_landmark || '', md.delivery_map_link || '', JSON.stringify(md.items || []), Number(md.subtotal || 0), Number(md.fee || 0), Number(tx.amount || 0) / 100, tx.paid_at || new Date().toISOString()
        ]);
      }
    }
    return res.json({ status: tx.status, reference, amount: tx.amount });
  } catch (err) {
    console.error(err); return res.json({ status: 'pending', reference });
  }
});

app.post('/api/orders/whatsapp-sent', async (req, res) => {
  if (!(await requireDb(res))) return;
  const reference = String(req.body?.reference || '').trim();
  if (!reference) return jsonError(res, 400, 'Missing reference.');
  await pool.query('UPDATE orders SET whatsapp_sent=TRUE WHERE reference=$1', [reference]);
  return res.json({ ok: true });
});

app.get('*', (_req, res) => res.sendFile(require('path').join(__dirname, 'index.html')));

initDb().then(() => app.listen(PORT, () => console.log(`PureGlow running on port ${PORT}`))).catch(err => {
  console.error('Database initialization failed:', err);
  app.listen(PORT, () => console.log(`PureGlow running on port ${PORT}; database unavailable.`));
});
