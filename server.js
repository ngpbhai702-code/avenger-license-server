require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET;
const BOOTSTRAP_SECRET = process.env.BOOTSTRAP_SECRET;
const LICENSE_DAYS = Math.max(1, Math.min(3650, Number(process.env.LICENSE_DAYS || 30)));
const DEVICE_LIMIT = Math.max(1, Number(process.env.DEVICE_LIMIT || 1));
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });

const ROLE_PARENT = { master: null, super_seller: 'master', admin: 'super_seller', seller: 'admin' };
const ROLE_LABEL = { master: 'Master Admin', super_seller: 'Super Seller', admin: 'Admin', seller: 'Seller' };
const hash = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');// Generate an 8-letter license key using A-Z only
const makeKey = () => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let key = '';

  while (key.length < 8) {
    for (const byte of crypto.randomBytes(16)) {
      if (byte < 234) key += alphabet[byte % 26];
      if (key.length === 8) break;
    }
  }

  return key;
};
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

async function initDb() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters');
  if (!BOOTSTRAP_SECRET || BOOTSTRAP_SECRET.length < 24) throw new Error('BOOTSTRAP_SECRET must be at least 24 characters');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(60) NOT NULL UNIQUE,
      display_name VARCHAR(120) NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL CHECK (role IN ('master','super_seller','admin','seller')),
      parent_id BIGINT REFERENCES users(id),
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      token_balance INTEGER NOT NULL DEFAULT 0 CHECK (token_balance >= 0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS users_parent_idx ON users(parent_id);
    CREATE TABLE IF NOT EXISTS licenses (
      id BIGSERIAL PRIMARY KEY,
      key_hash CHAR(64) NOT NULL UNIQUE,
      key_preview VARCHAR(24) NOT NULL,
      created_by BIGINT NOT NULL REFERENCES users(id),
      owner_id BIGINT NOT NULL REFERENCES users(id),
      customer_name VARCHAR(120),
      status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
      device_id_hash CHAR(64),
      activated_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS licenses_owner_idx ON licenses(owner_id);
    CREATE INDEX IF NOT EXISTS licenses_expiry_idx ON licenses(expires_at);
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      actor_id BIGINT REFERENCES users(id),
      action VARCHAR(80) NOT NULL,
      target_type VARCHAR(40),
      target_id VARCHAR(80),
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  // Safe migration for databases created by earlier starter versions.
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS token_balance INTEGER NOT NULL DEFAULT 0 CHECK (token_balance >= 0)');
// License status migration: support temporary deactivation.
await pool.query(`
  ALTER TABLE licenses
  DROP CONSTRAINT IF EXISTS licenses_status_check;

  ALTER TABLE licenses
  ADD CONSTRAINT licenses_status_check
  CHECK (status IN ('active', 'revoked', 'deactivated', 'deleted'));
`);
}

function signUser(user) {
  return jwt.sign({ sub: String(user.id), role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '8h', issuer: 'avenger-license' });
}
const auth = asyncRoute(async (req, res, next) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'login_required' });
  let claims;
  try { claims = jwt.verify(token, JWT_SECRET, { issuer: 'avenger-license' }); }
  catch { return res.status(401).json({ error: 'invalid_or_expired_session' }); }
  const { rows } = await pool.query('SELECT id, username, display_name, role, parent_id, is_active, token_balance FROM users WHERE id=$1', [claims.sub]);
  if (!rows[0] || !rows[0].is_active) return res.status(401).json({ error: 'account_inactive' });
  req.user = rows[0];
  next();
});
function requireRole(...roles) { return (req, res, next) => roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'permission_denied' }); }
async function isInScope(actor, ownerId) {
  if (actor.role === 'master') return true;
  let cursor = String(ownerId);
  for (let i = 0; i < 8 && cursor; i++) {
    if (cursor === String(actor.id)) return true;
    const r = await pool.query('SELECT parent_id FROM users WHERE id=$1', [cursor]);
    cursor = r.rows[0]?.parent_id ? String(r.rows[0].parent_id) : '';
  }
  return false;
}
async function audit(actorId, action, targetType, targetId, details = {}) {
  await pool.query('INSERT INTO audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5)', [actorId || null, action, targetType || null, targetId == null ? null : String(targetId), JSON.stringify(details)]);
}
function publicUser(u) { return { id: String(u.id), username: u.username, displayName: u.display_name, role: u.role, roleLabel: ROLE_LABEL[u.role], parentId: u.parent_id == null ? null : String(u.parent_id), active: u.is_active, tokenBalance: Number(u.token_balance || 0), createdAt: u.created_at }; }

function licenseStatus(l) {
  if (l.status === 'revoked') return 'Revoked';
  if (l.status === 'deleted') return 'Deleted';
  if (l.status === 'deactivated') return 'Deactivated';

  const expired = new Date(l.expires_at) <= new Date();
  if (expired) return 'Expired';

  return l.device_id_hash ? 'Active' : 'Unused';
}


app.get('/health', (_req, res) => res.json({ ok: true, service: 'AVENGER License Server', time: new Date().toISOString() }));
app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'AVENGER License Server' }));

// One-time first Master bootstrap. Do not expose this secret to normal panel users.
app.post('/api/bootstrap-master', rateLimit({ windowMs: 15 * 60 * 1000, limit: 5 }), asyncRoute(async (req, res) => {
  if (!crypto.timingSafeEqual(Buffer.from(String(req.get('x-bootstrap-secret') || '').padEnd(64, '\0').slice(0,64)), Buffer.from(String(BOOTSTRAP_SECRET).padEnd(64, '\0').slice(0,64)))) return res.status(403).json({ error: 'bootstrap_forbidden' });
  const count = await pool.query('SELECT COUNT(*)::int AS n FROM users');
  if (count.rows[0].n > 0) return res.status(409).json({ error: 'master_already_initialized' });
  const username = String(req.body.username || '').trim().toLowerCase();
  const displayName = String(req.body.displayName || 'Master Admin').trim();
  const password = String(req.body.password || '');
  if (!/^[a-z0-9._-]{4,60}$/.test(username) || password.length < 12) return res.status(400).json({ error: 'username_format_or_password_too_short' });
  const ph = await bcrypt.hash(password, 12);
  const { rows } = await pool.query('INSERT INTO users(username,display_name,password_hash,role) VALUES($1,$2,$3,\'master\') RETURNING *', [username, displayName, ph]);
  await audit(rows[0].id, 'master_bootstrap', 'user', rows[0].id, {});
  res.status(201).json({ ok: true, user: publicUser(rows[0]), token: signUser(rows[0]), message: 'Master created. Remove BOOTSTRAP_SECRET from the service environment after setup.' });
}));

app.post('/api/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false }), asyncRoute(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
  const user = rows[0];
  if (!user || !user.is_active || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'invalid_login' });
  await audit(user.id, 'login', 'user', user.id, {});
  res.json({ ok: true, token: signUser(user), user: publicUser(user) });
}));
app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));
app.post('/api/logout', auth, asyncRoute(async (req, res) => { await audit(req.user.id, 'logout', 'user', req.user.id); res.json({ ok: true }); }));

app.get('/api/dashboard', auth, asyncRoute(async (req, res) => {
  const scope = req.user.role === 'master' ? null : String(req.user.id);
  const userCountSql = scope ? `WITH RECURSIVE team AS (SELECT id FROM users WHERE parent_id=$1 UNION ALL SELECT u.id FROM users u JOIN team t ON u.parent_id=t.id) SELECT role, COUNT(*)::int n FROM users WHERE id IN (SELECT id FROM team) GROUP BY role` : `SELECT role, COUNT(*)::int n FROM users GROUP BY role`;
  const licenseSql = scope ? `WITH RECURSIVE team AS (SELECT id FROM users WHERE id=$1 UNION ALL SELECT u.id FROM users u JOIN team t ON u.parent_id=t.id) SELECT COUNT(*)::int total, COUNT(*) FILTER (WHERE status='active' AND expires_at>NOW())::int valid, COUNT(*) FILTER (WHERE status='revoked')::int revoked, COUNT(*) FILTER (WHERE expires_at<=NOW() AND status='active')::int expired FROM licenses WHERE owner_id IN (SELECT id FROM team)` : `SELECT COUNT(*)::int total, COUNT(*) FILTER (WHERE status='active' AND expires_at>NOW())::int valid, COUNT(*) FILTER (WHERE status='revoked')::int revoked, COUNT(*) FILTER (WHERE expires_at<=NOW() AND status='active')::int expired FROM licenses`;
  const [users, licenses] = await Promise.all([pool.query(userCountSql, scope ? [scope] : []), pool.query(licenseSql, scope ? [scope] : [])]);
  const counts = { master: 0, super_seller: 0, admin: 0, seller: 0 };
  if (req.user.role === 'master') counts.master = 1;
  users.rows.forEach(r => counts[r.role] = Number(r.n));
  res.json({ users: counts, licenses: licenses.rows[0] });
}));

app.get('/api/users', auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`WITH RECURSIVE team AS (SELECT id FROM users WHERE parent_id=$1 UNION ALL SELECT u.id FROM users u JOIN team t ON u.parent_id=t.id) SELECT u.* FROM users u WHERE ($2::boolean OR u.id IN (SELECT id FROM team)) ORDER BY u.created_at DESC LIMIT 500`, [req.user.id, req.user.role === 'master']);
  res.json({ users: rows.map(publicUser) });
}));
app.post('/api/users', auth, asyncRoute(async (req, res) => {
  const childRole = String(req.body.role || '');
  const allowedChild = { master: ['super_seller'], super_seller: ['admin'], admin: ['seller'], seller: [] };
  if (!(allowedChild[req.user.role] || []).includes(childRole)) return res.status(403).json({ error: 'cannot_create_this_role' });
  const username = String(req.body.username || '').trim().toLowerCase();
  const displayName = String(req.body.displayName || '').trim();
  const password = String(req.body.password || '');
  if (!/^[a-z0-9._-]{4,60}$/.test(username)) return res.status(400).json({ error: 'username_must_be_4_to_60_valid_characters' });
  if (displayName.length < 2 || displayName.length > 120) return res.status(400).json({ error: 'display_name_invalid' });
  if (password.length < 12 || password.length > 200) return res.status(400).json({ error: 'password_must_be_at_least_12_characters' });
  const ph = await bcrypt.hash(password, 12);
  try {
    const { rows } = await pool.query('INSERT INTO users(username,display_name,password_hash,role,parent_id) VALUES($1,$2,$3,$4,$5) RETURNING *', [username, displayName, ph, childRole, req.user.id]);
    await audit(req.user.id, 'user_created', 'user', rows[0].id, { role: childRole });
    res.status(201).json({ ok: true, user: publicUser(rows[0]) });
  } catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'username_already_exists' }); throw e; }
}));

app.post('/api/users/:id/reset-password', auth, asyncRoute(async (req, res) => {
  if (req.user.role !== 'master') {
    return res.status(403).json({ error: 'master_only' });
  }

  const id = String(req.params.id);
  const password = String(req.body.password || '');

  if (password.length < 12 || password.length > 200) {
    return res.status(400).json({
      error: 'password_must_be_12_to_200_characters'
    });
  }

  const userQ = await pool.query(
    'SELECT id, username, role FROM users WHERE id=$1',
    [id]
  );

  const target = userQ.rows[0];

  if (!target || target.role === 'master') {
    return res.status(404).json({
      error: 'user_not_found_or_not_allowed'
    });
  }

  const passwordHash = await bcrypt.hash(password, 12);

  await pool.query(
    'UPDATE users SET password_hash=$1 WHERE id=$2',
    [passwordHash, id]
  );

  await audit(req.user.id, 'user_password_reset', 'user', id, {
    username: target.username,
    role: target.role
  });

  res.json({
    ok: true,
    message: 'Password reset successful',
    username: target.username
  });
}));

app.patch('/api/users/:id/status', auth, asyncRoute(async (req, res) => {
  const id = String(req.params.id);
  if (id === String(req.user.id)) return res.status(400).json({ error: 'cannot_change_own_status' });
  const active = req.body.active === true;
  const found = await pool.query('SELECT id,role,parent_id FROM users WHERE id=$1', [id]);
  if (!found.rows[0] || !(await isInScope(req.user, id)) || (req.user.role !== 'master' && found.rows[0].role === 'master')) return res.status(404).json({ error: 'user_not_found_in_your_team' });
  await pool.query('UPDATE users SET is_active=$1 WHERE id=$2', [active, id]);
  await audit(req.user.id, active ? 'user_enabled' : 'user_disabled', 'user', id);
  res.json({ ok: true });
}));

// Allocate tokens to a direct child only. Allocation cannot exceed the actor's balance,
// except Master Admin who is the token source. Each allocation is atomic.
app.post('/api/users/:id/tokens', auth, asyncRoute(async (req, res) => {
  const targetId = String(req.params.id);
  const amount = Number(req.body.amount);
  if (!Number.isSafeInteger(amount) || amount < 1 || amount > 100000) return res.status(400).json({ error: 'amount_must_be_integer_between_1_and_100000' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const targetQ = await client.query('SELECT id,username,role,parent_id FROM users WHERE id=$1 FOR UPDATE', [targetId]);
    const target = targetQ.rows[0];
    if (!target || String(target.parent_id) !== String(req.user.id)) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'direct_child_not_found' }); }
    const actorQ = await client.query('SELECT id,role,token_balance FROM users WHERE id=$1 FOR UPDATE', [req.user.id]);
    const actor = actorQ.rows[0];
    if (actor.role !== 'master' && Number(actor.token_balance) < amount) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'insufficient_tokens', available: Number(actor.token_balance) }); }
    if (actor.role !== 'master') await client.query('UPDATE users SET token_balance=token_balance-$1 WHERE id=$2', [amount, actor.id]);
    const updated = await client.query('UPDATE users SET token_balance=token_balance+$1 WHERE id=$2 RETURNING token_balance', [amount, targetId]);
    await client.query('INSERT INTO audit_logs(actor_id,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5)', [req.user.id, 'tokens_allocated', 'user', targetId, JSON.stringify({ amount, recipient: target.username })]);
    await client.query('COMMIT');
    res.json({ ok: true, allocated: amount, recipient: target.username, tokenBalance: Number(updated.rows[0].token_balance) });
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  finally { client.release(); }
}));

app.get('/api/licenses', auth, asyncRoute(async (req, res) => {
  const { rows } = await pool.query(`
  WITH RECURSIVE team AS (
    SELECT id FROM users WHERE id=$1
    UNION ALL
    SELECT u.id
    FROM users u
    JOIN team t ON u.parent_id=t.id
  )
  SELECT l.*, u.username AS owner_username
  FROM licenses l
  JOIN users u ON u.id=l.owner_id
  WHERE l.status <> 'deleted'
    AND ($2::boolean OR l.owner_id IN (SELECT id FROM team))
  ORDER BY l.created_at DESC
  LIMIT 500
`, [req.user.id, req.user.role === 'master']);
  res.json({ licenses: rows.map(l => ({ id: String(l.id), keyPreview: l.key_preview, status: licenseStatus(l), owner: l.owner_username, customerName: l.customer_name, createdAt: l.created_at, expiresAt: l.expires_at, deviceBound: !!l.device_id_hash, daysRemaining: Math.max(0, Math.ceil((new Date(l.expires_at) - Date.now()) / 86400000)) })) });
}));
app.post('/api/licenses', auth, asyncRoute(async (req, res) => {
  const customerName = String(req.body.customerName || '')
    .trim()
    .toUpperCase();

  if (!/^[A-Z0-9]{4,32}$/.test(customerName)) {
    return res.status(400).json({
      error: 'customer_name_must_be_4_to_32_letters_or_numbers'
    });
  }

  const quantity = Number(req.body.quantity ?? 1);

  if (quantity !== 1) {
    return res.status(400).json({
      error: 'customer_name_license_requires_quantity_1'
    });
  }

  const client = await pool.connect();
  const created = [];

  try {
    await client.query('BEGIN');

    const userQ = await client.query(
      'SELECT id, role, token_balance, is_active FROM users WHERE id=$1 FOR UPDATE',
      [req.user.id]
    );

    const actor = userQ.rows[0];

    if (!actor || !actor.is_active) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'account_inactive' });
    }

    if (
      actor.role !== 'master' &&
      Number(actor.token_balance) < quantity
    ) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'insufficient_tokens',
        available: Number(actor.token_balance),
        requested: quantity
      });
    }

    const key = customerName;
    const keyHash = hash(key);

    const existing = await client.query(
      'SELECT id FROM licenses WHERE key_hash=$1',
      [keyHash]
    );

    if (existing.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'duplicate_license_key',
        message: 'This customer name is already used as a license key.'
      });
    }

    const expires = new Date(
      Date.now() + LICENSE_DAYS * 86400000
    );

    const preview = key.length <= 24
      ? key
      : key.slice(0, 2) + '…' + key.slice(-2);

    const insertResult = await client.query(
      `INSERT INTO licenses
        (key_hash, key_preview, created_by, owner_id, customer_name, expires_at)
       VALUES ($1, $2, $3, $3, $4, $5)
       RETURNING id, created_at, expires_at`,
      [
        keyHash,
        preview,
        req.user.id,
        customerName,
        expires.toISOString()
      ]
    );

    const license = insertResult.rows[0];

    created.push({
      id: String(license.id),
      licenseKey: key,
      createdAt: license.created_at,
      expiresAt: license.expires_at
    });

    if (actor.role !== 'master') {
      await client.query(
        'UPDATE users SET token_balance=token_balance-$1 WHERE id=$2',
        [quantity, req.user.id]
      );
    }

    await client.query(
      `INSERT INTO audit_logs
        (actor_id, action, target_type, target_id, details)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        req.user.id,
        'licenses_bulk_created',
        'license_batch',
        null,
        JSON.stringify({
          quantity,
          validityDays: LICENSE_DAYS
        })
      ]
    );

    await client.query('COMMIT');

  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }

  const balanceQ = await pool.query(
    'SELECT token_balance FROM users WHERE id=$1',
    [req.user.id]
  );

  res.status(201).json({
    ok: true,
    quantity: created.length,
    licenses: created,
    licenseKey: created[0].licenseKey,
    validityDays: LICENSE_DAYS,
    expiresAt: created[0].expiresAt,
    remainingTokens: req.user.role === 'master'
      ? null
      : Number(balanceQ.rows[0]?.token_balance || 0),
    message: 'Copy or download this key now; the full key is not stored or shown again.'
  });
}));

app.post('/api/licenses/:id/revoke', auth, asyncRoute(async (req, res) => {
  const id = String(req.params.id);

  const q = await pool.query(
    'SELECT id, owner_id, status FROM licenses WHERE id=$1',
    [id]
  );

  if (!q.rows[0] || !(await isInScope(req.user, q.rows[0].owner_id))) {
    return res.status(404).json({
      error: 'license_not_found_in_your_team'
    });
  }

  if (q.rows[0].status === 'revoked') {
    return res.status(409).json({
      error: 'license_already_revoked'
    });
  }

  if (q.rows[0].status === 'deleted') {
    return res.status(409).json({
      error: 'license_already_deleted'
    });
  }

  await pool.query(
    "UPDATE licenses SET status='revoked' WHERE id=$1",
    [id]
  );

  await audit(req.user.id, 'license_revoked', 'license', id);

  res.json({ ok: true, revoked: true });
}));

// Delete License: hide it from inventory and reject future verification.
app.post('/api/licenses/:id/delete', auth, asyncRoute(async (req, res) => {
  const id = String(req.params.id);

  const q = await pool.query(
    'SELECT id, owner_id, status FROM licenses WHERE id=$1',
    [id]
  );

  if (!q.rows[0] || !(await isInScope(req.user, q.rows[0].owner_id))) {
    return res.status(404).json({
      error: 'license_not_found_in_your_team'
    });
  }

  if (q.rows[0].status === 'deleted') {
    return res.status(404).json({
      error: 'license_already_deleted'
    });
  }

  await pool.query(
    "UPDATE licenses SET status='deleted' WHERE id=$1",
    [id]
  );

  await audit(req.user.id, 'license_deleted', 'license', id);

  res.json({ ok: true, deleted: true });
}));

// Temporarily deactivate a license.
app.post('/api/licenses/:id/deactivate', auth, asyncRoute(async (req, res) => {
  // Access is checked below using isInScope().

  const id = String(req.params.id);
  const q = await pool.query(
    'SELECT id, owner_id, status FROM licenses WHERE id=$1',
    [id]
  );

  if (!q.rows[0] || !(await isInScope(req.user, q.rows[0].owner_id))) {
    return res.status(404).json({ error: 'license_not_found_in_your_team' });
  }

  if (q.rows[0].status === 'revoked') {
    return res.status(409).json({ error: 'license_permanently_revoked' });
  }

  if (q.rows[0].status === 'deactivated') {
    return res.status(409).json({ error: 'license_already_deactivated' });
  }

  await pool.query(
    "UPDATE licenses SET status='deactivated' WHERE id=$1",
    [id]
  );

  await audit(req.user.id, 'license_deactivated', 'license', id);

  res.json({ ok: true, deactivated: true });
}));

// Reactivate a temporarily deactivated license.
app.post('/api/licenses/:id/reactivate', auth, asyncRoute(async (req, res) => { 
  // Access is checked below using isInScope().

  const id = String(req.params.id);
  const q = await pool.query(
    'SELECT id, owner_id, status, expires_at FROM licenses WHERE id=$1',
    [id]
  );

  const l = q.rows[0];

  if (!l || !(await isInScope(req.user, l.owner_id))) {
    return res.status(404).json({ error: 'license_not_found_in_your_team' });
  }

  if (l.status === 'revoked') {
    return res.status(409).json({ error: 'license_permanently_revoked' });
  }

  if (l.status !== 'deactivated') {
    return res.status(409).json({ error: 'license_not_deactivated' });
  }

  if (new Date(l.expires_at).getTime() <= Date.now()) {
    return res.status(409).json({
      error: 'license_expired',
      message: 'Renew this license before reactivating it.'
    });
  }

  await pool.query(
    "UPDATE licenses SET status='active' WHERE id=$1",
    [id]
  );

  await audit(req.user.id, 'license_reactivated', 'license', id);

  res.json({ ok: true, reactivated: true });
}));
// Reset device binding for licenses within the user's team.
app.post('/api/licenses/:id/reset-device', auth, asyncRoute(async (req, res) => {
  const id = String(req.params.id);

  const q = await pool.query(
    'SELECT id, owner_id, status FROM licenses WHERE id=$1',
    [id]
  );

  const license = q.rows[0];

  if (!license || !(await isInScope(req.user, license.owner_id))) {
    return res.status(404).json({
      error: 'license_not_found_in_your_team'
    });
  }

  if (license.status === 'revoked' || license.status === 'deleted') {
    return res.status(409).json({
      error: 'license_not_resettable'
    });
  }

  await pool.query(
    'UPDATE licenses SET device_id_hash=NULL, activated_at=NULL WHERE id=$1',
    [id]
  );

  await audit(req.user.id, 'license_device_reset', 'license', id, {
    ownerId: String(license.owner_id)
  });

  res.json({
    ok: true,
    deviceReset: true,
    message: 'Device binding reset successfully.'
  });
}));
// Renew the same key for 30 days.
// If the key is expired, 30 days start from now.
// Otherwise, 30 days are added to its existing expiry.
app.post('/api/licenses/:id/renew', auth, asyncRoute(async (req, res) => {
  
// Access is checked below using isInScope().


  const id = String(req.params.id);
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const q = await client.query(
      'SELECT id, owner_id, status, expires_at FROM licenses WHERE id=$1 FOR UPDATE',
      [id]
    );

    const l = q.rows[0];

    if (!l || !(await isInScope(req.user, l.owner_id))) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'license_not_found_in_your_team' });
    }

    if (l.status === 'revoked') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'license_permanently_revoked' });
    }

    const now = Date.now();
    const oldExpiry = new Date(l.expires_at).getTime();
    const baseTime = Math.max(now, oldExpiry);
    const newExpiry = new Date(baseTime + 30 * 24 * 60 * 60 * 1000);

    await client.query(
      "UPDATE licenses SET expires_at=$1, status='active' WHERE id=$2",
      [newExpiry, id]
    );

    await client.query('COMMIT');

    await audit(req.user.id, 'license_renewed', 'license', id, {
      previousExpiry: l.expires_at,
      newExpiry: newExpiry.toISOString(),
      daysAdded: 30
    });

    res.json({
      ok: true,
      renewed: true,
      expiresAt: newExpiry.toISOString()
    });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}));


// Electron/client API: 30-day expiry, temporary deactivation,
// permanent revocation, and one-device binding.
async function checkLicense(key, deviceId, bind) {
  
  if (!key || !deviceId) {
    return {
      ok: false,
      code: 'missing_fields',
      reason: 'License key and device ID are required.'
    };
  }
  
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const q = await client.query(
      'SELECT * FROM licenses WHERE key_hash=$1 FOR UPDATE',
      [hash(key.trim())]
    );

    const l = q.rows[0];

    if (!l) {
      await client.query('ROLLBACK');
      return {
        ok: false,
        code: 'invalid_key',
        reason: 'License key not found.'
      };
    }

    if (l.status === 'revoked') {
      await client.query('ROLLBACK');
      return {
        ok: false,
        code: 'revoked',
        reason: 'This license has been permanently revoked.'
      };
    }
    if (l.status === 'deleted') {
  await client.query('ROLLBACK');
  return {
    ok: false,
    code: 'deleted',
    reason: 'This license has been deleted.'
  };
}

    if (l.status === 'deactivated') {
      await client.query('ROLLBACK');
      return {
        ok: false,
        code: 'deactivated',
        reason: 'This license is temporarily deactivated.'
      };
    }

    const now = Date.now();
    const expiresAt = new Date(l.expires_at).getTime();

    if (expiresAt <= now) {
      await client.query('ROLLBACK');
      return {
        ok: false,
        code: 'expired',
        reason: 'License has expired.',
        leftDays: 0
      };
    }

    const deviceHash = hash(deviceId);

    if (l.device_id_hash && l.device_id_hash !== deviceHash) {
      await client.query('ROLLBACK');
      return {
        ok: false,
        code: 'device_limit',
        reason: 'License is already activated on another device.'
      };
    }

    if (!l.device_id_hash && bind) {
      await client.query(
        'UPDATE licenses SET device_id_hash=$1, activated_at=NOW() WHERE id=$2',
        [deviceHash, l.id]
      );
    }

    await client.query('COMMIT');

    return {
      ok: true,
      code: 'valid',
      reason: 'License valid.',
      leftDays: Math.max(0, Math.ceil((expiresAt - now) / 86400000)),
      expiresAt: l.expires_at
    };
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}
// Compatibility endpoint for the existing AVENGER desktop license-gate.js.
// The legacy client POSTs { key, Machine, MSG } to the configured base URL.
app.post('/', asyncRoute(async (req, res) => {
  const key = req.body.licenseKey || req.body.key;
  const deviceId = req.body.deviceId || req.body.machineId || req.body.machine || req.body.Machine;
  const bind = req.body.MSG === false ? false : true;
  const r = await checkLicense(key, deviceId, bind);
  res.status(r.ok ? 200 : (r.code === 'missing_fields' ? 400 : 403)).json({
    ...r,
    machine: deviceId || null,
    appVersion: '1.0.0'
  });
}));

app.post('/license/activate', asyncRoute(async (req, res) => {
  const r = await checkLicense(req.body.licenseKey || req.body.key, req.body.deviceId || req.body.machineId || req.body.machine || req.body.Machine, true);
  if (r.ok) await audit(null, 'license_activated', 'license', null, { keyPreview: String(req.body.licenseKey || req.body.key || '').slice(0, 7) });
  res.status(r.ok ? 200 : (r.code === 'missing_fields' ? 400 : 403)).json({ ...r, machine: req.body.deviceId || req.body.machineId || req.body.machine || req.body.Machine || null, appVersion: '1.0.0' });
}));
app.post('/license/verify', asyncRoute(async (req, res) => {
  const r = await checkLicense(req.body.licenseKey || req.body.key, req.body.deviceId || req.body.machineId || req.body.machine || req.body.Machine, false);
  res.status(r.ok ? 200 : (r.code === 'missing_fields' ? 400 : 403)).json({ ...r, machine: req.body.deviceId || req.body.machineId || req.body.machine || req.body.Machine || null, appVersion: '1.0.0' });
}));

app.get('/api/audit', auth, requireRole('master'), asyncRoute(async (_req, res) => {
  const { rows } = await pool.query('SELECT a.id,a.action,a.target_type,a.target_id,a.details,a.created_at,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 200');
  res.json({ logs: rows });
}));
app.get('*', (req, res, next) => { if (req.path.startsWith('/api/') || req.path.startsWith('/license/')) return next(); res.sendFile(path.join(__dirname, 'public', 'index.html')); });
app.use((err, _req, res, _next) => {
  console.error('[server-error]', err.message);

  if (err.code === 'DUPLICATE_LICENSE_KEY' || err.code === '23505') {
    return res.status(409).json({
      error: 'duplicate_license_key',
      message: 'This customer name is already used as a license key.'
    });
  }

  res.status(500).json({ error: 'internal_server_error' });
});
console.log('DELETE ROUTE REGISTERED');
initDb().then(() => app.listen(PORT, () => console.log(`AVENGER License Server listening on ${PORT}`))).catch(err => { console.error('Startup failed:', err.message); process.exit(1); });
