const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const pool = require('../db');
const { requireAuth, JWT_SECRET } = require('../middleware/requireAuth');

const router = express.Router();

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '2h' }
  );
}

router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'name, email and password are required' });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  try {
    const [result] = await pool.query(
      'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)',
      [name, email, passwordHash, 'user']
    );
    const user = { id: result.insertId, email, role: 'user' };
    const token = signToken(user);
    res.status(201).json({ token, user: { id: user.id, name, email, role: 'user' } });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Email already registered' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
  const user = rows[0];

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // VULN: session-fixation
  // We reuse whatever session id the client already presented (see
  // sessions.js sessionMiddleware) instead of rotating to a fresh id on
  // privilege change. An attacker who fixated req.sessionId before the
  // victim logged in now shares an authenticated session with them.
  req.session.userId = user.id;

  const token = signToken(user);
  res.cookie('vm_token', token, { httpOnly: true, sameSite: 'lax' });
  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
  });
});

router.post('/logout', (req, res) => {
  if (req.session) req.session.userId = null;
  res.clearCookie('vm_token');
  res.json({ ok: true });
});

router.get('/me', requireAuth, async (req, res) => {
  const [rows] = await pool.query(
    'SELECT id, name, email, role FROM users WHERE id = ?',
    [req.user.id]
  );
  res.json(rows[0] || null);
});

// VULN: session-fixation
// A legacy, cookie-only session check (kept around alongside the JWT for a
// "remember me" widget) that trusts req.session.userId as populated by
// sessions.js. Since that session id can be fixated by an attacker before
// the victim ever logs in (see sessions.js and the /login handler above),
// whoever holds the vm_sid cookie value - attacker included - can hit this
// endpoint and be treated as the logged-in victim, no JWT required.
router.get('/session', async (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'No active session' });
  }
  const [rows] = await pool.query(
    'SELECT id, name, email, role FROM users WHERE id = ?',
    [req.session.userId]
  );
  res.json(rows[0] || null);
});

// VULN: role-mass-assignment
// This endpoint blindly applies every field the client sends - including
// `role` - straight onto the user's row. A logged-in "user" can PATCH their
// own profile with { "role": "admin" }, re-login (or just re-request /me)
// to mint a fresh JWT carrying role: "admin", and requireAdmin.js will
// trust it from then on. A real implementation would only ever allow an
// existing admin to change roles, via a separate endpoint.
router.patch('/profile', requireAuth, async (req, res) => {
  const allowedColumns = ['name', 'email', 'role'];
  const updates = Object.keys(req.body).filter((key) => allowedColumns.includes(key));

  if (updates.length === 0) {
    return res.status(400).json({ error: 'No updatable fields provided' });
  }

  const setClause = updates.map((col) => `${col} = ?`).join(', ');
  const values = updates.map((col) => req.body[col]);
  values.push(req.user.id);

  await pool.query(`UPDATE users SET ${setClause} WHERE id = ?`, values);

  const [rows] = await pool.query(
    'SELECT id, name, email, role FROM users WHERE id = ?',
    [req.user.id]
  );
  res.json(rows[0]);
});

// VULN: predictable-reset-token
// The reset token is just base64("<email>:<timestamp>") - no randomness,
// no HMAC, nothing tying it to the account beyond data an attacker already
// knows or can narrow down (server time, to the second, is visible in the
// HTTP Date header). On top of that, this endpoint returns the token/link
// directly in the JSON response ("email delivery is mocked in this demo"),
// so anyone who can submit a victim's email can fetch their reset link
// with no email access required at all.
router.post('/password-reset/request', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'email is required' });

  const timestamp = Date.now();
  const token = Buffer.from(`${email}:${timestamp}`).toString('base64');
  const expiresAt = new Date(timestamp + 15 * 60 * 1000);

  await pool.query(
    'INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)',
    [email, token, expiresAt]
  );

  res.json({
    message: 'If that email exists, a reset link has been generated.',
    // Demo-only stand-in for "sent via email" - this is the vulnerability.
    resetLink: `/reset.html?token=${encodeURIComponent(token)}`,
    token,
  });
});

// VULN: no-expiry-enforcement
// `expires_at` is stored but this handler never checks it (and never
// checks `used` before allowing reuse of an already-consumed token
// either), so an old or already-used reset token/link keeps working
// indefinitely.
router.post('/password-reset/confirm', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) {
    return res.status(400).json({ error: 'token and newPassword are required' });
  }

  const [rows] = await pool.query(
    'SELECT * FROM password_resets WHERE token = ? ORDER BY id DESC LIMIT 1',
    [token]
  );
  const reset = rows[0];
  if (!reset) {
    return res.status(400).json({ error: 'Invalid reset token' });
  }

  const passwordHash = await bcrypt.hash(newPassword, 10);
  await pool.query('UPDATE users SET password_hash = ? WHERE email = ?', [
    passwordHash,
    reset.email,
  ]);
  await pool.query('UPDATE password_resets SET used = 1 WHERE id = ?', [reset.id]);

  res.json({ ok: true, message: 'Password updated' });
});

module.exports = router;
