const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const pool = require('../db');
const { requireAuth, JWT_SECRET } = require('../middleware/requireAuth');

const router = express.Router();

const KNOWN_CLIENTS = new Set([process.env.OAUTH_CLIENT_ID || 'vulnmart-demo-client']);

// VULN: oauth-open-redirect
// A real authorization server checks `redirect_uri` against a list of URIs
// pre-registered for this `client_id` and rejects anything else. Here we
// only check that `client_id` itself is one we recognize, then trust
// *whatever* redirect_uri the caller supplies. An attacker sends a victim
// (who is already logged into VulnMart) a link such as:
//   /oauth/authorize?client_id=vulnmart-demo-client&redirect_uri=https://evil.example/cb&state=x
// The victim's browser follows it while authenticated, VulnMart mints an
// auth code for the victim's account, and redirects it straight to the
// attacker's server - handing over the code (and, after /oauth/token, an
// access token for the victim's account) with no consent screen.
router.get('/authorize', requireAuth, async (req, res) => {
  const { client_id: clientId, redirect_uri: redirectUri, state } = req.query;

  if (!clientId || !KNOWN_CLIENTS.has(clientId)) {
    return res.status(400).json({ error: 'Unknown client_id' });
  }
  if (!redirectUri) {
    return res.status(400).json({ error: 'redirect_uri is required' });
  }

  // Resolve a relative redirect_uri (e.g. "/oauth-callback.html") against
  // this server's own origin so the demo works out of the box; an absolute
  // URL (e.g. "https://evil.example/cb") is passed through untouched - this
  // is what makes the open redirect exploitable.
  const origin = `${req.protocol}://${req.get('host')}`;
  const resolvedRedirectUri = new URL(redirectUri, origin).toString();

  const code = crypto.randomBytes(20).toString('hex');
  await pool.query(
    'INSERT INTO oauth_codes (code, user_id, client_id, redirect_uri) VALUES (?, ?, ?, ?)',
    [code, req.user.id, clientId, resolvedRedirectUri]
  );

  const redirectTo = new URL(resolvedRedirectUri);
  redirectTo.searchParams.set('code', code);
  if (state) redirectTo.searchParams.set('state', state);

  res.redirect(redirectTo.toString());
});

router.post('/token', async (req, res) => {
  const { client_id: clientId, code, redirect_uri: redirectUri } = req.body;

  if (!clientId || !KNOWN_CLIENTS.has(clientId)) {
    return res.status(400).json({ error: 'Unknown client_id' });
  }

  const [rows] = await pool.query('SELECT * FROM oauth_codes WHERE code = ?', [code]);
  const grant = rows[0];

  if (!grant || grant.client_id !== clientId || grant.redirect_uri !== redirectUri) {
    return res.status(400).json({ error: 'Invalid grant' });
  }

  await pool.query('DELETE FROM oauth_codes WHERE id = ?', [grant.id]);

  const [userRows] = await pool.query(
    'SELECT id, email, role FROM users WHERE id = ?',
    [grant.user_id]
  );
  const user = userRows[0];
  const accessToken = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 });
});

module.exports = router;
