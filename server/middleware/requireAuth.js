const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'vulnmart-super-secret';

// Verifies the JWT signature, but the payload's `role` claim is trusted
// as-is from here on (see routes/auth.js "VULN: role-mass-assignment" for
// how an attacker gets an admin-flavored token issued in the first place).
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : req.cookies.vm_token;

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { id, email, role }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { requireAuth, JWT_SECRET };
