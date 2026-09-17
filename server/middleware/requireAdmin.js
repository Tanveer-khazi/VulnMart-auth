// VULN: role-tampering-trusted
// The only "authorization" check for admin-only routes is the `role` claim
// embedded in the caller's JWT. The token signature is verified upstream in
// requireAuth, but there is no re-check against the users table here, so
// once a token carries role: "admin" (see routes/auth.js profile update
// mass-assignment bug) this middleware accepts it forever, even if the
// account is later demoted in the database.
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

module.exports = { requireAdmin };
