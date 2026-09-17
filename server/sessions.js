const crypto = require('crypto');

// Toy in-memory session store, keyed by session id.
// { [sid]: { userId: number|null, createdAt: number } }
const sessions = new Map();

function createSession() {
  const sid = crypto.randomBytes(16).toString('hex');
  sessions.set(sid, { userId: null, createdAt: Date.now() });
  return sid;
}

function getSession(sid) {
  return sessions.get(sid);
}

// VULN: session-fixation
// Middleware accepts a session id supplied by the client (query string OR
// cookie) and happily adopts it instead of only trusting server-issued,
// HttpOnly cookies. Combined with routes/auth.js never rotating the id at
// login, an attacker can hand a victim a link like
//   https://target/login?sid=KNOWN_SESSION_ID
// wait for the victim to log in, then reuse KNOWN_SESSION_ID themselves to
// ride the now-authenticated session.
function sessionMiddleware(req, res, next) {
  let sid = req.query.sid || req.cookies.vm_sid;

  if (!sid || !sessions.has(sid)) {
    sid = createSession();
  }

  res.cookie('vm_sid', sid, { httpOnly: false, sameSite: 'lax' });
  req.sessionId = sid;
  req.session = sessions.get(sid);
  next();
}

module.exports = { sessionMiddleware, getSession, createSession, sessions };
