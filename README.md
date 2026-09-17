# VulnMart Auth

> **FOR AUTHORIZED SECURITY EDUCATION ONLY — DO NOT DEPLOY PUBLICLY**
>
> This is a deliberately vulnerable authentication / SSO service built for
> teaching web application security. Every vulnerability in this codebase is
> planted on purpose and documented with a `// VULN: <name>` comment at the
> point it lives in the code. Do not reuse this code in a real product, and
> only run it in an isolated lab environment you control.

VulnMart Auth is a small Node.js/Express service implementing:

- Registration & login (JWT-based)
- A profile endpoint
- Password reset (request + confirm)
- A mini OAuth-style authorization code flow
- An admin panel gated on role

## Tech stack

- Backend: Node.js + Express
- Database: MySQL
- Frontend: plain HTML/CSS/JS (served statically by Express)
- Containerization: Docker + docker-compose

## Setup

### Option 1: Docker Compose (recommended)

```bash
docker-compose up --build
```

This starts a MySQL 8 container (seeded from `init.sql`) and the app on
[http://localhost:4000](http://localhost:4000).

Demo accounts (seeded by `init.sql`), password for both is `Password123!`:

- `admin@vulnmart.test` (role: admin)
- `shopper@vulnmart.test` (role: user)

### Option 2: Run locally

Requires a running MySQL instance.

```bash
npm install
cp .env.example .env   # edit DB_HOST/etc. to point at your MySQL instance
mysql -u root -p < init.sql
npm start
```

The app listens on `PORT` from `.env` (default `4000`).

## Pages

- `/` — landing page
- `/register.html`, `/login.html` — account creation & login
- `/profile.html` — view your account and PATCH your own profile
- `/admin.html` — admin-only user list
- `/reset.html` — password reset request/confirm
- `/oauth-demo.html`, `/oauth-callback.html` — mini OAuth authorize/token flow

## Planted vulnerabilities

<details>
<summary>Click to expand the list of intentionally planted vulnerabilities (names only — exploit walkthroughs are saved for the video)</summary>

1. **Weak / predictable password reset token** (`server/routes/auth.js`,
   `password-reset/request` and `password-reset/confirm`) — the reset token
   is derived from predictable, non-secret inputs, and the confirm endpoint
   never enforces the token's stored expiry or single-use status.
2. **Privilege escalation via role mass-assignment**
   (`server/routes/auth.js`, `PATCH /api/auth/profile`) — the profile-update
   endpoint applies a client-supplied `role` field directly to the database
   with no authorization check.
3. **Session fixation** (`server/sessions.js`, `server/routes/auth.js`
   `/login` and `/session`) — the session id is accepted from the client
   and never rotated on login/privilege change.
4. **OAuth `redirect_uri` open redirect** (`server/routes/oauth.js`,
   `GET /oauth/authorize`) — the authorization endpoint does not validate
   `redirect_uri` against a per-client allowlist.

Search the codebase for `// VULN:` to jump straight to each one.

</details>

## Disclaimer

This project is for authorized security education, CTF, and pentesting-lab
use only. The maintainers accept no responsibility for misuse. Do not deploy
this application on a public network or use it to store real user data.
