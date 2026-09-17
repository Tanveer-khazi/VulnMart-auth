require('dotenv').config();

const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const { sessionMiddleware } = require('./sessions');
const authRoutes = require('./routes/auth');
const oauthRoutes = require('./routes/oauth');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(sessionMiddleware);

app.use(express.static(path.join(__dirname, '..', 'public')));

app.use('/api/auth', authRoutes);
app.use('/oauth', oauthRoutes);
app.use('/api/admin', adminRoutes);

app.get('/health', (req, res) => res.json({ ok: true }));

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`VulnMart Auth listening on port ${PORT}`);
    console.log('FOR AUTHORIZED SECURITY EDUCATION ONLY - DO NOT DEPLOY PUBLICLY');
  });
}

module.exports = app;
