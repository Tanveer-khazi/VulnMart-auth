const express = require('express');
const pool = require('../db');
const { requireAuth } = require('../middleware/requireAuth');
const { requireAdmin } = require('../middleware/requireAdmin');

const router = express.Router();

router.get('/users', requireAuth, requireAdmin, async (req, res) => {
  const [rows] = await pool.query('SELECT id, name, email, role, created_at FROM users');
  res.json(rows);
});

module.exports = router;
