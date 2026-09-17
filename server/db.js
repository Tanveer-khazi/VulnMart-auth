const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'mysql',
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || 'vulnmart',
  password: process.env.DB_PASSWORD || 'vulnmart_pw',
  database: process.env.DB_NAME || 'vulnmart_auth',
  waitForConnections: true,
  connectionLimit: 10,
});

module.exports = pool;
