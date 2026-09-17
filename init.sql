CREATE DATABASE IF NOT EXISTS vulnmart_auth;
USE vulnmart_auth;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS password_resets (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  token VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oauth_codes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  code VARCHAR(255) NOT NULL,
  user_id INT NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  redirect_uri VARCHAR(500) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed a demo admin and a demo shopper. Password for both is "Password123!"
-- Hash generated with bcryptjs (cost 10).
INSERT INTO users (name, email, password_hash, role)
VALUES
  ('Vulnmart Admin', 'admin@vulnmart.test', '$2a$10$lEg0pdHIi7j9oFPFC8Q4ceJ16387jXPMtgg.x2HMrutbx3IzCkgLC', 'admin'),
  ('Demo Shopper', 'shopper@vulnmart.test', '$2a$10$lEg0pdHIi7j9oFPFC8Q4ceJ16387jXPMtgg.x2HMrutbx3IzCkgLC', 'user')
ON DUPLICATE KEY UPDATE email = email;
