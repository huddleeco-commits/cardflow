#!/usr/bin/env node
/**
 * CardFlow - Railway Migration Script
 *
 * Runs database migrations on Railway deployment.
 * Called automatically before server starts via railway.json startCommand.
 *
 * Environment variables (injected by Railway):
 * - DATABASE_URL: PostgreSQL connection string
 * - JWT_SECRET: Should be set in Railway dashboard
 */

const { Pool } = require('pg');

// Console colors
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m'
};

function log(msg, type = 'info') {
  const icons = {
    info: `${colors.cyan}[migrate]${colors.reset}`,
    success: `${colors.green}[migrate]${colors.reset}`,
    error: `${colors.red}[migrate]${colors.reset}`,
    warn: `${colors.yellow}[migrate]${colors.reset}`
  };
  console.log(`${icons[type] || '[migrate]'} ${msg}`);
}

// Full database schema
const SCHEMA_SQL = `
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  name VARCHAR(255),
  role VARCHAR(50) DEFAULT 'user',
  api_key TEXT,
  subscription_tier VARCHAR(50) DEFAULT 'free',
  scans_used INTEGER DEFAULT 0,
  monthly_limit INTEGER DEFAULT 50,
  reset_token TEXT,
  reset_token_expires TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  last_login_at TIMESTAMP
);

-- Cards table (stores all card data as JSONB)
CREATE TABLE IF NOT EXISTS cards (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  card_data JSONB NOT NULL,
  front_image_path TEXT,
  back_image_path TEXT,
  status VARCHAR(50) DEFAULT 'identified',
  session_id UUID,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- API usage tracking
CREATE TABLE IF NOT EXISTS api_usage (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  operation VARCHAR(50) NOT NULL,
  model_used VARCHAR(100),
  tokens_input INTEGER DEFAULT 0,
  tokens_output INTEGER DEFAULT 0,
  cost DECIMAL(10,6) DEFAULT 0,
  card_id UUID REFERENCES cards(id) ON DELETE SET NULL,
  metadata JSONB,
  timestamp TIMESTAMP DEFAULT NOW()
);

-- Processing sessions
CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(255),
  card_count INTEGER DEFAULT 0,
  total_cost DECIMAL(10,4) DEFAULT 0,
  status VARCHAR(50) DEFAULT 'active',
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- eBay OAuth tokens table
CREATE TABLE IF NOT EXISTS ebay_user_tokens (
  id SERIAL PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  access_token TEXT NOT NULL,
  refresh_token TEXT NOT NULL,
  token_expires_at TIMESTAMP NOT NULL,
  ebay_user_id VARCHAR(255),
  scope TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id)
);

-- eBay OAuth states (CSRF protection)
CREATE TABLE IF NOT EXISTS ebay_oauth_states (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  state VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL
);

-- eBay listings tracking
CREATE TABLE IF NOT EXISTS ebay_listings (
  id SERIAL PRIMARY KEY,
  card_id UUID REFERENCES cards(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  ebay_listing_id VARCHAR(255) NOT NULL,
  ebay_url TEXT,
  sku VARCHAR(255),
  offer_id VARCHAR(255),
  status VARCHAR(50) DEFAULT 'active',
  price DECIMAL(10,2),
  listing_type VARCHAR(50) DEFAULT 'single',
  shipping_method VARCHAR(50),
  lot_card_ids UUID[],
  collage_url TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  ended_at TIMESTAMP
);

-- Add eBay policy columns to users (if not exist)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'ebay_payment_policy_id') THEN
    ALTER TABLE users ADD COLUMN ebay_payment_policy_id VARCHAR(255);
    ALTER TABLE users ADD COLUMN ebay_return_policy_id VARCHAR(255);
    ALTER TABLE users ADD COLUMN ebay_fulfillment_policy_id VARCHAR(255);
    ALTER TABLE users ADD COLUMN ebay_marketplace_id VARCHAR(50) DEFAULT 'EBAY_US';
    ALTER TABLE users ADD COLUMN ebay_currency VARCHAR(10) DEFAULT 'USD';
    ALTER TABLE users ADD COLUMN ebay_country_code VARCHAR(10) DEFAULT 'US';
  END IF;
  -- Shipping settings columns
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'ebay_default_shipping') THEN
    ALTER TABLE users ADD COLUMN ebay_default_shipping VARCHAR(50) DEFAULT 'calculated';
    ALTER TABLE users ADD COLUMN ebay_flat_rate_price DECIMAL(10,2) DEFAULT 4.99;
    ALTER TABLE users ADD COLUMN ebay_free_shipping_minimum DECIMAL(10,2) DEFAULT 50.00;
  END IF;
  -- Merchant location key for eBay listings
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'ebay_merchant_location_key') THEN
    ALTER TABLE users ADD COLUMN ebay_merchant_location_key VARCHAR(255);
  END IF;
END $$;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_cards_user_id ON cards(user_id);
CREATE INDEX IF NOT EXISTS idx_cards_status ON cards(status);
CREATE INDEX IF NOT EXISTS idx_cards_session_id ON cards(session_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_user_id ON api_usage(user_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_timestamp ON api_usage(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_ebay_tokens_user ON ebay_user_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_ebay_tokens_expiry ON ebay_user_tokens(token_expires_at);
CREATE INDEX IF NOT EXISTS idx_ebay_listings_card ON ebay_listings(card_id);
CREATE INDEX IF NOT EXISTS idx_ebay_listings_user ON ebay_listings(user_id);
CREATE INDEX IF NOT EXISTS idx_ebay_listings_status ON ebay_listings(status);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for updated_at
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_cards_updated_at ON cards;
CREATE TRIGGER update_cards_updated_at BEFORE UPDATE ON cards
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_sessions_updated_at ON sessions;
CREATE TRIGGER update_sessions_updated_at BEFORE UPDATE ON sessions
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
`;

async function migrate() {
  const DATABASE_URL = process.env.DATABASE_URL;

  if (!DATABASE_URL) {
    log('DATABASE_URL not set - skipping migration (probably local dev)', 'warn');
    process.exit(0);
  }

  log('Starting database migration...', 'info');
  log(`Database: ${DATABASE_URL.split('@')[1]?.split('/')[0] || 'connected'}`, 'info');

  // Railway internal connections don't use SSL
  const isInternalConnection = DATABASE_URL.includes('.railway.internal');
  const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: isInternalConnection ? false : (process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false)
  });

  try {
    // Test connection
    await pool.query('SELECT NOW()');
    log('Database connection successful', 'success');

    // Run schema
    await pool.query(SCHEMA_SQL);
    log('Schema migration completed', 'success');

    // Check for admin user
    const adminCheck = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'admin'");
    const adminCount = parseInt(adminCheck.rows[0].count);

    if (adminCount === 0) {
      log('No admin user exists - create one via the register page', 'warn');
      log('First registered user should be promoted to admin manually', 'info');
    } else {
      log(`Found ${adminCount} admin user(s)`, 'info');
    }

    // Get table stats
    const stats = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM users) as users,
        (SELECT COUNT(*) FROM cards) as cards
    `);
    log(`Database stats: ${stats.rows[0].users} users, ${stats.rows[0].cards} cards`, 'info');

  } catch (error) {
    log(`Migration failed: ${error.message}`, 'error');
    process.exit(1);
  } finally {
    await pool.end();
  }

  log('Migration complete!', 'success');
}

migrate();
