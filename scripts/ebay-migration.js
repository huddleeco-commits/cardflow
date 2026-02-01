#!/usr/bin/env node
/**
 * eBay OAuth Tables Migration
 *
 * Adds tables for eBay OAuth tokens, OAuth states, and listings
 *
 * Usage: node scripts/ebay-migration.js
 */

require('dotenv').config();
const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://localhost/cardflow';

async function runMigration() {
  const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: DATABASE_URL.includes('.railway.internal') ? false :
         (DATABASE_URL.includes('railway') ? { rejectUnauthorized: false } : false)
  });

  try {
    console.log('Connecting to database...');
    await pool.query('SELECT NOW()');
    console.log('Connected!\n');

    // Start transaction
    await pool.query('BEGIN');

    // 1. Create ebay_user_tokens table
    console.log('Creating ebay_user_tokens table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ebay_user_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        access_token TEXT NOT NULL,
        refresh_token TEXT NOT NULL,
        token_expires_at TIMESTAMP NOT NULL,
        ebay_user_id VARCHAR(255),
        scope TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id)
      )
    `);
    console.log('  ebay_user_tokens created');

    // 2. Create ebay_oauth_states table (CSRF protection)
    console.log('Creating ebay_oauth_states table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ebay_oauth_states (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        state VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP NOT NULL
      )
    `);
    console.log('  ebay_oauth_states created');

    // 3. Create ebay_listings table
    console.log('Creating ebay_listings table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ebay_listings (
        id SERIAL PRIMARY KEY,
        card_id INTEGER REFERENCES cards(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        ebay_listing_id VARCHAR(255) NOT NULL,
        ebay_url TEXT,
        sku VARCHAR(255),
        offer_id VARCHAR(255),
        status VARCHAR(50) DEFAULT 'active',
        price DECIMAL(10,2),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ended_at TIMESTAMP,
        UNIQUE(card_id)
      )
    `);
    console.log('  ebay_listings created');

    // 4. Add eBay policy columns to users table
    console.log('Adding eBay policy columns to users table...');

    // Check if columns exist first
    const columnsResult = await pool.query(`
      SELECT column_name FROM information_schema.columns
      WHERE table_name = 'users' AND column_name = 'ebay_payment_policy_id'
    `);

    if (columnsResult.rows.length === 0) {
      await pool.query(`
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS ebay_payment_policy_id VARCHAR(255),
        ADD COLUMN IF NOT EXISTS ebay_return_policy_id VARCHAR(255),
        ADD COLUMN IF NOT EXISTS ebay_fulfillment_policy_id VARCHAR(255),
        ADD COLUMN IF NOT EXISTS ebay_marketplace_id VARCHAR(50) DEFAULT 'EBAY_US',
        ADD COLUMN IF NOT EXISTS ebay_currency VARCHAR(10) DEFAULT 'USD',
        ADD COLUMN IF NOT EXISTS ebay_country_code VARCHAR(10) DEFAULT 'US'
      `);
      console.log('  eBay policy columns added');
    } else {
      console.log('  eBay policy columns already exist');
    }

    // 5. Create indexes
    console.log('Creating indexes...');
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_ebay_tokens_user ON ebay_user_tokens(user_id);
      CREATE INDEX IF NOT EXISTS idx_ebay_tokens_expiry ON ebay_user_tokens(token_expires_at);
      CREATE INDEX IF NOT EXISTS idx_ebay_listings_card ON ebay_listings(card_id);
      CREATE INDEX IF NOT EXISTS idx_ebay_listings_user ON ebay_listings(user_id);
      CREATE INDEX IF NOT EXISTS idx_ebay_listings_status ON ebay_listings(status);
    `);
    console.log('  Indexes created');

    // Commit transaction
    await pool.query('COMMIT');

    console.log('\nMigration completed successfully!');
    console.log('\nNew tables:');
    console.log('  - ebay_user_tokens (stores OAuth tokens)');
    console.log('  - ebay_oauth_states (CSRF protection)');
    console.log('  - ebay_listings (tracks eBay listings)');
    console.log('\nNew columns in users table:');
    console.log('  - ebay_payment_policy_id');
    console.log('  - ebay_return_policy_id');
    console.log('  - ebay_fulfillment_policy_id');

  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Migration failed:', error.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

runMigration();
