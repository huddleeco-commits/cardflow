#!/usr/bin/env node
/**
 * CardFlow - Database Setup Script
 *
 * Sets up PostgreSQL database with schema for multi-user SaaS.
 * Run: node scripts/setup-db.js
 *
 * Prerequisites:
 * - PostgreSQL installed and running
 * - DATABASE_URL in .env or environment
 */

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const readline = require('readline');

// Load environment variables
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://localhost/cardflow';

// Schema SQL
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

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_cards_user_id ON cards(user_id);
CREATE INDEX IF NOT EXISTS idx_cards_status ON cards(status);
CREATE INDEX IF NOT EXISTS idx_cards_session_id ON cards(session_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_user_id ON api_usage(user_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_timestamp ON api_usage(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

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

// Console colors
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m'
};

function log(msg, type = 'info') {
  const icons = {
    info: `${colors.cyan}[i]${colors.reset}`,
    success: `${colors.green}[+]${colors.reset}`,
    error: `${colors.red}[x]${colors.reset}`,
    warn: `${colors.yellow}[!]${colors.reset}`
  };
  console.log(`${icons[type] || '[*]'} ${msg}`);
}

async function prompt(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer);
    });
  });
}

async function testConnection(pool) {
  try {
    const result = await pool.query('SELECT NOW()');
    return true;
  } catch (e) {
    return false;
  }
}

async function runSchema(pool) {
  log('Running database schema...', 'info');

  try {
    await pool.query(SCHEMA_SQL);
    log('Schema created successfully', 'success');
    return true;
  } catch (e) {
    log(`Schema error: ${e.message}`, 'error');
    return false;
  }
}

async function createAdminUser(pool) {
  console.log('\n--- Create Admin User ---\n');

  const email = await prompt('Admin email: ');
  const password = await prompt('Admin password: ');
  const name = await prompt('Admin name (optional): ');

  if (!email || !password) {
    log('Email and password required', 'error');
    return null;
  }

  if (password.length < 6) {
    log('Password must be at least 6 characters', 'error');
    return null;
  }

  try {
    // Check if user already exists
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);

    if (existing.rows.length > 0) {
      log('User already exists, updating to admin...', 'warn');
      await pool.query('UPDATE users SET role = $1 WHERE email = $2', ['admin', email.toLowerCase()]);
      log(`Updated ${email} to admin role`, 'success');
      return existing.rows[0].id;
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Create admin user
    const result = await pool.query(`
      INSERT INTO users (email, password_hash, name, role, subscription_tier, monthly_limit)
      VALUES ($1, $2, $3, 'admin', 'admin', 999999)
      RETURNING id
    `, [email.toLowerCase(), passwordHash, name || 'Admin']);

    log(`Admin user created: ${email}`, 'success');
    return result.rows[0].id;

  } catch (e) {
    log(`Failed to create admin: ${e.message}`, 'error');
    return null;
  }
}

async function migrateExistingData(pool, adminUserId) {
  const cardsJsonPath = path.join(__dirname, '..', 'cards.json');

  if (!fs.existsSync(cardsJsonPath)) {
    log('No existing cards.json to migrate', 'info');
    return 0;
  }

  log('Migrating existing cards from cards.json...', 'info');

  try {
    const cardsData = JSON.parse(fs.readFileSync(cardsJsonPath, 'utf8'));

    if (!Array.isArray(cardsData) || cardsData.length === 0) {
      log('No cards to migrate', 'info');
      return 0;
    }

    let migrated = 0;

    for (const card of cardsData) {
      try {
        // Extract image paths
        const frontPath = card.front || null;
        const backPath = card.back || null;

        // Store full card data as JSONB
        const cardData = { ...card };
        delete cardData.front;
        delete cardData.back;
        delete cardData.id;

        await pool.query(`
          INSERT INTO cards (user_id, card_data, front_image_path, back_image_path, status, created_at)
          VALUES ($1, $2, $3, $4, $5, $6)
        `, [
          adminUserId,
          JSON.stringify(cardData),
          frontPath,
          backPath,
          card.status || 'identified',
          card.identified_at || card.created_at || new Date().toISOString()
        ]);

        migrated++;
      } catch (e) {
        log(`Failed to migrate card: ${e.message}`, 'warn');
      }
    }

    log(`Migrated ${migrated}/${cardsData.length} cards`, 'success');

    // Backup original file
    const backupPath = cardsJsonPath.replace('.json', '.backup.json');
    fs.copyFileSync(cardsJsonPath, backupPath);
    log(`Original cards.json backed up to ${backupPath}`, 'info');

    return migrated;

  } catch (e) {
    log(`Migration error: ${e.message}`, 'error');
    return 0;
  }
}

async function migrateCostsData(pool, adminUserId) {
  const costsJsonPath = path.join(__dirname, '..', 'costs.json');

  if (!fs.existsSync(costsJsonPath)) {
    return;
  }

  log('Migrating API usage from costs.json...', 'info');

  try {
    const costsData = JSON.parse(fs.readFileSync(costsJsonPath, 'utf8'));

    // Migrate by_model data as summary records
    if (costsData.by_model) {
      for (const [modelKey, stats] of Object.entries(costsData.by_model)) {
        if (stats.cards_processed > 0) {
          await pool.query(`
            INSERT INTO api_usage (user_id, operation, model_used, tokens_input, tokens_output, cost, metadata)
            VALUES ($1, 'migration', $2, $3, $4, $5, $6)
          `, [
            adminUserId,
            modelKey,
            stats.input_tokens || 0,
            stats.output_tokens || 0,
            stats.estimated_cost || 0,
            JSON.stringify({
              migrated: true,
              identify_count: stats.identify_count || 0,
              price_count: stats.price_count || 0
            })
          ]);
        }
      }
    }

    log('API usage data migrated', 'success');

  } catch (e) {
    log(`Costs migration error: ${e.message}`, 'warn');
  }
}

async function generateEnvFile() {
  const envPath = path.join(__dirname, '..', '.env');
  const envExamplePath = path.join(__dirname, '..', '.env.example');

  // Generate a random JWT secret
  const crypto = require('crypto');
  const jwtSecret = crypto.randomBytes(32).toString('hex');

  const envContent = `# CardFlow Environment Configuration
# Generated: ${new Date().toISOString()}

# Database
DATABASE_URL=postgresql://localhost/cardflow

# Authentication
JWT_SECRET=${jwtSecret}

# Server
NODE_ENV=development
PORT=3005

# Anthropic API (optional - users can add their own)
# ANTHROPIC_API_KEY=sk-ant-api03-...

# Email (optional - for password reset)
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=your-email@gmail.com
# SMTP_PASS=your-app-password
# EMAIL_FROM=CardFlow <noreply@cardflow.app>
`;

  // Write .env.example
  fs.writeFileSync(envExamplePath, envContent);
  log('Created .env.example', 'success');

  // Write .env if it doesn't exist
  if (!fs.existsSync(envPath)) {
    fs.writeFileSync(envPath, envContent);
    log('Created .env with generated JWT_SECRET', 'success');
  } else {
    log('.env already exists, not overwriting', 'info');
  }
}

async function main() {
  console.log('\n' + '='.repeat(60));
  console.log('  CARDFLOW - DATABASE SETUP');
  console.log('='.repeat(60) + '\n');

  log(`Database URL: ${DATABASE_URL.replace(/:[^:@]+@/, ':****@')}`, 'info');

  // Create pool
  const pool = new Pool({ connectionString: DATABASE_URL });

  // Test connection
  log('Testing database connection...', 'info');
  const connected = await testConnection(pool);

  if (!connected) {
    log('Cannot connect to database', 'error');
    console.log('\nMake sure PostgreSQL is running and the database exists.');
    console.log('\nTo create the database:');
    console.log('  1. Open psql: psql -U postgres');
    console.log('  2. Create database: CREATE DATABASE cardflow;');
    console.log('  3. Run this script again\n');
    process.exit(1);
  }

  log('Database connection successful', 'success');

  // Run schema
  const schemaOk = await runSchema(pool);
  if (!schemaOk) {
    process.exit(1);
  }

  // Create admin user
  const adminId = await createAdminUser(pool);

  if (adminId) {
    // Migrate existing data
    await migrateExistingData(pool, adminId);
    await migrateCostsData(pool, adminId);
  }

  // Generate .env file
  await generateEnvFile();

  // Summary
  console.log('\n' + '='.repeat(60));
  log('DATABASE SETUP COMPLETE', 'success');
  console.log('='.repeat(60));

  console.log(`
Next steps:

  1. Start the server:
     npm run dashboard

  2. Access the app:
     http://localhost:3005

  3. Login with your admin credentials

  4. Add your Anthropic API key in Settings
`);

  await pool.end();
}

main().catch(e => {
  console.error('Setup failed:', e.message);
  process.exit(1);
});
