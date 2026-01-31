#!/usr/bin/env node
/**
 * CardFlow - Local Development Setup
 *
 * Complete setup script for local development:
 * 1. Check PostgreSQL is installed
 * 2. Create cardflow database
 * 3. Run schema migrations
 * 4. Create first admin user
 * 5. Migrate existing cards to database (if any)
 * 6. Generate .env file
 *
 * Run: npm run setup
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

// Console colors
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  dim: '\x1b[2m'
};

function log(msg, type = 'info') {
  const icons = {
    info: `${colors.cyan}[i]${colors.reset}`,
    success: `${colors.green}[+]${colors.reset}`,
    error: `${colors.red}[x]${colors.reset}`,
    warn: `${colors.yellow}[!]${colors.reset}`,
    step: `${colors.magenta}[>]${colors.reset}`
  };
  console.log(`${icons[type] || '[*]'} ${msg}`);
}

function header(text) {
  console.log('\n' + colors.cyan + '='.repeat(60) + colors.reset);
  console.log(colors.bold + '  ' + text + colors.reset);
  console.log(colors.cyan + '='.repeat(60) + colors.reset + '\n');
}

async function prompt(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise(resolve => {
    rl.question(colors.yellow + question + colors.reset, answer => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function promptPassword(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  // Simple password prompt (not hidden, but works cross-platform)
  return new Promise(resolve => {
    rl.question(colors.yellow + question + colors.reset, answer => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function checkCommand(command) {
  try {
    if (process.platform === 'win32') {
      execSync(`where ${command}`, { stdio: 'pipe' });
    } else {
      execSync(`which ${command}`, { stdio: 'pipe' });
    }
    return true;
  } catch {
    return false;
  }
}

function runCommand(command, options = {}) {
  try {
    const result = execSync(command, {
      encoding: 'utf8',
      stdio: options.silent ? 'pipe' : 'inherit',
      ...options
    });
    return { success: true, output: result };
  } catch (e) {
    return { success: false, error: e.message, output: e.stdout || '' };
  }
}

async function checkPostgres() {
  log('Checking PostgreSQL installation...', 'step');

  // Check for psql command
  const hasPsql = checkCommand('psql');

  if (!hasPsql) {
    log('PostgreSQL is not installed or not in PATH', 'error');
    console.log(`
${colors.yellow}Please install PostgreSQL:${colors.reset}

${colors.cyan}Windows:${colors.reset}
  1. Download from: https://www.postgresql.org/download/windows/
  2. Run the installer
  3. Add PostgreSQL bin folder to PATH
     (e.g., C:\\Program Files\\PostgreSQL\\16\\bin)
  4. Restart your terminal

${colors.cyan}macOS:${colors.reset}
  brew install postgresql@16
  brew services start postgresql@16

${colors.cyan}Linux (Ubuntu/Debian):${colors.reset}
  sudo apt update
  sudo apt install postgresql postgresql-contrib
  sudo systemctl start postgresql
`);
    return false;
  }

  log('PostgreSQL found', 'success');

  // Check if PostgreSQL is running
  log('Checking if PostgreSQL is running...', 'step');

  const testResult = runCommand('psql -U postgres -c "SELECT 1" -t', { silent: true });

  if (!testResult.success) {
    log('PostgreSQL is not running or requires authentication', 'warn');
    console.log(`
${colors.yellow}Make sure PostgreSQL is running:${colors.reset}

${colors.cyan}Windows:${colors.reset}
  - Check Windows Services for "postgresql" service
  - Or run: net start postgresql-x64-16

${colors.cyan}macOS:${colors.reset}
  brew services start postgresql@16

${colors.cyan}Linux:${colors.reset}
  sudo systemctl start postgresql
`);

    const continueAnyway = await prompt('Continue anyway? (y/n): ');
    if (continueAnyway.toLowerCase() !== 'y') {
      return false;
    }
  } else {
    log('PostgreSQL is running', 'success');
  }

  return true;
}

async function createDatabase() {
  log('Creating cardflow database...', 'step');

  // Check if database already exists
  const checkDb = runCommand('psql -U postgres -lqt', { silent: true });

  if (checkDb.success && checkDb.output.includes('cardflow')) {
    log('Database "cardflow" already exists', 'success');
    return true;
  }

  // Create database
  const createResult = runCommand('psql -U postgres -c "CREATE DATABASE cardflow"', { silent: true });

  if (createResult.success) {
    log('Database "cardflow" created', 'success');
    return true;
  } else {
    log('Could not create database automatically', 'warn');
    console.log(`
${colors.yellow}Please create the database manually:${colors.reset}

  1. Open psql: psql -U postgres
  2. Run: CREATE DATABASE cardflow;
  3. Exit: \\q
  4. Run this setup again
`);

    const continueAnyway = await prompt('Continue anyway (if database exists)? (y/n): ');
    return continueAnyway.toLowerCase() === 'y';
  }
}

async function generateEnvFile() {
  log('Generating environment files...', 'step');

  const envPath = path.join(__dirname, '..', '.env');
  const envExamplePath = path.join(__dirname, '..', '.env.example');

  // Generate JWT secret
  const crypto = require('crypto');
  const jwtSecret = crypto.randomBytes(32).toString('hex');

  const envContent = `# CardFlow Environment Configuration
# Generated: ${new Date().toISOString()}

# Database
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/cardflow

# Authentication
JWT_SECRET=${jwtSecret}

# Server
NODE_ENV=development
PORT=3005

# Anthropic API (optional - users can add their own in Settings)
# ANTHROPIC_API_KEY=sk-ant-api03-...

# Email (optional - for password reset)
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=your-email@gmail.com
# SMTP_PASS=your-app-password
# EMAIL_FROM=CardFlow <noreply@cardflow.app>
`;

  // Always create .env.example
  fs.writeFileSync(envExamplePath, envContent);
  log('Created .env.example', 'success');

  // Create .env if it doesn't exist
  if (!fs.existsSync(envPath)) {
    fs.writeFileSync(envPath, envContent);
    log('Created .env with generated JWT_SECRET', 'success');
  } else {
    log('.env already exists, not overwriting', 'info');

    // Check if JWT_SECRET is set
    const existingEnv = fs.readFileSync(envPath, 'utf8');
    if (!existingEnv.includes('JWT_SECRET=') || existingEnv.includes('JWT_SECRET=\n')) {
      log('Adding JWT_SECRET to existing .env', 'info');
      fs.appendFileSync(envPath, `\nJWT_SECRET=${jwtSecret}\n`);
    }
  }

  return true;
}

async function runSchemaAndSetup() {
  log('Running database schema...', 'step');

  // Load environment
  require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

  const { Pool } = require('pg');
  const bcrypt = require('bcrypt');

  const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/cardflow';

  const pool = new Pool({ connectionString: DATABASE_URL });

  // Test connection
  try {
    await pool.query('SELECT NOW()');
    log('Database connection successful', 'success');
  } catch (e) {
    log(`Database connection failed: ${e.message}`, 'error');
    console.log(`
${colors.yellow}Connection string:${colors.reset} ${DATABASE_URL.replace(/:[^:@]+@/, ':****@')}

${colors.yellow}Common fixes:${colors.reset}
  1. Make sure PostgreSQL is running
  2. Check username/password in DATABASE_URL
  3. Ensure the database "cardflow" exists
`);
    await pool.end();
    return false;
  }

  // Run schema
  const SCHEMA_SQL = `
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";

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

    CREATE INDEX IF NOT EXISTS idx_cards_user_id ON cards(user_id);
    CREATE INDEX IF NOT EXISTS idx_cards_status ON cards(status);
    CREATE INDEX IF NOT EXISTS idx_cards_session_id ON cards(session_id);
    CREATE INDEX IF NOT EXISTS idx_api_usage_user_id ON api_usage(user_id);
    CREATE INDEX IF NOT EXISTS idx_api_usage_timestamp ON api_usage(timestamp);
    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

    CREATE OR REPLACE FUNCTION update_updated_at_column()
    RETURNS TRIGGER AS $$
    BEGIN
      NEW.updated_at = NOW();
      RETURN NEW;
    END;
    $$ language 'plpgsql';

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

  try {
    await pool.query(SCHEMA_SQL);
    log('Schema created successfully', 'success');
  } catch (e) {
    log(`Schema error: ${e.message}`, 'error');
    await pool.end();
    return false;
  }

  // Check if admin exists
  const adminCheck = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'admin'");

  if (parseInt(adminCheck.rows[0].count) > 0) {
    log('Admin user already exists', 'info');
  } else {
    // Create admin user
    console.log('\n' + colors.cyan + '--- Create Admin User ---' + colors.reset + '\n');

    const email = await prompt('Admin email: ');
    const password = await promptPassword('Admin password: ');
    const name = await prompt('Admin name (optional): ');

    if (!email || !password) {
      log('Email and password required, skipping admin creation', 'warn');
    } else if (password.length < 6) {
      log('Password must be at least 6 characters, skipping admin creation', 'warn');
    } else {
      try {
        const passwordHash = await bcrypt.hash(password, 10);
        await pool.query(`
          INSERT INTO users (email, password_hash, name, role, subscription_tier, monthly_limit)
          VALUES ($1, $2, $3, 'admin', 'admin', 999999)
        `, [email.toLowerCase(), passwordHash, name || 'Admin']);

        log(`Admin user created: ${email}`, 'success');
      } catch (e) {
        if (e.code === '23505') {
          log('User already exists, updating to admin...', 'warn');
          await pool.query('UPDATE users SET role = $1 WHERE email = $2', ['admin', email.toLowerCase()]);
          log(`Updated ${email} to admin role`, 'success');
        } else {
          log(`Failed to create admin: ${e.message}`, 'error');
        }
      }
    }
  }

  // Migrate existing data
  const cardsJsonPath = path.join(__dirname, '..', 'cards.json');

  if (fs.existsSync(cardsJsonPath)) {
    log('Migrating existing cards from cards.json...', 'step');

    try {
      const cardsData = JSON.parse(fs.readFileSync(cardsJsonPath, 'utf8'));

      if (Array.isArray(cardsData) && cardsData.length > 0) {
        // Get first admin user for migration
        const adminResult = await pool.query("SELECT id FROM users WHERE role = 'admin' LIMIT 1");

        if (adminResult.rows.length > 0) {
          const adminId = adminResult.rows[0].id;
          let migrated = 0;

          for (const card of cardsData) {
            try {
              const frontPath = card.front || null;
              const backPath = card.back || null;
              const cardData = { ...card };
              delete cardData.front;
              delete cardData.back;
              delete cardData.id;

              await pool.query(`
                INSERT INTO cards (user_id, card_data, front_image_path, back_image_path, status, created_at)
                VALUES ($1, $2, $3, $4, $5, $6)
              `, [
                adminId,
                JSON.stringify(cardData),
                frontPath,
                backPath,
                card.status || 'identified',
                card.identified_at || card.created_at || new Date().toISOString()
              ]);

              migrated++;
            } catch (e) {
              // Skip duplicates or errors
            }
          }

          log(`Migrated ${migrated}/${cardsData.length} cards`, 'success');

          // Backup original
          const backupPath = cardsJsonPath.replace('.json', '.backup.json');
          fs.copyFileSync(cardsJsonPath, backupPath);
          log(`Original cards.json backed up`, 'info');
        }
      }
    } catch (e) {
      log(`Migration error: ${e.message}`, 'warn');
    }
  }

  await pool.end();
  return true;
}

async function main() {
  console.clear();
  header('CARDFLOW - LOCAL DEVELOPMENT SETUP');

  console.log(`${colors.dim}This script will set up CardFlow for local development.${colors.reset}\n`);

  // Step 1: Check PostgreSQL
  const hasPostgres = await checkPostgres();
  if (!hasPostgres) {
    process.exit(1);
  }

  // Step 2: Create database
  const dbCreated = await createDatabase();
  if (!dbCreated) {
    process.exit(1);
  }

  // Step 3: Generate .env
  const envCreated = await generateEnvFile();
  if (!envCreated) {
    process.exit(1);
  }

  // Step 4: Run schema and create admin
  const schemaReady = await runSchemaAndSetup();
  if (!schemaReady) {
    process.exit(1);
  }

  // Success!
  header('SETUP COMPLETE');

  console.log(`
${colors.green}CardFlow is ready for development!${colors.reset}

${colors.cyan}Next steps:${colors.reset}

  1. Start the server:
     ${colors.yellow}npm run dashboard${colors.reset}

  2. Open in browser:
     ${colors.yellow}http://localhost:3005${colors.reset}

  3. Login with your admin credentials

  4. Add your Anthropic API key in Settings

${colors.cyan}Useful commands:${colors.reset}

  ${colors.dim}npm run dashboard${colors.reset}  - Start the web server
  ${colors.dim}npm run identify${colors.reset}   - Run batch identification
  ${colors.dim}npm run price${colors.reset}      - Run batch pricing
  ${colors.dim}npm run export${colors.reset}     - Export data to Excel
  ${colors.dim}npm run setup:db${colors.reset}   - Re-run database setup only

${colors.dim}Happy collecting!${colors.reset}
`);
}

main().catch(e => {
  log(`Setup failed: ${e.message}`, 'error');
  console.error(e.stack);
  process.exit(1);
});
