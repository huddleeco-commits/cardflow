#!/usr/bin/env node
/**
 * CardFlow Dashboard Server v2.0
 *
 * Multi-user SaaS server with:
 * - JWT authentication
 * - PostgreSQL database
 * - Admin dashboard
 * - Real-time WebSocket updates
 *
 * Usage: node web/server.js
 * URL: http://localhost:3005
 */

require('dotenv').config();

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');
const chokidar = require('chokidar');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const multer = require('multer');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3005;
const JWT_SECRET = process.env.JWT_SECRET || 'cardflow-dev-secret-change-in-production';
const JWT_EXPIRY = '7d';

// Database connection
// Railway internal connections don't use SSL
const dbUrl = process.env.DATABASE_URL || 'postgresql://localhost/cardflow';
const isInternalConnection = dbUrl.includes('.railway.internal');
const pool = new Pool({
  connectionString: dbUrl,
  ssl: isInternalConnection ? false : (process.env.DATABASE_URL && process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false)
});

// Check if database is available
let dbAvailable = false;
pool.query('SELECT NOW()')
  .then(() => {
    dbAvailable = true;
    console.log('[DB] PostgreSQL connected');
  })
  .catch(e => {
    console.log('[DB] PostgreSQL not available, using file fallback');
    dbAvailable = false;
  });

// Paths
const BASE_DIR = path.join(__dirname, '..');
const FOLDERS = {
  new: path.join(BASE_DIR, '1-new'),
  identified: path.join(BASE_DIR, '2-identified'),
  priced: path.join(BASE_DIR, '3-priced'),
  exported: path.join(BASE_DIR, '4-exported'),
  rejected: path.join(BASE_DIR, 'rejected')
};
const DB_PATH = path.join(BASE_DIR, 'cards.json');
const CONFIG_PATH = path.join(BASE_DIR, 'config.json');
const COSTS_PATH = path.join(BASE_DIR, 'costs.json');

// Ensure folders exist
Object.values(FOLDERS).forEach(folder => {
  if (!fs.existsSync(folder)) {
    fs.mkdirSync(folder, { recursive: true });
  }
});

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, FOLDERS.new);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB limit
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only image files allowed'));
    }
  }
});

// File-based fallback functions
function loadFileDb() {
  try {
    if (fs.existsSync(DB_PATH)) {
      return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    }
  } catch (e) {}
  return [];
}

function saveFileDb(cards) {
  fs.writeFileSync(DB_PATH, JSON.stringify(cards, null, 2));
}

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    }
  } catch (e) {}
  return { models: {}, defaults: {} };
}

function saveConfig(config) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

function loadCosts() {
  try {
    if (fs.existsSync(COSTS_PATH)) {
      return JSON.parse(fs.readFileSync(COSTS_PATH, 'utf8'));
    }
  } catch (e) {}
  return { total: {}, by_model: {}, by_date: {} };
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

function optionalAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (!err) {
        req.user = user;
      }
    });
  }
  next();
}

async function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const result = await pool.query('SELECT role FROM users WHERE id = $1', [req.user.id]);
    if (result.rows.length === 0 || result.rows[0].role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  } catch (e) {
    return res.status(500).json({ error: 'Failed to verify admin status' });
  }
}

// ============================================
// STATIC FILES
// ============================================

// Serve static files (but not auth-protected pages directly)
app.use(express.static(__dirname));

// Serve images from all folders
app.use('/images/1-new', express.static(FOLDERS.new));
app.use('/images/2-identified', express.static(FOLDERS.identified));
app.use('/images/3-priced', express.static(FOLDERS.priced));
app.use('/images/4-exported', express.static(FOLDERS.exported));
app.use('/images/rejected', express.static(FOLDERS.rejected));

// ============================================
// HEALTH CHECK
// ============================================

app.get('/api/health', async (req, res) => {
  const health = {
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: dbAvailable ? 'connected' : 'disconnected'
  };

  // Test database connection
  if (dbAvailable) {
    try {
      await pool.query('SELECT 1');
    } catch (e) {
      health.database = 'error';
      health.status = 'degraded';
    }
  }

  res.status(health.status === 'ok' ? 200 : 503).json(health);
});

// ============================================
// AUTH ROUTES
// ============================================

// Register
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const emailLower = email.toLowerCase().trim();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(emailLower)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  try {
    // Check if user exists
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [emailLower]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user
    const result = await pool.query(`
      INSERT INTO users (email, password_hash, name, role, subscription_tier)
      VALUES ($1, $2, $3, 'user', 'free')
      RETURNING id, email, name, role, subscription_tier, created_at
    `, [emailLower, passwordHash, name || null]);

    const user = result.rows[0];

    // Generate token
    const token = jwt.sign({
      id: user.id,
      email: user.email,
      role: user.role,
      subscription_tier: user.subscription_tier
    }, JWT_SECRET, { expiresIn: JWT_EXPIRY });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        subscriptionTier: user.subscription_tier
      }
    });

  } catch (e) {
    console.error('Registration error:', e);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
    const result = await pool.query(`
      SELECT id, email, password_hash, name, role, subscription_tier, api_key
      FROM users WHERE email = $1
    `, [email.toLowerCase().trim()]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Update last login
    await pool.query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [user.id]);

    // Generate token
    const token = jwt.sign({
      id: user.id,
      email: user.email,
      role: user.role,
      subscription_tier: user.subscription_tier
    }, JWT_SECRET, { expiresIn: JWT_EXPIRY });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        subscriptionTier: user.subscription_tier,
        hasApiKey: !!user.api_key
      }
    });

  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, email, name, role, subscription_tier, api_key, scans_used, monthly_limit, created_at
      FROM users WHERE id = $1
    `, [req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];

    // Get user stats
    const cardCount = await pool.query('SELECT COUNT(*) FROM cards WHERE user_id = $1', [user.id]);
    const usageTotal = await pool.query('SELECT SUM(cost) as total FROM api_usage WHERE user_id = $1', [user.id]);

    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      subscriptionTier: user.subscription_tier,
      hasApiKey: !!user.api_key,
      apiKeyPreview: user.api_key ? user.api_key.substring(0, 15) + '...' : null,
      scansUsed: user.scans_used,
      monthlyLimit: user.monthly_limit,
      createdAt: user.created_at,
      stats: {
        totalCards: parseInt(cardCount.rows[0].count),
        totalSpent: parseFloat(usageTotal.rows[0].total || 0)
      }
    });

  } catch (e) {
    console.error('Get user error:', e);
    res.status(500).json({ error: 'Failed to get user info' });
  }
});

// Logout (client-side token removal, but we track it)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  // In a production app, you might blacklist the token
  res.json({ success: true });
});

// Update user API key
app.put('/api/auth/api-key', authenticateToken, async (req, res) => {
  const { api_key } = req.body;

  try {
    if (api_key === null || api_key === '') {
      await pool.query('UPDATE users SET api_key = NULL WHERE id = $1', [req.user.id]);
    } else if (api_key && api_key.startsWith('sk-ant-api03-')) {
      await pool.query('UPDATE users SET api_key = $1 WHERE id = $2', [api_key, req.user.id]);
    } else if (api_key) {
      return res.status(400).json({ error: 'Invalid API key format' });
    }

    res.json({ success: true, hasKey: !!api_key });

  } catch (e) {
    res.status(500).json({ error: 'Failed to update API key' });
  }
});

// Test API key
app.post('/api/auth/test-key', async (req, res) => {
  const { api_key } = req.body;

  if (!api_key) {
    return res.status(400).json({ valid: false, error: 'No API key provided' });
  }

  if (!api_key.startsWith('sk-ant-api03-')) {
    return res.status(400).json({
      valid: false,
      error: 'Invalid format. Key should start with sk-ant-api03-'
    });
  }

  try {
    const Anthropic = require('@anthropic-ai/sdk');
    const client = new Anthropic({ apiKey: api_key });

    const response = await client.messages.create({
      model: 'claude-3-5-haiku-20241022',
      max_tokens: 10,
      messages: [{ role: 'user', content: 'Say "ok"' }]
    });

    if (response.content) {
      res.json({ valid: true, message: 'API key is valid!' });
    } else {
      res.json({ valid: false, error: 'Unexpected response' });
    }
  } catch (e) {
    if (e.status === 401) {
      res.json({ valid: false, error: 'Invalid API key' });
    } else {
      res.json({ valid: false, error: e.message });
    }
  }
});

// ============================================
// CARDS API (Protected)
// ============================================

// Get all cards for user
app.get('/api/cards', authenticateToken, async (req, res) => {
  const { status } = req.query;

  try {
    let query = 'SELECT * FROM cards WHERE user_id = $1';
    const params = [req.user.id];

    if (status) {
      query += ' AND status = $2';
      params.push(status);
    }

    query += ' ORDER BY created_at DESC';

    const result = await pool.query(query, params);

    // Transform card data
    const cards = result.rows.map(row => ({
      id: row.id,
      ...row.card_data,
      front: row.front_image_path,
      back: row.back_image_path,
      status: row.status,
      created_at: row.created_at,
      updated_at: row.updated_at
    }));

    res.json({ cards, total: cards.length });

  } catch (e) {
    console.error('Get cards error:', e);
    res.status(500).json({ error: 'Failed to load cards' });
  }
});

// Get single card
app.get('/api/cards/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM cards WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Card not found' });
    }

    const row = result.rows[0];
    const card = {
      id: row.id,
      ...row.card_data,
      front: row.front_image_path,
      back: row.back_image_path,
      status: row.status,
      created_at: row.created_at,
      updated_at: row.updated_at
    };

    res.json(card);

  } catch (e) {
    res.status(500).json({ error: 'Failed to load card' });
  }
});

// Update card
app.put('/api/cards/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM cards WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Card not found' });
    }

    const existingData = result.rows[0].card_data;
    const updates = req.body;

    // Merge updates into card_data
    const newCardData = { ...existingData, ...updates };
    delete newCardData.front;
    delete newCardData.back;
    delete newCardData.id;

    const newStatus = updates.status || result.rows[0].status;

    await pool.query(
      'UPDATE cards SET card_data = $1, status = $2 WHERE id = $3',
      [JSON.stringify(newCardData), newStatus, req.params.id]
    );

    const card = {
      id: req.params.id,
      ...newCardData,
      front: result.rows[0].front_image_path,
      back: result.rows[0].back_image_path,
      status: newStatus
    };

    broadcast({ type: 'card_updated', card, userId: req.user.id });
    res.json(card);

  } catch (e) {
    console.error('Update card error:', e);
    res.status(500).json({ error: 'Failed to update card' });
  }
});

// Approve card
app.post('/api/cards/:id/approve', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE cards SET status = 'approved', card_data = card_data || '{"approved_at": "${new Date().toISOString()}"}'::jsonb
       WHERE id = $1 AND user_id = $2 RETURNING *`,
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Card not found' });
    }

    res.json({ success: true });

  } catch (e) {
    res.status(500).json({ error: 'Failed to approve card' });
  }
});

// Approve all cards
app.post('/api/cards/approve-all', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE cards SET status = 'approved'
       WHERE user_id = $1 AND status IN ('identified', 'pending')
       RETURNING id`,
      [req.user.id]
    );

    broadcast({ type: 'cards_approved', count: result.rowCount, userId: req.user.id });
    res.json({ approved: result.rowCount });

  } catch (e) {
    res.status(500).json({ error: 'Failed to approve cards' });
  }
});

// Delete card
app.delete('/api/cards/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM cards WHERE id = $1 AND user_id = $2 RETURNING *',
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Card not found' });
    }

    broadcast({ type: 'card_deleted', id: req.params.id, userId: req.user.id });
    res.json({ deleted: true });

  } catch (e) {
    res.status(500).json({ error: 'Failed to delete card' });
  }
});

// Reset all cards
app.post('/api/reset', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM cards WHERE user_id = $1 RETURNING id',
      [req.user.id]
    );

    broadcast({ type: 'reset', userId: req.user.id });
    res.json({ success: true, cardsCleared: result.rowCount });

  } catch (e) {
    res.status(500).json({ error: 'Failed to reset' });
  }
});

// ============================================
// PIPELINE STATUS
// ============================================

app.get('/api/status', authenticateToken, async (req, res) => {
  try {
    // Count cards by status
    const statusCounts = await pool.query(`
      SELECT status, COUNT(*) as count
      FROM cards WHERE user_id = $1
      GROUP BY status
    `, [req.user.id]);

    const counts = {};
    statusCounts.rows.forEach(row => {
      counts[row.status] = parseInt(row.count);
    });

    // Get total value
    const valueResult = await pool.query(`
      SELECT SUM((card_data->>'recommended_price')::numeric) as total
      FROM cards WHERE user_id = $1 AND card_data->>'recommended_price' IS NOT NULL
    `, [req.user.id]);

    const countFiles = (folder) => {
      try {
        return fs.readdirSync(folder).filter(f =>
          ['.jpg', '.jpeg', '.png', '.webp'].includes(path.extname(f).toLowerCase())
        ).length;
      } catch { return 0; }
    };

    res.json({
      pipeline: {
        new: countFiles(FOLDERS.new),
        identified: countFiles(FOLDERS.identified),
        priced: countFiles(FOLDERS.priced),
        exported: countFiles(FOLDERS.exported),
        rejected: countFiles(FOLDERS.rejected)
      },
      cards: {
        total: Object.values(counts).reduce((a, b) => a + b, 0),
        pending: counts.pending || 0,
        identified: counts.identified || 0,
        approved: counts.approved || 0,
        priced: counts.priced || 0,
        exported: counts.exported || 0,
        rejected: counts.rejected || 0
      },
      totalValue: parseFloat(valueResult.rows[0].total || 0)
    });

  } catch (e) {
    console.error('Status error:', e);
    res.status(500).json({ error: 'Failed to get status' });
  }
});

// ============================================
// CONFIG & COSTS
// ============================================

app.get('/api/config', optionalAuth, (req, res) => {
  const config = loadConfig();
  // Don't expose api_key in config
  const safeConfig = { ...config };
  delete safeConfig.api_key;
  res.json(safeConfig);
});

app.put('/api/config', authenticateToken, (req, res) => {
  const config = loadConfig();
  const updates = req.body;

  if (updates.mode) config.mode = updates.mode;
  if (updates.defaults) config.defaults = { ...config.defaults, ...updates.defaults };
  if (updates.smart_selection !== undefined) {
    config.smart_selection = { ...config.smart_selection, ...updates.smart_selection };
  }

  saveConfig(config);
  res.json(config);
});

app.get('/api/costs', authenticateToken, async (req, res) => {
  try {
    // Get user's usage from database
    const totalResult = await pool.query(`
      SELECT SUM(cost) as total_cost, SUM(tokens_input) as input_tokens,
             SUM(tokens_output) as output_tokens, COUNT(*) as operations
      FROM api_usage WHERE user_id = $1
    `, [req.user.id]);

    const byModelResult = await pool.query(`
      SELECT model_used, SUM(cost) as cost, COUNT(*) as count
      FROM api_usage WHERE user_id = $1
      GROUP BY model_used
    `, [req.user.id]);

    const byDateResult = await pool.query(`
      SELECT DATE(timestamp) as date, SUM(cost) as cost, COUNT(*) as count
      FROM api_usage WHERE user_id = $1
      GROUP BY DATE(timestamp)
      ORDER BY date DESC
      LIMIT 30
    `, [req.user.id]);

    res.json({
      total: {
        estimated_cost: parseFloat(totalResult.rows[0].total_cost || 0),
        input_tokens: parseInt(totalResult.rows[0].input_tokens || 0),
        output_tokens: parseInt(totalResult.rows[0].output_tokens || 0),
        cards_processed: parseInt(totalResult.rows[0].operations || 0)
      },
      by_model: byModelResult.rows.reduce((acc, row) => {
        acc[row.model_used] = {
          estimated_cost: parseFloat(row.cost || 0),
          cards_processed: parseInt(row.count || 0)
        };
        return acc;
      }, {}),
      by_date: byDateResult.rows.reduce((acc, row) => {
        acc[row.date] = {
          estimated_cost: parseFloat(row.cost || 0),
          cards_processed: parseInt(row.count || 0)
        };
        return acc;
      }, {})
    });

  } catch (e) {
    // Fallback to file-based costs
    res.json(loadCosts());
  }
});

// ============================================
// ADMIN API
// ============================================

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.email, u.name, u.role, u.subscription_tier, u.created_at, u.last_login_at,
             (SELECT COUNT(*) FROM cards WHERE user_id = u.id) as card_count,
             (SELECT COALESCE(SUM(cost), 0) FROM api_usage WHERE user_id = u.id) as total_cost
      FROM users u
      ORDER BY u.created_at DESC
    `);

    res.json({ users: result.rows });

  } catch (e) {
    res.status(500).json({ error: 'Failed to get users' });
  }
});

// Get user details (admin only)
app.get('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];
    delete user.password_hash;

    const cardsResult = await pool.query(
      'SELECT COUNT(*), status FROM cards WHERE user_id = $1 GROUP BY status',
      [req.params.id]
    );

    const usageResult = await pool.query(`
      SELECT DATE(timestamp) as date, SUM(cost) as cost, COUNT(*) as operations
      FROM api_usage WHERE user_id = $1
      GROUP BY DATE(timestamp)
      ORDER BY date DESC
      LIMIT 30
    `, [req.params.id]);

    res.json({
      user,
      cardStats: cardsResult.rows,
      usageHistory: usageResult.rows
    });

  } catch (e) {
    res.status(500).json({ error: 'Failed to get user details' });
  }
});

// Update user (admin only)
app.put('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { role, subscription_tier, monthly_limit } = req.body;

  try {
    await pool.query(`
      UPDATE users SET role = COALESCE($1, role),
                       subscription_tier = COALESCE($2, subscription_tier),
                       monthly_limit = COALESCE($3, monthly_limit)
      WHERE id = $4
    `, [role, subscription_tier, monthly_limit, req.params.id]);

    res.json({ success: true });

  } catch (e) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// System analytics (admin only)
app.get('/api/admin/analytics', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userCount = await pool.query('SELECT COUNT(*) FROM users');
    const activeUsers = await pool.query(
      "SELECT COUNT(*) FROM users WHERE last_login_at > NOW() - INTERVAL '24 hours'"
    );
    const cardCount = await pool.query('SELECT COUNT(*) FROM cards');
    const todayCards = await pool.query(
      "SELECT COUNT(*) FROM cards WHERE created_at > NOW() - INTERVAL '24 hours'"
    );
    const totalCost = await pool.query('SELECT COALESCE(SUM(cost), 0) as total FROM api_usage');
    const todayCost = await pool.query(
      "SELECT COALESCE(SUM(cost), 0) as total FROM api_usage WHERE timestamp > NOW() - INTERVAL '24 hours'"
    );

    // Daily stats for chart
    const dailyStats = await pool.query(`
      SELECT DATE(timestamp) as date,
             COUNT(DISTINCT user_id) as users,
             COUNT(*) as operations,
             SUM(cost) as cost
      FROM api_usage
      WHERE timestamp > NOW() - INTERVAL '30 days'
      GROUP BY DATE(timestamp)
      ORDER BY date
    `);

    // Top users
    const topUsers = await pool.query(`
      SELECT u.email, u.name, COUNT(c.id) as cards, COALESCE(SUM(a.cost), 0) as cost
      FROM users u
      LEFT JOIN cards c ON c.user_id = u.id
      LEFT JOIN api_usage a ON a.user_id = u.id
      GROUP BY u.id, u.email, u.name
      ORDER BY cards DESC
      LIMIT 10
    `);

    res.json({
      overview: {
        totalUsers: parseInt(userCount.rows[0].count),
        activeUsers24h: parseInt(activeUsers.rows[0].count),
        totalCards: parseInt(cardCount.rows[0].count),
        cardsToday: parseInt(todayCards.rows[0].count),
        totalCost: parseFloat(totalCost.rows[0].total),
        costToday: parseFloat(todayCost.rows[0].total)
      },
      dailyStats: dailyStats.rows,
      topUsers: topUsers.rows
    });

  } catch (e) {
    console.error('Analytics error:', e);
    res.status(500).json({ error: 'Failed to get analytics' });
  }
});

// ============================================
// FILE UPLOAD ENDPOINT
// ============================================

app.post('/api/upload', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    console.log(`[Upload] ${req.file.filename} by user ${req.user.id}`);

    // Notify via WebSocket
    broadcast({
      type: 'file_uploaded',
      filename: req.file.filename,
      userId: req.user.id
    });

    res.json({
      success: true,
      filename: req.file.filename,
      size: req.file.size
    });
  } catch (e) {
    console.error('Upload error:', e);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Upload front/back pair
const pairUpload = multer({
  storage: storage,
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only image files allowed'));
    }
  }
}).fields([
  { name: 'front', maxCount: 1 },
  { name: 'back', maxCount: 1 }
]);

app.post('/api/upload-pair', authenticateToken, (req, res) => {
  pairUpload(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }

    try {
      const frontFile = req.files['front'] ? req.files['front'][0] : null;
      const backFile = req.files['back'] ? req.files['back'][0] : null;

      if (!frontFile) {
        return res.status(400).json({ error: 'Front image required' });
      }

      // Store pending pair in database (status: pending)
      await pool.query(`
        INSERT INTO cards (user_id, card_data, front_image_path, back_image_path, status)
        VALUES ($1, $2, $3, $4, 'pending')
      `, [
        req.user.id,
        JSON.stringify({ uploaded_at: new Date().toISOString() }),
        frontFile.filename,
        backFile ? backFile.filename : null
      ]);

      console.log(`[Upload] Pair: ${frontFile.filename}${backFile ? ' + ' + backFile.filename : ' (single)'}`);

      broadcast({
        type: 'pair_uploaded',
        front: frontFile.filename,
        back: backFile ? backFile.filename : null,
        userId: req.user.id
      });

      res.json({
        success: true,
        front: frontFile.filename,
        back: backFile ? backFile.filename : null
      });

    } catch (e) {
      console.error('Pair upload error:', e);
      res.status(500).json({ error: 'Upload failed' });
    }
  });
});

// ============================================
// IMPORT ENDPOINTS
// ============================================

app.post('/api/import/identify', authenticateToken, async (req, res) => {
  try {
    const results = req.body.results;
    if (!Array.isArray(results)) {
      return res.status(400).json({ error: 'Results must be an array' });
    }

    const imageExts = ['.jpg', '.jpeg', '.png', '.webp'];
    let availableImages = [];
    try {
      availableImages = fs.readdirSync(FOLDERS.new).filter(f =>
        imageExts.includes(path.extname(f).toLowerCase())
      );
    } catch (e) {}

    let imported = 0;

    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      let filename = result.filename;
      if (!filename && availableImages[i]) {
        filename = availableImages[i];
      }

      const cardData = { ...result };
      delete cardData.filename;

      await pool.query(`
        INSERT INTO cards (user_id, card_data, front_image_path, status)
        VALUES ($1, $2, $3, 'identified')
      `, [req.user.id, JSON.stringify(cardData), filename]);

      // Move image
      if (filename) {
        const srcPath = path.join(FOLDERS.new, filename);
        const dstPath = path.join(FOLDERS.identified, filename);
        if (fs.existsSync(srcPath)) {
          try { fs.renameSync(srcPath, dstPath); } catch (e) {}
        }
      }

      imported++;
    }

    broadcast({ type: 'cards_imported', count: imported, userId: req.user.id });
    res.json({ success: true, imported });

  } catch (e) {
    console.error('Import error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ============================================
// PROCESSING ENDPOINTS (Identify & Price)
// ============================================

// Get user's API key
async function getUserApiKey(userId) {
  try {
    const result = await pool.query('SELECT api_key FROM users WHERE id = $1', [userId]);
    if (result.rows.length > 0 && result.rows[0].api_key) {
      return result.rows[0].api_key;
    }
  } catch (e) {}
  return process.env.ANTHROPIC_API_KEY || null;
}

// Convert image to base64
function imageToBase64(imagePath) {
  const buffer = fs.readFileSync(imagePath);
  const ext = path.extname(imagePath).toLowerCase();
  const mediaTypes = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.webp': 'image/webp'
  };
  return {
    type: 'base64',
    media_type: mediaTypes[ext] || 'image/jpeg',
    data: buffer.toString('base64')
  };
}

// Identify cards endpoint
app.post('/api/process/identify', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    // Get API key
    const apiKey = await getUserApiKey(userId);
    if (!apiKey) {
      return res.status(400).json({ error: 'No API key configured. Add your Anthropic API key in Settings.' });
    }

    // Get pending cards from database
    const pendingResult = await pool.query(`
      SELECT * FROM cards WHERE user_id = $1 AND status = 'pending'
      ORDER BY created_at
    `, [userId]);

    if (pendingResult.rows.length === 0) {
      return res.status(400).json({ error: 'No pending cards to identify. Upload images first.' });
    }

    const pendingCards = pendingResult.rows;

    // Initialize Anthropic
    const Anthropic = require('@anthropic-ai/sdk');
    const anthropic = new Anthropic({ apiKey });

    // Send initial response
    res.json({
      success: true,
      message: `Processing ${pendingCards.length} cards...`,
      count: pendingCards.length
    });

    // Process each card
    let processed = 0;
    let totalCost = 0;

    for (const card of pendingCards) {
      try {
        const frontPath = path.join(FOLDERS.new, card.front_image_path);
        const backPath = card.back_image_path ? path.join(FOLDERS.new, card.back_image_path) : null;

        broadcast({
          type: 'identify_progress',
          current: processed + 1,
          total: pendingCards.length,
          filename: card.front_image_path,
          userId
        });

        // Build content with images
        const content = [];

        // Add front image
        if (fs.existsSync(frontPath)) {
          content.push({ type: 'image', source: imageToBase64(frontPath) });
        }

        // Add back image if exists
        if (backPath && fs.existsSync(backPath)) {
          content.push({ type: 'image', source: imageToBase64(backPath) });
        }

        // Add prompt
        const hasBack = backPath && fs.existsSync(backPath);
        content.push({
          type: 'text',
          text: `Analyze this sports card${hasBack ? ' (front and back images provided)' : ' image'} and identify it.

${hasBack ? 'I have provided both the FRONT and BACK of the card. Use both images to accurately identify it.' : 'This appears to be a single image (likely a graded/slabbed card).'}

Return ONLY a JSON object with these fields (no other text):
{
  "player": "Full player name",
  "year": 2024,
  "set_name": "Full set name (e.g., Topps Chrome, Panini Prizm)",
  "card_number": "Card number",
  "parallel": "Parallel type if any (Base, Refractor, Silver, Gold, etc.)",
  "numbered": "Serial numbering if any (/99, /25, etc.) or null",
  "team": "Team name",
  "sport": "Sport (Baseball, Basketball, Football, Hockey, Soccer, Pokemon)",
  "is_graded": true,
  "grading_company": "PSA, BGS, SGC, CGC, or null if raw",
  "grade": "Grade number (10, 9.5, 9, etc.) or null",
  "cert_number": "Certification number or null",
  "condition": "mint, near_mint, excellent, good, fair, poor",
  "confidence": "high, medium, or low",
  "notes": "Any special observations"
}`
        });

        const response = await anthropic.messages.create({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 1024,
          messages: [{ role: 'user', content }]
        });

        const textContent = response.content.find(c => c.type === 'text');
        const jsonMatch = textContent?.text?.match(/\{[\s\S]*\}/);

        if (jsonMatch) {
          const cardData = JSON.parse(jsonMatch[0]);
          cardData.identified_at = new Date().toISOString();

          // Calculate cost
          const inputTokens = response.usage?.input_tokens || 0;
          const outputTokens = response.usage?.output_tokens || 0;
          const cost = (inputTokens / 1000000) * 3 + (outputTokens / 1000000) * 15;
          totalCost += cost;

          // Update card in database
          await pool.query(`
            UPDATE cards SET card_data = $1, status = 'identified'
            WHERE id = $2
          `, [JSON.stringify(cardData), card.id]);

          // Track API usage
          await pool.query(`
            INSERT INTO api_usage (user_id, operation, model_used, tokens_input, tokens_output, cost)
            VALUES ($1, 'identify', 'sonnet4', $2, $3, $4)
          `, [userId, inputTokens, outputTokens, cost]);

          // Move images to identified folder
          if (fs.existsSync(frontPath)) {
            const dstPath = path.join(FOLDERS.identified, card.front_image_path);
            try { fs.renameSync(frontPath, dstPath); } catch (e) {}
          }
          if (backPath && fs.existsSync(backPath)) {
            const dstPath = path.join(FOLDERS.identified, card.back_image_path);
            try { fs.renameSync(backPath, dstPath); } catch (e) {}
          }
        }

        processed++;
      } catch (e) {
        console.error(`Error identifying card ${card.id}:`, e.message);
      }
    }

    broadcast({
      type: 'identify_complete',
      processed,
      total: pendingCards.length,
      cost: totalCost,
      userId
    });

  } catch (e) {
    console.error('Identify error:', e);
    broadcast({ type: 'identify_error', error: e.message, userId });
  }
});

// Price cards endpoint
app.post('/api/process/price', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  console.log(`[Price] Starting pricing for user ${userId}`);

  try {
    // Get cards to price
    const cardsResult = await pool.query(`
      SELECT * FROM cards
      WHERE user_id = $1 AND status IN ('identified', 'approved')
      ORDER BY created_at
    `, [userId]);

    console.log(`[Price] Found ${cardsResult.rows.length} cards to price`);

    if (cardsResult.rows.length === 0) {
      return res.status(400).json({ error: 'No cards ready for pricing. Identify cards first.' });
    }

    const cards = cardsResult.rows;

    res.json({
      success: true,
      message: `Pricing ${cards.length} cards...`,
      count: cards.length
    });

    const axios = require('axios');
    const cheerio = require('cheerio');

    const BROWSER_HEADERS = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5'
    };

    let processed = 0;
    let totalValue = 0;

    for (const row of cards) {
      const card = row.card_data;

      broadcast({
        type: 'price_progress',
        current: processed + 1,
        total: cards.length,
        player: card.player,
        userId
      });

      try {
        // Build search query
        const parts = [card.year, card.set_name, card.player, card.card_number].filter(Boolean);
        const query = parts.join(' ');
        const ebayUrl = `https://www.ebay.com/sch/i.html?_nkw=${encodeURIComponent(query)}&LH_Complete=1&LH_Sold=1&_sop=13`;

        console.log(`[Price] Searching: "${query}"`);

        // Scrape eBay
        let ebayPrices = [];
        try {
          const response = await axios.get(ebayUrl, {
            headers: BROWSER_HEADERS,
            timeout: 15000
          });

          console.log(`[Price] eBay response: ${response.status}, ${response.data.length} bytes`);

          const $ = cheerio.load(response.data);
          $('.s-item').each((idx, el) => {
            if (idx === 0) return;
            const priceText = $(el).find('.s-item__price').text().trim();
            if (priceText && !priceText.includes(' to ')) {
              const price = parseFloat(priceText.replace(/[^0-9.]/g, ''));
              if (price > 0.5 && price < 50000) {
                ebayPrices.push(price);
              }
            }
          });

          console.log(`[Price] Found ${ebayPrices.length} prices for "${card.player}"`);
        } catch (e) {
          console.error(`[Price] eBay scrape error for "${query}":`, e.message);
        }

        // Calculate price
        let recommendedPrice = null;
        let confidence = 'none';
        let pricingMethod = 'manual';

        if (ebayPrices.length >= 3) {
          ebayPrices.sort((a, b) => a - b);
          recommendedPrice = ebayPrices.reduce((a, b) => a + b, 0) / ebayPrices.length;
          recommendedPrice = Math.round(recommendedPrice * 100) / 100;
          confidence = 'high';
          pricingMethod = 'scraped';
          totalValue += recommendedPrice;
        } else if (ebayPrices.length > 0) {
          recommendedPrice = ebayPrices.reduce((a, b) => a + b, 0) / ebayPrices.length;
          recommendedPrice = Math.round(recommendedPrice * 100) / 100;
          confidence = 'medium';
          pricingMethod = 'scraped';
          totalValue += recommendedPrice;
        }

        // Update card in database
        const updatedData = {
          ...card,
          recommended_price: recommendedPrice,
          confidence,
          pricing_method: pricingMethod,
          ebay_url: ebayUrl,
          sample_size: ebayPrices.length,
          priced_at: new Date().toISOString()
        };

        await pool.query(`
          UPDATE cards SET card_data = $1, status = 'priced'
          WHERE id = $2
        `, [JSON.stringify(updatedData), row.id]);

        // Move image if exists
        if (row.front_image_path) {
          const srcPath = path.join(FOLDERS.identified, row.front_image_path);
          const dstPath = path.join(FOLDERS.priced, row.front_image_path);
          if (fs.existsSync(srcPath)) {
            try { fs.renameSync(srcPath, dstPath); } catch (e) {}
          }
        }

        processed++;

        // Rate limiting
        await new Promise(r => setTimeout(r, 1000));

      } catch (e) {
        console.error(`Error pricing card:`, e.message);
      }
    }

    broadcast({
      type: 'price_complete',
      processed,
      total: cards.length,
      totalValue,
      userId
    });

  } catch (e) {
    console.error('Price error:', e);
    broadcast({ type: 'price_error', error: e.message, userId });
  }
});

// ============================================
// WEBSOCKET
// ============================================

const clients = new Map(); // Map of userId -> Set of WebSocket connections

wss.on('connection', (ws, req) => {
  let userId = null;

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);

      // Handle authentication
      if (data.type === 'auth' && data.token) {
        jwt.verify(data.token, JWT_SECRET, (err, user) => {
          if (!err) {
            userId = user.id;
            if (!clients.has(userId)) {
              clients.set(userId, new Set());
            }
            clients.get(userId).add(ws);
            ws.send(JSON.stringify({ type: 'authenticated' }));
          }
        });
      }
    } catch (e) {}
  });

  ws.on('close', () => {
    if (userId && clients.has(userId)) {
      clients.get(userId).delete(ws);
      if (clients.get(userId).size === 0) {
        clients.delete(userId);
      }
    }
  });
});

function broadcast(message) {
  const data = JSON.stringify(message);

  // If message has userId, only send to that user
  if (message.userId) {
    const userClients = clients.get(message.userId);
    if (userClients) {
      userClients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(data);
        }
      });
    }
  } else {
    // Broadcast to all
    clients.forEach((userClients) => {
      userClients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(data);
        }
      });
    });
  }
}

// ============================================
// FILE WATCHER
// ============================================

const watcher = chokidar.watch([FOLDERS.new, FOLDERS.identified, FOLDERS.priced], {
  ignoreInitial: true,
  awaitWriteFinish: { stabilityThreshold: 1000 }
});

watcher.on('add', (filePath) => {
  const ext = path.extname(filePath).toLowerCase();
  if (['.jpg', '.jpeg', '.png', '.webp'].includes(ext)) {
    console.log('New file detected:', path.basename(filePath));
    broadcast({ type: 'file_added', file: path.basename(filePath) });
  }
});

// ============================================
// PAGE ROUTES
// ============================================

// Serve login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Serve register page
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

// Serve admin page
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Default route - serve main dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ============================================
// START SERVER
// ============================================

const HOST = process.env.NODE_ENV === 'production' ? '0.0.0.0' : 'localhost';

server.listen(PORT, HOST, () => {
  console.log(`
══════════════════════════════════════════════════
  CARDFLOW v2.0 - Multi-User SaaS
══════════════════════════════════════════════════

  Server:    http://${HOST}:${PORT}
  Dashboard: http://localhost:${PORT}
  Login:     http://localhost:${PORT}/login
  Register:  http://localhost:${PORT}/register
  Admin:     http://localhost:${PORT}/admin

  Database:  ${dbAvailable ? 'PostgreSQL' : 'File-based (fallback)'}

══════════════════════════════════════════════════
  `);
});
