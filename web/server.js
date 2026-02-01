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
const crypto = require('crypto');
const axios = require('axios');

// eBay OAuth Config
const EBAY_APP_ID = process.env.EBAY_APP_ID;
const EBAY_CERT_ID = process.env.EBAY_CERT_ID;
const EBAY_DEV_ID = process.env.EBAY_DEV_ID;
const EBAY_REDIRECT_URI = process.env.EBAY_REDIRECT_URI ||
  (process.env.NODE_ENV === 'production'
    ? 'https://cardflow.be1st.io/api/ebay/callback'
    : 'http://localhost:3005/api/ebay/callback');
const FRONTEND_URL = process.env.FRONTEND_URL ||
  (process.env.NODE_ENV === 'production'
    ? 'https://cardflow.be1st.io'
    : 'http://localhost:3005');

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

// Configure Cloudinary for persistent image storage
const cloudinary = require('cloudinary').v2;
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Helper: Upload buffer to Cloudinary
async function uploadToCloudinary(buffer, folder = 'cards') {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: `cardflow/${folder}`,
        resource_type: 'image',
        format: 'jpg',
        quality: 'auto:good'
      },
      (error, result) => {
        if (error) reject(error);
        else resolve(result);
      }
    );
    uploadStream.end(buffer);
  });
}

// Configure multer for memory storage (upload to Cloudinary)
const memoryStorage = multer.memoryStorage();

const upload = multer({
  storage: memoryStorage,
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

// Upload front/back pair with Cloudinary storage
const pairUpload = multer({
  storage: memoryStorage,
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

      // Check if Cloudinary is configured
      const useCloudinary = process.env.CLOUDINARY_CLOUD_NAME &&
                            process.env.CLOUDINARY_API_KEY &&
                            process.env.CLOUDINARY_API_SECRET;

      let frontUrl, backUrl;

      if (useCloudinary) {
        // Upload to Cloudinary for persistent storage
        console.log('[Upload] Uploading to Cloudinary...');

        const frontResult = await uploadToCloudinary(frontFile.buffer, `user-${req.user.id}`);
        frontUrl = frontResult.secure_url;
        console.log('[Upload] Front uploaded:', frontUrl);

        if (backFile) {
          const backResult = await uploadToCloudinary(backFile.buffer, `user-${req.user.id}`);
          backUrl = backResult.secure_url;
          console.log('[Upload] Back uploaded:', backUrl);
        }
      } else {
        // Fallback to local storage (won't persist on Railway restart)
        console.log('[Upload] WARNING: Cloudinary not configured, using local storage');
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);

        const frontFilename = `front-${uniqueSuffix}.jpg`;
        const frontPath = path.join(FOLDERS.new, frontFilename);
        await fs.writeFile(frontPath, frontFile.buffer);
        frontUrl = frontFilename;

        if (backFile) {
          const backFilename = `back-${uniqueSuffix}.jpg`;
          const backPath = path.join(FOLDERS.new, backFilename);
          await fs.writeFile(backPath, backFile.buffer);
          backUrl = backFilename;
        }
      }

      // Store in database
      await pool.query(`
        INSERT INTO cards (user_id, card_data, front_image_path, back_image_path, status)
        VALUES ($1, $2, $3, $4, 'pending')
      `, [
        req.user.id,
        JSON.stringify({ uploaded_at: new Date().toISOString(), cloudinary: useCloudinary }),
        frontUrl,
        backUrl || null
      ]);

      console.log(`[Upload] Pair saved: ${frontUrl}${backUrl ? ' + ' + backUrl : ' (single)'}`);

      broadcast({
        type: 'pair_uploaded',
        front: frontUrl,
        back: backUrl || null,
        userId: req.user.id
      });

      res.json({
        success: true,
        front: frontUrl,
        back: backUrl || null,
        cloudinary: useCloudinary
      });

    } catch (e) {
      console.error('Pair upload error:', e);
      res.status(500).json({ error: 'Upload failed: ' + e.message });
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

// Convert image to base64 (local file)
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

// Convert image to base64 - handles both URLs (Cloudinary) and local files
async function getImageBase64(imagePathOrUrl, folder = null) {
  // Check if it's a URL (Cloudinary)
  if (imagePathOrUrl.startsWith('http://') || imagePathOrUrl.startsWith('https://')) {
    console.log('[Identify] Fetching image from URL:', imagePathOrUrl.substring(0, 60) + '...');
    const response = await axios.get(imagePathOrUrl, { responseType: 'arraybuffer', timeout: 30000 });
    const buffer = Buffer.from(response.data);
    const contentType = response.headers['content-type'] || 'image/jpeg';
    return {
      type: 'base64',
      media_type: contentType,
      data: buffer.toString('base64')
    };
  }

  // Local file path
  const localPath = folder ? path.join(folder, imagePathOrUrl) : imagePathOrUrl;
  if (!fs.existsSync(localPath)) {
    console.error('[Identify] Local file not found:', localPath);
    return null;
  }

  console.log('[Identify] Reading local file:', localPath);
  return imageToBase64(localPath);
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
        broadcast({
          type: 'identify_progress',
          current: processed + 1,
          total: pendingCards.length,
          filename: card.front_image_path,
          userId
        });

        // Build content with images - handles both Cloudinary URLs and local files
        const content = [];
        let hasBack = false;

        // Add front image
        const frontImageData = await getImageBase64(card.front_image_path, FOLDERS.new);
        if (frontImageData) {
          content.push({ type: 'image', source: frontImageData });
          console.log('[Identify] Front image added to request');
        } else {
          console.error('[Identify] FAILED to load front image:', card.front_image_path);
        }

        // Add back image if exists
        if (card.back_image_path) {
          const backImageData = await getImageBase64(card.back_image_path, FOLDERS.new);
          if (backImageData) {
            content.push({ type: 'image', source: backImageData });
            hasBack = true;
            console.log('[Identify] Back image added to request');
          }
        }

        // Check if we have at least the front image
        if (content.length === 0) {
          console.error('[Identify] NO IMAGES LOADED for card:', card.id);
          processed++;
          continue;
        }
        content.push({
          type: 'text',
          text: `CAREFULLY analyze this sports card image and identify it accurately.

IMPORTANT INSTRUCTIONS:
1. LOOK AT THE ACTUAL CARD IMAGE - identify the player shown on the card
2. READ THE PLAYER NAME printed on the card itself
3. If this is a GRADED/SLABBED card, READ THE GRADING LABEL carefully:
   - The PSA/BGS/SGC label contains the player name, year, set, and card number
   - Read the certification number from the label
   - Read the grade from the label
4. Do NOT guess or assume - only report what you can actually see in the image
5. If you cannot clearly identify something, set confidence to "low"

${hasBack ? 'I have provided both the FRONT and BACK of the card. Use both images.' : 'This is a single image (likely a graded/slabbed card). Read the label text carefully.'}

Return ONLY a JSON object with these fields (no other text):
{
  "player": "Full player name AS SHOWN ON CARD/LABEL",
  "year": 2024,
  "set_name": "Full set name (e.g., Topps Chrome, Panini Prizm)",
  "card_number": "Card number from label or card",
  "parallel": "Parallel type if any (Base, Refractor, Silver, Gold, etc.)",
  "numbered": "Serial numbering if any (/99, /25, etc.) or null",
  "team": "Team name visible on card",
  "sport": "Sport (Baseball, Basketball, Football, Hockey, Soccer, Pokemon)",
  "is_graded": true,
  "grading_company": "PSA, BGS, SGC, CGC - READ FROM LABEL",
  "grade": "Grade number from label (10, 9.5, 9, etc.)",
  "cert_number": "Certification number from label",
  "condition": "mint, near_mint, excellent, good, fair, poor",
  "confidence": "high, medium, or low - be honest if unclear",
  "notes": "What text did you read from the grading label?"
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

          // Move local images to identified folder (skip for Cloudinary URLs)
          const isCloudinaryFront = card.front_image_path.startsWith('http');
          if (!isCloudinaryFront) {
            const frontPath = path.join(FOLDERS.new, card.front_image_path);
            if (fs.existsSync(frontPath)) {
              const dstPath = path.join(FOLDERS.identified, card.front_image_path);
              try { fs.renameSync(frontPath, dstPath); } catch (e) {}
            }
          }
          if (card.back_image_path && !card.back_image_path.startsWith('http')) {
            const backPath = path.join(FOLDERS.new, card.back_image_path);
            if (fs.existsSync(backPath)) {
              const dstPath = path.join(FOLDERS.identified, card.back_image_path);
              try { fs.renameSync(backPath, dstPath); } catch (e) {}
            }
          }

          console.log(`[Identify] Card ${card.id} identified as: ${cardData.player} - ${cardData.year} ${cardData.set_name}`);
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

    // SlabTrack browser headers - full set for legitimacy
    const BROWSER_HEADERS = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'DNT': '1',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1'
    };

    // Build cascading search queries (specific to broad)
    function buildQueries(card) {
      const queries = [];
      const player = card.player || '';
      const year = card.year || '';
      const setName = card.set_name || '';
      const cardNum = card.card_number || '';
      const parallel = card.parallel && card.parallel !== 'Base' ? card.parallel : '';
      const gradeStr = card.is_graded ? `${card.grading_company} ${card.grade}` : '';

      // Query 1: Full with grade
      if (gradeStr) {
        queries.push([year, setName, player, cardNum, parallel, gradeStr].filter(Boolean).join(' '));
      }
      // Query 2: Full without grade
      queries.push([year, setName, player, cardNum, parallel].filter(Boolean).join(' '));
      // Query 3: Without card number
      queries.push([year, setName, player, parallel].filter(Boolean).join(' '));
      // Query 4: Without parallel
      queries.push([year, setName, player].filter(Boolean).join(' '));
      // Query 5: Just year + player
      if (year && player) queries.push(`${year} ${player}`);

      return [...new Set(queries)].filter(q => q.length > 0);
    }

    // Scrape eBay with cascading queries
    async function scrapeEbay(queries) {
      for (let i = 0; i < Math.min(queries.length, 4); i++) {
        const query = queries[i];
        const url = `https://www.ebay.com/sch/i.html?_nkw=${encodeURIComponent(query)}&LH_Complete=1&LH_Sold=1&_sop=13`;

        console.log(`[Price] Query ${i + 1}/${queries.length}: "${query}"`);

        try {
          const response = await axios.get(url, {
            headers: { ...BROWSER_HEADERS, 'Referer': 'https://www.ebay.com/' },
            timeout: 15000
          });

          console.log(`[Price] Response: ${response.status}, ${response.data.length} bytes`);

          const $ = cheerio.load(response.data);

          // Debug: Check what we're getting
          const itemCount = $('.s-item').length;
          const title = $('title').text();
          console.log(`[Price] Page title: "${title.substring(0, 50)}...", Items found: ${itemCount}`);

          // Check if we got a captcha or error page
          if (response.data.includes('captcha') || response.data.includes('robot')) {
            console.log('[Price] WARNING: Possible captcha/bot detection');
          }

          const prices = [];

          $('.s-item').each((idx, el) => {
            if (idx === 0) return; // Skip header
            const priceText = $(el).find('.s-item__price').text().trim();
            if (priceText && !priceText.includes(' to ')) {
              const price = parseFloat(priceText.replace(/[^0-9.]/g, ''));
              if (price > 0.5 && price < 50000) {
                prices.push(price);
              }
            }
          });

          console.log(`[Price] Found ${prices.length} prices`);

          if (prices.length >= 3) {
            prices.sort((a, b) => a - b);
            return {
              success: true,
              prices,
              avg: prices.reduce((a, b) => a + b, 0) / prices.length,
              low: prices[0],
              high: prices[prices.length - 1],
              query,
              url
            };
          }

          // Wait before trying next query
          await new Promise(r => setTimeout(r, 500));

        } catch (e) {
          console.error(`[Price] Error: ${e.message}`);
          if (e.response?.status === 429 || e.response?.status === 503) {
            console.log('[Price] Rate limited, stopping');
            break;
          }
        }
      }
      return { success: false, prices: [], query: queries[0], url: `https://www.ebay.com/sch/i.html?_nkw=${encodeURIComponent(queries[0])}&LH_Complete=1&LH_Sold=1` };
    }

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
        const queries = buildQueries(card);
        console.log(`[Price] ${card.player}: ${queries.length} queries`);

        const result = await scrapeEbay(queries);

        let recommendedPrice = null;
        let confidence = 'none';
        let pricingMethod = 'manual';

        if (result.success) {
          recommendedPrice = Math.round(result.avg * 100) / 100;
          confidence = result.prices.length >= 5 ? 'high' : 'medium';
          pricingMethod = 'scraped';
          totalValue += recommendedPrice;
          console.log(`[Price] ${card.player}: $${recommendedPrice} (${result.prices.length} sales)`);
        } else {
          console.log(`[Price] ${card.player}: No prices found`);
        }

        // Update card in database
        const updatedData = {
          ...card,
          recommended_price: recommendedPrice,
          confidence,
          pricing_method: pricingMethod,
          ebay_url: result.url,
          ebay_low: result.low || null,
          ebay_high: result.high || null,
          sample_size: result.prices.length,
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
// EBAY OAUTH ROUTES
// ============================================

// eBay OAuth Status
app.get('/api/ebay/status', authenticateToken, async (req, res) => {
  try {
    const tokenResult = await pool.query(
      'SELECT created_at, ebay_user_id FROM ebay_user_tokens WHERE user_id = $1',
      [req.user.id]
    );

    const userResult = await pool.query(
      'SELECT ebay_payment_policy_id, ebay_return_policy_id, ebay_fulfillment_policy_id, ebay_merchant_location_key FROM users WHERE id = $1',
      [req.user.id]
    );

    const policies = userResult.rows[0] || {};

    res.json({
      success: true,
      connected: tokenResult.rows.length > 0,
      connectedAt: tokenResult.rows[0]?.created_at || null,
      ebayUserId: tokenResult.rows[0]?.ebay_user_id || null,
      policies: {
        paymentPolicyId: policies.ebay_payment_policy_id || null,
        returnPolicyId: policies.ebay_return_policy_id || null,
        fulfillmentPolicyId: policies.ebay_fulfillment_policy_id || null
      }
    });
  } catch (error) {
    console.error('eBay status error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to check eBay status' });
  }
});

// eBay OAuth Connect - Initiate OAuth flow
app.get('/api/ebay/connect', authenticateToken, async (req, res) => {
  try {
    if (!EBAY_APP_ID || !EBAY_CERT_ID) {
      return res.status(500).json({
        success: false,
        error: 'eBay integration not configured. Add EBAY_APP_ID and EBAY_CERT_ID to environment.'
      });
    }

    // Generate cryptographically secure state token
    const state = crypto.randomBytes(32).toString('hex');

    // Store state with user ID (with expiry)
    await pool.query(`
      INSERT INTO ebay_oauth_states (user_id, state, expires_at)
      VALUES ($1, $2, NOW() + INTERVAL '10 minutes')
      ON CONFLICT (user_id)
      DO UPDATE SET state = EXCLUDED.state, expires_at = EXCLUDED.expires_at
    `, [req.user.id, state]);

    console.log('[eBay] OAuth initiated for user:', req.user.id);

    // Build OAuth URL
    const scopes = [
      'https://api.ebay.com/oauth/api_scope/sell.inventory',
      'https://api.ebay.com/oauth/api_scope/sell.inventory.readonly',
      'https://api.ebay.com/oauth/api_scope/sell.fulfillment',
      'https://api.ebay.com/oauth/api_scope/sell.fulfillment.readonly',
      'https://api.ebay.com/oauth/api_scope/sell.account',
      'https://api.ebay.com/oauth/api_scope/sell.account.readonly'
    ].join(' ');

    const authUrl = `https://auth.ebay.com/oauth2/authorize?` +
      `client_id=${encodeURIComponent(EBAY_APP_ID)}&` +
      `response_type=code&` +
      `redirect_uri=${encodeURIComponent(EBAY_REDIRECT_URI)}&` +
      `scope=${encodeURIComponent(scopes)}&` +
      `state=${state}`;

    res.json({ success: true, authUrl });

  } catch (error) {
    console.error('eBay connect error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to initiate eBay connection' });
  }
});

// eBay OAuth Callback
app.get('/api/ebay/callback', async (req, res) => {
  try {
    const { code, state, error: oauthError } = req.query;

    if (oauthError) {
      console.error('eBay OAuth error:', oauthError);
      return res.redirect(`${FRONTEND_URL}?ebay_error=oauth_denied`);
    }

    if (!code || !state) {
      return res.redirect(`${FRONTEND_URL}?ebay_error=missing_params`);
    }

    // Verify state and get user ID
    const stateResult = await pool.query(
      `SELECT user_id FROM ebay_oauth_states WHERE state = $1 AND expires_at > NOW()`,
      [state]
    );

    if (stateResult.rows.length === 0) {
      return res.redirect(`${FRONTEND_URL}?ebay_error=expired_state`);
    }

    const userId = stateResult.rows[0].user_id;
    console.log('[eBay] Valid OAuth state for user:', userId);

    // Exchange code for tokens
    const auth = Buffer.from(`${EBAY_APP_ID}:${EBAY_CERT_ID}`).toString('base64');

    const tokenResponse = await axios.post(
      'https://api.ebay.com/identity/v1/oauth2/token',
      `grant_type=authorization_code&code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(EBAY_REDIRECT_URI)}`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${auth}`
        },
        timeout: 10000
      }
    );

    const { access_token, refresh_token, expires_in } = tokenResponse.data;

    if (!access_token || !refresh_token) {
      return res.redirect(`${FRONTEND_URL}?ebay_error=invalid_response`);
    }

    const expiresAt = new Date(Date.now() + (expires_in * 1000));

    // Store tokens
    await pool.query(`
      INSERT INTO ebay_user_tokens (user_id, access_token, refresh_token, token_expires_at, updated_at)
      VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
      ON CONFLICT (user_id)
      DO UPDATE SET
        access_token = EXCLUDED.access_token,
        refresh_token = EXCLUDED.refresh_token,
        token_expires_at = EXCLUDED.token_expires_at,
        updated_at = CURRENT_TIMESTAMP
    `, [userId, access_token, refresh_token, expiresAt]);

    // Clean up used state
    await pool.query('DELETE FROM ebay_oauth_states WHERE user_id = $1', [userId]);

    console.log('[eBay] OAuth successful for user:', userId);

    // Auto-create business policies
    await autoCreateEbayPolicies(userId, access_token);

    res.redirect(`${FRONTEND_URL}?ebay_success=true`);

  } catch (error) {
    console.error('eBay callback error:', error.message);
    res.redirect(`${FRONTEND_URL}?ebay_error=connection_failed`);
  }
});

// eBay Disconnect
app.post('/api/ebay/disconnect', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM ebay_user_tokens WHERE user_id = $1 RETURNING id',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'No eBay connection found' });
    }

    // Clear policy IDs
    await pool.query(`
      UPDATE users SET
        ebay_payment_policy_id = NULL,
        ebay_return_policy_id = NULL,
        ebay_fulfillment_policy_id = NULL
      WHERE id = $1
    `, [req.user.id]);

    console.log('[eBay] Disconnected for user:', req.user.id);
    res.json({ success: true });

  } catch (error) {
    console.error('eBay disconnect error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to disconnect eBay' });
  }
});

// Helper: Get valid user eBay token (with auto-refresh)
async function getUserEbayToken(userId) {
  const result = await pool.query(
    'SELECT * FROM ebay_user_tokens WHERE user_id = $1',
    [userId]
  );

  if (result.rows.length === 0) {
    throw new Error('eBay account not connected');
  }

  const tokenData = result.rows[0];

  // Check if token needs refresh (5 minute buffer)
  const needsRefresh = new Date(tokenData.token_expires_at) < new Date(Date.now() + 5 * 60 * 1000);

  if (needsRefresh) {
    console.log('[eBay] Refreshing token for user:', userId);

    const auth = Buffer.from(`${EBAY_APP_ID}:${EBAY_CERT_ID}`).toString('base64');

    const refreshResponse = await axios.post(
      'https://api.ebay.com/identity/v1/oauth2/token',
      `grant_type=refresh_token&refresh_token=${encodeURIComponent(tokenData.refresh_token)}`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${auth}`
        },
        timeout: 10000
      }
    );

    const { access_token, expires_in } = refreshResponse.data;
    const expiresAt = new Date(Date.now() + (expires_in * 1000));

    await pool.query(`
      UPDATE ebay_user_tokens
      SET access_token = $1, token_expires_at = $2, updated_at = CURRENT_TIMESTAMP
      WHERE user_id = $3
    `, [access_token, expiresAt, userId]);

    console.log('[eBay] Token refreshed for user:', userId);
    return access_token;
  }

  return tokenData.access_token;
}

// Helper: Fetch or create eBay business policies
async function autoCreateEbayPolicies(userId, accessToken) {
  try {
    console.log('[eBay] Fetching existing policies for user:', userId);

    const headers = {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
};

    let paymentPolicyId = null;
    let returnPolicyId = null;
    let fulfillmentPolicyId = null;

    // 1. Try to get existing Payment Policy
    try {
      const paymentRes = await axios.get(
        'https://api.ebay.com/sell/account/v1/payment_policy?marketplace_id=EBAY_US',
        { headers }
      );
      if (paymentRes.data.paymentPolicies?.length > 0) {
        paymentPolicyId = paymentRes.data.paymentPolicies[0].paymentPolicyId;
        console.log('[eBay] Found existing payment policy:', paymentPolicyId);
      }
    } catch (e) {
      console.log('[eBay] No existing payment policies found');
    }

    // 2. Try to get existing Return Policy
    try {
      const returnRes = await axios.get(
        'https://api.ebay.com/sell/account/v1/return_policy?marketplace_id=EBAY_US',
        { headers }
      );
      if (returnRes.data.returnPolicies?.length > 0) {
        returnPolicyId = returnRes.data.returnPolicies[0].returnPolicyId;
        console.log('[eBay] Found existing return policy:', returnPolicyId);
      }
    } catch (e) {
      console.log('[eBay] No existing return policies found');
    }

    // 3. Try to get existing Fulfillment Policy
    try {
      const fulfillmentRes = await axios.get(
        'https://api.ebay.com/sell/account/v1/fulfillment_policy?marketplace_id=EBAY_US',
        { headers }
      );
      if (fulfillmentRes.data.fulfillmentPolicies?.length > 0) {
        fulfillmentPolicyId = fulfillmentRes.data.fulfillmentPolicies[0].fulfillmentPolicyId;
        console.log('[eBay] Found existing fulfillment policy:', fulfillmentPolicyId);
      }
    } catch (e) {
      console.log('[eBay] No existing fulfillment policies found');
    }

    // Create any missing policies
    if (!paymentPolicyId) {
      console.log('[eBay] Creating payment policy...');
      const paymentResponse = await axios.post(
        'https://api.ebay.com/sell/account/v1/payment_policy',
        {
          name: `CardFlow Payment`,
          description: 'Immediate payment required',
          marketplaceId: 'EBAY_US',
          categoryTypes: [{ name: 'ALL_EXCLUDING_MOTORS_VEHICLES' }],
          immediatePay: true
        },
        { headers }
      );
      paymentPolicyId = paymentResponse.data.paymentPolicyId;
      console.log('[eBay] Payment policy created:', paymentPolicyId);
    }

    if (!returnPolicyId) {
      console.log('[eBay] Creating return policy...');
      const returnResponse = await axios.post(
        'https://api.ebay.com/sell/account/v1/return_policy',
        {
          name: `CardFlow Returns`,
          description: 'No returns accepted',
          marketplaceId: 'EBAY_US',
          categoryTypes: [{ name: 'ALL_EXCLUDING_MOTORS_VEHICLES' }],
          returnsAccepted: false
        },
        { headers }
      );
      returnPolicyId = returnResponse.data.returnPolicyId;
      console.log('[eBay] Return policy created:', returnPolicyId);
    }

    if (!fulfillmentPolicyId) {
      console.log('[eBay] Creating fulfillment policy...');
      const fulfillmentResponse = await axios.post(
        'https://api.ebay.com/sell/account/v1/fulfillment_policy',
        {
          name: `CardFlow Shipping`,
          description: 'USPS First Class shipping',
          marketplaceId: 'EBAY_US',
          categoryTypes: [{ name: 'ALL_EXCLUDING_MOTORS_VEHICLES' }],
          handlingTime: { value: 1, unit: 'DAY' },
          shipToLocations: {
            regionIncluded: [{ regionName: 'US', regionType: 'COUNTRY' }]
          },
          shippingOptions: [{
            optionType: 'DOMESTIC',
            costType: 'FLAT_RATE',
            shippingServices: [{
              shippingCarrierCode: 'USPS',
              shippingServiceCode: 'USPSFirstClass',
              shippingCost: { value: '4.99', currency: 'USD' },
              freeShipping: false,
              sortOrder: 1
            }]
          }],
          globalShipping: false,
          pickupDropOff: false
        },
        { headers }
      );
      fulfillmentPolicyId = fulfillmentResponse.data.fulfillmentPolicyId;
      console.log('[eBay] Fulfillment policy created:', fulfillmentPolicyId);
    }

    // 4. Try to get or create inventory location
    let merchantLocationKey = null;
    try {
      const locationRes = await axios.get(
        'https://api.ebay.com/sell/inventory/v1/location?limit=1',
        { headers }
      );
      if (locationRes.data.locations?.length > 0) {
        merchantLocationKey = locationRes.data.locations[0].merchantLocationKey;
        console.log('[eBay] Found existing location:', merchantLocationKey);
      }
    } catch (e) {
      console.log('[eBay] No existing locations found, will create one');
    }

    if (!merchantLocationKey) {
      try {
        merchantLocationKey = `cardflow_${userId}_${Date.now()}`;
        console.log('[eBay] Creating inventory location:', merchantLocationKey);
        await axios.post(
          `https://api.ebay.com/sell/inventory/v1/location/${merchantLocationKey}`,
          {
            location: {
              address: {
                city: 'New York',
                stateOrProvince: 'NY',
                postalCode: '10001',
                country: 'US'
              }
            },
            locationTypes: ['WAREHOUSE'],
            name: 'CardFlow Shipping Location',
            merchantLocationStatus: 'ENABLED'
          },
          { headers: { ...headers, 'Content-Language': 'en-US' } }
        );
        console.log('[eBay] Location created:', merchantLocationKey);
      } catch (locErr) {
        console.log('[eBay] Could not create location:', locErr.response?.data || locErr.message);
        // Use a default placeholder - some accounts may not support location API
        merchantLocationKey = 'default';
      }
    }

    // Save policy IDs and location to database
    await pool.query(`
      UPDATE users SET
        ebay_payment_policy_id = $1,
        ebay_return_policy_id = $2,
        ebay_fulfillment_policy_id = $3,
        ebay_merchant_location_key = $4
      WHERE id = $5
    `, [paymentPolicyId, returnPolicyId, fulfillmentPolicyId, merchantLocationKey, userId]);

    console.log('[eBay] All policies and location saved for user:', userId);
    return { success: true };

  } catch (error) {
    console.error('[eBay] Failed to setup policies:', error.response?.data || error.message);
    return { success: false, error: error.response?.data?.errors?.[0]?.longMessage || error.message };
  }
}

// Fix/Create eBay Business Policies
app.post('/api/ebay/create-policies', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    console.log('[eBay] Manual policy creation for user:', userId);

    // Get user's eBay token
    const accessToken = await getUserEbayToken(userId);

    // Create policies
    const result = await autoCreateEbayPolicies(userId, accessToken);

    if (result.success) {
      res.json({ success: true, message: 'eBay policies created successfully' });
    } else {
      res.status(500).json({ success: false, error: result.error || 'Failed to create policies' });
    }
  } catch (error) {
    console.error('[eBay] Create policies error:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// EBAY LISTING ROUTES
// ============================================

// Generate listing title (max 80 chars)
function generateListingTitle(card) {
  const parts = [];
  if (card.year) parts.push(card.year);
  if (card.set_name) parts.push(card.set_name.replace(/^\d{4}\s+/, ''));
  if (card.player) parts.push(card.player);
  if (card.card_number) parts.push(`#${card.card_number}`);
  if (card.grading_company && card.grade) {
    parts.push(`${card.grading_company} ${card.grade}`);
  }
  if (card.parallel && card.parallel !== 'Base') {
    parts.push(card.parallel);
  }

  let title = parts.join(' ');
  if (title.length > 80) {
    title = title.substring(0, 77) + '...';
  }
  return title;
}

// Generate listing description (HTML)
function generateListingDescription(card) {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #0654ba; text-align: center;">${card.year} ${card.set_name} - ${card.player}</h2>
      <div style="background: #f7f7f7; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3 style="margin-top: 0; color: #333;">Card Details</h3>
        <table style="width: 100%; border-collapse: collapse;">
          <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Player:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${card.player}</td></tr>
          <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Year:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${card.year}</td></tr>
          <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Set:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${card.set_name}</td></tr>
          <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Card Number:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">#${card.card_number || 'N/A'}</td></tr>
          <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Team:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${card.team || 'N/A'}</td></tr>
          ${card.grading_company ? `
          <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Grading:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${card.grading_company} ${card.grade}</td></tr>
          ` : ''}
          ${card.parallel && card.parallel !== 'Base' ? `
          <tr><td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Parallel:</strong></td><td style="padding: 8px; border-bottom: 1px solid #ddd;">${card.parallel}</td></tr>
          ` : ''}
        </table>
      </div>
      <div style="background: #e8f4f8; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3 style="margin-top: 0; color: #333;">Shipping & Returns</h3>
        <ul style="list-style: none; padding: 0;">
          <li style="margin: 8px 0;">Ships within 1 business day</li>
          <li style="margin: 8px 0;">Securely packed in sleeve & toploader</li>
          <li style="margin: 8px 0;">USPS First Class with tracking</li>
        </ul>
      </div>
      <p style="text-align: center; color: #666; font-size: 12px; margin-top: 30px;">
        Listed via <strong>CardFlow</strong>
      </p>
    </div>
  `.trim();
}

// List card on eBay
app.post('/api/ebay/list/:cardId', authenticateToken, async (req, res) => {
  try {
    const { cardId } = req.params;
    const { price, quantity = 1 } = req.body;

    if (!price || price <= 0) {
      return res.status(400).json({ success: false, error: 'Price is required' });
    }

    console.log(`[eBay] Creating listing for card ${cardId}...`);

    // Get card from database
    const cardResult = await pool.query(
      'SELECT * FROM cards WHERE id = $1 AND user_id = $2',
      [cardId, req.user.id]
    );

    if (cardResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Card not found' });
    }

    const row = cardResult.rows[0];
    const card = row.card_data;

    // Check if already listed
    const existingListing = await pool.query(
      'SELECT * FROM ebay_listings WHERE card_id = $1 AND status = $2',
      [cardId, 'active']
    );

    if (existingListing.rows.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'Card is already listed on eBay',
        listingId: existingListing.rows[0].ebay_listing_id
      });
    }

    // Get user's eBay token
    const accessToken = await getUserEbayToken(req.user.id);

    // Get user's policy IDs
    const userResult = await pool.query(
      'SELECT ebay_payment_policy_id, ebay_return_policy_id, ebay_fulfillment_policy_id, ebay_merchant_location_key FROM users WHERE id = $1',
      [req.user.id]
    );

    const policies = userResult.rows[0];
    if (!policies.ebay_payment_policy_id) {
      return res.status(400).json({
        success: false,
        error: 'eBay business policies not set up. Try disconnecting and reconnecting eBay.'
      });
    }

    const title = generateListingTitle(card);
    const description = generateListingDescription(card);
    const sku = `CF${cardId.replace(/-/g, '').substring(0, 20)}${Date.now().toString().slice(-8)}`;

    console.log('[eBay] Listing title:', title);
    console.log('[eBay] SKU:', sku, 'Length:', sku.length);

    // Step 1: Create inventory item
    // eBay trading cards: 2750 = Graded, 4000 = Ungraded
    const inventoryPayload = {
      availability: {
        shipToLocationAvailability: { quantity }
      },
      condition: card.is_graded ? 'LIKE_NEW' : 'USED_VERY_GOOD',
      conditionDescription: card.is_graded
        ? `${card.grading_company || 'PSA'} ${card.grade || '10'}`
        : 'Ungraded card in excellent condition',
      product: {
        title,
        description,
        aspects: {
          'Sport': [card.sport || 'Baseball'],
          'Player': [card.player],
          'Team': [card.team || 'N/A'],
          'Year': [String(card.year)],
          'Card Number': [card.card_number || 'N/A'],
          ...(card.grading_company && {
            'Professional Grader': [card.grading_company],
            'Grade': [String(card.grade)]
          }),
          ...(card.parallel && card.parallel !== 'Base' && {
            'Parallel/Variety': [card.parallel]
          })
        }
      }
    };

    await axios.put(
      `https://api.ebay.com/sell/inventory/v1/inventory_item/${sku}`,
      inventoryPayload,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Language': 'en-US'
        }
      }
    );

    console.log('[eBay] Inventory item created');

    // Step 2: Create offer
    const offerPayload = {
      sku,
      marketplaceId: 'EBAY_US',
      format: 'FIXED_PRICE',
      availableQuantity: quantity,
      categoryId: '261328', // Sports Trading Cards
      listingDescription: description,
      merchantLocationKey: policies.ebay_merchant_location_key || 'default',
      listingPolicies: {
        fulfillmentPolicyId: policies.ebay_fulfillment_policy_id,
        paymentPolicyId: policies.ebay_payment_policy_id,
        returnPolicyId: policies.ebay_return_policy_id
      },
      pricingSummary: {
        price: { value: String(price), currency: 'USD' }
      }
    };

    const offerResponse = await axios.post(
      'https://api.ebay.com/sell/inventory/v1/offer',
      offerPayload,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Language': 'en-US'
        }
      }
    );

    const offerId = offerResponse.data.offerId;
    console.log('[eBay] Offer created:', offerId);

    // Step 3: Publish listing
    const publishResponse = await axios.post(
      `https://api.ebay.com/sell/inventory/v1/offer/${offerId}/publish`,
      {},
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Language': 'en-US'
        }
      }
    );

    const listingId = publishResponse.data.listingId;
    console.log('[eBay] Listing published:', listingId);

    // Save listing to database
    await pool.query(`
      INSERT INTO ebay_listings (card_id, user_id, ebay_listing_id, ebay_url, sku, offer_id, price, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, 'active')
    `, [
      cardId,
      req.user.id,
      listingId,
      `https://www.ebay.com/itm/${listingId}`,
      sku,
      offerId,
      price
    ]);

    // Update card status
    await pool.query(`
      UPDATE cards SET status = 'listed', card_data = card_data || $1::jsonb
      WHERE id = $2
    `, [JSON.stringify({ ebay_listing_id: listingId, ebay_price: price, listed_at: new Date().toISOString() }), cardId]);

    broadcast({ type: 'card_listed', cardId, listingId, userId: req.user.id });

    res.json({
      success: true,
      listingId,
      listingUrl: `https://www.ebay.com/itm/${listingId}`,
      message: 'Card listed on eBay successfully!'
    });

  } catch (error) {
    console.error('[eBay] Listing error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to create eBay listing',
      details: error.response?.data?.errors?.[0]?.message || error.message
    });
  }
});

// Get user's eBay listings
app.get('/api/ebay/listings', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT el.*, c.card_data, c.front_image_path
      FROM ebay_listings el
      JOIN cards c ON c.id = el.card_id
      WHERE el.user_id = $1
      ORDER BY el.created_at DESC
    `, [req.user.id]);

    res.json({ success: true, listings: result.rows });

  } catch (error) {
    console.error('Get listings error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to get listings' });
  }
});

// Listing preview
app.get('/api/ebay/preview/:cardId', authenticateToken, async (req, res) => {
  try {
    const cardResult = await pool.query(
      'SELECT * FROM cards WHERE id = $1 AND user_id = $2',
      [req.params.cardId, req.user.id]
    );

    if (cardResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Card not found' });
    }

    const card = cardResult.rows[0].card_data;

    res.json({
      success: true,
      preview: {
        title: generateListingTitle(card),
        description: generateListingDescription(card),
        suggestedPrice: card.recommended_price || 9.99,
        condition: card.is_graded ? 'New (Graded)' : 'Used - Excellent'
      }
    });

  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to generate preview' });
  }
});

// ============================================
// SHIPPING METHODS & POLICIES
// ============================================

// Shipping method configurations (matching SlabTrack)
const SHIPPING_METHODS = {
  standard_envelope: {
    name: 'Standard Envelope',
    description: 'eBay Standard Envelope - best for single cards under $20',
    price: 1.32,
    maxValue: 20,
    maxCards: 2,
    service: 'USPSFirstClass',
    carrier: 'USPS'
  },
  calculated: {
    name: 'Calculated Shipping',
    description: 'USPS calculates based on buyer location',
    price: null, // Calculated by eBay
    maxCards: 999,
    service: 'USPSFirstClass',
    carrier: 'USPS'
  },
  flat_rate: {
    name: 'Flat Rate',
    description: 'Fixed shipping price you set',
    price: 4.99,
    maxCards: 999,
    service: 'USPSFirstClass',
    carrier: 'USPS'
  },
  free: {
    name: 'Free Shipping',
    description: 'Free shipping (built into price)',
    price: 0,
    maxCards: 999,
    service: 'USPSFirstClass',
    carrier: 'USPS'
  }
};

// Get shipping methods
app.get('/api/ebay/shipping-methods', authenticateToken, (req, res) => {
  res.json({ success: true, methods: SHIPPING_METHODS });
});

// Calculate smart shipping recommendation
function getSmartShipping(cards, totalValue) {
  const cardCount = cards.length;
  const toploadersNeeded = Math.ceil(cardCount / 2);

  // Rules from SlabTrack:
  // - 7+ cards = bubble mailer required (no standard envelope)
  // - Total value > $20 = no standard envelope
  // - 1-2 cards under $20 = standard envelope eligible

  if (cardCount >= 7 || totalValue > 20) {
    return {
      method: 'calculated',
      reason: cardCount >= 7
        ? 'Bubble mailer required for 7+ cards'
        : 'Value exceeds standard envelope limit',
      toploaders: toploadersNeeded,
      requiresBubbleMailer: true
    };
  }

  if (cardCount <= 2 && totalValue <= 20) {
    return {
      method: 'standard_envelope',
      reason: 'Eligible for eBay Standard Envelope',
      toploaders: toploadersNeeded,
      requiresBubbleMailer: false
    };
  }

  return {
    method: 'flat_rate',
    reason: 'Flat rate shipping recommended',
    toploaders: toploadersNeeded,
    requiresBubbleMailer: false
  };
}

// Update user shipping settings
app.put('/api/ebay/shipping-settings', authenticateToken, async (req, res) => {
  try {
    const { defaultMethod, flatRatePrice, freeShippingMinimum } = req.body;

    await pool.query(`
      UPDATE users SET
        ebay_default_shipping = $1,
        ebay_flat_rate_price = $2,
        ebay_free_shipping_minimum = $3
      WHERE id = $4
    `, [defaultMethod, flatRatePrice || 4.99, freeShippingMinimum || 50, req.user.id]);

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to update shipping settings' });
  }
});

// Get user shipping settings
app.get('/api/ebay/shipping-settings', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT ebay_default_shipping, ebay_flat_rate_price, ebay_free_shipping_minimum
      FROM users WHERE id = $1
    `, [req.user.id]);

    const settings = result.rows[0] || {};
    res.json({
      success: true,
      settings: {
        defaultMethod: settings.ebay_default_shipping || 'calculated',
        flatRatePrice: settings.ebay_flat_rate_price || 4.99,
        freeShippingMinimum: settings.ebay_free_shipping_minimum || 50
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to get shipping settings' });
  }
});

// ============================================
// BULK LISTING ROUTES
// ============================================

// Get bulk listing preview for multiple cards
app.post('/api/ebay/bulk-preview', authenticateToken, async (req, res) => {
  try {
    const { cardIds } = req.body;

    if (!cardIds || !Array.isArray(cardIds) || cardIds.length === 0) {
      return res.status(400).json({ success: false, error: 'Card IDs required' });
    }

    const result = await pool.query(`
      SELECT * FROM cards WHERE id = ANY($1) AND user_id = $2
    `, [cardIds, req.user.id]);

    const cards = result.rows.map(row => ({
      id: row.id,
      ...row.card_data,
      front: row.front_image_path,
      title: generateListingTitle(row.card_data),
      suggestedPrice: row.card_data.recommended_price || 9.99
    }));

    // Calculate totals
    const totalValue = cards.reduce((sum, c) => sum + (c.suggestedPrice || 0), 0);
    const shipping = getSmartShipping(cards, totalValue);

    // Calculate eBay fees (approximate: 13.25% + $0.30)
    const totalFees = cards.reduce((sum, c) => {
      const price = c.suggestedPrice || 9.99;
      return sum + (price * 0.1325 + 0.30);
    }, 0);

    res.json({
      success: true,
      cards,
      summary: {
        count: cards.length,
        totalValue: Math.round(totalValue * 100) / 100,
        totalFees: Math.round(totalFees * 100) / 100,
        netProfit: Math.round((totalValue - totalFees) * 100) / 100
      },
      shippingRecommendation: shipping
    });

  } catch (error) {
    console.error('Bulk preview error:', error);
    res.status(500).json({ success: false, error: 'Failed to generate preview' });
  }
});

// Create bulk listings (multiple individual cards)
app.post('/api/ebay/bulk-create', authenticateToken, async (req, res) => {
  try {
    const { listings } = req.body;

    if (!listings || !Array.isArray(listings) || listings.length === 0) {
      return res.status(400).json({ success: false, error: 'Listings array required' });
    }

    console.log(`[eBay] Creating ${listings.length} bulk listings...`);

    const accessToken = await getUserEbayToken(req.user.id);

    // Get user's policy IDs
    const userResult = await pool.query(
      'SELECT ebay_payment_policy_id, ebay_return_policy_id, ebay_fulfillment_policy_id, ebay_merchant_location_key FROM users WHERE id = $1',
      [req.user.id]
    );

    const policies = userResult.rows[0];
    if (!policies.ebay_payment_policy_id) {
      return res.status(400).json({
        success: false,
        error: 'eBay business policies not set up'
      });
    }

    const results = [];
    let successCount = 0;
    let errorCount = 0;

    for (const listing of listings) {
      const { cardId, price, title: customTitle, shippingMethod = 'calculated', shippingPrice } = listing;

      try {
        // Get card
        const cardResult = await pool.query(
          'SELECT * FROM cards WHERE id = $1 AND user_id = $2',
          [cardId, req.user.id]
        );

        if (cardResult.rows.length === 0) {
          results.push({ cardId, success: false, error: 'Card not found' });
          errorCount++;
          continue;
        }

        const row = cardResult.rows[0];
        const card = row.card_data;
        const title = customTitle || generateListingTitle(card);
        const description = generateListingDescription(card);
        const sku = `CF${cardId.replace(/-/g, '').substring(0, 20)}${Date.now().toString().slice(-8)}`;

        // Create fulfillment policy for this shipping method
        let fulfillmentPolicyId = policies.ebay_fulfillment_policy_id;

        // Create inventory item
        // eBay trading cards: LIKE_NEW = Graded, USED_VERY_GOOD = Ungraded
        const inventoryPayload = {
          availability: { shipToLocationAvailability: { quantity: 1 } },
          condition: card.is_graded ? 'LIKE_NEW' : 'USED_VERY_GOOD',
          conditionDescription: card.is_graded
            ? `${card.grading_company || 'PSA'} ${card.grade || '10'}`
            : 'Ungraded card in excellent condition',
          product: {
            title,
            description,
            aspects: {
              'Sport': [card.sport || 'Baseball'],
              'Player': [card.player],
              'Team': [card.team || 'N/A'],
              'Year': [String(card.year)],
              'Card Number': [card.card_number || 'N/A']
            }
          }
        };

        await axios.put(
          `https://api.ebay.com/sell/inventory/v1/inventory_item/${sku}`,
          inventoryPayload,
          {
            headers: {
              'Authorization': `Bearer ${accessToken}`,
              'Content-Type': 'application/json',
              'Content-Language': 'en-US'
            }
          }
        );

        // Build offer based on shipping method
        const offerPayload = {
          sku,
          marketplaceId: 'EBAY_US',
          format: 'FIXED_PRICE',
          availableQuantity: 1,
          categoryId: '261328',
          listingDescription: description,
          merchantLocationKey: policies.ebay_merchant_location_key || 'default',
          listingPolicies: {
            fulfillmentPolicyId,
            paymentPolicyId: policies.ebay_payment_policy_id,
            returnPolicyId: policies.ebay_return_policy_id
          },
          pricingSummary: {
            price: { value: String(price), currency: 'USD' }
          }
        };

        const offerResponse = await axios.post(
          'https://api.ebay.com/sell/inventory/v1/offer',
          offerPayload,
          {
            headers: {
              'Authorization': `Bearer ${accessToken}`,
              'Content-Type': 'application/json',
              'Content-Language': 'en-US'
            }
          }
        );

        const offerId = offerResponse.data.offerId;

        // Publish
        const publishResponse = await axios.post(
          `https://api.ebay.com/sell/inventory/v1/offer/${offerId}/publish`,
          {},
          {
            headers: {
              'Authorization': `Bearer ${accessToken}`,
              'Content-Type': 'application/json',
              'Content-Language': 'en-US'
            }
          }
        );

        const listingId = publishResponse.data.listingId;

        // Save to database
        await pool.query(`
          INSERT INTO ebay_listings (card_id, user_id, ebay_listing_id, ebay_url, sku, offer_id, price, status, shipping_method)
          VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8)
        `, [cardId, req.user.id, listingId, `https://www.ebay.com/itm/${listingId}`, sku, offerId, price, shippingMethod]);

        // Update card status
        await pool.query(`
          UPDATE cards SET status = 'listed', card_data = card_data || $1::jsonb WHERE id = $2
        `, [JSON.stringify({ ebay_listing_id: listingId, ebay_price: price, listed_at: new Date().toISOString() }), cardId]);

        results.push({
          cardId,
          success: true,
          listingId,
          listingUrl: `https://www.ebay.com/itm/${listingId}`
        });
        successCount++;

        // Rate limit
        await new Promise(r => setTimeout(r, 500));

      } catch (error) {
        console.error(`[eBay] Error listing card ${cardId}:`, error.response?.data || error.message);
        results.push({
          cardId,
          success: false,
          error: error.response?.data?.errors?.[0]?.message || error.message
        });
        errorCount++;
      }
    }

    broadcast({ type: 'bulk_listings_complete', successCount, errorCount, userId: req.user.id });

    res.json({
      success: true,
      results,
      summary: {
        total: listings.length,
        successful: successCount,
        failed: errorCount
      }
    });

  } catch (error) {
    console.error('Bulk create error:', error);
    res.status(500).json({ success: false, error: 'Failed to create bulk listings' });
  }
});

// ============================================
// COLLAGE SERVICE
// ============================================

const sharp = require('sharp');
// Note: cloudinary already configured at top of file

// Grid presets (matching SlabTrack)
const GRID_PRESETS = {
  large: { cols: 4, rows: 5, cardsPerPage: 20, cellWidth: 300, cellHeight: 420 },
  medium: { cols: 5, rows: 6, cardsPerPage: 30, cellWidth: 240, cellHeight: 336 },
  small: { cols: 6, rows: 7, cardsPerPage: 42, cellWidth: 200, cellHeight: 280 }
};

// Generate collage from card images
async function generateCollage(imagePaths, gridSize = 'medium') {
  const grid = GRID_PRESETS[gridSize] || GRID_PRESETS.medium;
  const { cols, rows, cellWidth, cellHeight } = grid;

  const totalWidth = cols * cellWidth;
  const totalHeight = rows * cellHeight;

  console.log(`[Collage] Creating ${cols}x${rows} grid (${totalWidth}x${totalHeight}px)`);

  // Create blank canvas
  const compositeImages = [];

  for (let i = 0; i < Math.min(imagePaths.length, cols * rows); i++) {
    const imagePath = imagePaths[i];
    const col = i % cols;
    const row = Math.floor(i / cols);

    try {
      // Resize image to fit cell
      const resizedImage = await sharp(imagePath)
        .resize(cellWidth - 10, cellHeight - 10, { fit: 'contain', background: { r: 255, g: 255, b: 255, alpha: 1 } })
        .toBuffer();

      compositeImages.push({
        input: resizedImage,
        left: col * cellWidth + 5,
        top: row * cellHeight + 5
      });
    } catch (err) {
      console.error(`[Collage] Error processing image ${imagePath}:`, err.message);
    }
  }

  // Create collage
  const collageBuffer = await sharp({
    create: {
      width: totalWidth,
      height: totalHeight,
      channels: 3,
      background: { r: 255, g: 255, b: 255 }
    }
  })
    .composite(compositeImages)
    .jpeg({ quality: 90 })
    .toBuffer();

  console.log(`[Collage] Generated ${collageBuffer.length} bytes`);

  return collageBuffer;
}

// Upload collage to Cloudinary
async function uploadCollageToCloudinary(collageBuffer, lotId) {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: 'cardflow-lots',
        public_id: `lot-${lotId}`,
        resource_type: 'image'
      },
      (error, result) => {
        if (error) reject(error);
        else resolve(result);
      }
    );

    const Readable = require('stream').Readable;
    const stream = new Readable();
    stream.push(collageBuffer);
    stream.push(null);
    stream.pipe(uploadStream);
  });
}

// Generate collage preview endpoint
app.post('/api/ebay/lot-preview', authenticateToken, async (req, res) => {
  try {
    const { cardIds, gridSize = 'medium' } = req.body;

    if (!cardIds || cardIds.length < 2) {
      return res.status(400).json({ success: false, error: 'At least 2 cards required for lot' });
    }

    // Get cards
    const result = await pool.query(`
      SELECT * FROM cards WHERE id = ANY($1) AND user_id = $2
    `, [cardIds, req.user.id]);

    const cards = result.rows;

    // Calculate totals
    const totalValue = cards.reduce((sum, c) => sum + (c.card_data.recommended_price || 0), 0);
    const grid = GRID_PRESETS[gridSize] || GRID_PRESETS.medium;
    const pagesNeeded = Math.ceil(cards.length / grid.cardsPerPage);

    // Calculate toploaders and shipping
    const toploadersNeeded = Math.ceil(cards.length / 2);
    const requiresBubbleMailer = cards.length >= 7;

    // Lot pricing suggestion (10-15% discount)
    const suggestedLotPrice = Math.round(totalValue * 0.88 * 100) / 100;

    // Generate lot title
    const sports = [...new Set(cards.map(c => c.card_data.sport))];
    const years = [...new Set(cards.map(c => c.card_data.year))].sort();
    const yearRange = years.length > 1 ? `${years[0]}-${years[years.length - 1]}` : years[0];

    const lotTitle = `LOT of ${cards.length} ${sports.join('/')} Cards ${yearRange} - Mixed`;

    res.json({
      success: true,
      preview: {
        cardCount: cards.length,
        gridSize,
        pagesNeeded,
        totalIndividualValue: Math.round(totalValue * 100) / 100,
        suggestedLotPrice,
        lotTitle,
        cards: cards.map(c => ({
          id: c.id,
          player: c.card_data.player,
          year: c.card_data.year,
          price: c.card_data.recommended_price
        }))
      },
      shipping: {
        toploadersNeeded,
        requiresBubbleMailer,
        recommendedMethod: requiresBubbleMailer ? 'calculated' : 'flat_rate'
      }
    });

  } catch (error) {
    console.error('Lot preview error:', error);
    res.status(500).json({ success: false, error: 'Failed to generate lot preview' });
  }
});

// Create lot listing
app.post('/api/ebay/create-lot', authenticateToken, async (req, res) => {
  try {
    const {
      cardIds,
      title: customTitle,
      price,
      gridSize = 'medium',
      shippingMethod = 'calculated',
      shippingPrice,
      generateCollageImage = true
    } = req.body;

    if (!cardIds || cardIds.length < 2) {
      return res.status(400).json({ success: false, error: 'At least 2 cards required' });
    }

    if (!price || price <= 0) {
      return res.status(400).json({ success: false, error: 'Price required' });
    }

    console.log(`[eBay] Creating lot listing with ${cardIds.length} cards...`);

    const accessToken = await getUserEbayToken(req.user.id);

    // Get cards
    const cardsResult = await pool.query(`
      SELECT * FROM cards WHERE id = ANY($1) AND user_id = $2
    `, [cardIds, req.user.id]);

    const cards = cardsResult.rows;

    if (cards.length !== cardIds.length) {
      return res.status(400).json({ success: false, error: 'Some cards not found' });
    }

    // Get user's policies
    const userResult = await pool.query(
      'SELECT ebay_payment_policy_id, ebay_return_policy_id, ebay_fulfillment_policy_id, ebay_merchant_location_key FROM users WHERE id = $1',
      [req.user.id]
    );

    const policies = userResult.rows[0];
    if (!policies.ebay_payment_policy_id) {
      return res.status(400).json({ success: false, error: 'eBay business policies not set up' });
    }

    // Generate lot ID and SKU (alphanumeric only, max 50 chars)
    const lotId = `LOT${Date.now()}`;
    const sku = `CF${lotId}`;

    // Generate collage if requested
    let collageUrl = null;
    if (generateCollageImage) {
      try {
        const imagePaths = cards.map(c => {
          const folder = c.status === 'priced' ? FOLDERS.priced :
                        c.status === 'identified' ? FOLDERS.identified : FOLDERS.new;
          return path.join(folder, c.front_image_path);
        }).filter(p => fs.existsSync(p));

        if (imagePaths.length >= 2) {
          const collageBuffer = await generateCollage(imagePaths, gridSize);
          const uploadResult = await uploadCollageToCloudinary(collageBuffer, lotId);
          collageUrl = uploadResult.secure_url;
          console.log('[eBay] Collage uploaded:', collageUrl);
        }
      } catch (err) {
        console.error('[eBay] Collage generation failed:', err.message);
        // Continue without collage
      }
    }

    // Generate title
    const sports = [...new Set(cards.map(c => c.card_data.sport))];
    const years = [...new Set(cards.map(c => c.card_data.year))].sort();
    const yearRange = years.length > 1 ? `${years[0]}-${years[years.length - 1]}` : years[0];
    const title = customTitle || `LOT of ${cards.length} ${sports.join('/')} Cards ${yearRange}`;

    // Generate description
    const description = generateLotDescription(cards, collageUrl);

    // Create inventory item
    // eBay trading cards: USED_VERY_GOOD = Ungraded/Lot
    const inventoryPayload = {
      availability: { shipToLocationAvailability: { quantity: 1 } },
      condition: 'USED_VERY_GOOD',
      conditionDescription: 'Lot of trading cards in excellent condition',
      product: {
        title: title.substring(0, 80),
        description,
        aspects: {
          'Sport': sports,
          'Card Condition': ['Excellent'],
          'Features': ['Lot']
        },
        imageUrls: collageUrl ? [collageUrl] : []
      }
    };

    await axios.put(
      `https://api.ebay.com/sell/inventory/v1/inventory_item/${sku}`,
      inventoryPayload,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Language': 'en-US'
        }
      }
    );

    // Create offer
    const offerPayload = {
      sku,
      marketplaceId: 'EBAY_US',
      format: 'FIXED_PRICE',
      availableQuantity: 1,
      categoryId: '261328',
      listingDescription: description,
      merchantLocationKey: policies.ebay_merchant_location_key || 'default',
      listingPolicies: {
        fulfillmentPolicyId: policies.ebay_fulfillment_policy_id,
        paymentPolicyId: policies.ebay_payment_policy_id,
        returnPolicyId: policies.ebay_return_policy_id
      },
      pricingSummary: {
        price: { value: String(price), currency: 'USD' }
      }
    };

    const offerResponse = await axios.post(
      'https://api.ebay.com/sell/inventory/v1/offer',
      offerPayload,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Language': 'en-US'
        }
      }
    );

    const offerId = offerResponse.data.offerId;

    // Publish
    const publishResponse = await axios.post(
      `https://api.ebay.com/sell/inventory/v1/offer/${offerId}/publish`,
      {},
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Language': 'en-US'
        }
      }
    );

    const listingId = publishResponse.data.listingId;
    console.log('[eBay] Lot listing published:', listingId);

    // Save lot listing
    await pool.query(`
      INSERT INTO ebay_listings (user_id, ebay_listing_id, ebay_url, sku, offer_id, price, status, listing_type, lot_card_ids, collage_url)
      VALUES ($1, $2, $3, $4, $5, $6, 'active', 'lot', $7, $8)
    `, [req.user.id, listingId, `https://www.ebay.com/itm/${listingId}`, sku, offerId, price, cardIds, collageUrl]);

    // Update all cards as listed
    await pool.query(`
      UPDATE cards SET status = 'listed', card_data = card_data || $1::jsonb
      WHERE id = ANY($2)
    `, [JSON.stringify({ lot_listing_id: listingId, lot_id: lotId, listed_at: new Date().toISOString() }), cardIds]);

    broadcast({ type: 'lot_listed', lotId, listingId, cardCount: cards.length, userId: req.user.id });

    res.json({
      success: true,
      listingId,
      listingUrl: `https://www.ebay.com/itm/${listingId}`,
      lotId,
      collageUrl,
      message: `Lot of ${cards.length} cards listed successfully!`
    });

  } catch (error) {
    console.error('[eBay] Lot listing error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to create lot listing',
      details: error.response?.data?.errors?.[0]?.message || error.message
    });
  }
});

// Generate lot description HTML
function generateLotDescription(cards, collageUrl) {
  const players = cards.map(c => c.card_data.player).slice(0, 10);
  const hasMore = cards.length > 10;

  return `
    <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto;">
      <h2 style="color: #0654ba; text-align: center;">Lot of ${cards.length} Trading Cards</h2>

      ${collageUrl ? `<div style="text-align: center; margin: 20px 0;"><img src="${collageUrl}" style="max-width: 100%; border: 1px solid #ddd; border-radius: 8px;" alt="Card Lot Preview"></div>` : ''}

      <div style="background: #f7f7f7; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3 style="margin-top: 0; color: #333;">Lot Contents</h3>
        <p><strong>${cards.length} cards total</strong></p>
        <ul style="list-style: disc; padding-left: 20px;">
          ${players.map(p => `<li>${p}</li>`).join('')}
          ${hasMore ? `<li><em>...and ${cards.length - 10} more!</em></li>` : ''}
        </ul>
      </div>

      <div style="background: #e8f4f8; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3 style="margin-top: 0; color: #333;">Shipping Info</h3>
        <ul style="list-style: none; padding: 0;">
          <li>Ships within 1 business day</li>
          <li>Cards in sleeves & toploaders</li>
          <li>Securely packed in bubble mailer</li>
        </ul>
      </div>

      <p style="text-align: center; color: #666; font-size: 12px;">Listed via <strong>CardFlow</strong></p>
    </div>
  `.trim();
}

// ============================================
// AUCTION LISTING
// ============================================

app.post('/api/ebay/create-auction', authenticateToken, async (req, res) => {
  try {
    const {
      cardId,
      startingPrice,
      buyItNowPrice,
      duration = 7, // days
      shippingMethod = 'calculated'
    } = req.body;

    if (!cardId || !startingPrice) {
      return res.status(400).json({ success: false, error: 'Card ID and starting price required' });
    }

    console.log(`[eBay] Creating auction for card ${cardId}...`);

    const accessToken = await getUserEbayToken(req.user.id);

    // Get card
    const cardResult = await pool.query(
      'SELECT * FROM cards WHERE id = $1 AND user_id = $2',
      [cardId, req.user.id]
    );

    if (cardResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Card not found' });
    }

    const row = cardResult.rows[0];
    const card = row.card_data;

    // Get policies
    const userResult = await pool.query(
      'SELECT ebay_payment_policy_id, ebay_return_policy_id, ebay_fulfillment_policy_id, ebay_merchant_location_key FROM users WHERE id = $1',
      [req.user.id]
    );

    const policies = userResult.rows[0];

    const title = generateListingTitle(card);
    const description = generateListingDescription(card);
    const sku = `CFAUC${cardId.replace(/-/g, '').substring(0, 16)}${Date.now().toString().slice(-8)}`;

    // Create inventory item
    // eBay trading cards: LIKE_NEW = Graded, USED_VERY_GOOD = Ungraded
    await axios.put(
      `https://api.ebay.com/sell/inventory/v1/inventory_item/${sku}`,
      {
        availability: { shipToLocationAvailability: { quantity: 1 } },
        condition: card.is_graded ? 'LIKE_NEW' : 'USED_VERY_GOOD',
        conditionDescription: card.is_graded
          ? `${card.grading_company || 'PSA'} ${card.grade || '10'}`
          : 'Ungraded card in excellent condition',
        product: {
          title,
          description,
          aspects: {
            'Sport': [card.sport || 'Baseball'],
            'Player': [card.player],
            'Year': [String(card.year)]
          }
        }
      },
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Language': 'en-US'
        }
      }
    );

    // Create auction offer
    const offerPayload = {
      sku,
      marketplaceId: 'EBAY_US',
      format: 'AUCTION',
      availableQuantity: 1,
      categoryId: '261328',
      listingDescription: description,
      merchantLocationKey: policies.ebay_merchant_location_key || 'default',
      listingPolicies: {
        fulfillmentPolicyId: policies.ebay_fulfillment_policy_id,
        paymentPolicyId: policies.ebay_payment_policy_id,
        returnPolicyId: policies.ebay_return_policy_id
      },
      pricingSummary: {
        auctionStartPrice: { value: String(startingPrice), currency: 'USD' },
        ...(buyItNowPrice && { buyItNowPrice: { value: String(buyItNowPrice), currency: 'USD' } })
      },
      listingDuration: `DAYS_${duration}`
    };

    const offerResponse = await axios.post(
      'https://api.ebay.com/sell/inventory/v1/offer',
      offerPayload,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Language': 'en-US'
        }
      }
    );

    const offerId = offerResponse.data.offerId;

    // Publish
    const publishResponse = await axios.post(
      `https://api.ebay.com/sell/inventory/v1/offer/${offerId}/publish`,
      {},
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Language': 'en-US'
        }
      }
    );

    const listingId = publishResponse.data.listingId;
    console.log('[eBay] Auction published:', listingId);

    // Save listing
    await pool.query(`
      INSERT INTO ebay_listings (card_id, user_id, ebay_listing_id, ebay_url, sku, offer_id, price, status, listing_type)
      VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', 'auction')
    `, [cardId, req.user.id, listingId, `https://www.ebay.com/itm/${listingId}`, sku, offerId, startingPrice]);

    // Update card
    await pool.query(`
      UPDATE cards SET status = 'listed', card_data = card_data || $1::jsonb WHERE id = $2
    `, [JSON.stringify({
      ebay_listing_id: listingId,
      listing_type: 'auction',
      auction_start_price: startingPrice,
      listed_at: new Date().toISOString()
    }), cardId]);

    broadcast({ type: 'auction_listed', cardId, listingId, userId: req.user.id });

    res.json({
      success: true,
      listingId,
      listingUrl: `https://www.ebay.com/itm/${listingId}`,
      message: 'Auction created successfully!'
    });

  } catch (error) {
    console.error('[eBay] Auction error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to create auction',
      details: error.response?.data?.errors?.[0]?.message || error.message
    });
  }
});

// End listing
app.post('/api/ebay/end-listing/:listingId', authenticateToken, async (req, res) => {
  try {
    const { listingId } = req.params;

    const listingResult = await pool.query(
      'SELECT * FROM ebay_listings WHERE ebay_listing_id = $1 AND user_id = $2',
      [listingId, req.user.id]
    );

    if (listingResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Listing not found' });
    }

    const accessToken = await getUserEbayToken(req.user.id);

    // End the listing via eBay API
    await axios.post(
      `https://api.ebay.com/sell/inventory/v1/offer/${listingResult.rows[0].offer_id}/withdraw`,
      {},
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Content-Language': 'en-US'
        }
      }
    );

    // Update database
    await pool.query(
      'UPDATE ebay_listings SET status = $1 WHERE ebay_listing_id = $2',
      ['ended', listingId]
    );

    // Update card status back to priced
    if (listingResult.rows[0].card_id) {
      await pool.query(
        'UPDATE cards SET status = $1 WHERE id = $2',
        ['priced', listingResult.rows[0].card_id]
      );
    }

    res.json({ success: true, message: 'Listing ended' });

  } catch (error) {
    console.error('End listing error:', error.response?.data || error.message);
    res.status(500).json({ success: false, error: 'Failed to end listing' });
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

// Serve collection page
app.get('/collection', (req, res) => {
  res.sendFile(path.join(__dirname, 'collection.html'));
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
  CARDFLOW v2.0 - Multi-User SaaS (Build 0201f)
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
