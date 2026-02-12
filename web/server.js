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

// ============================================
// SENTRY ERROR MONITORING (Initialize first!)
// ============================================
const Sentry = require('@sentry/node');
if (process.env.SENTRY_DSN) {
  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV || 'development',
    tracesSampleRate: 0.1, // 10% of transactions for performance monitoring
    beforeSend(event) {
      // Don't send errors in development unless explicitly enabled
      if (process.env.NODE_ENV !== 'production' && !process.env.SENTRY_DEV) {
        return null;
      }
      return event;
    }
  });
  console.log('[Sentry] Error monitoring initialized');
}

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
const ExcelJS = require('exceljs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3005;
const crypto = require('crypto');
const axios = require('axios');

// ============================================
// SECURITY: JWT Secret - REQUIRED in production
// ============================================
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET && process.env.NODE_ENV === 'production') {
  console.error('[FATAL] JWT_SECRET environment variable is required in production');
  process.exit(1);
}
// Allow dev fallback only in development
const EFFECTIVE_JWT_SECRET = JWT_SECRET || 'cardflow-dev-only-not-for-production';
const JWT_EXPIRY = '7d';

// API Key encryption for storing user's Anthropic keys securely
const API_KEY_ENCRYPTION_KEY = process.env.API_KEY_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';

function encryptApiKey(plaintext) {
  if (!plaintext) return null;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, Buffer.from(API_KEY_ENCRYPTION_KEY.slice(0, 32)), iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decryptApiKey(encryptedData) {
  if (!encryptedData) return null;
  // Handle legacy unencrypted keys (starts with sk-)
  if (encryptedData.startsWith('sk-')) return encryptedData;
  try {
    const [ivHex, authTagHex, encrypted] = encryptedData.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, Buffer.from(API_KEY_ENCRYPTION_KEY.slice(0, 32)), iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    console.error('[Encryption] Failed to decrypt API key:', e.message);
    return null;
  }
}

// Email configuration for password reset
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = process.env.SMTP_PORT || 587;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const FROM_EMAIL = process.env.FROM_EMAIL || 'noreply@cardflow.io';
const XLSX = require('xlsx');

// Stripe for subscriptions
const stripe = process.env.STRIPE_SECRET_KEY ? require('stripe')(process.env.STRIPE_SECRET_KEY) : null;
const STRIPE_PRICES = {
  basic: 'price_1Sx6ZOQ20P462xlWsLAS7rRx',
  pro: 'price_1Sx6aRQ20P462xlWf8RCHVYD'
};
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

// SlabTrack API
const SLABTRACK_API = process.env.SLABTRACK_API_URL || 'https://slabtrack.io/api';

// SportsCardsPro API
const SPORTSCARDSPRO_TOKEN = process.env.SPORTSCARDSPRO_TOKEN;
const SCP_API_BASE = 'https://www.sportscardspro.com/api';

// In-memory cache for set search results (30-min TTL, max 500 entries)
const setCache = new Map();
const SET_CACHE_TTL = 30 * 60 * 1000; // 30 minutes
const SET_CACHE_MAX = 500;

function getCachedSet(key) {
  const entry = setCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > SET_CACHE_TTL) {
    setCache.delete(key);
    return null;
  }
  return entry.data;
}

function setCachedSet(key, data) {
  // Evict oldest if at max
  if (setCache.size >= SET_CACHE_MAX) {
    const oldest = setCache.keys().next().value;
    setCache.delete(oldest);
  }
  setCache.set(key, { data, ts: Date.now() });
}

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

// ============================================
// SECURITY: Rate Limiting
// ============================================
const rateLimit = require('express-rate-limit');

// General API rate limiter
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500, // 500 requests per window
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

// Strict limiter for authentication endpoints (brute force protection)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window
  message: { error: 'Too many login attempts, please try again in 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true // Don't count successful logins
});

// Password reset limiter (prevent email flooding)
const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 reset requests per hour
  message: { error: 'Too many password reset requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

// ============================================
// MIDDLEWARE
// ============================================

app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? ['https://cardflow.be1st.io', 'https://www.cardflow.be1st.io']
    : true,
  credentials: true
}));
app.use(generalLimiter);
app.use(express.json({ limit: '10mb' })); // Reduced from 50mb for security

// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, EFFECTIVE_JWT_SECRET, (err, user) => {
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
    jwt.verify(token, EFFECTIVE_JWT_SECRET, (err, user) => {
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

// Tier definitions
const TIERS = {
  free: { name: 'Free Trial', price: 0, features: ['scan', 'export_csv', 'export_slabtrack', 'price_links'], limit: 10 },
  basic: { name: 'Basic', price: 2.99, features: ['scan', 'export_csv', 'export_slabtrack', 'price_links', 'unlimited_scans'] },
  pro: { name: 'Pro', price: 5.99, features: ['scan', 'export_csv', 'export_slabtrack', 'price_links', 'unlimited_scans', 'ebay_integration'] }
};

// Middleware to require Pro tier for eBay features
async function requireProTier(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const result = await pool.query('SELECT subscription_tier, role FROM users WHERE id = $1', [req.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const { subscription_tier, role } = result.rows[0];

    // Admins always have access
    if (role === 'admin') {
      return next();
    }

    // Pro tier required
    if (subscription_tier !== 'pro') {
      return res.status(403).json({
        error: 'Pro subscription required',
        message: 'eBay integration requires a Pro subscription ($6.99/month)',
        upgrade_url: '/pricing'
      });
    }

    next();
  } catch (e) {
    console.error('Tier check error:', e);
    return res.status(500).json({ error: 'Failed to verify subscription' });
  }
}

// Get user's tier info
function getTierInfo(subscription_tier) {
  const tier = TIERS[subscription_tier] || TIERS.free;
  return {
    tier: subscription_tier || 'free',
    name: tier.name,
    features: tier.features,
    hasEbay: tier.features.includes('ebay_integration'),
    hasUnlimitedScans: tier.features.includes('unlimited_scans')
  };
}

// Middleware to check scan limit for free tier
async function checkScanLimit(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const result = await pool.query(`
      SELECT subscription_tier, role, slabtrack_tier
      FROM users WHERE id = $1
    `, [req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const { subscription_tier, role, slabtrack_tier } = result.rows[0];

    // Admins always have unlimited access
    if (role === 'admin') {
      return next();
    }

    // SlabTrack power/dealer tiers have free access
    if (['power', 'dealer'].includes(slabtrack_tier)) {
      return next();
    }

    // Paid tiers have unlimited scans
    const tier = TIERS[subscription_tier] || TIERS.free;
    if (tier.features.includes('unlimited_scans')) {
      return next();
    }

    // Free tier - check card count
    const cardCount = await pool.query(
      'SELECT COUNT(*) FROM cards WHERE user_id = $1',
      [req.user.id]
    );
    const count = parseInt(cardCount.rows[0].count);
    const limit = tier.limit || 10;

    if (count >= limit) {
      return res.status(403).json({
        error: 'Scan limit reached',
        message: `Free tier is limited to ${limit} cards. Upgrade to continue scanning!`,
        currentCount: count,
        limit: limit,
        upgrade_url: '/pricing'
      });
    }

    next();
  } catch (e) {
    console.error('Scan limit check error:', e);
    return res.status(500).json({ error: 'Failed to verify scan limit' });
  }
}

// ============================================
// STRIPE SUBSCRIPTION ENDPOINTS
// ============================================

// Stripe webhook - MUST be before express.json() middleware for raw body
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    return res.status(400).json({ error: 'Stripe not configured' });
  }

  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('[Stripe] Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  console.log('[Stripe] Webhook received:', event.type);

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const userId = session.metadata?.user_id;
        const tier = session.metadata?.tier;

        if (userId && tier) {
          await pool.query(`
            UPDATE users SET
              subscription_tier = $1,
              stripe_customer_id = $2,
              stripe_subscription_id = $3
            WHERE id = $4
          `, [tier, session.customer, session.subscription, userId]);
          console.log(`[Stripe] User ${userId} upgraded to ${tier}`);
        }
        break;
      }

      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        const priceId = subscription.items.data[0]?.price?.id;

        // Determine tier from price ID
        let tier = 'free';
        if (priceId === STRIPE_PRICES.pro) tier = 'pro';
        else if (priceId === STRIPE_PRICES.basic) tier = 'basic';

        await pool.query(`
          UPDATE users SET subscription_tier = $1
          WHERE stripe_subscription_id = $2
        `, [tier, subscription.id]);
        console.log(`[Stripe] Subscription ${subscription.id} updated to ${tier}`);
        break;
      }

      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        await pool.query(`
          UPDATE users SET
            subscription_tier = 'free',
            stripe_subscription_id = NULL
          WHERE stripe_subscription_id = $1
        `, [subscription.id]);
        console.log(`[Stripe] Subscription ${subscription.id} cancelled`);
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        console.log(`[Stripe] Payment failed for customer ${invoice.customer}`);
        // Optionally downgrade or send email
        break;
      }
    }
  } catch (err) {
    console.error('[Stripe] Webhook handler error:', err);
  }

  res.json({ received: true });
});

// Create checkout session
app.post('/api/stripe/checkout', authenticateToken, async (req, res) => {
  if (!stripe) {
    return res.status(400).json({ error: 'Stripe not configured' });
  }

  const { tier } = req.body;
  const priceId = STRIPE_PRICES[tier];

  if (!priceId) {
    return res.status(400).json({ error: 'Invalid tier' });
  }

  try {
    // Get or create Stripe customer
    const userResult = await pool.query(
      'SELECT email, stripe_customer_id FROM users WHERE id = $1',
      [req.user.id]
    );
    const user = userResult.rows[0];

    let customerId = user.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user.email,
        metadata: { user_id: req.user.id }
      });
      customerId = customer.id;
      await pool.query(
        'UPDATE users SET stripe_customer_id = $1 WHERE id = $2',
        [customerId, req.user.id]
      );
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{
        price: priceId,
        quantity: 1
      }],
      mode: 'subscription',
      success_url: `${FRONTEND_URL}/app?subscription=success`,
      cancel_url: `${FRONTEND_URL}/pricing?cancelled=true`,
      metadata: {
        user_id: req.user.id,
        tier: tier
      }
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('[Stripe] Checkout error:', err);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Customer portal (manage subscription)
app.post('/api/stripe/portal', authenticateToken, async (req, res) => {
  if (!stripe) {
    return res.status(400).json({ error: 'Stripe not configured' });
  }

  try {
    const userResult = await pool.query(
      'SELECT stripe_customer_id FROM users WHERE id = $1',
      [req.user.id]
    );
    const customerId = userResult.rows[0]?.stripe_customer_id;

    if (!customerId) {
      return res.status(400).json({ error: 'No subscription found' });
    }

    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: `${FRONTEND_URL}/app`
    });

    res.json({ url: portalSession.url });
  } catch (err) {
    console.error('[Stripe] Portal error:', err);
    res.status(500).json({ error: 'Failed to create portal session' });
  }
});

// Get subscription status
app.get('/api/stripe/status', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT subscription_tier, stripe_customer_id, stripe_subscription_id
      FROM users WHERE id = $1
    `, [req.user.id]);

    const user = result.rows[0];
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    let subscriptionDetails = null;
    if (stripe && user.stripe_subscription_id) {
      try {
        const sub = await stripe.subscriptions.retrieve(user.stripe_subscription_id);
        subscriptionDetails = {
          status: sub.status,
          currentPeriodEnd: new Date(sub.current_period_end * 1000),
          cancelAtPeriodEnd: sub.cancel_at_period_end
        };
      } catch (e) {
        console.error('[Stripe] Error fetching subscription:', e.message);
      }
    }

    res.json({
      tier: user.subscription_tier || 'free',
      tierInfo: getTierInfo(user.subscription_tier),
      hasStripeSubscription: !!user.stripe_subscription_id,
      subscription: subscriptionDetails
    });
  } catch (err) {
    console.error('[Stripe] Status error:', err);
    res.status(500).json({ error: 'Failed to get subscription status' });
  }
});

// ============================================
// PAGE ROUTES (before static files)
// ============================================

// Landing page - public marketing page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'landing.html'));
});

// Main app dashboard
app.get('/app', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Phone scanner
app.get('/scan', (req, res) => {
  res.sendFile(path.join(__dirname, 'scan.html'));
});

// Login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Register page
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

// Forgot password page
app.get('/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'forgot-password.html'));
});

// Reset password page
app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'reset-password.html'));
});

// SlabTrack OAuth callback
app.get('/auth/slabtrack', (req, res) => {
  res.sendFile(path.join(__dirname, 'auth-slabtrack.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

// Pricing redirects to landing
app.get('/pricing', (req, res) => {
  res.redirect('/#pricing');
});

// Privacy Policy
app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, 'privacy.html'));
});

// Terms of Service
app.get('/terms', (req, res) => {
  res.sendFile(path.join(__dirname, 'terms.html'));
});

// Contact page
app.get('/contact', (req, res) => {
  res.sendFile(path.join(__dirname, 'contact.html'));
});

// ============================================
// STATIC FILES
// ============================================

// Serve static files (but not index.html at root - we handle that above)
app.use(express.static(__dirname, { index: false }));

// Serve downloads folder
app.use('/downloads', express.static(path.join(__dirname, 'downloads')));

// Download page - admin only (check is done client-side via localStorage token)
app.get('/download', async (req, res) => {
  res.sendFile(path.join(__dirname, 'download.html'));
});

// Scanner download URL (use GitHub Releases or other CDN in production)
const SCANNER_DOWNLOAD_URL = process.env.SCANNER_DOWNLOAD_URL || null;

// Direct download endpoint
app.get('/api/download/scanner', (req, res) => {
  // If external URL is configured, redirect to it
  if (SCANNER_DOWNLOAD_URL) {
    return res.redirect(SCANNER_DOWNLOAD_URL);
  }

  // Otherwise serve local file (development only)
  const filePath = path.join(__dirname, 'downloads', 'CardFlowScanner-Setup.exe');
  if (fs.existsSync(filePath)) {
    // Add no-cache headers to force fresh download
    res.set({
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    });
    res.download(filePath, 'CardFlow Scanner Setup.exe');
  } else {
    res.status(404).json({ error: 'Installer not available. Set SCANNER_DOWNLOAD_URL in environment.' });
  }
});

// API to get download info
app.get('/api/download/info', (req, res) => {
  const filePath = path.join(__dirname, 'downloads', 'CardFlowScanner-Setup.exe');
  let fileModTime = null;
  let fileSize = null;

  if (fs.existsSync(filePath)) {
    const stats = fs.statSync(filePath);
    fileModTime = stats.mtime.toISOString();
    fileSize = stats.size;
  }

  res.json({
    version: process.env.SCANNER_VERSION || '1.0.1',
    platform: 'windows',
    downloadUrl: SCANNER_DOWNLOAD_URL || `/api/download/scanner?t=${Date.now()}`,
    available: !!SCANNER_DOWNLOAD_URL || fs.existsSync(filePath),
    lastModified: fileModTime,
    fileSize: fileSize
  });
});

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

// Register (rate limited)
app.post('/api/auth/register', authLimiter, async (req, res) => {
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
    }, EFFECTIVE_JWT_SECRET, { expiresIn: JWT_EXPIRY });

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

// Login (rate limited)
app.post('/api/auth/login', authLimiter, async (req, res) => {
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
    }, EFFECTIVE_JWT_SECRET, { expiresIn: JWT_EXPIRY });

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

// SlabTrack Login - Verify token, create/link account (rate limited)
app.post('/api/auth/slabtrack-login', authLimiter, async (req, res) => {
  const { slabtrackToken } = req.body;

  if (!slabtrackToken) {
    return res.status(400).json({ error: 'SlabTrack token required' });
  }

  try {
    // Verify token with SlabTrack API
    console.log('[SlabTrack Auth] Verifying token...');
    const stResponse = await axios.get(`${SLABTRACK_API}/users/me`, {
      headers: { 'X-API-Token': slabtrackToken },
      timeout: 15000
    });

    if (!stResponse.data?.success || !stResponse.data?.user) {
      return res.status(401).json({ error: 'Invalid SlabTrack token' });
    }

    const stUser = stResponse.data.user;
    console.log(`[SlabTrack Auth] Token verified for: ${stUser.email}`);

    // Find or create CardFlow user by email
    const email = stUser.email.toLowerCase().trim();
    let user;

    const existingUser = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      // Update existing user with SlabTrack link
      user = existingUser.rows[0];
      await pool.query(`
        UPDATE users SET
          slabtrack_api_token = $1,
          slabtrack_user_id = $2,
          slabtrack_tier = $3,
          last_login_at = NOW()
        WHERE id = $4
      `, [slabtrackToken, stUser.id, stUser.subscription_tier, user.id]);

      console.log(`[SlabTrack Auth] Linked existing user: ${user.id}`);
    } else {
      // Create new CardFlow account (no password - they use SlabTrack)
      const result = await pool.query(`
        INSERT INTO users (email, name, slabtrack_api_token, slabtrack_user_id, slabtrack_tier, auth_method, last_login_at)
        VALUES ($1, $2, $3, $4, $5, 'slabtrack', NOW())
        RETURNING *
      `, [email, stUser.fullName || stUser.full_name || 'SlabTrack User', slabtrackToken, stUser.id, stUser.subscription_tier]);

      user = result.rows[0];
      console.log(`[SlabTrack Auth] Created new user: ${user.id}`);
    }

    // Determine if user can use SlabTrack scanning API
    const scanApiTiers = ['power', 'dealer'];
    const canUseScanAPI = scanApiTiers.includes(stUser.subscription_tier);

    // Generate CardFlow JWT
    const token = jwt.sign({
      id: user.id,
      email: user.email,
      role: user.role || 'user',
      subscription_tier: user.subscription_tier || 'free'
    }, EFFECTIVE_JWT_SECRET, { expiresIn: JWT_EXPIRY });

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role || 'user',
        subscriptionTier: user.subscription_tier || 'free',
        hasApiKey: !!user.api_key
      },
      slabtrackLinked: true,
      slabtrackTier: stUser.subscription_tier,
      canUseScanAPI
    });

  } catch (e) {
    console.error('[SlabTrack Auth] Error:', e.message);
    if (e.response?.status === 401) {
      return res.status(401).json({ error: 'Invalid or expired SlabTrack token' });
    }
    res.status(500).json({ error: 'Failed to verify SlabTrack token' });
  }
});

// ============================================
// PASSWORD RESET FLOW
// ============================================

// Forgot Password - Request reset email (rate limited)
app.post('/api/auth/forgot-password', passwordResetLimiter, async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const emailLower = email.toLowerCase().trim();

  try {
    // Check if user exists
    const result = await pool.query(
      'SELECT id, email, name, auth_method FROM users WHERE email = $1',
      [emailLower]
    );

    // Always return success to prevent email enumeration
    if (result.rows.length === 0) {
      console.log(`[Password Reset] No user found for email: ${emailLower}`);
      return res.json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent.'
      });
    }

    const user = result.rows[0];

    // Check if user uses SlabTrack auth (no password to reset)
    if (user.auth_method === 'slabtrack') {
      return res.json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent.'
      });
    }

    // Generate secure reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Store hashed token in database
    await pool.query(`
      UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE id = $3
    `, [resetTokenHash, expiresAt, user.id]);

    // Build reset URL
    const resetUrl = `${FRONTEND_URL}/reset-password?token=${resetToken}&email=${encodeURIComponent(emailLower)}`;

    // Send email (if SMTP is configured)
    if (SMTP_USER && SMTP_PASS) {
      try {
        const nodemailer = require('nodemailer');
        const transporter = nodemailer.createTransport({
          host: SMTP_HOST,
          port: SMTP_PORT,
          secure: SMTP_PORT === 465,
          auth: {
            user: SMTP_USER,
            pass: SMTP_PASS
          }
        });

        await transporter.sendMail({
          from: `"CardFlow" <${FROM_EMAIL}>`,
          to: user.email,
          subject: 'Reset Your CardFlow Password',
          html: `
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
              <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #0a0e1a; margin: 0;">CardFlow</h1>
                <p style="color: #666; margin: 5px 0 0 0;">Password Reset Request</p>
              </div>

              <div style="background: #f8f9fa; border-radius: 8px; padding: 30px; margin-bottom: 20px;">
                <p style="color: #333; margin: 0 0 20px 0;">Hi${user.name ? ' ' + user.name : ''},</p>
                <p style="color: #333; margin: 0 0 20px 0;">We received a request to reset your password. Click the button below to create a new password:</p>

                <div style="text-align: center; margin: 30px 0;">
                  <a href="${resetUrl}" style="display: inline-block; background: linear-gradient(135deg, #00f6ff, #7b2ff7); color: #000; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600;">Reset Password</a>
                </div>

                <p style="color: #666; font-size: 14px; margin: 0;">This link will expire in 1 hour.</p>
              </div>

              <div style="color: #999; font-size: 12px; text-align: center;">
                <p style="margin: 0 0 10px 0;">If you didn't request this, you can safely ignore this email.</p>
                <p style="margin: 0;">Your password won't change until you click the link above and create a new one.</p>
              </div>
            </div>
          `
        });

        console.log(`[Password Reset] Email sent to: ${user.email}`);
      } catch (emailError) {
        console.error('[Password Reset] Email send failed:', emailError.message);
        // Don't expose email failure to user
      }
    } else {
      // Development mode - log the reset URL
      console.log(`[Password Reset] SMTP not configured. Reset URL for ${user.email}:`);
      console.log(resetUrl);
    }

    res.json({
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent.'
    });

  } catch (e) {
    console.error('[Password Reset] Error:', e);
    res.status(500).json({ error: 'Failed to process password reset request' });
  }
});

// Reset Password - Verify token and set new password (rate limited)
app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  const { email, token, password } = req.body;

  if (!email || !token || !password) {
    return res.status(400).json({ error: 'Email, token, and new password are required' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const emailLower = email.toLowerCase().trim();
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  try {
    // Find user with valid reset token
    const result = await pool.query(`
      SELECT id, email, reset_token, reset_token_expires
      FROM users
      WHERE email = $1 AND reset_token = $2 AND reset_token_expires > NOW()
    `, [emailLower, tokenHash]);

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset link. Please request a new one.' });
    }

    const user = result.rows[0];

    // Hash new password
    const passwordHash = await bcrypt.hash(password, 10);

    // Update password and clear reset token
    await pool.query(`
      UPDATE users
      SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL, updated_at = NOW()
      WHERE id = $2
    `, [passwordHash, user.id]);

    console.log(`[Password Reset] Password updated for: ${user.email}`);

    res.json({
      success: true,
      message: 'Password reset successful. You can now log in with your new password.'
    });

  } catch (e) {
    console.error('[Password Reset] Error:', e);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Verify reset token (for frontend validation)
app.get('/api/auth/verify-reset-token', async (req, res) => {
  const { email, token } = req.query;

  if (!email || !token) {
    return res.status(400).json({ valid: false, error: 'Missing email or token' });
  }

  const emailLower = email.toLowerCase().trim();
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  try {
    const result = await pool.query(`
      SELECT id FROM users
      WHERE email = $1 AND reset_token = $2 AND reset_token_expires > NOW()
    `, [emailLower, tokenHash]);

    res.json({ valid: result.rows.length > 0 });
  } catch (e) {
    res.status(500).json({ valid: false, error: 'Verification failed' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, email, name, role, subscription_tier, api_key, scans_used, monthly_limit, created_at, slabtrack_tier, stripe_subscription_id
      FROM users WHERE id = $1
    `, [req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];

    // Get user stats
    const cardCount = await pool.query('SELECT COUNT(*) FROM cards WHERE user_id = $1', [user.id]);
    const usageTotal = await pool.query('SELECT SUM(cost) as total FROM api_usage WHERE user_id = $1', [user.id]);

    // Get tier info
    const tierInfo = getTierInfo(user.subscription_tier);

    // SlabTrack power/dealer tiers get free access
    const slabtrackFreeAccess = ['power', 'dealer'].includes(user.slabtrack_tier);

    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      subscriptionTier: user.subscription_tier || 'free',
      tier: tierInfo,
      hasApiKey: !!user.api_key,
      apiKeyPreview: user.api_key ? user.api_key.substring(0, 15) + '...' : null,
      scansUsed: user.scans_used,
      monthlyLimit: user.monthly_limit,
      createdAt: user.created_at,
      slabtrackTier: user.slabtrack_tier,
      slabtrackFreeAccess: slabtrackFreeAccess,
      hasStripeSubscription: !!user.stripe_subscription_id,
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

// Update user API key (encrypted at rest)
app.put('/api/auth/api-key', authenticateToken, async (req, res) => {
  const { api_key } = req.body;

  try {
    if (api_key === null || api_key === '') {
      await pool.query('UPDATE users SET api_key = NULL WHERE id = $1', [req.user.id]);
    } else if (api_key && api_key.startsWith('sk-ant-api03-')) {
      // Encrypt the API key before storing
      const encryptedKey = encryptApiKey(api_key);
      await pool.query('UPDATE users SET api_key = $1 WHERE id = $2', [encryptedKey, req.user.id]);
    } else if (api_key) {
      return res.status(400).json({ error: 'Invalid API key format' });
    }

    res.json({ success: true, hasKey: !!api_key });

  } catch (e) {
    console.error('API key update error:', e);
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

// Swap front/back images
app.post('/api/cards/:id/swap', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE cards
       SET front_image_path = back_image_path,
           back_image_path = front_image_path
       WHERE id = $1 AND user_id = $2
       RETURNING *`,
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Card not found' });
    }

    const card = result.rows[0];
    broadcast({ type: 'card_updated', cardId: card.id, userId: req.user.id });
    res.json({
      success: true,
      front_image: card.front_image_path,
      back_image: card.back_image_path
    });

  } catch (e) {
    console.error('Swap images error:', e);
    res.status(500).json({ error: 'Failed to swap images' });
  }
});

// Reject card (soft delete or mark as rejected)
app.post('/api/cards/:id/reject', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE cards SET status = 'rejected', card_data = card_data || '{"rejected_at": "${new Date().toISOString()}"}'::jsonb
       WHERE id = $1 AND user_id = $2 RETURNING *`,
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Card not found' });
    }

    broadcast({ type: 'card_rejected', cardId: req.params.id, userId: req.user.id });
    res.json({ success: true });

  } catch (e) {
    console.error('Reject card error:', e);
    res.status(500).json({ error: 'Failed to reject card' });
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

// Delete user (admin only)
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  const userId = req.params.id;

  // Prevent self-deletion
  if (userId === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }

  try {
    // Check if user exists
    const userCheck = await pool.query('SELECT email, role FROM users WHERE id = $1', [userId]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const targetUser = userCheck.rows[0];

    // Prevent deleting other admins (extra safety)
    if (targetUser.role === 'admin' && req.user.email !== 'huddleeco@gmail.com') {
      return res.status(403).json({ error: 'Only super admin can delete admin users' });
    }

    // Delete user's data in order (foreign key constraints)
    const deletedCards = await pool.query('DELETE FROM cards WHERE user_id = $1 RETURNING id', [userId]);
    await pool.query('DELETE FROM api_usage WHERE user_id = $1', [userId]);

    // Delete the user
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);

    console.log(`[Admin] User deleted: ${targetUser.email} (${deletedCards.rowCount} cards removed)`);

    res.json({
      success: true,
      message: `User ${targetUser.email} deleted`,
      deletedCards: deletedCards.rowCount
    });

  } catch (e) {
    console.error('Delete user error:', e);
    res.status(500).json({ error: 'Failed to delete user' });
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

    // Top users (fixed: use subqueries to avoid cartesian product)
    const topUsers = await pool.query(`
      SELECT
        u.id,
        u.email,
        u.name,
        u.role,
        u.created_at,
        COALESCE(card_counts.count, 0) as cards,
        COALESCE(cost_totals.total, 0) as cost
      FROM users u
      LEFT JOIN (
        SELECT user_id, COUNT(*) as count FROM cards GROUP BY user_id
      ) card_counts ON card_counts.user_id = u.id
      LEFT JOIN (
        SELECT user_id, SUM(cost) as total FROM api_usage GROUP BY user_id
      ) cost_totals ON cost_totals.user_id = u.id
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

// Admin: Get detailed scan history with filtering
app.get('/api/admin/scan-history', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { userId, source, startDate, endDate, limit = 50, offset = 0 } = req.query;

    let query = `
      SELECT
        a.id,
        a.user_id,
        u.email,
        u.name as full_name,
        a.operation,
        a.model_used,
        a.tokens_input,
        a.tokens_output,
        a.cost,
        a.card_id,
        a.metadata,
        a.timestamp
      FROM api_usage a
      LEFT JOIN users u ON a.user_id = u.id
      WHERE a.operation = 'identify'
    `;

    const params = [];
    let paramIndex = 1;

    if (userId) {
      query += ` AND a.user_id = $${paramIndex++}`;
      params.push(userId);
    }

    if (source) {
      query += ` AND a.metadata->>'scan_source' = $${paramIndex++}`;
      params.push(source);
    }

    if (startDate) {
      query += ` AND DATE(a.timestamp) >= $${paramIndex++}`;
      params.push(startDate);
    }

    if (endDate) {
      query += ` AND DATE(a.timestamp) <= $${paramIndex++}`;
      params.push(endDate);
    }

    query += ` ORDER BY a.timestamp DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    params.push(parseInt(limit), parseInt(offset));

    const scans = await pool.query(query, params);

    // Calculate summary stats
    const summaryQuery = await pool.query(`
      SELECT
        COUNT(*) as total_scans,
        COALESCE(SUM(cost), 0) as total_cost,
        COALESCE(SUM(tokens_input + tokens_output), 0) as total_tokens,
        COUNT(CASE WHEN metadata->>'scan_source' = 'batch' THEN 1 END) as batch_scans,
        COUNT(CASE WHEN metadata->>'scan_source' = 'platform' THEN 1 END) as platform_scans,
        COUNT(CASE WHEN (metadata->>'image_count')::int = 1 THEN 1 END) as single_image_scans,
        COUNT(CASE WHEN (metadata->>'image_count')::int = 2 THEN 1 END) as double_image_scans
      FROM api_usage
      WHERE operation = 'identify'
      AND timestamp > NOW() - INTERVAL '30 days'
    `);

    const summary = summaryQuery.rows[0] || {};

    res.json({
      success: true,
      scans: scans.rows.map(scan => ({
        ...scan,
        metadata: typeof scan.metadata === 'string' ? JSON.parse(scan.metadata) : scan.metadata
      })),
      summary: {
        totalScans: parseInt(summary.total_scans || 0),
        totalCost: parseFloat(summary.total_cost || 0),
        totalTokens: parseInt(summary.total_tokens || 0),
        batchScans: parseInt(summary.batch_scans || 0),
        platformScans: parseInt(summary.platform_scans || 0),
        singleImageScans: parseInt(summary.single_image_scans || 0),
        doubleImageScans: parseInt(summary.double_image_scans || 0),
        avgCostPerScan: parseInt(summary.total_scans) > 0
          ? (parseFloat(summary.total_cost) / parseInt(summary.total_scans)).toFixed(6)
          : '0'
      }
    });

  } catch (e) {
    console.error('Scan history error:', e);
    res.status(500).json({ error: 'Failed to get scan history' });
  }
});

// Admin: SlabTrack Usage Dashboard - Track platform costs
app.get('/api/admin/slabtrack-usage', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { startDate, endDate, limit = 100, offset = 0 } = req.query;

    // Get all SlabTrack scans with full details
    let query = `
      SELECT
        a.id,
        a.user_id,
        a.card_id,
        a.metadata,
        a.timestamp,
        u.email,
        u.name,
        u.slabtrack_tier,
        u.slabtrack_user_id,
        c.front_image_path,
        c.back_image_path,
        c.card_data
      FROM api_usage a
      LEFT JOIN users u ON a.user_id = u.id
      LEFT JOIN cards c ON a.card_id = c.id
      WHERE a.operation = 'slabtrack_scan'
    `;

    const params = [];
    let paramIndex = 1;

    if (startDate) {
      query += ` AND DATE(a.timestamp) >= $${paramIndex++}`;
      params.push(startDate);
    }

    if (endDate) {
      query += ` AND DATE(a.timestamp) <= $${paramIndex++}`;
      params.push(endDate);
    }

    query += ` ORDER BY a.timestamp DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    params.push(parseInt(limit), parseInt(offset));

    const scans = await pool.query(query, params);

    // Summary stats
    const summaryQuery = await pool.query(`
      SELECT
        COUNT(*) as total_scans,
        COUNT(DISTINCT user_id) as unique_users,
        COUNT(CASE WHEN timestamp > NOW() - INTERVAL '24 hours' THEN 1 END) as scans_24h,
        COUNT(CASE WHEN timestamp > NOW() - INTERVAL '7 days' THEN 1 END) as scans_7d,
        COUNT(CASE WHEN timestamp > NOW() - INTERVAL '30 days' THEN 1 END) as scans_30d
      FROM api_usage
      WHERE operation = 'slabtrack_scan'
    `);

    // Top users by SlabTrack scan count
    const topUsersQuery = await pool.query(`
      SELECT
        u.email,
        u.name,
        u.slabtrack_tier,
        COUNT(*) as scan_count,
        MAX(a.timestamp) as last_scan
      FROM api_usage a
      JOIN users u ON a.user_id = u.id
      WHERE a.operation = 'slabtrack_scan'
      AND a.timestamp > NOW() - INTERVAL '30 days'
      GROUP BY u.id, u.email, u.name, u.slabtrack_tier
      ORDER BY scan_count DESC
      LIMIT 20
    `);

    // Daily breakdown (last 30 days)
    const dailyQuery = await pool.query(`
      SELECT
        DATE(timestamp) as date,
        COUNT(*) as scan_count,
        COUNT(DISTINCT user_id) as unique_users
      FROM api_usage
      WHERE operation = 'slabtrack_scan'
      AND timestamp > NOW() - INTERVAL '30 days'
      GROUP BY DATE(timestamp)
      ORDER BY date DESC
    `);

    const summary = summaryQuery.rows[0] || {};

    res.json({
      success: true,
      summary: {
        totalScans: parseInt(summary.total_scans || 0),
        uniqueUsers: parseInt(summary.unique_users || 0),
        scans24h: parseInt(summary.scans_24h || 0),
        scans7d: parseInt(summary.scans_7d || 0),
        scans30d: parseInt(summary.scans_30d || 0)
      },
      topUsers: topUsersQuery.rows,
      dailyBreakdown: dailyQuery.rows,
      scans: scans.rows.map(scan => ({
        id: scan.id,
        timestamp: scan.timestamp,
        user: {
          id: scan.user_id,
          email: scan.email,
          name: scan.name,
          slabtrack_tier: scan.slabtrack_tier,
          slabtrack_user_id: scan.slabtrack_user_id
        },
        card: {
          id: scan.card_id,
          front_image: scan.front_image_path,
          back_image: scan.back_image_path,
          data: typeof scan.card_data === 'string' ? JSON.parse(scan.card_data) : scan.card_data
        },
        metadata: typeof scan.metadata === 'string' ? JSON.parse(scan.metadata) : scan.metadata
      }))
    });

  } catch (e) {
    console.error('SlabTrack usage error:', e);
    res.status(500).json({ error: 'Failed to get SlabTrack usage' });
  }
});

// Admin: Get scan stats overview
app.get('/api/admin/scan-stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // Today's scans
    const todayScans = await pool.query(`
      SELECT
        COUNT(*) as count,
        COALESCE(SUM(cost), 0) as cost,
        COALESCE(SUM(tokens_input + tokens_output), 0) as tokens
      FROM api_usage
      WHERE operation = 'identify'
      AND timestamp > NOW() - INTERVAL '24 hours'
    `);

    // This month's scans
    const monthScans = await pool.query(`
      SELECT
        COUNT(*) as count,
        COALESCE(SUM(cost), 0) as cost,
        COALESCE(SUM(tokens_input + tokens_output), 0) as tokens
      FROM api_usage
      WHERE operation = 'identify'
      AND timestamp > DATE_TRUNC('month', NOW())
    `);

    // Cost trend last 7 days
    const costTrend = await pool.query(`
      SELECT
        DATE(timestamp) as date,
        COUNT(*) as scans,
        COALESCE(SUM(cost), 0) as cost,
        COALESCE(SUM(tokens_input + tokens_output), 0) as tokens
      FROM api_usage
      WHERE operation = 'identify'
      AND timestamp > NOW() - INTERVAL '7 days'
      GROUP BY DATE(timestamp)
      ORDER BY date DESC
    `);

    // Recent scans (last 10)
    const recentScans = await pool.query(`
      SELECT
        a.id,
        u.email,
        u.name,
        a.cost,
        a.tokens_input + a.tokens_output as tokens,
        a.metadata,
        a.timestamp
      FROM api_usage a
      LEFT JOIN users u ON a.user_id = u.id
      WHERE a.operation = 'identify'
      ORDER BY a.timestamp DESC
      LIMIT 10
    `);

    res.json({
      today: {
        scans: parseInt(todayScans.rows[0]?.count || 0),
        cost: parseFloat(todayScans.rows[0]?.cost || 0),
        tokens: parseInt(todayScans.rows[0]?.tokens || 0)
      },
      month: {
        scans: parseInt(monthScans.rows[0]?.count || 0),
        cost: parseFloat(monthScans.rows[0]?.cost || 0),
        tokens: parseInt(monthScans.rows[0]?.tokens || 0)
      },
      costTrend: costTrend.rows,
      recentScans: recentScans.rows.map(scan => ({
        ...scan,
        metadata: typeof scan.metadata === 'string' ? JSON.parse(scan.metadata) : scan.metadata
      }))
    });

  } catch (e) {
    console.error('Scan stats error:', e);
    res.status(500).json({ error: 'Failed to get scan stats' });
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
      // Check scan limit for free tier users
      const userResult = await pool.query(`
        SELECT subscription_tier, role, slabtrack_tier
        FROM users WHERE id = $1
      `, [req.user.id]);

      if (userResult.rows.length > 0) {
        const { subscription_tier, role, slabtrack_tier } = userResult.rows[0];

        // Skip limit check for admin, SlabTrack power/dealer, or paid tiers
        const isAdmin = role === 'admin';
        const hasSlabtrackAccess = ['power', 'dealer'].includes(slabtrack_tier);
        const tier = TIERS[subscription_tier] || TIERS.free;
        const hasUnlimited = tier.features.includes('unlimited_scans');

        if (!isAdmin && !hasSlabtrackAccess && !hasUnlimited) {
          const cardCount = await pool.query(
            'SELECT COUNT(*) FROM cards WHERE user_id = $1',
            [req.user.id]
          );
          const count = parseInt(cardCount.rows[0].count);
          const limit = tier.limit || 10;

          if (count >= limit) {
            return res.status(403).json({
              error: 'Scan limit reached',
              message: `Free tier is limited to ${limit} cards. Upgrade to continue scanning!`,
              currentCount: count,
              limit: limit,
              upgrade_url: '/pricing'
            });
          }
        }
      }

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

      // Store in database and get the card ID
      const isBatchMode = req.body && req.body.batch === 'true';
      const uploadSource = req.body && req.body.source ? req.body.source : 'web'; // phone, desktop, or web
      console.log(`[Upload] Body fields:`, req.body); // Debug: see what's in req.body

      // Parse optional set_context for focused identification
      let setContext = null;
      if (req.body && req.body.set_context) {
        try {
          setContext = typeof req.body.set_context === 'string'
            ? JSON.parse(req.body.set_context)
            : req.body.set_context;
        } catch (e) {
          console.log('[Upload] Invalid set_context, ignoring:', e.message);
        }
      }

      const cardMeta = { uploaded_at: new Date().toISOString(), cloudinary: useCloudinary, batch: isBatchMode, source: uploadSource };
      if (setContext) {
        cardMeta.set_context = setContext;
      }

      const insertResult = await pool.query(`
        INSERT INTO cards (user_id, card_data, front_image_path, back_image_path, status)
        VALUES ($1, $2, $3, $4, 'pending')
        RETURNING id
      `, [
        req.user.id,
        JSON.stringify(cardMeta),
        frontUrl,
        backUrl || null
      ]);

      const cardId = insertResult.rows[0].id;
      console.log(`[Upload] Pair saved: ${cardId} - ${frontUrl}${backUrl ? ' + ' + backUrl : ' (single)'}${isBatchMode ? ' [BATCH]' : ''} [source: ${uploadSource}]`);

      broadcast({
        type: isBatchMode ? 'batch_card_uploaded' : 'pair_uploaded',
        cardId,
        front: frontUrl,
        back: backUrl || null,
        userId: req.user.id,
        source: uploadSource
      });

      // Auto-identify in batch mode
      if (isBatchMode) {
        console.log(`[Batch] Triggering auto-identify for card ${cardId}`);
        identifySingleCard(req.user.id, cardId).catch(e => {
          console.error(`[Batch] Auto-identify error for ${cardId}:`, e.message);
        });
      } else {
        console.log(`[Upload] Not batch mode, skipping auto-identify`);
      }

      res.json({
        success: true,
        cardId,
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

// Get user's API key (decrypted)
async function getUserApiKey(userId) {
  try {
    const result = await pool.query('SELECT api_key FROM users WHERE id = $1', [userId]);
    if (result.rows.length > 0 && result.rows[0].api_key) {
      // Decrypt the API key before returning
      return decryptApiKey(result.rows[0].api_key);
    }
  } catch (e) {
    console.error('[API Key] Error retrieving key:', e.message);
  }
  // No fallback to platform key - true BYOK model
  // Users must have their own API key or use SlabTrack Power/Dealer
  return null;
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

// Check if user can use SlabTrack scanning API (Power/Dealer tiers)
async function canUseSlabTrackScan(userId) {
  try {
    const result = await pool.query(
      'SELECT slabtrack_api_token FROM users WHERE id = $1',
      [userId]
    );
    const slabtrackToken = result.rows[0]?.slabtrack_api_token;
    if (!slabtrackToken) return { canUse: false };

    // Verify token and check tier
    const stResponse = await axios.get(`${SLABTRACK_API}/users/api-token`, {
      headers: { 'X-API-Token': slabtrackToken },
      timeout: 10000
    });

    if (stResponse.data?.success) {
      // Power/Dealer tiers can use SlabTrack scanning API
      const scanApiTiers = ['power', 'dealer'];
      const canUse = scanApiTiers.includes(stResponse.data.user.subscription_tier);
      return { canUse, token: slabtrackToken, tier: stResponse.data.user.subscription_tier };
    }
  } catch (e) {
    console.log('[SlabTrack] Token verification failed:', e.message);
  }
  return { canUse: false };
}

// Identify a single card (for batch mode auto-identification)
// Supports dual-mode: SlabTrack API for Pro users, BYOK for others
async function identifySingleCard(userId, cardId) {
  console.log(`[Batch] Auto-identifying card ${cardId} for user ${userId}`);

  // Get user info for logging
  const userResult = await pool.query(
    'SELECT email, name, slabtrack_tier, slabtrack_user_id FROM users WHERE id = $1',
    [userId]
  );
  const userInfo = userResult.rows[0] || {};

  // Check if user can use SlabTrack scanning (Power/Dealer tier)
  const slabTrackCheck = await canUseSlabTrackScan(userId);

  // Get BYOK API key as fallback
  const apiKey = await getUserApiKey(userId);

  // Need at least one method
  if (!slabTrackCheck.canUse && !apiKey) {
    console.error('[Batch] No API key or SlabTrack Pro for user', userId);
    return;
  }

  // Get the card
  const cardResult = await pool.query('SELECT * FROM cards WHERE id = $1 AND user_id = $2', [cardId, userId]);
  if (cardResult.rows.length === 0) {
    console.error('[Batch] Card not found:', cardId);
    return;
  }

  const card = cardResult.rows[0];
  const cardMeta = typeof card.card_data === 'string' ? JSON.parse(card.card_data) : (card.card_data || {});
  const uploadSource = cardMeta.source || 'web';

  // Notify that identification started
  broadcast({
    type: 'batch_identify_start',
    cardId,
    userId,
    source: uploadSource,
    scanMode: slabTrackCheck.canUse ? 'slabtrack' : 'byok'
  });

  // Try SlabTrack API first if available
  if (slabTrackCheck.canUse) {
    try {
      console.log(`[Batch] Using SlabTrack API for card ${cardId}`);

      // Get images as base64
      const frontBase64 = await getImageBase64(card.front_image_path, FOLDERS.new);
      let backBase64 = null;
      if (card.back_image_path) {
        backBase64 = await getImageBase64(card.back_image_path, FOLDERS.new);
      }

      // Call SlabTrack scanning API (scanner/scan endpoint)
      // Always send base64 data URIs (SlabTrack expects base64, not URLs)
      if (!frontBase64) {
        throw new Error('Failed to load front image');
      }
      const frontImageData = `data:${frontBase64.media_type};base64,${frontBase64.data}`;
      const backImageData = backBase64 ? `data:${backBase64.media_type};base64,${backBase64.data}` : null;

      console.log(`[SlabTrack Scan] Sending to SlabTrack: front=${frontBase64.media_type}, back=${backBase64?.media_type || 'none'}`);

      const stResponse = await axios.post(`${SLABTRACK_API}/scanner/scan`, {
        frontImage: frontImageData,
        backImage: backImageData,
        source: 'cardflow'
      }, {
        headers: {
          'Content-Type': 'application/json',
          'X-API-Token': slabTrackCheck.token
        },
        timeout: 60000
      });

      if (stResponse.data?.success) {
        const cardData = stResponse.data.card;
        cardData.identified_at = new Date().toISOString();
        cardData.scan_source = 'slabtrack';

        // Include pricing data if available
        if (stResponse.data.pricing) {
          cardData.pricing = stResponse.data.pricing;
        }
        if (stResponse.data.sportsCardsPro) {
          cardData.sportsCardsPro = stResponse.data.sportsCardsPro;
        }

        // Update the card
        await pool.query(`
          UPDATE cards SET card_data = $1, status = 'identified', updated_at = NOW()
          WHERE id = $2
        `, [JSON.stringify(cardData), cardId]);

        // Log SlabTrack scan with FULL details for admin tracking (costs platform money)
        const slabtrackMetadata = {
          scan_source: 'slabtrack',
          scan_type: 'slabtrack_api',
          // User info
          user_email: userInfo.email,
          user_name: userInfo.name,
          slabtrack_tier: slabTrackCheck.tier || userInfo.slabtrack_tier,
          slabtrack_user_id: userInfo.slabtrack_user_id,
          // Images
          front_image_url: card.front_image_path,
          back_image_url: card.back_image_path,
          // Card result
          card_identified: {
            player: cardData.player,
            year: cardData.year,
            set_name: cardData.set_name,
            card_number: cardData.card_number,
            parallel: cardData.parallel,
            serial_number: cardData.serial_number,
            sport: cardData.sport,
            is_graded: cardData.is_graded,
            grading_company: cardData.grading_company,
            grade: cardData.grade,
            cert_number: cardData.cert_number
          },
          // Pricing if available
          pricing: stResponse.data.pricing || null,
          sportsCardsPro: stResponse.data.sportsCardsPro || null,
          // Timestamp
          scanned_at: new Date().toISOString()
        };

        await pool.query(`
          INSERT INTO api_usage (user_id, operation, model_used, tokens_input, tokens_output, cost, card_id, metadata)
          VALUES ($1, 'slabtrack_scan', 'slabtrack_api', 0, 0, 0, $2, $3)
        `, [userId, cardId, JSON.stringify(slabtrackMetadata)]);

        console.log(`[SlabTrack Scan] ${userInfo.email} (${slabTrackCheck.tier}) scanned: ${cardData.player}`);

        console.log(`[Batch] Card ${cardId} identified via SlabTrack: ${cardData.player}`);

        broadcast({
          type: 'batch_card_identified',
          cardId,
          cardData,
          userId,
          source: uploadSource,
          scanMode: 'slabtrack'
        });
        return;
      }

      // Handle non-success response from SlabTrack
      if (!stResponse.data?.success) {
        const errorMsg = stResponse.data?.error || stResponse.data?.message || 'Unknown error';
        console.error(`[SlabTrack Scan] API returned error for card ${cardId}: ${errorMsg}`);

        if (stResponse.data?.error === 'TIER_REQUIRED') {
          console.log(`[Batch] SlabTrack tier downgraded for user ${userId}, falling back to BYOK`);
          // Fall through to BYOK if available
        } else {
          // Other error - still try BYOK if available
          console.log(`[Batch] SlabTrack scan failed, will try BYOK if available`);
        }
      }
    } catch (e) {
      // Detailed error logging for SlabTrack scan failures
      const errorDetails = {
        message: e.message,
        status: e.response?.status,
        statusText: e.response?.statusText,
        data: e.response?.data,
        url: `${SLABTRACK_API}/scanner/scan`
      };
      console.error(`[SlabTrack Scan Error] Card ${cardId}:`, JSON.stringify(errorDetails, null, 2));

      // Fall through to BYOK if available
      if (!apiKey) {
        broadcast({
          type: 'batch_identify_error',
          cardId,
          error: 'SlabTrack scan failed: ' + (e.response?.data?.message || e.message),
          userId
        });
        return;
      }
      console.log(`[Batch] Falling back to BYOK for card ${cardId}`);
    }
  }

  // Use BYOK (Anthropic API) - only if we have an API key
  if (!apiKey) {
    console.error(`[Batch] No API key available for BYOK fallback, card ${cardId}`);
    broadcast({
      type: 'batch_identify_error',
      cardId,
      error: 'No scanning method available. Connect SlabTrack Power/Dealer or add your Anthropic API key.',
      userId
    });
    return;
  }

  try {
    console.log(`[Batch] Using BYOK for card ${cardId}`);
    const Anthropic = require('@anthropic-ai/sdk');
    const anthropic = new Anthropic({ apiKey });

    // Build content with images
    const content = [];
    let hasBack = false;

    // Add front image
    const frontBase64 = await getImageBase64(card.front_image_path, FOLDERS.new);
    if (frontBase64) {
      content.push({ type: 'image', source: frontBase64 });
    }

    // Add back image if exists
    if (card.back_image_path) {
      const backBase64 = await getImageBase64(card.back_image_path, FOLDERS.new);
      if (backBase64) {
        content.push({ type: 'image', source: backBase64 });
        hasBack = true;
      }
    }

    // Build prompt - focused if set_context provided, generic otherwise
    const setCtx = cardMeta.set_context;
    let promptText;

    if (setCtx && setCtx.set_name) {
      // Focused prompt with known set context
      const parallelList = (setCtx.parallels && setCtx.parallels.length > 0)
        ? setCtx.parallels.join(', ')
        : 'Base, and any visible parallel/variation';
      const sport = setCtx.sport || 'sports';
      const yearStr = setCtx.year ? `${setCtx.year} ` : '';
      console.log(`[Batch] Using focused prompt for card ${cardId}: ${yearStr}${setCtx.set_name} (${parallelList.split(',').length} parallels)`);

      promptText = `Identify this ${sport} card from the set: ${yearStr}${setCtx.set_name}.
Known parallels for this set: ${parallelList}

${hasBack ? 'I have provided both the FRONT and BACK of the card. Use both images.' : 'This is a single image. Read any label text carefully.'}

Return ONLY a JSON object (no other text):
{
  "player": "Full player name AS SHOWN ON CARD",
  "year": ${setCtx.year || 2024},
  "set_name": "${setCtx.set_name}",
  "card_number": "Card number",
  "parallel": "Pick from known parallels above, or describe if not listed",
  "serial_number": "If numbered (e.g., 25/99) or null",
  "is_autograph": false,
  "is_graded": true,
  "grading_company": "PSA, BGS, SGC, or null",
  "grade": "10, 9.5, 9, etc. or null",
  "cert_number": "Certification number or null",
  "sport": "${setCtx.sport || 'baseball'}",
  "confidence": "high, medium, or low"
}`;
    } else {
      // Generic prompt (unchanged)
      promptText = `CAREFULLY analyze this sports card image and identify it accurately.

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
  "serial_number": "If numbered card, the serial (e.g., 25/99) or null",
  "is_autograph": false,
  "is_graded": true,
  "grading_company": "PSA, BGS, SGC, or null",
  "grade": "10, 9.5, 9, etc. or null",
  "cert_number": "Certification number from label or null",
  "sport": "baseball, basketball, football, hockey, soccer",
  "confidence": "high, medium, or low"
}`;
    }

    content.push({ type: 'text', text: promptText });

    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1024,
      messages: [{ role: 'user', content }]
    });

    const responseText = response.content[0].text;
    const jsonMatch = responseText.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      throw new Error('No JSON in response');
    }

    const cardData = JSON.parse(jsonMatch[0]);
    cardData.identified_at = new Date().toISOString();
    cardData.scan_source = 'byok';

    // Calculate cost
    const inputTokens = response.usage?.input_tokens || 0;
    const outputTokens = response.usage?.output_tokens || 0;
    const cost = (inputTokens * 0.003 + outputTokens * 0.015) / 1000;

    // Update the card
    await pool.query(`
      UPDATE cards SET card_data = $1, status = 'identified', updated_at = NOW()
      WHERE id = $2
    `, [JSON.stringify(cardData), cardId]);

    // Log usage with full metadata for admin tracking
    const metadata = {
      front_image: card.front_image_path,
      back_image: card.back_image_path,
      card_data: cardData,
      scan_source: 'batch',
      image_count: card.back_image_path ? 2 : 1
    };
    await pool.query(`
      INSERT INTO api_usage (user_id, operation, model_used, tokens_input, tokens_output, cost, card_id, metadata)
      VALUES ($1, 'identify', 'sonnet4', $2, $3, $4, $5, $6)
    `, [userId, inputTokens, outputTokens, cost, cardId, JSON.stringify(metadata)]);

    console.log(`[Batch] Card ${cardId} identified via BYOK: ${cardData.player}`);

    // Broadcast completion with card data
    broadcast({
      type: 'batch_card_identified',
      cardId,
      cardData,
      userId,
      source: uploadSource,
      scanMode: 'byok'
    });

  } catch (e) {
    console.error(`[Batch] Error identifying card ${cardId}:`, e.message);
    broadcast({
      type: 'batch_identify_error',
      cardId,
      error: e.message,
      userId
    });
  }
}

// Identify cards endpoint (supports SlabTrack API for Power/Dealer users)
app.post('/api/process/identify', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    // Check if user can use SlabTrack scanning
    const slabTrackCheck = await canUseSlabTrackScan(userId);

    // Get BYOK API key as fallback
    const apiKey = await getUserApiKey(userId);

    // Need at least one method
    if (!slabTrackCheck.canUse && !apiKey) {
      return res.status(400).json({
        error: 'No scanning method available.',
        message: slabTrackCheck.token
          ? 'Your SlabTrack account is Free tier. Upgrade to Power for SlabTrack scanning, or add your own Anthropic API key.'
          : 'Add your Anthropic API key in Settings, or connect a SlabTrack Power/Dealer account.'
      });
    }

    const scanMode = slabTrackCheck.canUse ? 'slabtrack' : 'byok';
    console.log(`[Identify] User ${userId} using ${scanMode} mode`);

    // Get pending cards from database
    const pendingResult = await pool.query(`
      SELECT * FROM cards WHERE user_id = $1 AND status = 'pending'
      ORDER BY created_at
    `, [userId]);

    if (pendingResult.rows.length === 0) {
      return res.status(400).json({ error: 'No pending cards to identify. Upload images first.' });
    }

    const pendingCards = pendingResult.rows;

    // If using SlabTrack, process cards in parallel with concurrency limit
    if (slabTrackCheck.canUse) {
      res.json({
        success: true,
        message: `Processing ${pendingCards.length} cards via SlabTrack (parallel)...`,
        count: pendingCards.length,
        scanMode: 'slabtrack'
      });

      // Process cards in parallel with concurrency limit of 5
      const PARALLEL_LIMIT = 5;
      const processInBatches = async () => {
        for (let i = 0; i < pendingCards.length; i += PARALLEL_LIMIT) {
          const batch = pendingCards.slice(i, i + PARALLEL_LIMIT);
          console.log(`[Identify] Processing batch ${Math.floor(i/PARALLEL_LIMIT) + 1}: ${batch.length} cards in parallel`);

          await Promise.all(
            batch.map(card =>
              identifySingleCard(userId, card.id).catch(e => {
                console.error(`[Identify] SlabTrack error for ${card.id}:`, e.message);
              })
            )
          );
        }
        console.log(`[Identify] All ${pendingCards.length} cards processed`);
      };

      // Fire and forget - don't block response
      processInBatches().catch(e => console.error('[Identify] Batch processing error:', e));
      return;
    }

    // BYOK path - Initialize Anthropic
    const Anthropic = require('@anthropic-ai/sdk');
    const anthropic = new Anthropic({ apiKey });

    // Send initial response
    res.json({
      success: true,
      message: `Processing ${pendingCards.length} cards with your API key...`,
      count: pendingCards.length,
      scanMode: 'byok'
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
  "serial_number": "If numbered card, the serial (e.g., 25/99) or null",
  "is_autograph": false,
  "team": "Team name visible on card",
  "sport": "baseball, basketball, football, hockey, soccer",
  "is_graded": true,
  "grading_company": "PSA, BGS, SGC, CGC - READ FROM LABEL",
  "grade": "Grade number from label (10, 9.5, 9, etc.)",
  "cert_number": "Certification number from label",
  "condition": "mint, near_mint, excellent, good, fair, poor",
  "confidence": "high, medium, or low - be honest if unclear"
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

          // Track API usage with full metadata
          const usageMetadata = {
            front_image: card.front_image_path,
            back_image: card.back_image_path,
            card_data: cardData,
            scan_source: 'platform',
            image_count: card.back_image_path ? 2 : 1
          };
          await pool.query(`
            INSERT INTO api_usage (user_id, operation, model_used, tokens_input, tokens_output, cost, card_id, metadata)
            VALUES ($1, 'identify', 'sonnet4', $2, $3, $4, $5, $6)
          `, [userId, inputTokens, outputTokens, cost, card.id, JSON.stringify(usageMetadata)]);

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

// eBay OAuth Connect - Initiate OAuth flow (PRO TIER REQUIRED)
app.get('/api/ebay/connect', authenticateToken, requireProTier, async (req, res) => {
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

// Map grading company names to eBay condition descriptor IDs
function getGraderEbayId(graderName) {
  const graderMap = {
    'PSA': '275010',
    'BCCG': '275011',
    'BVG': '275012',
    'BGS': '275013',
    'CSG': '275014',
    'SGC': '275016',
    'KSA': '275017',
    'GMA': '275018',
    'HGA': '275019',
    'ISA': '2750110',
    'GSG': '2750112',
    'CGC': '275014',  // Map CGC to CSG
    'Other': '2750123'
  };
  const upper = (graderName || '').toUpperCase();
  return graderMap[upper] || '2750123'; // Default to "Other"
}

// Map grade values to eBay condition descriptor IDs
function getGradeEbayId(grade) {
  const gradeMap = {
    '10': '275020',
    '9.5': '275021',
    '9': '275022',
    '8.5': '275023',
    '8': '275024',
    '7.5': '275025',
    '7': '275026',
    '6.5': '275027',
    '6': '275028',
    '5.5': '275029',
    '5': '2750210',
    '4.5': '2750211',
    '4': '2750212',
    '3.5': '2750213',
    '3': '2750214',
    '2.5': '2750215',
    '2': '2750216',
    '1.5': '2750217',
    '1': '2750218',
    'A': '2750219',      // Authentic
    'AA': '2750220',     // Authentic Altered
    'AT': '2750221',     // Authentic Trimmed
    'AC': '2750222'      // Authentic Coloured
  };
  return gradeMap[String(grade)] || '275020'; // Default to 10
}

// Build conditionDescriptors for trading cards (graded and ungraded)
function buildConditionDescriptors(card) {
  if (card.is_graded && card.grading_company) {
    // Graded cards: Professional Grader + Grade
    return [
      {
        name: '27501', // Professional Grader
        values: [getGraderEbayId(card.grading_company)]
      },
      {
        name: '27502', // Grade
        values: [getGradeEbayId(card.grade)]
      }
    ];
  } else {
    // Ungraded cards: Card Condition
    // 400010 = Near mint or better, 400011 = Excellent, 400012 = Very good, 400013 = Poor
    return [
      {
        name: '40001', // Card Condition
        values: ['400010'] // Default to "Near mint or better"
      }
    ];
  }
}

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

// List card on eBay (PRO TIER REQUIRED)
app.post('/api/ebay/list/:cardId', authenticateToken, requireProTier, async (req, res) => {
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
    // eBay trading cards: LIKE_NEW (2750) = Graded, USED_VERY_GOOD (4000) = Ungraded
    const conditionDescriptors = buildConditionDescriptors(card);

    // Get image URLs (must be publicly accessible - Cloudinary URLs)
    const imageUrls = [row.front_image_path, row.back_image_path]
      .filter(url => url && url.startsWith('http'));

    const inventoryPayload = {
      availability: {
        shipToLocationAvailability: { quantity }
      },
      condition: card.is_graded ? 'LIKE_NEW' : 'USED_VERY_GOOD',
      ...(conditionDescriptors && { conditionDescriptors }),
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
        },
        imageUrls: imageUrls.length > 0 ? imageUrls : undefined
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
app.post('/api/ebay/bulk-create', authenticateToken, requireProTier, async (req, res) => {
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
        // eBay trading cards: LIKE_NEW (2750) = Graded, USED_VERY_GOOD (4000) = Ungraded
        const conditionDescriptors = buildConditionDescriptors(card);
        const imageUrls = [row.front_image_path, row.back_image_path]
          .filter(url => url && url.startsWith('http'));
        const inventoryPayload = {
          availability: { shipToLocationAvailability: { quantity: 1 } },
          condition: card.is_graded ? 'LIKE_NEW' : 'USED_VERY_GOOD',
          ...(conditionDescriptors && { conditionDescriptors }),
          product: {
            title,
            description,
            aspects: {
              'Sport': [card.sport || 'Baseball'],
              'Player': [card.player],
              'Team': [card.team || 'N/A'],
              'Year': [String(card.year)],
              'Card Number': [card.card_number || 'N/A']
            },
            imageUrls: imageUrls.length > 0 ? imageUrls : undefined
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
app.post('/api/ebay/create-lot', authenticateToken, requireProTier, async (req, res) => {
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

app.post('/api/ebay/create-auction', authenticateToken, requireProTier, async (req, res) => {
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
    // eBay trading cards: LIKE_NEW (2750) = Graded, USED_VERY_GOOD (4000) = Ungraded
    const conditionDescriptors = buildConditionDescriptors(card);
    const imageUrls = [row.front_image_path, row.back_image_path]
      .filter(url => url && url.startsWith('http'));
    await axios.put(
      `https://api.ebay.com/sell/inventory/v1/inventory_item/${sku}`,
      {
        availability: { shipToLocationAvailability: { quantity: 1 } },
        condition: card.is_graded ? 'LIKE_NEW' : 'USED_VERY_GOOD',
        ...(conditionDescriptors && { conditionDescriptors }),
        product: {
          title,
          description,
          aspects: {
            'Sport': [card.sport || 'Baseball'],
            'Player': [card.player],
            'Year': [String(card.year)]
          },
          imageUrls: imageUrls.length > 0 ? imageUrls : undefined
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
// BULK OPERATIONS API
// ============================================

// Bulk update cards (price, status)
app.put('/api/cards/bulk-update', authenticateToken, async (req, res) => {
  try {
    const { cardIds, updates } = req.body;

    if (!cardIds || !Array.isArray(cardIds) || cardIds.length === 0) {
      return res.status(400).json({ error: 'No cards selected' });
    }

    let updated = 0;
    for (const cardId of cardIds) {
      const result = await pool.query(
        'SELECT * FROM cards WHERE id = $1 AND user_id = $2',
        [cardId, req.user.id]
      );

      if (result.rows.length > 0) {
        const existingData = result.rows[0].card_data;
        const newCardData = { ...existingData };

        if (updates.recommended_price !== undefined) {
          newCardData.recommended_price = updates.recommended_price;
        }
        if (updates.notes !== undefined) {
          newCardData.notes = updates.notes;
        }

        const newStatus = updates.status || result.rows[0].status;

        await pool.query(
          'UPDATE cards SET card_data = $1, status = $2 WHERE id = $3',
          [JSON.stringify(newCardData), newStatus, cardId]
        );
        updated++;
      }
    }

    broadcast({ type: 'bulk_updated', count: updated, userId: req.user.id });
    res.json({ success: true, updated });

  } catch (e) {
    console.error('Bulk update error:', e);
    res.status(500).json({ error: 'Failed to update cards' });
  }
});

// Bulk delete cards (supports both DELETE and POST for compatibility)
app.delete('/api/cards/bulk-delete', authenticateToken, bulkDeleteHandler);
app.post('/api/cards/bulk-delete', authenticateToken, bulkDeleteHandler);

async function bulkDeleteHandler(req, res) {
  try {
    const { cardIds } = req.body;

    if (!cardIds || !Array.isArray(cardIds) || cardIds.length === 0) {
      return res.status(400).json({ error: 'No cards selected' });
    }

    const result = await pool.query(
      'DELETE FROM cards WHERE id = ANY($1) AND user_id = $2 RETURNING id',
      [cardIds, req.user.id]
    );

    broadcast({ type: 'bulk_deleted', count: result.rowCount, userId: req.user.id });
    res.json({ success: true, deleted: result.rowCount });

  } catch (e) {
    console.error('Bulk delete error:', e);
    res.status(500).json({ error: 'Failed to delete cards' });
  }
}

// ============================================
// LISTING TEMPLATES API
// ============================================

// Get all templates for user
app.get('/api/templates', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM listing_templates WHERE user_id = $1 ORDER BY is_default DESC, name ASC',
      [req.user.id]
    );
    res.json({ templates: result.rows });
  } catch (e) {
    console.error('Get templates error:', e);
    res.status(500).json({ error: 'Failed to load templates' });
  }
});

// Create template
app.post('/api/templates', authenticateToken, async (req, res) => {
  try {
    const { name, title_format, description_template, default_shipping, default_condition, default_quantity, is_default, settings } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Template name required' });
    }

    // If setting as default, unset other defaults first
    if (is_default) {
      await pool.query(
        'UPDATE listing_templates SET is_default = false WHERE user_id = $1',
        [req.user.id]
      );
    }

    const result = await pool.query(`
      INSERT INTO listing_templates (user_id, name, title_format, description_template, default_shipping, default_condition, default_quantity, is_default, settings)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `, [req.user.id, name, title_format || '{year} {set_name} {player} #{card_number} {parallel} {grade}', description_template || '', default_shipping || 'standard_envelope', default_condition || 'USED_VERY_GOOD', default_quantity || 1, is_default || false, JSON.stringify(settings || {})]);

    res.json({ success: true, template: result.rows[0] });

  } catch (e) {
    console.error('Create template error:', e);
    res.status(500).json({ error: 'Failed to create template' });
  }
});

// Update template
app.put('/api/templates/:id', authenticateToken, async (req, res) => {
  try {
    const { name, title_format, description_template, default_shipping, default_condition, default_quantity, is_default, settings } = req.body;

    // Verify ownership
    const check = await pool.query(
      'SELECT id FROM listing_templates WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    if (check.rows.length === 0) {
      return res.status(404).json({ error: 'Template not found' });
    }

    // If setting as default, unset other defaults first
    if (is_default) {
      await pool.query(
        'UPDATE listing_templates SET is_default = false WHERE user_id = $1',
        [req.user.id]
      );
    }

    await pool.query(`
      UPDATE listing_templates SET
        name = COALESCE($1, name),
        title_format = COALESCE($2, title_format),
        description_template = COALESCE($3, description_template),
        default_shipping = COALESCE($4, default_shipping),
        default_condition = COALESCE($5, default_condition),
        default_quantity = COALESCE($6, default_quantity),
        is_default = COALESCE($7, is_default),
        settings = COALESCE($8, settings),
        updated_at = NOW()
      WHERE id = $9
    `, [name, title_format, description_template, default_shipping, default_condition, default_quantity, is_default, settings ? JSON.stringify(settings) : null, req.params.id]);

    res.json({ success: true });

  } catch (e) {
    console.error('Update template error:', e);
    res.status(500).json({ error: 'Failed to update template' });
  }
});

// Delete template
app.delete('/api/templates/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM listing_templates WHERE id = $1 AND user_id = $2 RETURNING id',
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Template not found' });
    }

    res.json({ success: true });

  } catch (e) {
    console.error('Delete template error:', e);
    res.status(500).json({ error: 'Failed to delete template' });
  }
});

// ============================================
// SALES TRACKING API
// ============================================

// Get all sales for user
app.get('/api/sales', authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate, platform } = req.query;
    let query = 'SELECT * FROM sales WHERE user_id = $1';
    const params = [req.user.id];
    let paramIndex = 2;

    if (startDate) {
      query += ` AND sale_date >= $${paramIndex}`;
      params.push(startDate);
      paramIndex++;
    }
    if (endDate) {
      query += ` AND sale_date <= $${paramIndex}`;
      params.push(endDate);
      paramIndex++;
    }
    if (platform) {
      query += ` AND platform = $${paramIndex}`;
      params.push(platform);
    }

    query += ' ORDER BY sale_date DESC';

    const result = await pool.query(query, params);

    // Calculate totals
    const totals = result.rows.reduce((acc, sale) => ({
      revenue: acc.revenue + parseFloat(sale.sale_price || 0),
      shipping: acc.shipping + parseFloat(sale.shipping_cost || 0),
      fees: acc.fees + parseFloat(sale.fees || 0),
      profit: acc.profit + parseFloat(sale.profit || 0),
      count: acc.count + 1
    }), { revenue: 0, shipping: 0, fees: 0, profit: 0, count: 0 });

    res.json({ sales: result.rows, totals });

  } catch (e) {
    console.error('Get sales error:', e);
    res.status(500).json({ error: 'Failed to load sales' });
  }
});

// Record a sale
app.post('/api/sales', authenticateToken, async (req, res) => {
  try {
    const { card_id, sale_price, sale_date, platform, buyer_username, shipping_cost, fees, notes, ebay_listing_id } = req.body;

    if (!sale_price) {
      return res.status(400).json({ error: 'Sale price required' });
    }

    // Get card snapshot if card_id provided
    let cardSnapshot = null;
    if (card_id) {
      const cardResult = await pool.query(
        'SELECT * FROM cards WHERE id = $1 AND user_id = $2',
        [card_id, req.user.id]
      );
      if (cardResult.rows.length > 0) {
        const row = cardResult.rows[0];
        cardSnapshot = {
          ...row.card_data,
          front_image: row.front_image_path,
          back_image: row.back_image_path
        };

        // Update card status to sold
        await pool.query(
          "UPDATE cards SET status = 'sold', card_data = card_data || $1::jsonb WHERE id = $2",
          [JSON.stringify({ sold_at: new Date().toISOString(), sold_price: sale_price }), card_id]
        );
      }
    }

    // Calculate profit
    const saleAmount = parseFloat(sale_price) || 0;
    const shippingAmount = parseFloat(shipping_cost) || 0;
    const feeAmount = parseFloat(fees) || (saleAmount * 0.1325); // Default eBay fees ~13.25%
    const profit = saleAmount - feeAmount;

    const result = await pool.query(`
      INSERT INTO sales (user_id, card_id, sale_price, sale_date, platform, buyer_username, shipping_cost, fees, profit, notes, ebay_listing_id, card_snapshot)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *
    `, [req.user.id, card_id, saleAmount, sale_date || new Date(), platform || 'ebay', buyer_username, shippingAmount, feeAmount, profit, notes, ebay_listing_id, cardSnapshot ? JSON.stringify(cardSnapshot) : null]);

    broadcast({ type: 'sale_recorded', sale: result.rows[0], userId: req.user.id });
    res.json({ success: true, sale: result.rows[0] });

  } catch (e) {
    console.error('Record sale error:', e);
    res.status(500).json({ error: 'Failed to record sale' });
  }
});

// Get sales dashboard/summary
app.get('/api/sales/summary', authenticateToken, async (req, res) => {
  try {
    // Total all time
    const totalResult = await pool.query(`
      SELECT
        COUNT(*) as total_sales,
        COALESCE(SUM(sale_price), 0) as total_revenue,
        COALESCE(SUM(profit), 0) as total_profit,
        COALESCE(SUM(fees), 0) as total_fees
      FROM sales WHERE user_id = $1
    `, [req.user.id]);

    // This month
    const monthResult = await pool.query(`
      SELECT
        COUNT(*) as sales,
        COALESCE(SUM(sale_price), 0) as revenue,
        COALESCE(SUM(profit), 0) as profit
      FROM sales
      WHERE user_id = $1 AND sale_date >= date_trunc('month', CURRENT_DATE)
    `, [req.user.id]);

    // By platform
    const platformResult = await pool.query(`
      SELECT platform, COUNT(*) as count, COALESCE(SUM(sale_price), 0) as revenue
      FROM sales WHERE user_id = $1
      GROUP BY platform
    `, [req.user.id]);

    // Recent sales (last 30 days by day)
    const dailyResult = await pool.query(`
      SELECT DATE(sale_date) as date, COUNT(*) as count, COALESCE(SUM(sale_price), 0) as revenue
      FROM sales
      WHERE user_id = $1 AND sale_date >= CURRENT_DATE - INTERVAL '30 days'
      GROUP BY DATE(sale_date)
      ORDER BY date
    `, [req.user.id]);

    res.json({
      allTime: totalResult.rows[0],
      thisMonth: monthResult.rows[0],
      byPlatform: platformResult.rows,
      daily: dailyResult.rows
    });

  } catch (e) {
    console.error('Sales summary error:', e);
    res.status(500).json({ error: 'Failed to load sales summary' });
  }
});

// ============================================
// EXPORT API (CSV/Excel with images)
// ============================================

// Export cards to CSV
app.get('/api/export/csv', authenticateToken, async (req, res) => {
  try {
    const { cardIds, status } = req.query;

    let query = 'SELECT * FROM cards WHERE user_id = $1';
    const params = [req.user.id];

    if (cardIds) {
      const ids = cardIds.split(',');
      query += ' AND id = ANY($2)';
      params.push(ids);
    } else if (status) {
      query += ' AND status = $2';
      params.push(status);
    }

    query += ' ORDER BY created_at DESC';

    const result = await pool.query(query, params);

    // Build CSV
    const headers = ['Player', 'Year', 'Set', 'Card #', 'Parallel', 'Grading Company', 'Grade', 'Condition', 'Recommended Price', 'eBay Low', 'eBay Avg', 'eBay High', 'Status', 'Front Image', 'Back Image', 'Notes'];

    let csv = headers.join(',') + '\n';

    for (const row of result.rows) {
      const card = row.card_data;
      const values = [
        `"${(card.player || '').replace(/"/g, '""')}"`,
        card.year || '',
        `"${(card.set_name || '').replace(/"/g, '""')}"`,
        card.card_number || '',
        `"${(card.parallel || '').replace(/"/g, '""')}"`,
        card.grading_company || '',
        card.grade || '',
        card.condition || '',
        card.recommended_price || '',
        card.ebay_low || '',
        card.ebay_avg || '',
        card.ebay_high || '',
        row.status || '',
        row.front_image_path || '',
        row.back_image_path || '',
        `"${(card.notes || '').replace(/"/g, '""')}"`
      ];
      csv += values.join(',') + '\n';
    }

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="cardflow-export-${Date.now()}.csv"`);
    res.send(csv);

  } catch (e) {
    console.error('CSV export error:', e);
    res.status(500).json({ error: 'Failed to export CSV' });
  }
});

// Export cards to Excel with images
app.get('/api/export/excel', authenticateToken, async (req, res) => {
  try {
    const { cardIds, status, includeImages } = req.query;

    let query = 'SELECT * FROM cards WHERE user_id = $1';
    const params = [req.user.id];

    if (cardIds) {
      const ids = cardIds.split(',');
      query += ' AND id = ANY($2)';
      params.push(ids);
    } else if (status) {
      query += ' AND status = $2';
      params.push(status);
    }

    query += ' ORDER BY created_at DESC';

    const result = await pool.query(query, params);

    // Build worksheet data
    const wsData = [
      ['Player', 'Year', 'Set', 'Card #', 'Parallel', 'Grading Company', 'Grade', 'Condition', 'Recommended Price', 'eBay Low', 'eBay Avg', 'eBay High', 'Status', 'Front Image URL', 'Back Image URL', 'Notes']
    ];

    for (const row of result.rows) {
      const card = row.card_data;
      wsData.push([
        card.player || '',
        card.year || '',
        card.set_name || '',
        card.card_number || '',
        card.parallel || '',
        card.grading_company || '',
        card.grade || '',
        card.condition || '',
        card.recommended_price || '',
        card.ebay_low || '',
        card.ebay_avg || '',
        card.ebay_high || '',
        row.status || '',
        row.front_image_path || '',
        row.back_image_path || '',
        card.notes || ''
      ]);
    }

    // Create workbook
    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.aoa_to_sheet(wsData);

    // Set column widths
    ws['!cols'] = [
      { wch: 25 }, // Player
      { wch: 8 },  // Year
      { wch: 30 }, // Set
      { wch: 8 },  // Card #
      { wch: 20 }, // Parallel
      { wch: 15 }, // Grading
      { wch: 8 },  // Grade
      { wch: 15 }, // Condition
      { wch: 12 }, // Price
      { wch: 10 }, // Low
      { wch: 10 }, // Avg
      { wch: 10 }, // High
      { wch: 10 }, // Status
      { wch: 50 }, // Front URL
      { wch: 50 }, // Back URL
      { wch: 30 }  // Notes
    ];

    XLSX.utils.book_append_sheet(wb, ws, 'Cards');

    // Add summary sheet
    const totalValue = result.rows.reduce((sum, row) => sum + (parseFloat(row.card_data.recommended_price) || 0), 0);
    const summaryData = [
      ['CardFlow Export Summary'],
      [''],
      ['Total Cards', result.rows.length],
      ['Total Value', `$${totalValue.toFixed(2)}`],
      ['Export Date', new Date().toLocaleString()],
      [''],
      ['Status Breakdown'],
      ...Object.entries(result.rows.reduce((acc, row) => {
        acc[row.status] = (acc[row.status] || 0) + 1;
        return acc;
      }, {})).map(([status, count]) => [status, count])
    ];

    const summaryWs = XLSX.utils.aoa_to_sheet(summaryData);
    XLSX.utils.book_append_sheet(wb, summaryWs, 'Summary');

    // Generate buffer
    const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="cardflow-export-${Date.now()}.xlsx"`);
    res.send(buffer);

  } catch (e) {
    console.error('Excel export error:', e);
    res.status(500).json({ error: 'Failed to export Excel' });
  }
});

// ============================================
// DUPLICATE DETECTION API
// ============================================

// Check for duplicate cards
app.post('/api/cards/check-duplicates', authenticateToken, async (req, res) => {
  try {
    const { player, year, set_name, card_number, grading_company, grade } = req.body;

    let query = `
      SELECT id, card_data, status, front_image_path
      FROM cards
      WHERE user_id = $1
    `;
    const params = [req.user.id];
    let paramIndex = 2;

    const conditions = [];

    if (player) {
      conditions.push(`card_data->>'player' ILIKE $${paramIndex}`);
      params.push(`%${player}%`);
      paramIndex++;
    }
    if (year) {
      conditions.push(`card_data->>'year' = $${paramIndex}`);
      params.push(String(year));
      paramIndex++;
    }
    if (set_name) {
      conditions.push(`card_data->>'set_name' ILIKE $${paramIndex}`);
      params.push(`%${set_name}%`);
      paramIndex++;
    }
    if (card_number) {
      conditions.push(`card_data->>'card_number' = $${paramIndex}`);
      params.push(String(card_number));
      paramIndex++;
    }

    if (conditions.length > 0) {
      query += ' AND (' + conditions.join(' AND ') + ')';
    }

    const result = await pool.query(query, params);

    // Score matches
    const matches = result.rows.map(row => {
      const card = row.card_data;
      let score = 0;

      if (player && card.player && card.player.toLowerCase().includes(player.toLowerCase())) score += 30;
      if (year && card.year === String(year)) score += 20;
      if (set_name && card.set_name && card.set_name.toLowerCase().includes(set_name.toLowerCase())) score += 25;
      if (card_number && card.card_number === String(card_number)) score += 25;

      // Exact match bonus
      if (grading_company && card.grading_company === grading_company) score += 10;
      if (grade && card.grade === String(grade)) score += 10;

      return {
        id: row.id,
        card: { ...card, front: row.front_image_path },
        status: row.status,
        matchScore: score
      };
    }).filter(m => m.matchScore >= 50) // Only return likely matches
      .sort((a, b) => b.matchScore - a.matchScore)
      .slice(0, 5); // Top 5 matches

    res.json({
      hasDuplicates: matches.length > 0,
      matches
    });

  } catch (e) {
    console.error('Duplicate check error:', e);
    res.status(500).json({ error: 'Failed to check duplicates' });
  }
});

// ============================================
// EXPORT ENDPOINTS
// ============================================

// Export to Whatnot CSV format
app.post('/api/export/whatnot', authenticateToken, async (req, res) => {
  try {
    const { cardIds } = req.body;
    const userId = req.user.id;

    if (!cardIds || cardIds.length === 0) {
      return res.status(400).json({ error: 'No cards selected' });
    }

    console.log(`[Export] Whatnot CSV: ${cardIds.length} cards for user ${userId}`);

    // Get cards
    const placeholders = cardIds.map((_, i) => `$${i + 1}`).join(',');
    const result = await pool.query(`
      SELECT * FROM cards
      WHERE id IN (${placeholders}) AND user_id = $${cardIds.length + 1}
    `, [...cardIds, userId]);

    const cards = result.rows;

    // Sport to subcategory mapping
    const getSubCategory = (sport) => {
      const sportMap = {
        'baseball': 'Baseball Singles',
        'basketball': 'Basketball Singles',
        'football': 'Football Singles',
        'hockey': 'Hockey Singles',
        'soccer': 'Soccer Singles'
      };
      return sportMap[sport?.toLowerCase()] || 'Other Sports Cards';
    };

    // Whatnot CSV headers
    const headers = [
      'Category', 'Sub Category', 'Title', 'Description', 'Quantity', 'Type',
      'Price', 'Shipping Profile', 'Offerable', 'Hazmat', 'Condition',
      'Cost Per Item', 'SKU', 'Image URL 1', 'Image URL 2', 'Image URL 3',
      'Image URL 4', 'Image URL 5', 'Image URL 6', 'Image URL 7', 'Image URL 8'
    ];

    const csvRows = [
      headers.join(','),
      ...cards.map(card => {
        const data = typeof card.card_data === 'string' ? JSON.parse(card.card_data) : card.card_data;

        const category = 'Sports Cards';
        const subCategory = getSubCategory(data.sport);

        // Build title (max 80 chars)
        let title = `${data.year || ''} ${data.set_name || ''} ${data.player || ''}`.trim();
        if (data.is_graded && data.grading_company && data.grade) {
          title += ` ${data.grading_company} ${data.grade}`;
        }
        if (data.card_number) title += ` #${data.card_number}`;
        if (data.parallel && data.parallel !== 'Base') title += ` ${data.parallel}`;
        if (title.length > 80) title = title.substring(0, 77) + '...';

        // Build description
        let description = `${data.year || ''} ${data.set_name || ''} ${data.player || ''}`;
        if (data.card_number) description += ` #${data.card_number}`;
        if (data.parallel && data.parallel !== 'Base') description += ` - ${data.parallel}`;
        if (data.is_graded) {
          description += `\\nGraded: ${data.grading_company} ${data.grade}`;
          if (data.cert_number) description += `\\nCert #: ${data.cert_number}`;
        }
        if (data.is_autograph) description += `\\nAutographed`;
        if (data.serial_number) description += `\\nNumbered: ${data.serial_number}`;

        const type = 'Auction';
        const price = '';
        const shippingProfile = '0-1 oz';
        const offerable = 'TRUE';
        const hazmat = 'Not Hazmat';
        const condition = data.is_graded ? 'Graded' : 'Used';
        const costPerItem = '';
        const sku = `CARDFLOW-${card.id}`;

        return [
          `"${category}"`,
          `"${subCategory}"`,
          `"${title.replace(/"/g, '""')}"`,
          `"${description.replace(/"/g, '""')}"`,
          '1',
          `"${type}"`,
          price,
          `"${shippingProfile}"`,
          offerable,
          `"${hazmat}"`,
          `"${condition}"`,
          costPerItem,
          `"${sku}"`,
          card.front_image_path || '',
          card.back_image_path || '',
          '', '', '', '', '', ''
        ].join(',');
      })
    ];

    const csv = csvRows.join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="CardFlow-Whatnot-${Date.now()}.csv"`);
    res.send(csv);

    console.log(`[Export] Whatnot CSV complete: ${cards.length} cards`);

  } catch (e) {
    console.error('Whatnot export error:', e);
    res.status(500).json({ error: 'Export failed' });
  }
});

// Export to SlabTrack Excel format with exact column names for import compatibility
// SlabTrack expects specific column names and data types (booleans, not Yes/No)
app.post('/api/export/slabtrack', authenticateToken, async (req, res) => {
  try {
    const { cardIds } = req.body;
    const userId = req.user.id;

    if (!cardIds || cardIds.length === 0) {
      return res.status(400).json({ error: 'No cards selected' });
    }

    console.log(`[Export] SlabTrack Excel: ${cardIds.length} cards for user ${userId}`);

    const placeholders = cardIds.map((_, i) => `$${i + 1}`).join(',');
    const result = await pool.query(`
      SELECT * FROM cards
      WHERE id IN (${placeholders}) AND user_id = $${cardIds.length + 1}
    `, [...cardIds, userId]);

    const cards = result.rows;

    // Create Excel workbook
    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'CardFlow';
    workbook.created = new Date();
    const worksheet = workbook.addWorksheet('Cards');

    // SlabTrack exact column names (required for import compatibility)
    worksheet.columns = [
      { header: 'player', key: 'player', width: 20 },
      { header: 'year', key: 'year', width: 8 },
      { header: 'set_name', key: 'set_name', width: 25 },
      { header: 'card_number', key: 'card_number', width: 10 },
      { header: 'parallel', key: 'parallel', width: 15 },
      { header: 'sport', key: 'sport', width: 12 },
      { header: 'team', key: 'team', width: 15 },
      { header: 'is_graded', key: 'is_graded', width: 10 },
      { header: 'grading_company', key: 'grading_company', width: 12 },
      { header: 'grade', key: 'grade', width: 8 },
      { header: 'cert_number', key: 'cert_number', width: 15 },
      { header: 'is_autographed', key: 'is_autographed', width: 12 },
      { header: 'serial_number', key: 'serial_number', width: 12 },
      { header: 'numbered_to', key: 'numbered_to', width: 10 },
      { header: 'asking_price', key: 'asking_price', width: 12 },
      { header: 'purchase_price', key: 'purchase_price', width: 12 },
      { header: 'condition', key: 'condition', width: 12 },
      { header: 'notes', key: 'notes', width: 25 },
      { header: 'front_image_url', key: 'front_image_url', width: 40 },
      { header: 'back_image_url', key: 'back_image_url', width: 40 }
    ];

    // Style header row
    worksheet.getRow(1).font = { bold: true };
    worksheet.getRow(1).fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'FF2563EB' }
    };
    worksheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };

    // Process each card with SlabTrack-compatible data types
    for (let i = 0; i < cards.length; i++) {
      const card = cards[i];
      const data = typeof card.card_data === 'string' ? JSON.parse(card.card_data) : card.card_data;

      // Convert values to SlabTrack format
      // Booleans: true/false (not "Yes"/"No")
      // Numbers: actual numbers (not strings)
      const isGraded = data.is_graded === true || data.is_graded === 'Yes' || data.is_graded === 'yes';
      const isAutographed = data.is_autograph === true || data.is_autograph === 'Yes' || data.is_autograph === 'yes' ||
                            data.is_autographed === true || data.is_autographed === 'Yes';

      worksheet.addRow({
        player: data.player || '',
        year: data.year ? parseInt(data.year) : '',
        set_name: data.set_name || '',
        card_number: String(data.card_number || ''),
        parallel: data.parallel || 'Base',
        sport: (data.sport || '').toLowerCase(),
        team: data.team || '',
        is_graded: isGraded,
        grading_company: isGraded ? (data.grading_company || '') : '',
        grade: isGraded ? (data.grade || '') : '',
        cert_number: isGraded ? (data.cert_number || '') : '',
        is_autographed: isAutographed,
        serial_number: data.serial_number || '',
        numbered_to: data.numbered_to ? parseInt(data.numbered_to) : '',
        asking_price: data.my_price ? parseFloat(data.my_price) : (data.asking_price ? parseFloat(data.asking_price) : ''),
        purchase_price: data.purchase_price ? parseFloat(data.purchase_price) : '',
        condition: !isGraded ? (data.condition || '') : '',
        notes: data.notes || '',
        front_image_url: card.front_image_path || '',
        back_image_url: card.back_image_path || ''
      });

      // Log progress for large exports
      if ((i + 1) % 50 === 0) {
        console.log(`[Export] Processed ${i + 1}/${cards.length} cards...`);
      }
    }

    // Generate Excel buffer
    const buffer = await workbook.xlsx.writeBuffer();

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="CardFlow-SlabTrack-${Date.now()}.xlsx"`);
    res.send(buffer);

    console.log(`[Export] SlabTrack Excel complete: ${cards.length} cards`);

  } catch (e) {
    console.error('SlabTrack export error:', e);
    res.status(500).json({ error: 'Export failed' });
  }
});

// ==============================
// SLABTRACK DIRECT API INTEGRATION
// ==============================

// Get SlabTrack connection status (with user info from SlabTrack API)
app.get('/api/slabtrack/status', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT slabtrack_api_token FROM users WHERE id = $1',
      [req.user.id]
    );

    const slabtrackToken = result.rows[0]?.slabtrack_api_token;

    if (!slabtrackToken) {
      return res.json({
        connected: false,
        tokenPreview: null,
        user: null,
        canUseScanAPI: false
      });
    }

    // Verify token and get user info from SlabTrack
    try {
      const stResponse = await axios.get(`${SLABTRACK_API}/users/api-token`, {
        headers: { 'X-API-Token': slabtrackToken },
        timeout: 10000
      });

      if (stResponse.data?.success) {
        const stUser = stResponse.data.user;
        // Power/Dealer tiers can use SlabTrack scanning API
        const scanApiTiers = ['power', 'dealer'];
        const canUseScanAPI = scanApiTiers.includes(stUser.subscription_tier);

        return res.json({
          connected: true,
          tokenPreview: '••••••••' + slabtrackToken.slice(-4),
          user: {
            email: stUser.email,
            name: stUser.full_name,
            tier: stUser.subscription_tier,
            scansUsed: stUser.scansUsed || 0
          },
          canUseScanAPI
        });
      }
    } catch (stError) {
      console.error('SlabTrack API error:', stError.message);
      // Token exists but couldn't verify - still show as connected
    }

    res.json({
      connected: true,
      tokenPreview: '••••••••' + slabtrackToken.slice(-4),
      user: null,
      canUseScanAPI: false
    });
  } catch (e) {
    console.error('SlabTrack status error:', e);
    res.status(500).json({ error: 'Failed to get status' });
  }
});

// Save SlabTrack API token
app.post('/api/slabtrack/token', authenticateToken, async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }

    // Store the token
    await pool.query(
      'UPDATE users SET slabtrack_api_token = $1 WHERE id = $2',
      [token, req.user.id]
    );

    console.log(`[SlabTrack] Token saved for user ${req.user.id}`);
    res.json({ success: true, message: 'SlabTrack token saved' });

  } catch (e) {
    console.error('SlabTrack token save error:', e);
    res.status(500).json({ error: 'Failed to save token' });
  }
});

// Remove SlabTrack token
app.delete('/api/slabtrack/token', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      'UPDATE users SET slabtrack_api_token = NULL WHERE id = $1',
      [req.user.id]
    );

    console.log(`[SlabTrack] Token removed for user ${req.user.id}`);
    res.json({ success: true, message: 'SlabTrack disconnected' });

  } catch (e) {
    console.error('SlabTrack token remove error:', e);
    res.status(500).json({ error: 'Failed to disconnect' });
  }
});

// Scan card via SlabTrack API (for Pro users)
// This uses SlabTrack's AI credits instead of BYOK
app.post('/api/slabtrack/scan', authenticateToken, async (req, res) => {
  try {
    const { frontImage, backImage } = req.body;

    if (!frontImage) {
      return res.status(400).json({ error: 'Front image is required' });
    }

    // Get user's SlabTrack token
    const userResult = await pool.query(
      'SELECT slabtrack_api_token FROM users WHERE id = $1',
      [req.user.id]
    );

    const slabtrackToken = userResult.rows[0]?.slabtrack_api_token;
    if (!slabtrackToken) {
      return res.status(400).json({
        error: 'SlabTrack not connected',
        message: 'Connect your SlabTrack account to use SlabTrack scanning'
      });
    }

    console.log(`[SlabTrack] Scanning card via SlabTrack API for user ${req.user.id}`);

    // Call SlabTrack's scanner/scan API
    const response = await axios.post(`${SLABTRACK_API}/scanner/scan`, {
      frontImage,
      backImage: backImage || null,
      source: 'cardflow'
    }, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Token': slabtrackToken
      },
      timeout: 60000
    });

    if (!response.data?.success) {
      throw new Error(response.data?.error || 'Scan failed');
    }

    console.log(`[SlabTrack] Scan successful: ${response.data.card?.player || 'Unknown'}`);

    res.json({
      success: true,
      card: response.data.card,
      pricing: response.data.pricing || null,
      source: 'slabtrack'
    });

  } catch (e) {
    console.error('SlabTrack scan error:', e.response?.data || e.message);

    if (e.response?.status === 401) {
      return res.status(401).json({
        error: 'SlabTrack authentication failed',
        message: 'Your SlabTrack token may be invalid. Please reconnect.'
      });
    }

    if (e.response?.status === 402) {
      return res.status(402).json({
        error: 'No scan credits remaining',
        message: 'Your SlabTrack scan credits have been exhausted. Upgrade your plan or use BYOK mode.'
      });
    }

    if (e.response?.status === 403) {
      return res.status(403).json({
        error: 'SlabTrack Pro required',
        message: 'SlabTrack scanning requires a Pro subscription. Use BYOK mode instead.'
      });
    }

    res.status(500).json({
      error: 'Scan failed',
      message: e.message
    });
  }
});

// Send cards directly to SlabTrack
app.post('/api/slabtrack/send', authenticateToken, async (req, res) => {
  try {
    const { cardIds } = req.body;
    const userId = req.user.id;

    if (!cardIds || cardIds.length === 0) {
      return res.status(400).json({ error: 'No cards selected' });
    }

    // Get user's SlabTrack token
    const userResult = await pool.query(
      'SELECT slabtrack_api_token FROM users WHERE id = $1',
      [userId]
    );

    const slabtrackToken = userResult.rows[0]?.slabtrack_api_token;
    if (!slabtrackToken) {
      return res.status(400).json({
        error: 'SlabTrack not connected',
        message: 'Please connect your SlabTrack account in Settings first'
      });
    }

    console.log(`[SlabTrack] Sending ${cardIds.length} cards for user ${userId}`);

    // Fetch the cards
    const placeholders = cardIds.map((_, i) => `$${i + 1}`).join(',');
    const cardsResult = await pool.query(`
      SELECT * FROM cards
      WHERE id IN (${placeholders}) AND user_id = $${cardIds.length + 1}
    `, [...cardIds, userId]);

    const cards = cardsResult.rows;

    // Map CardFlow format to SlabTrack format
    const mappedCards = cards.map(card => {
      const data = typeof card.card_data === 'string' ? JSON.parse(card.card_data) : card.card_data;

      // Convert booleans properly
      const isGraded = data.is_graded === true || data.is_graded === 'Yes' || data.is_graded === 'yes';
      const isAutographed = data.is_autograph === true || data.is_autograph === 'Yes' ||
                            data.is_autographed === true || data.is_autographed === 'Yes';

      return {
        player: data.player || '',
        year: data.year ? parseInt(data.year) : null,
        set_name: data.set_name || '',
        card_number: String(data.card_number || ''),
        parallel: data.parallel || 'Base',
        sport: (data.sport || '').toLowerCase(),
        team: data.team || '',
        is_graded: isGraded,
        grading_company: isGraded ? (data.grading_company || '') : null,
        grade: isGraded ? (data.grade || '') : null,
        cert_number: isGraded ? (data.cert_number || '') : null,
        is_autographed: isAutographed,
        serial_number: data.serial_number || null,
        numbered_to: data.numbered_to ? parseInt(data.numbered_to) : null,
        asking_price: data.my_price ? parseFloat(data.my_price) : (data.asking_price ? parseFloat(data.asking_price) : null),
        purchase_price: data.purchase_price ? parseFloat(data.purchase_price) : null,
        condition: !isGraded ? (data.condition || '') : null,
        notes: data.notes || '',
        front_image_url: card.front_image_path || '',
        back_image_url: card.back_image_path || ''
      };
    });

    // Send to SlabTrack
    const response = await axios.post(`${SLABTRACK_API}/atlas/bulk-import`, {
      cards: mappedCards
    }, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Token': slabtrackToken
      },
      timeout: 60000 // 60 second timeout for large imports
    });

    // Check for success: false in response (SlabTrack may return 200 with error)
    if (response.data?.success === false) {
      console.error('[SlabTrack] API returned error:', response.data);
      const errorMsg = response.data?.error || 'Unknown error';

      if (errorMsg.toLowerCase().includes('token') || errorMsg.toLowerCase().includes('auth')) {
        return res.status(401).json({
          error: 'SlabTrack token expired',
          message: 'Your SlabTrack token is invalid or expired. Please reconnect in Settings → SlabTrack.'
        });
      }

      return res.status(400).json({
        error: 'SlabTrack error',
        message: errorMsg
      });
    }

    console.log(`[SlabTrack] Send complete: ${response.data?.imported || cards.length} cards imported`);

    res.json({
      success: true,
      imported: response.data?.imported || cards.length,
      message: `Successfully sent ${response.data?.imported || cards.length} cards to SlabTrack`
    });

  } catch (e) {
    console.error('SlabTrack send error:', e.response?.data || e.message);

    // Handle specific errors
    if (e.response?.status === 401) {
      return res.status(401).json({
        error: 'SlabTrack authentication failed',
        message: 'Your SlabTrack token may be invalid or expired. Please reconnect in Settings.'
      });
    }

    if (e.response?.status === 400) {
      return res.status(400).json({
        error: 'SlabTrack rejected the data',
        message: e.response.data?.error || 'Invalid card data format'
      });
    }

    res.status(500).json({
      error: 'Failed to send to SlabTrack',
      message: e.message
    });
  }
});

// Export to generic CSV
app.post('/api/export/csv', authenticateToken, async (req, res) => {
  try {
    const { cardIds } = req.body;
    const userId = req.user.id;

    if (!cardIds || cardIds.length === 0) {
      return res.status(400).json({ error: 'No cards selected' });
    }

    console.log(`[Export] Generic CSV: ${cardIds.length} cards for user ${userId}`);

    const placeholders = cardIds.map((_, i) => `$${i + 1}`).join(',');
    const result = await pool.query(`
      SELECT * FROM cards
      WHERE id IN (${placeholders}) AND user_id = $${cardIds.length + 1}
    `, [...cardIds, userId]);

    const cards = result.rows;

    const headers = [
      'Player', 'Year', 'Set', 'Card Number', 'Parallel', 'Sport',
      'Graded', 'Grading Company', 'Grade', 'Cert Number',
      'Autograph', 'Serial Number', 'Front Image', 'Back Image'
    ];

    const csvRows = [
      headers.join(','),
      ...cards.map(card => {
        const data = typeof card.card_data === 'string' ? JSON.parse(card.card_data) : card.card_data;

        return [
          `"${data.player || ''}"`,
          data.year || '',
          `"${data.set_name || ''}"`,
          data.card_number || '',
          `"${data.parallel || 'Base'}"`,
          data.sport || '',
          data.is_graded ? 'Yes' : 'No',
          data.grading_company || '',
          data.grade || '',
          data.cert_number || '',
          data.is_autograph ? 'Yes' : 'No',
          data.serial_number || '',
          card.front_image_path || '',
          card.back_image_path || ''
        ].join(',');
      })
    ];

    const csv = csvRows.join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="CardFlow-Export-${Date.now()}.csv"`);
    res.send(csv);

    console.log(`[Export] Generic CSV complete: ${cards.length} cards`);

  } catch (e) {
    console.error('CSV export error:', e);
    res.status(500).json({ error: 'Export failed' });
  }
});

// Export as JSON (for API integrations)
app.post('/api/export/json', authenticateToken, async (req, res) => {
  try {
    const { cardIds } = req.body;
    const userId = req.user.id;

    if (!cardIds || cardIds.length === 0) {
      return res.status(400).json({ error: 'No cards selected' });
    }

    const placeholders = cardIds.map((_, i) => `$${i + 1}`).join(',');
    const result = await pool.query(`
      SELECT * FROM cards
      WHERE id IN (${placeholders}) AND user_id = $${cardIds.length + 1}
    `, [...cardIds, userId]);

    const cards = result.rows.map(card => {
      const data = typeof card.card_data === 'string' ? JSON.parse(card.card_data) : card.card_data;
      return {
        id: card.id,
        ...data,
        front_image_url: card.front_image_path,
        back_image_url: card.back_image_path,
        created_at: card.created_at
      };
    });

    res.json({
      success: true,
      count: cards.length,
      cards,
      exported_at: new Date().toISOString(),
      source: 'CardFlow'
    });

  } catch (e) {
    console.error('JSON export error:', e);
    res.status(500).json({ error: 'Export failed' });
  }
});

// Export for CardLadder (CSV format for their bulk upload)
app.post('/api/export/cardladder', authenticateToken, async (req, res) => {
  try {
    const { cardIds } = req.body;
    const userId = req.user.id;

    if (!cardIds || cardIds.length === 0) {
      return res.status(400).json({ error: 'No cards selected' });
    }

    const placeholders = cardIds.map((_, i) => `$${i + 1}`).join(',');
    const result = await pool.query(`
      SELECT * FROM cards
      WHERE id IN (${placeholders}) AND user_id = $${cardIds.length + 1}
    `, [...cardIds, userId]);

    // CardLadder CSV format columns (based on their template)
    const headers = [
      'Year',
      'Set',
      'Player',
      'Card Number',
      'Variation',
      'Grading Company',
      'Grade',
      'Cert Number',
      'Purchase Price',
      'Purchase Date',
      'Notes'
    ];

    const rows = result.rows.map(card => {
      const data = typeof card.card_data === 'string' ? JSON.parse(card.card_data) : card.card_data;
      return [
        data.year || '',
        data.set_name || '',
        data.player || data.subject || '',
        data.card_number || '',
        data.parallel && data.parallel !== 'Base' ? data.parallel : '',
        data.is_graded ? (data.grading_company || '') : '',
        data.is_graded ? (data.grade || '') : '',
        data.cert_number || '',
        '', // Purchase price - user can fill in
        '', // Purchase date - user can fill in
        data.notes || ''
      ];
    });

    // Build CSV
    const escapeCSV = (val) => {
      if (val === null || val === undefined) return '';
      const str = String(val);
      if (str.includes(',') || str.includes('"') || str.includes('\n')) {
        return '"' + str.replace(/"/g, '""') + '"';
      }
      return str;
    };

    const csv = [
      headers.join(','),
      ...rows.map(row => row.map(escapeCSV).join(','))
    ].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="CardFlow-CardLadder-${Date.now()}.csv"`);
    res.send(csv);

  } catch (e) {
    console.error('CardLadder export error:', e);
    res.status(500).json({ error: 'Export failed' });
  }
});

// ============================================
// AI AGENT ANALYSIS (Beta Feature)
// ============================================

// Supported AI providers configuration
const AI_PROVIDERS = {
  anthropic: {
    name: 'Anthropic Claude',
    models: ['claude-sonnet-4-20250514', 'claude-3-5-sonnet-20241022'],
    defaultModel: 'claude-sonnet-4-20250514',
    supportsVision: true,
    supportsWebSearch: true,
    costPer1M: { input: 3, output: 15, cacheRead: 0.30, cacheWrite: 3.75 }
  },
  openai: {
    name: 'OpenAI GPT-4',
    models: ['gpt-4o', 'gpt-4-turbo'],
    defaultModel: 'gpt-4o',
    supportsVision: true,
    supportsWebSearch: false,
    costPer1M: { input: 2.5, output: 10 }
  },
  google: {
    name: 'Google Gemini',
    models: ['gemini-1.5-pro', 'gemini-1.5-flash'],
    defaultModel: 'gemini-1.5-pro',
    supportsVision: true,
    supportsWebSearch: true,
    costPer1M: { input: 1.25, output: 5 }
  }
};

// Helper: Calculate cost from tokens
function calculateAgentCost(provider, tokens) {
  const pricing = AI_PROVIDERS[provider]?.costPer1M || { input: 3, output: 15 };
  let cost = (tokens.input / 1_000_000 * pricing.input) +
             (tokens.output / 1_000_000 * pricing.output);
  if (tokens.cacheRead && pricing.cacheRead) {
    cost += tokens.cacheRead / 1_000_000 * pricing.cacheRead;
  }
  if (tokens.cacheWrite && pricing.cacheWrite) {
    cost += tokens.cacheWrite / 1_000_000 * pricing.cacheWrite;
  }
  return parseFloat(cost.toFixed(6));
}

// Helper: Check if user can analyze (quota check)
async function canUserAnalyze(userId) {
  const result = await pool.query(
    'SELECT role, agent_analyses_used, agent_analyses_limit, agent_analyses_reset, beta_features, anthropic_api_key, openai_api_key, google_api_key FROM users WHERE id = $1',
    [userId]
  );
  if (result.rows.length === 0) return { allowed: false, reason: 'User not found' };

  const user = result.rows[0];
  const betaFeatures = user.beta_features || {};
  const isAdmin = user.role === 'admin';
  const hasOwnApiKey = !!(user.anthropic_api_key || user.openai_api_key || user.google_api_key);

  // Admins always have unlimited access
  if (isAdmin) {
    return {
      allowed: true,
      used: user.agent_analyses_used || 0,
      limit: 999999,
      remaining: 999999,
      isAdmin: true
    };
  }

  // Users with their own API key get unlimited access (BYOK model)
  if (hasOwnApiKey) {
    return {
      allowed: true,
      used: user.agent_analyses_used || 0,
      limit: 999999,
      remaining: 999999,
      hasOwnKey: true
    };
  }

  // For users without API key, check beta access
  if (!betaFeatures.agentAnalysis) {
    return { allowed: false, reason: 'Add your API key in Settings to use AI Analysis', needsApiKey: true };
  }

  // Reset quota if needed (monthly reset) - only for quota-limited users
  const now = new Date();
  if (!user.agent_analyses_reset || new Date(user.agent_analyses_reset) < now) {
    const nextReset = new Date(now.getFullYear(), now.getMonth() + 1, 1);
    await pool.query(
      'UPDATE users SET agent_analyses_used = 0, agent_analyses_reset = $1 WHERE id = $2',
      [nextReset, userId]
    );
    user.agent_analyses_used = 0;
  }

  if (user.agent_analyses_used >= user.agent_analyses_limit) {
    return {
      allowed: false,
      reason: 'Monthly analysis quota exceeded',
      used: user.agent_analyses_used,
      limit: user.agent_analyses_limit,
      needsUpgrade: true
    };
  }

  return {
    allowed: true,
    used: user.agent_analyses_used,
    limit: user.agent_analyses_limit,
    remaining: user.agent_analyses_limit - user.agent_analyses_used
  };
}

// Helper: Track analysis in database
async function trackAgentAnalysis(data) {
  try {
    await pool.query(`
      INSERT INTO agent_analyses (
        user_id, card_id, analysis_type, ai_provider, model, cost,
        tokens_input, tokens_output, cache_read_tokens, cache_write_tokens,
        response_time, success, error_type, card_data, result_summary, analysis_result, source
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
    `, [
      data.userId,
      data.cardId || null,
      data.analysisType || 'single-card',
      data.provider || 'anthropic',
      data.model,
      data.cost || 0,
      data.tokens?.input || 0,
      data.tokens?.output || 0,
      data.tokens?.cacheRead || 0,
      data.tokens?.cacheWrite || 0,
      data.responseTime || null,
      data.success !== false,
      data.errorType || null,
      JSON.stringify(data.cardData || {}),
      JSON.stringify(data.resultSummary || {}),
      JSON.stringify(data.analysisResult || {}),
      data.source || 'cardflow-web'
    ]);
  } catch (e) {
    console.error('[Agent] Failed to track analysis:', e);
  }
}

// Helper: Generate analysis prompt
function generatePriceCheckPrompt(card) {
  const cardName = [
    card.year,
    card.set_name,
    card.player,
    card.card_number ? `#${card.card_number}` : '',
    card.parallel && card.parallel !== 'Base' ? card.parallel : ''
  ].filter(Boolean).join(' ');

  return `Search for current market prices for this sports card:

CARD: ${cardName}

SEARCH MULTIPLE SOURCES for recent sold prices:
1. eBay sold listings (last 90 days)
2. COMC (Check Out My Cards)
3. PSA auction prices / cert verification
4. 130point.com
5. Any other card pricing sites

FIND PRICES FOR:
- Raw/ungraded card sales
- PSA 9 graded sales
- PSA 10 graded sales

GRADING COST REFERENCE: PSA grading costs $20-25 (value tier) to $50+ (faster tiers)

RESPOND WITH ONLY VALID JSON. NO NEWLINES INSIDE STRING VALUES. Keep all text on single lines.

{"card":"${cardName}","prices":{"raw":{"low":0,"high":0,"avg":0,"salesCount":0},"psa9":{"low":null,"high":null,"avg":null,"salesCount":0},"psa10":{"low":null,"high":null,"avg":null,"salesCount":0}},"sources":[{"name":"eBay","salesFound":0}],"gradeRecommendation":{"shouldGrade":false,"reason":"brief reason here","potentialProfit":null,"breakEvenGrade":null},"lastUpdated":"2024-01-01","notes":"market notes here"}`;
}

// Helper: Parse JSON from AI response (handles common formatting issues)
function parseAiJsonResponse(text) {
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) return null;

  let jsonStr = jsonMatch[0];

  // Fix common JSON issues from AI responses:
  // 1. Fix pattern where colon is followed by newline then unquoted text: "key": \nvalue" -> "key": "value"
  jsonStr = jsonStr.replace(/:\s*\n\s*([^"\[\]{},]+)"/g, ': "$1"');
  // 2. Fix newlines inside already-quoted strings
  jsonStr = jsonStr.replace(/"([^"]*?)"/g, (match, content) => {
    return '"' + content.replace(/[\n\r]+/g, ' ').trim() + '"';
  });
  // 3. Remove trailing commas
  jsonStr = jsonStr.replace(/,\s*([}\]])/g, '$1');

  try {
    return JSON.parse(jsonStr);
  } catch (e) {
    // Last resort: try to extract key values manually
    console.error('[Agent] JSON parse failed, attempting manual extraction:', e.message);
    console.error('[Agent] Raw response:', jsonStr.substring(0, 500));

    // Try a more aggressive cleanup - remove all newlines except in specific places
    jsonStr = jsonMatch[0]
      .replace(/\n/g, ' ')
      .replace(/\r/g, '')
      .replace(/\s+/g, ' ')
      .replace(/,\s*([}\]])/g, '$1');

    return JSON.parse(jsonStr);
  }
}

// GET /api/agent/providers - List available AI providers
app.get('/api/agent/providers', authenticateToken, (req, res) => {
  const providers = Object.entries(AI_PROVIDERS).map(([key, config]) => ({
    id: key,
    name: config.name,
    models: config.models,
    defaultModel: config.defaultModel,
    supportsVision: config.supportsVision,
    supportsWebSearch: config.supportsWebSearch
  }));
  res.json({ providers });
});

// GET /api/agent/usage - Get user's analysis usage stats
app.get('/api/agent/usage', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const quotaCheck = await canUserAnalyze(userId);

    // Get user's API keys (masked)
    const userResult = await pool.query(
      'SELECT anthropic_api_key, openai_api_key, google_api_key, preferred_ai_provider, beta_features FROM users WHERE id = $1',
      [userId]
    );
    const user = userResult.rows[0];

    // Beta is enabled for: admins, users with their own API key, or users with beta flag
    const isBetaEnabled = quotaCheck.isAdmin || quotaCheck.hasOwnKey || user?.beta_features?.agentAnalysis || false;

    // Decrypt keys for display preview (show last 4 chars only)
    const decryptedAnthropic = user?.anthropic_api_key ? decryptApiKey(user.anthropic_api_key) : null;
    const decryptedOpenai = user?.openai_api_key ? decryptApiKey(user.openai_api_key) : null;
    const decryptedGoogle = user?.google_api_key ? decryptApiKey(user.google_api_key) : null;

    res.json({
      quota: {
        used: quotaCheck.used || 0,
        limit: quotaCheck.limit || 3,
        remaining: quotaCheck.remaining || 0,
        canAnalyze: quotaCheck.allowed,
        isAdmin: quotaCheck.isAdmin || false,
        hasOwnKey: quotaCheck.hasOwnKey || false
      },
      betaEnabled: isBetaEnabled,
      apiKeys: {
        anthropic: decryptedAnthropic ? '....' + decryptedAnthropic.slice(-4) : null,
        openai: decryptedOpenai ? '....' + decryptedOpenai.slice(-4) : null,
        google: decryptedGoogle ? '....' + decryptedGoogle.slice(-4) : null
      },
      preferredProvider: user?.preferred_ai_provider || 'anthropic'
    });
  } catch (e) {
    console.error('[Agent] Usage check error:', e);
    res.status(500).json({ error: 'Failed to get usage stats' });
  }
});

// POST /api/agent/save-settings - Save user's AI settings (encrypted at rest)
app.post('/api/agent/save-settings', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { anthropicKey, openaiKey, googleKey, preferredProvider } = req.body;

    const updates = [];
    const values = [];
    let paramIndex = 1;

    // Encrypt API keys before storing
    if (anthropicKey !== undefined) {
      updates.push(`anthropic_api_key = $${paramIndex++}`);
      values.push(anthropicKey ? encryptApiKey(anthropicKey) : null);
    }
    if (openaiKey !== undefined) {
      updates.push(`openai_api_key = $${paramIndex++}`);
      values.push(openaiKey ? encryptApiKey(openaiKey) : null);
    }
    if (googleKey !== undefined) {
      updates.push(`google_api_key = $${paramIndex++}`);
      values.push(googleKey ? encryptApiKey(googleKey) : null);
    }
    if (preferredProvider) {
      updates.push(`preferred_ai_provider = $${paramIndex++}`);
      values.push(preferredProvider);
    }

    if (updates.length > 0) {
      values.push(userId);
      await pool.query(
        `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIndex}`,
        values
      );
    }

    res.json({ success: true, message: 'Settings saved' });
  } catch (e) {
    console.error('[Agent] Save settings error:', e);
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

// POST /api/agent/analyze-card - Price check endpoint (simplified - no image analysis)
app.post('/api/agent/analyze-card', authenticateToken, async (req, res) => {
  const startTime = Date.now();
  const userId = req.user.id;

  try {
    const { cardId, provider = 'anthropic', apiKey } = req.body;

    // 1. CHECK QUOTA
    const quotaCheck = await canUserAnalyze(userId);
    if (!quotaCheck.allowed) {
      return res.status(403).json({
        success: false,
        error: quotaCheck.reason,
        needsUpgrade: quotaCheck.needsUpgrade,
        needsBeta: quotaCheck.needsBeta,
        usage: { used: quotaCheck.used, limit: quotaCheck.limit }
      });
    }

    // 2. GET API KEY (from request or user's saved key - decrypt if stored)
    let userApiKey = apiKey;
    if (!userApiKey) {
      const keyResult = await pool.query(
        `SELECT ${provider}_api_key as api_key FROM users WHERE id = $1`,
        [userId]
      );
      const encryptedKey = keyResult.rows[0]?.api_key;
      userApiKey = encryptedKey ? decryptApiKey(encryptedKey) : null;
    }

    if (!userApiKey) {
      return res.status(400).json({
        success: false,
        error: `No ${AI_PROVIDERS[provider]?.name || provider} API key provided. Please add your API key in settings.`,
        needsApiKey: true
      });
    }

    // 3. GET CARD DATA (required - we use card info for price search, not images)
    if (!cardId) {
      return res.status(400).json({ success: false, error: 'Card ID is required' });
    }

    const cardResult = await pool.query(
      'SELECT * FROM cards WHERE id = $1 AND user_id = $2',
      [cardId, userId]
    );

    if (cardResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Card not found' });
    }

    const row = cardResult.rows[0];
    const card = typeof row.card_data === 'string' ? JSON.parse(row.card_data) : row.card_data;

    // 4. CALL AI API (text-only, no images - much cheaper!)
    let priceResult, tokensUsed, modelUsed;
    const pricePrompt = generatePriceCheckPrompt(card);

    if (provider === 'anthropic') {
      // Use Haiku for price checks - much cheaper than Sonnet
      const priceCheckModel = 'claude-3-5-haiku-20241022';

      const claudeResponse = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': userApiKey,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          model: priceCheckModel,
          max_tokens: 1500,
          messages: [{
            role: 'user',
            content: pricePrompt
          }],
          tools: [{ type: 'web_search_20250305', name: 'web_search' }]
        })
      });

      if (!claudeResponse.ok) {
        const errorData = await claudeResponse.json().catch(() => ({}));
        throw new Error(errorData.error?.message || `Claude API error: ${claudeResponse.status}`);
      }

      const claudeData = await claudeResponse.json();
      modelUsed = claudeData.model || priceCheckModel;
      tokensUsed = {
        input: claudeData.usage?.input_tokens || 0,
        output: claudeData.usage?.output_tokens || 0,
        cacheRead: claudeData.usage?.cache_read_input_tokens || 0,
        cacheWrite: claudeData.usage?.cache_creation_input_tokens || 0
      };

      // Extract text response
      const responseText = claudeData.content
        .filter(block => block.type === 'text')
        .map(block => block.text)
        .join('\n');

      // Parse JSON from response
      priceResult = parseAiJsonResponse(responseText);
      if (!priceResult) {
        throw new Error('Failed to parse price response');
      }

    } else if (provider === 'openai') {
      // Use GPT-4o-mini for price checks - cheaper than GPT-4o
      const priceCheckModel = 'gpt-4o-mini';

      const openaiResponse = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${userApiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: priceCheckModel,
          max_tokens: 1500,
          messages: [{
            role: 'user',
            content: pricePrompt
          }],
          response_format: { type: 'json_object' }
        })
      });

      if (!openaiResponse.ok) {
        const errorData = await openaiResponse.json().catch(() => ({}));
        throw new Error(errorData.error?.message || `OpenAI API error: ${openaiResponse.status}`);
      }

      const openaiData = await openaiResponse.json();
      modelUsed = openaiData.model || priceCheckModel;
      tokensUsed = {
        input: openaiData.usage?.prompt_tokens || 0,
        output: openaiData.usage?.completion_tokens || 0
      };
      priceResult = JSON.parse(openaiData.choices[0].message.content);

    } else if (provider === 'google') {
      // Use Gemini Flash for price checks - cheaper
      const priceCheckModel = 'gemini-1.5-flash';

      const geminiResponse = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${priceCheckModel}:generateContent?key=${userApiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{
              parts: [{ text: pricePrompt }]
            }],
            generationConfig: { maxOutputTokens: 1500 }
          })
        }
      );

      if (!geminiResponse.ok) {
        const errorData = await geminiResponse.json().catch(() => ({}));
        throw new Error(errorData.error?.message || `Gemini API error: ${geminiResponse.status}`);
      }

      const geminiData = await geminiResponse.json();
      modelUsed = priceCheckModel;
      tokensUsed = {
        input: geminiData.usageMetadata?.promptTokenCount || 0,
        output: geminiData.usageMetadata?.candidatesTokenCount || 0
      };

      const responseText = geminiData.candidates[0].content.parts[0].text;
      priceResult = parseAiJsonResponse(responseText);
      if (!priceResult) {
        throw new Error('Failed to parse Gemini response');
      }

    } else {
      return res.status(400).json({ success: false, error: 'Unsupported AI provider' });
    }

    const responseTime = (Date.now() - startTime) / 1000;
    const cost = calculateAgentCost(provider, tokensUsed);

    // 5. UPDATE USER QUOTA
    await pool.query(
      'UPDATE users SET agent_analyses_used = agent_analyses_used + 1 WHERE id = $1',
      [userId]
    );

    // 6. TRACK ANALYSIS
    await trackAgentAnalysis({
      userId,
      cardId,
      analysisType: 'price-check',
      provider,
      model: modelUsed,
      cost,
      tokens: tokensUsed,
      responseTime,
      success: true,
      cardData: { year: card.year, set_name: card.set_name, player: card.player, card_number: card.card_number },
      resultSummary: {
        rawPrice: priceResult.prices?.raw?.avg,
        psa9Price: priceResult.prices?.psa9?.avg,
        psa10Price: priceResult.prices?.psa10?.avg,
        shouldGrade: priceResult.gradeRecommendation?.shouldGrade
      },
      analysisResult: priceResult
    });

    // 7. RETURN RESPONSE
    res.json({
      success: true,
      prices: priceResult,
      usage: {
        analysesRemaining: quotaCheck.remaining - 1,
        limit: quotaCheck.limit,
        resetDate: new Date(new Date().getFullYear(), new Date().getMonth() + 1, 1).toISOString()
      },
      meta: {
        provider,
        model: modelUsed,
        cost,
        responseTime,
        tokensUsed
      }
    });

  } catch (error) {
    console.error('[Agent] Analysis error:', error);

    // Track failed analysis
    await trackAgentAnalysis({
      userId,
      success: false,
      errorType: error.message.includes('API key') || error.message.includes('401') ? 'INVALID_API_KEY' :
                 error.message.includes('rate') ? 'RATE_LIMIT' :
                 error.message.includes('timeout') ? 'TIMEOUT' : 'API_ERROR',
      responseTime: (Date.now() - startTime) / 1000
    });

    res.status(500).json({
      success: false,
      error: error.message || 'Analysis failed',
      errorType: error.message.includes('API key') ? 'INVALID_API_KEY' : 'API_ERROR'
    });
  }
});

// Helper: Fetch image as base64 (for Gemini)
async function fetchImageAsBase64(url) {
  const response = await axios.get(url, { responseType: 'arraybuffer' });
  return Buffer.from(response.data).toString('base64');
}

// ============================================
// ADMIN: AGENT ANALYTICS
// ============================================

// GET /api/admin/agent-analytics/overview
app.get('/api/admin/agent-analytics/overview', authenticateToken, async (req, res) => {
  try {
    // Check admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const last30Days = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    // Today's stats
    const todayResult = await pool.query(`
      SELECT
        COUNT(*) as total_analyses,
        COALESCE(SUM(cost), 0) as total_cost,
        COUNT(DISTINCT user_id) as unique_users,
        COALESCE(AVG(response_time), 0) as avg_response_time,
        COUNT(*) FILTER (WHERE success = false) as errors
      FROM agent_analyses
      WHERE timestamp >= $1
    `, [startOfToday]);

    // This month's stats
    const monthResult = await pool.query(`
      SELECT
        COUNT(*) as total_analyses,
        COALESCE(SUM(cost), 0) as total_cost,
        COUNT(DISTINCT user_id) as unique_users
      FROM agent_analyses
      WHERE timestamp >= $1
    `, [startOfMonth]);

    // All-time stats
    const allTimeResult = await pool.query(`
      SELECT
        COUNT(*) as total_analyses,
        COALESCE(SUM(cost), 0) as total_cost,
        COUNT(DISTINCT user_id) as unique_users
      FROM agent_analyses
    `);

    // By provider
    const providerResult = await pool.query(`
      SELECT
        ai_provider,
        COUNT(*) as count,
        COALESCE(SUM(cost), 0) as cost
      FROM agent_analyses
      GROUP BY ai_provider
    `);

    // By plan (would need join with users)
    const planResult = await pool.query(`
      SELECT
        u.subscription_tier as plan,
        COUNT(a.*) as count,
        COALESCE(SUM(a.cost), 0) as cost
      FROM agent_analyses a
      JOIN users u ON a.user_id = u.id
      GROUP BY u.subscription_tier
    `);

    // Cost trend (last 30 days)
    const trendResult = await pool.query(`
      SELECT
        DATE(timestamp) as date,
        COUNT(*) as count,
        COALESCE(SUM(cost), 0) as cost
      FROM agent_analyses
      WHERE timestamp >= $1
      GROUP BY DATE(timestamp)
      ORDER BY date
    `, [last30Days]);

    // Error rate
    const errorResult = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE success = false) as errors,
        COUNT(*) as total
      FROM agent_analyses
    `);

    res.json({
      today: {
        analyses: parseInt(todayResult.rows[0].total_analyses),
        cost: parseFloat(todayResult.rows[0].total_cost),
        users: parseInt(todayResult.rows[0].unique_users),
        avgResponseTime: parseFloat(todayResult.rows[0].avg_response_time).toFixed(2),
        errors: parseInt(todayResult.rows[0].errors)
      },
      month: {
        analyses: parseInt(monthResult.rows[0].total_analyses),
        cost: parseFloat(monthResult.rows[0].total_cost),
        users: parseInt(monthResult.rows[0].unique_users)
      },
      allTime: {
        analyses: parseInt(allTimeResult.rows[0].total_analyses),
        cost: parseFloat(allTimeResult.rows[0].total_cost),
        users: parseInt(allTimeResult.rows[0].unique_users)
      },
      byProvider: providerResult.rows,
      byPlan: planResult.rows,
      costTrend: trendResult.rows,
      errorRate: errorResult.rows[0].total > 0
        ? ((errorResult.rows[0].errors / errorResult.rows[0].total) * 100).toFixed(2) + '%'
        : '0%'
    });

  } catch (e) {
    console.error('[Admin Analytics] Overview error:', e);
    res.status(500).json({ error: 'Failed to load analytics' });
  }
});

// GET /api/admin/agent-analytics/users
app.get('/api/admin/agent-analytics/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { limit = 50 } = req.query;

    const result = await pool.query(`
      SELECT
        u.id,
        u.email,
        u.subscription_tier,
        u.agent_analyses_used,
        u.agent_analyses_limit,
        u.beta_features,
        COUNT(a.id) as total_analyses,
        COALESCE(SUM(a.cost), 0) as total_cost,
        MAX(a.timestamp) as last_analysis,
        COALESCE(AVG(a.response_time), 0) as avg_response_time
      FROM users u
      LEFT JOIN agent_analyses a ON u.id = a.user_id
      GROUP BY u.id
      HAVING COUNT(a.id) > 0
      ORDER BY total_analyses DESC
      LIMIT $1
    `, [parseInt(limit)]);

    res.json({ users: result.rows });

  } catch (e) {
    console.error('[Admin Analytics] Users error:', e);
    res.status(500).json({ error: 'Failed to load user stats' });
  }
});

// GET /api/admin/agent-analytics/recent
app.get('/api/admin/agent-analytics/recent', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { limit = 50 } = req.query;

    const result = await pool.query(`
      SELECT
        a.*,
        u.email as user_email
      FROM agent_analyses a
      JOIN users u ON a.user_id = u.id
      ORDER BY a.timestamp DESC
      LIMIT $1
    `, [parseInt(limit)]);

    res.json({ analyses: result.rows });

  } catch (e) {
    console.error('[Admin Analytics] Recent error:', e);
    res.status(500).json({ error: 'Failed to load recent analyses' });
  }
});

// GET /api/admin/agent-analytics/errors
app.get('/api/admin/agent-analytics/errors', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    // Error breakdown
    const errorTypes = await pool.query(`
      SELECT
        error_type,
        COUNT(*) as count,
        MAX(timestamp) as last_seen
      FROM agent_analyses
      WHERE success = false
      GROUP BY error_type
      ORDER BY count DESC
    `);

    // Recent errors
    const recentErrors = await pool.query(`
      SELECT
        a.*,
        u.email as user_email
      FROM agent_analyses a
      JOIN users u ON a.user_id = u.id
      WHERE a.success = false
      ORDER BY a.timestamp DESC
      LIMIT 20
    `);

    res.json({
      byType: errorTypes.rows,
      recent: recentErrors.rows
    });

  } catch (e) {
    console.error('[Admin Analytics] Errors error:', e);
    res.status(500).json({ error: 'Failed to load error stats' });
  }
});

// POST /api/admin/agent-analytics/enable-beta - Enable beta for a user
app.post('/api/admin/agent-analytics/enable-beta', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { userId, enabled = true, limit = 3 } = req.body;

    await pool.query(`
      UPDATE users
      SET beta_features = jsonb_set(COALESCE(beta_features, '{}'), '{agentAnalysis}', $1::jsonb),
          agent_analyses_limit = $2
      WHERE id = $3
    `, [JSON.stringify(enabled), limit, userId]);

    res.json({ success: true, message: `Beta ${enabled ? 'enabled' : 'disabled'} for user` });

  } catch (e) {
    console.error('[Admin] Enable beta error:', e);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// POST /api/admin/agent-analytics/export
app.post('/api/admin/agent-analytics/export', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { startDate, endDate } = req.body;

    let query = `
      SELECT
        a.*,
        u.email as user_email,
        u.subscription_tier
      FROM agent_analyses a
      JOIN users u ON a.user_id = u.id
    `;
    const params = [];

    if (startDate || endDate) {
      const conditions = [];
      if (startDate) {
        params.push(startDate);
        conditions.push(`a.timestamp >= $${params.length}`);
      }
      if (endDate) {
        params.push(endDate);
        conditions.push(`a.timestamp <= $${params.length}`);
      }
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += ' ORDER BY a.timestamp DESC';

    const result = await pool.query(query, params);

    // Convert to CSV
    const headers = ['Timestamp', 'User Email', 'Plan', 'Provider', 'Model', 'Cost', 'Success', 'Response Time', 'Action'];
    const rows = result.rows.map(r => [
      r.timestamp,
      r.user_email,
      r.subscription_tier,
      r.ai_provider,
      r.model,
      r.cost,
      r.success,
      r.response_time,
      r.result_summary?.action || ''
    ]);

    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="agent-analytics-${Date.now()}.csv"`);
    res.send(csv);

  } catch (e) {
    console.error('[Admin Analytics] Export error:', e);
    res.status(500).json({ error: 'Export failed' });
  }
});

// ============================================
// WEBSOCKET
// ============================================

const clients = new Map(); // Map of userId -> Set of WebSocket connections
const scannerClients = new Map(); // Map of userId -> scanner WebSocket

wss.on('connection', (ws, req) => {
  let userId = null;
  let isScanner = false;

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);

      // Handle authentication
      if (data.type === 'auth' && data.token) {
        jwt.verify(data.token, EFFECTIVE_JWT_SECRET, (err, user) => {
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

      // Handle scanner agent authentication
      if (data.type === 'scanner_auth' && data.token) {
        jwt.verify(data.token, EFFECTIVE_JWT_SECRET, (err, user) => {
          if (!err) {
            userId = user.id;
            isScanner = true;
            scannerClients.set(userId, ws);
            ws.send(JSON.stringify({ type: 'auth_success' }));
            // Notify user's browser clients that scanner connected
            broadcastToUser(userId, {
              type: 'scanner_connected',
              message: 'Scanner agent connected'
            });
            console.log(`Scanner agent connected for user ${userId}`);
          } else {
            ws.send(JSON.stringify({ type: 'auth_error', error: 'Invalid token' }));
          }
        });
      }

      // Forward scanner status events to user's browser clients
      if (isScanner && userId) {
        const scannerEvents = [
          'scanner_file_detected',
          'scanner_front_captured',
          'scanner_back_captured',
          'scanner_uploading',
          'scanner_card_uploaded',
          'scanner_upload_error'
        ];
        if (scannerEvents.includes(data.type)) {
          broadcastToUser(userId, data);
        }
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
    if (isScanner && userId) {
      scannerClients.delete(userId);
      broadcastToUser(userId, {
        type: 'scanner_disconnected',
        message: 'Scanner agent disconnected'
      });
      console.log(`Scanner agent disconnected for user ${userId}`);
    }
  });
});

// Broadcast to a specific user's browser clients
function broadcastToUser(userId, message) {
  const userClients = clients.get(userId);
  if (userClients) {
    const data = JSON.stringify(message);
    userClients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(data);
      }
    });
  }
}

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

// Serve phone scanner page
app.get('/scan', (req, res) => {
  res.sendFile(path.join(__dirname, 'scan.html'));
});

// Serve desktop scanner mode page
app.get('/scanner', (req, res) => {
  res.sendFile(path.join(__dirname, 'scanner.html'));
});

// ============================================
// SOCIAL MEDIA IMAGE GENERATION
// ============================================

// Generate a social media image for a card
async function generateSocialImage(card, style = 'default') {
  const width = 1080;
  const height = 1080;

  // Style configurations
  const styles = {
    default: {
      bgGradient: ['#1a1a2e', '#0f3460'],
      accentColor: '#00f6ff',
      textColor: '#ffffff'
    },
    fire: {
      bgGradient: ['#1a0a0a', '#4a1010'],
      accentColor: '#ff6b35',
      textColor: '#ffffff'
    },
    gold: {
      bgGradient: ['#1a1500', '#3d3000'],
      accentColor: '#ffd700',
      textColor: '#ffffff'
    },
    minimal: {
      bgGradient: ['#ffffff', '#f0f0f0'],
      accentColor: '#000000',
      textColor: '#000000'
    }
  };

  const s = styles[style] || styles.default;

  // Build card info text
  const playerName = card.player || 'Unknown Player';
  const yearSet = [card.year, card.set_name].filter(Boolean).join(' ');
  const cardNum = card.card_number ? `#${card.card_number}` : '';
  const parallel = card.parallel && card.parallel !== 'Base' ? card.parallel : '';
  const gradeInfo = card.is_graded ? `${card.grading_company} ${card.grade}` : '';
  const serialNum = card.serial_number || '';
  const price = card.recommended_price ? `$${card.recommended_price.toFixed(2)}` : '';

  // Create SVG overlay
  const overlayHeight = 280;
  const svg = `
    <svg width="${width}" height="${height}">
      <defs>
        <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" style="stop-color:${s.bgGradient[0]}"/>
          <stop offset="100%" style="stop-color:${s.bgGradient[1]}"/>
        </linearGradient>
        <linearGradient id="overlayGrad" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" style="stop-color:rgba(0,0,0,0)"/>
          <stop offset="100%" style="stop-color:rgba(0,0,0,0.9)"/>
        </linearGradient>
      </defs>
      <!-- Background -->
      <rect width="${width}" height="${height}" fill="url(#bgGrad)"/>
      <!-- Bottom overlay gradient -->
      <rect y="${height - overlayHeight}" width="${width}" height="${overlayHeight}" fill="url(#overlayGrad)"/>
      <!-- Branding -->
      <text x="40" y="50" font-family="Arial, sans-serif" font-size="24" font-weight="bold" fill="${s.accentColor}">CARDFLOW</text>
      <!-- Card Info -->
      <text x="40" y="${height - 180}" font-family="Arial, sans-serif" font-size="42" font-weight="bold" fill="${s.textColor}">${escapeXml(playerName)}</text>
      <text x="40" y="${height - 130}" font-family="Arial, sans-serif" font-size="24" fill="${s.textColor}" opacity="0.8">${escapeXml(yearSet)} ${escapeXml(cardNum)}</text>
      ${parallel ? `<text x="40" y="${height - 95}" font-family="Arial, sans-serif" font-size="20" fill="${s.accentColor}">${escapeXml(parallel)}</text>` : ''}
      ${gradeInfo ? `<rect x="40" y="${height - 70}" width="${gradeInfo.length * 14 + 30}" height="36" rx="18" fill="${s.accentColor}"/><text x="55" y="${height - 44}" font-family="Arial, sans-serif" font-size="20" font-weight="bold" fill="#000">${escapeXml(gradeInfo)}</text>` : ''}
      ${serialNum ? `<text x="${gradeInfo ? 40 + gradeInfo.length * 14 + 50 : 40}" y="${height - 44}" font-family="Arial, sans-serif" font-size="18" fill="${s.accentColor}">${escapeXml(serialNum)}</text>` : ''}
      ${price ? `<text x="${width - 40}" y="${height - 44}" font-family="Arial, sans-serif" font-size="36" font-weight="bold" fill="#00ff88" text-anchor="end">${escapeXml(price)}</text>` : ''}
    </svg>
  `;

  // Load card image
  let cardImage;
  const frontUrl = card.front_image_path || card.front;

  if (frontUrl && (frontUrl.startsWith('http://') || frontUrl.startsWith('https://'))) {
    // Fetch from URL (Cloudinary)
    const response = await axios.get(frontUrl, { responseType: 'arraybuffer', timeout: 30000 });
    cardImage = sharp(Buffer.from(response.data));
  } else if (frontUrl) {
    // Local file
    const localPath = path.join(FOLDERS.new, frontUrl);
    if (fs.existsSync(localPath)) {
      cardImage = sharp(localPath);
    } else {
      const identifiedPath = path.join(FOLDERS.identified, frontUrl);
      if (fs.existsSync(identifiedPath)) {
        cardImage = sharp(identifiedPath);
      }
    }
  }

  // Create base image with gradient
  let composite = sharp(Buffer.from(svg)).png();

  if (cardImage) {
    // Resize card image to fit (leaving room for text overlay)
    const cardHeight = height - overlayHeight - 80;
    const cardWidth = Math.floor(cardHeight * 0.714); // Card aspect ratio
    const resizedCard = await cardImage
      .resize(cardWidth, cardHeight, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
      .png()
      .toBuffer();

    // Center the card horizontally
    const cardX = Math.floor((width - cardWidth) / 2);

    // Composite card image onto background
    composite = sharp(Buffer.from(svg))
      .composite([
        { input: resizedCard, left: cardX, top: 60 }
      ])
      .png();
  }

  return composite.toBuffer();
}

// Escape XML special characters
function escapeXml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// Generate social image for a single card
app.get('/api/cards/:id/social-image', authenticateToken, async (req, res) => {
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
      ...row.card_data,
      front_image_path: row.front_image_path,
      back_image_path: row.back_image_path
    };

    const style = req.query.style || 'default';
    const imageBuffer = await generateSocialImage(card, style);

    res.set('Content-Type', 'image/png');
    res.set('Content-Disposition', `inline; filename="card-${req.params.id}.png"`);
    res.send(imageBuffer);

  } catch (e) {
    console.error('Social image generation error:', e);
    res.status(500).json({ error: 'Failed to generate image' });
  }
});

// Generate social images for multiple cards (batch)
app.post('/api/social/batch-images', authenticateToken, async (req, res) => {
  try {
    const { cardIds, style = 'default' } = req.body;

    if (!cardIds || !Array.isArray(cardIds)) {
      return res.status(400).json({ error: 'cardIds array required' });
    }

    const result = await pool.query(
      'SELECT * FROM cards WHERE id = ANY($1) AND user_id = $2',
      [cardIds, req.user.id]
    );

    const images = [];
    for (const row of result.rows) {
      const card = {
        ...row.card_data,
        id: row.id,
        front_image_path: row.front_image_path,
        back_image_path: row.back_image_path
      };

      try {
        const imageBuffer = await generateSocialImage(card, style);

        // Upload to Cloudinary if available
        if (process.env.CLOUDINARY_CLOUD_NAME) {
          const uploadResult = await uploadToCloudinary(imageBuffer, `social-${req.user.id}`);
          images.push({
            cardId: row.id,
            player: card.player,
            url: uploadResult.secure_url
          });
        } else {
          // Return base64 for download
          images.push({
            cardId: row.id,
            player: card.player,
            base64: imageBuffer.toString('base64')
          });
        }
      } catch (imgErr) {
        console.error(`Error generating image for card ${row.id}:`, imgErr.message);
        images.push({ cardId: row.id, error: imgErr.message });
      }
    }

    res.json({ images });

  } catch (e) {
    console.error('Batch social image error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Generate caption/text for social media
app.get('/api/cards/:id/social-caption', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM cards WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Card not found' });
    }

    const card = result.rows[0].card_data;
    const style = req.query.style || 'default';

    // Build caption
    const lines = [];

    if (style === 'hype') {
      lines.push('🔥 FOR SALE 🔥');
      lines.push('');
    }

    lines.push(card.player || 'Card');
    lines.push([card.year, card.set_name].filter(Boolean).join(' '));

    if (card.card_number) lines.push(`Card #${card.card_number}`);
    if (card.parallel && card.parallel !== 'Base') lines.push(`✨ ${card.parallel}`);
    if (card.serial_number) lines.push(`📊 ${card.serial_number}`);
    if (card.is_autograph) lines.push('✍️ Autograph');
    if (card.is_graded) lines.push(`🏆 ${card.grading_company} ${card.grade}`);
    if (card.recommended_price) lines.push(`💰 $${card.recommended_price.toFixed(2)}`);

    lines.push('');

    // Generate hashtags
    const hashtags = ['#sportscards', '#cardcollector'];
    if (card.sport) hashtags.push(`#${card.sport}cards`);
    if (card.is_graded && card.grading_company) hashtags.push(`#${card.grading_company.toLowerCase()}`);
    if (card.player) {
      const playerTag = card.player.replace(/[^a-zA-Z]/g, '');
      hashtags.push(`#${playerTag}`);
    }
    lines.push(hashtags.join(' '));

    res.json({ caption: lines.join('\n') });

  } catch (e) {
    console.error('Caption generation error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ============================================
// API COST TRACKING (Claude only)
// ============================================

// Cost rates for Claude API
const COST_RATES = {
  claude: {
    'claude-sonnet-4-20250514': { inputPer1M: 3.00, outputPer1M: 15.00 },
    'claude-3-5-sonnet-20241022': { inputPer1M: 3.00, outputPer1M: 15.00 },
    'claude-3-5-haiku-20241022': { inputPer1M: 0.80, outputPer1M: 4.00 },
    'sonnet4': { inputPer1M: 3.00, outputPer1M: 15.00 }  // alias
  }
};

// Calculate cost for Claude
function calculateClaudeCost(model, inputTokens, outputTokens) {
  const rates = COST_RATES.claude[model] || COST_RATES.claude['sonnet4'];
  const inputCost = (inputTokens / 1_000_000) * rates.inputPer1M;
  const outputCost = (outputTokens / 1_000_000) * rates.outputPer1M;
  return parseFloat((inputCost + outputCost).toFixed(6));
}

// Track API cost in database
async function trackApiCost({
  userId,
  provider,
  model,
  operation,
  feature,
  cost,
  tokensInput = 0,
  tokensOutput = 0,
  requestSize = null,
  success = true,
  errorMessage = null,
  metadata = {}
}) {
  try {
    await pool.query(`
      INSERT INTO api_usage (user_id, operation, model_used, tokens_input, tokens_output, cost, metadata)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [
      userId,
      operation,
      `${provider}:${model}`,
      tokensInput,
      tokensOutput,
      cost,
      JSON.stringify({
        provider,
        feature,
        requestSize,
        success,
        errorMessage,
        ...metadata
      })
    ]);
  } catch (e) {
    console.error('[Cost Tracker] Failed to log cost:', e.message);
    // Don't throw - cost tracking shouldn't break main flow
  }
}

// ============================================
// ADMIN COST ANALYTICS
// ============================================

// Get cost overview (admin)
app.get('/api/admin/costs/overview', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    // Today's costs by provider
    const todayResult = await pool.query(`
      SELECT
        SPLIT_PART(model_used, ':', 1) as provider,
        SUM(cost) as total_cost,
        COUNT(*) as request_count,
        SUM(tokens_input) as total_input,
        SUM(tokens_output) as total_output
      FROM api_usage
      WHERE timestamp >= $1
      GROUP BY SPLIT_PART(model_used, ':', 1)
    `, [startOfToday]);

    // This month's costs by provider
    const monthResult = await pool.query(`
      SELECT
        SPLIT_PART(model_used, ':', 1) as provider,
        SUM(cost) as total_cost,
        COUNT(*) as request_count
      FROM api_usage
      WHERE timestamp >= $1
      GROUP BY SPLIT_PART(model_used, ':', 1)
    `, [startOfMonth]);

    // All-time costs by provider
    const allTimeResult = await pool.query(`
      SELECT
        SPLIT_PART(model_used, ':', 1) as provider,
        SUM(cost) as total_cost,
        COUNT(*) as request_count
      FROM api_usage
      GROUP BY SPLIT_PART(model_used, ':', 1)
    `);

    // Total all-time
    const totalResult = await pool.query(`
      SELECT SUM(cost) as total_cost, COUNT(*) as total_requests
      FROM api_usage
    `);

    res.json({
      today: todayResult.rows.map(r => ({
        provider: r.provider || 'claude',
        totalCost: parseFloat(r.total_cost || 0),
        requestCount: parseInt(r.request_count),
        inputTokens: parseInt(r.total_input || 0),
        outputTokens: parseInt(r.total_output || 0)
      })),
      month: monthResult.rows.map(r => ({
        provider: r.provider || 'claude',
        totalCost: parseFloat(r.total_cost || 0),
        requestCount: parseInt(r.request_count)
      })),
      allTime: allTimeResult.rows.map(r => ({
        provider: r.provider || 'claude',
        totalCost: parseFloat(r.total_cost || 0),
        requestCount: parseInt(r.request_count)
      })),
      grandTotal: {
        cost: parseFloat(totalResult.rows[0]?.total_cost || 0),
        requests: parseInt(totalResult.rows[0]?.total_requests || 0)
      }
    });

  } catch (e) {
    console.error('[Admin Costs] Overview error:', e);
    res.status(500).json({ error: 'Failed to get cost overview' });
  }
});

// Get costs by provider with daily breakdown
app.get('/api/admin/costs/by-provider', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { provider, days = 30 } = req.query;
    const startDate = new Date(Date.now() - parseInt(days) * 24 * 60 * 60 * 1000);

    let query = `
      SELECT
        DATE(timestamp) as date,
        SPLIT_PART(model_used, ':', 1) as provider,
        model_used,
        operation,
        SUM(cost) as total_cost,
        COUNT(*) as request_count,
        SUM(tokens_input) as total_input,
        SUM(tokens_output) as total_output
      FROM api_usage
      WHERE timestamp >= $1
    `;
    const params = [startDate];

    if (provider) {
      query += ` AND model_used LIKE $2`;
      params.push(`${provider}%`);
    }

    query += `
      GROUP BY DATE(timestamp), SPLIT_PART(model_used, ':', 1), model_used, operation
      ORDER BY date DESC, total_cost DESC
    `;

    const result = await pool.query(query, params);

    res.json({
      provider: provider || 'all',
      days: parseInt(days),
      costs: result.rows.map(r => ({
        date: r.date,
        provider: r.provider || 'claude',
        model: r.model_used,
        operation: r.operation,
        totalCost: parseFloat(r.total_cost || 0),
        requestCount: parseInt(r.request_count),
        inputTokens: parseInt(r.total_input || 0),
        outputTokens: parseInt(r.total_output || 0)
      }))
    });

  } catch (e) {
    console.error('[Admin Costs] By provider error:', e);
    res.status(500).json({ error: 'Failed to get costs by provider' });
  }
});

// Get costs by feature
app.get('/api/admin/costs/by-feature', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const startDate = new Date(Date.now() - parseInt(days) * 24 * 60 * 60 * 1000);

    const result = await pool.query(`
      SELECT
        operation as feature,
        SPLIT_PART(model_used, ':', 1) as provider,
        SUM(cost) as total_cost,
        COUNT(*) as request_count,
        AVG(cost) as avg_cost
      FROM api_usage
      WHERE timestamp >= $1
      GROUP BY operation, SPLIT_PART(model_used, ':', 1)
      ORDER BY total_cost DESC
    `, [startDate]);

    res.json({
      days: parseInt(days),
      features: result.rows.map(r => ({
        feature: r.feature,
        provider: r.provider || 'claude',
        totalCost: parseFloat(r.total_cost || 0),
        requestCount: parseInt(r.request_count),
        avgCostPerRequest: parseFloat(r.avg_cost || 0)
      }))
    });

  } catch (e) {
    console.error('[Admin Costs] By feature error:', e);
    res.status(500).json({ error: 'Failed to get costs by feature' });
  }
});

// Get costs by user (top spenders)
app.get('/api/admin/costs/by-user', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { days = 30, limit = 50 } = req.query;
    const startDate = new Date(Date.now() - parseInt(days) * 24 * 60 * 60 * 1000);

    const result = await pool.query(`
      SELECT
        u.id as user_id,
        u.email,
        u.name,
        u.subscription_tier,
        SUM(a.cost) as total_cost,
        COUNT(a.id) as request_count,
        MAX(a.timestamp) as last_activity
      FROM api_usage a
      JOIN users u ON a.user_id = u.id
      WHERE a.timestamp >= $1
      GROUP BY u.id, u.email, u.name, u.subscription_tier
      ORDER BY total_cost DESC
      LIMIT $2
    `, [startDate, parseInt(limit)]);

    res.json({
      days: parseInt(days),
      users: result.rows.map(r => ({
        userId: r.user_id,
        email: r.email,
        name: r.name,
        tier: r.subscription_tier,
        totalCost: parseFloat(r.total_cost || 0),
        requestCount: parseInt(r.request_count),
        lastActivity: r.last_activity
      }))
    });

  } catch (e) {
    console.error('[Admin Costs] By user error:', e);
    res.status(500).json({ error: 'Failed to get costs by user' });
  }
});

// Get itemized cost records
app.get('/api/admin/costs/itemized', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { startDate, endDate, provider, limit = 500 } = req.query;

    let query = `
      SELECT
        a.id,
        a.timestamp,
        a.user_id,
        u.email as user_email,
        a.operation,
        a.model_used,
        a.tokens_input,
        a.tokens_output,
        a.cost,
        a.metadata
      FROM api_usage a
      LEFT JOIN users u ON a.user_id = u.id
      WHERE 1=1
    `;
    const params = [];
    let paramIndex = 1;

    if (startDate) {
      query += ` AND a.timestamp >= $${paramIndex++}`;
      params.push(new Date(startDate));
    }
    if (endDate) {
      query += ` AND a.timestamp <= $${paramIndex++}`;
      params.push(new Date(endDate));
    }
    if (provider) {
      query += ` AND a.model_used LIKE $${paramIndex++}`;
      params.push(`${provider}%`);
    }

    query += ` ORDER BY a.timestamp DESC LIMIT $${paramIndex}`;
    params.push(parseInt(limit));

    const result = await pool.query(query, params);

    res.json({
      count: result.rows.length,
      records: result.rows.map(r => ({
        id: r.id,
        timestamp: r.timestamp,
        userId: r.user_id,
        userEmail: r.user_email,
        operation: r.operation,
        model: r.model_used,
        inputTokens: r.tokens_input,
        outputTokens: r.tokens_output,
        cost: parseFloat(r.cost || 0),
        metadata: r.metadata
      }))
    });

  } catch (e) {
    console.error('[Admin Costs] Itemized error:', e);
    res.status(500).json({ error: 'Failed to get itemized costs' });
  }
});

// Export costs to CSV
app.get('/api/admin/costs/export', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { startDate, endDate, format = 'csv' } = req.query;

    let query = `
      SELECT
        a.timestamp,
        u.email as user_email,
        a.operation,
        a.model_used as provider_model,
        a.tokens_input,
        a.tokens_output,
        a.cost,
        a.metadata->>'feature' as feature,
        a.metadata->>'success' as success
      FROM api_usage a
      LEFT JOIN users u ON a.user_id = u.id
      WHERE 1=1
    `;
    const params = [];
    let paramIndex = 1;

    if (startDate) {
      query += ` AND a.timestamp >= $${paramIndex++}`;
      params.push(new Date(startDate));
    }
    if (endDate) {
      query += ` AND a.timestamp <= $${paramIndex++}`;
      params.push(new Date(endDate));
    }

    query += ` ORDER BY a.timestamp DESC`;

    const result = await pool.query(query, params);

    if (format === 'csv') {
      const csv = [
        ['Timestamp', 'User', 'Operation', 'Provider/Model', 'Input Tokens', 'Output Tokens', 'Cost', 'Feature', 'Success'].join(','),
        ...result.rows.map(r => [
          r.timestamp.toISOString(),
          r.user_email || 'N/A',
          r.operation,
          r.provider_model,
          r.tokens_input || 0,
          r.tokens_output || 0,
          r.cost || 0,
          r.feature || 'N/A',
          r.success || 'true'
        ].join(','))
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=cardflow-costs-${new Date().toISOString().split('T')[0]}.csv`);
      res.send(csv);
    } else {
      res.json({ records: result.rows });
    }

  } catch (e) {
    console.error('[Admin Costs] Export error:', e);
    res.status(500).json({ error: 'Failed to export costs' });
  }
});

// ============================================
// SET CONTEXT MODE - Search & Parallels
// ============================================

// Hardcoded known parallels for common sets
const KNOWN_SET_PARALLELS = {
  'topps chrome': ['Base', 'Refractor', 'Pink Refractor', 'Sepia Refractor', 'Prism Refractor', 'Blue Refractor', 'Green Refractor', 'Gold Refractor', 'Orange Refractor', 'Red Refractor', 'Purple Refractor', 'Black Refractor', 'Superfractor', 'X-Fractor', 'Aqua Refractor', 'Negative Refractor'],
  'bowman chrome': ['Base', 'Refractor', 'Blue Refractor', 'Green Refractor', 'Gold Refractor', 'Orange Refractor', 'Purple Refractor', 'Red Refractor', 'Black Refractor', 'Superfractor', 'Aqua Refractor', 'Shimmer Refractor', 'Speckle Refractor'],
  'prizm': ['Base', 'Silver', 'Red White & Blue', 'Blue', 'Blue Shimmer', 'Green', 'Pink', 'Orange', 'Red', 'Purple', 'Gold', 'Black', 'Neon Green', 'Snakeskin', 'Mojo', 'Tiger Stripe', 'Camo', 'Disco', 'Fast Break', 'Choice', 'Green Shimmer'],
  'select': ['Base', 'Silver', 'Tri-Color', 'Blue', 'Maroon', 'Green', 'Orange', 'Red', 'Gold', 'Black', 'White', 'Tie-Dye', 'Zebra', 'Disco', 'Scope', 'Neon Green'],
  'donruss optic': ['Base', 'Holo', 'Red', 'Blue', 'Purple', 'Pink', 'Orange', 'Green', 'Gold', 'Black', 'Lime Green', 'Shock', 'White Sparkle', 'Purple Shock', 'Blue Velocity', 'Red Velocity'],
  'topps': ['Base', 'Gold', 'Rainbow Foil', 'Vintage Stock', 'Independence Day', 'Platinum', 'Printing Plate Black', 'Printing Plate Cyan', 'Printing Plate Magenta', 'Printing Plate Yellow', 'Clear', 'Mother\'s Day Pink', 'Father\'s Day Blue'],
  'bowman': ['Base', 'Blue', 'Green', 'Orange', 'Gold', 'Red', 'Purple', 'Yellow', 'Sky Blue', 'Camo'],
  'topps heritage': ['Base', 'Chrome', 'Chrome Refractor', 'Black Border', 'Mini', 'Red Border', 'Blue Border', 'French Text', 'Action Variation', 'Short Print'],
  'mosaic': ['Base', 'Silver', 'Blue', 'Green', 'Pink', 'Orange', 'Red', 'Gold', 'Black', 'Camo', 'Genesis', 'Disco', 'Fluorescent Green', 'Fluorescent Orange', 'Fluorescent Pink', 'Reactive Blue', 'Reactive Orange'],
  'panini prizm': ['Base', 'Silver', 'Red White & Blue', 'Blue', 'Blue Shimmer', 'Green', 'Pink', 'Orange', 'Red', 'Purple', 'Gold', 'Black', 'Neon Green', 'Snakeskin', 'Mojo', 'Tiger Stripe', 'Camo', 'Disco', 'Fast Break', 'Choice', 'Green Shimmer'],
  'topps series 1': ['Base', 'Gold', 'Rainbow Foil', 'Vintage Stock', 'Independence Day', 'Platinum', 'Clear'],
  'topps series 2': ['Base', 'Gold', 'Rainbow Foil', 'Vintage Stock', 'Independence Day', 'Platinum', 'Clear'],
  'topps update': ['Base', 'Gold', 'Rainbow Foil', 'Vintage Stock', 'Independence Day', 'Platinum', 'Clear'],
};

// GET /api/sets/search?q=topps+chrome
app.get('/api/sets/search', authenticateToken, async (req, res) => {
  try {
    const query = (req.query.q || '').trim();
    if (!query || query.length < 2) {
      return res.json({ sets: [] });
    }

    const cacheKey = `search:${query.toLowerCase()}`;
    const cached = getCachedSet(cacheKey);
    if (cached) return res.json(cached);

    const results = [];
    const seen = new Set();

    // Source 1: Local DB - distinct set names from previously identified cards
    if (dbAvailable) {
      const dbResult = await pool.query(`
        SELECT DISTINCT
          card_data->>'set_name' as set_name,
          card_data->>'year' as year,
          card_data->>'sport' as sport,
          COUNT(*) as card_count
        FROM cards
        WHERE card_data->>'set_name' IS NOT NULL
          AND card_data->>'set_name' != ''
          AND card_data->>'set_name' ILIKE $1
        GROUP BY card_data->>'set_name', card_data->>'year', card_data->>'sport'
        ORDER BY card_count DESC
        LIMIT 20
      `, [`%${query}%`]);

      for (const row of dbResult.rows) {
        const key = `${row.year || ''}-${row.set_name}`.toLowerCase();
        if (!seen.has(key)) {
          seen.add(key);
          results.push({
            set_name: row.set_name,
            year: row.year || null,
            sport: row.sport || null,
            card_count: parseInt(row.card_count),
            source: 'local'
          });
        }
      }
    }

    // Source 2: SCP API
    if (SPORTSCARDSPRO_TOKEN) {
      try {
        const scpRes = await axios.get(`${SCP_API_BASE}/products`, {
          params: { q: query, t: SPORTSCARDSPRO_TOKEN },
          timeout: 5000
        });
        const products = scpRes.data || [];
        for (const product of products.slice(0, 20)) {
          const name = product.name || product.title || '';
          // Extract set name from product - typically "YEAR SETNAME #NUM PLAYER"
          const yearMatch = name.match(/^(19|20)\d{2}/);
          const year = yearMatch ? yearMatch[0] : null;
          // Try to extract set name (text between year and card number)
          let setName = name;
          if (year) {
            setName = name.substring(year.length).trim();
          }
          // Remove card number and player info (after #)
          const hashIdx = setName.indexOf('#');
          if (hashIdx > 0) {
            setName = setName.substring(0, hashIdx).trim();
          }

          if (setName) {
            const key = `${year || ''}-${setName}`.toLowerCase();
            if (!seen.has(key)) {
              seen.add(key);
              results.push({
                set_name: setName,
                year: year || null,
                sport: null,
                card_count: 0,
                source: 'scp'
              });
            }
          }
        }
      } catch (e) {
        console.log('[SCP] Search failed, using DB-only results:', e.message);
      }
    }

    const response = { sets: results.slice(0, 20) };
    setCachedSet(cacheKey, response);
    res.json(response);

  } catch (e) {
    console.error('[Sets Search] Error:', e.message);
    res.status(500).json({ error: 'Search failed' });
  }
});

// GET /api/sets/parallels?set=Topps+Chrome&year=2020
app.get('/api/sets/parallels', authenticateToken, async (req, res) => {
  try {
    const setName = (req.query.set || '').trim();
    const year = (req.query.year || '').trim();

    if (!setName) {
      return res.json({ parallels: [] });
    }

    const cacheKey = `parallels:${setName.toLowerCase()}:${year}`;
    const cached = getCachedSet(cacheKey);
    if (cached) return res.json(cached);

    const parallels = new Set();

    // Source 1: Hardcoded known parallels
    const setLower = setName.toLowerCase();
    for (const [key, values] of Object.entries(KNOWN_SET_PARALLELS)) {
      if (setLower.includes(key) || key.includes(setLower)) {
        values.forEach(v => parallels.add(v));
        break;
      }
    }

    // Source 2: Local DB
    if (dbAvailable) {
      const params = [`%${setName}%`];
      let yearFilter = '';
      if (year) {
        yearFilter = `AND card_data->>'year' = $2`;
        params.push(year);
      }
      const dbResult = await pool.query(`
        SELECT DISTINCT card_data->>'parallel' as parallel
        FROM cards
        WHERE card_data->>'set_name' ILIKE $1
          AND card_data->>'parallel' IS NOT NULL
          AND card_data->>'parallel' != ''
          ${yearFilter}
      `, params);

      for (const row of dbResult.rows) {
        if (row.parallel) parallels.add(row.parallel);
      }
    }

    // Source 3: SCP product search for parallel keywords
    if (SPORTSCARDSPRO_TOKEN) {
      try {
        const searchQ = year ? `${year} ${setName}` : setName;
        const scpRes = await axios.get(`${SCP_API_BASE}/products`, {
          params: { q: searchQ, t: SPORTSCARDSPRO_TOKEN },
          timeout: 5000
        });
        const products = scpRes.data || [];
        const parallelKeywords = ['Refractor', 'Silver', 'Gold', 'Prizm', 'Holo', 'Chrome', 'Pink', 'Blue', 'Green', 'Red', 'Orange', 'Purple', 'Black', 'Mojo', 'Shimmer', 'Camo', 'Disco', 'Scope', 'Tie-Dye', 'Neon', 'Genesis', 'Fluorescent', 'Velocity', 'Sparkle'];
        for (const product of products) {
          const name = product.name || product.title || '';
          for (const kw of parallelKeywords) {
            if (name.toLowerCase().includes(kw.toLowerCase())) {
              // Try to extract the full parallel name (word(s) around the keyword)
              const regex = new RegExp(`(\\w+\\s+)?${kw}(\\s+\\w+)?`, 'i');
              const match = name.match(regex);
              if (match) {
                parallels.add(match[0].trim());
              }
            }
          }
        }
      } catch (e) {
        console.log('[SCP] Parallels search failed:', e.message);
      }
    }

    // Always include Base if we have any results
    if (parallels.size > 0) parallels.add('Base');

    const sorted = Array.from(parallels).sort((a, b) => {
      if (a === 'Base') return -1;
      if (b === 'Base') return 1;
      return a.localeCompare(b);
    });

    const response = { parallels: sorted };
    setCachedSet(cacheKey, response);
    res.json(response);

  } catch (e) {
    console.error('[Sets Parallels] Error:', e.message);
    res.status(500).json({ error: 'Parallels lookup failed' });
  }
});

// POST /api/sets/identify-from-image — Scan card back to identify set
app.post('/api/sets/identify-from-image', authenticateToken, upload.single('image'), async (req, res) => {
  const userId = req.user.id;

  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image provided' });
    }

    const imageBase64 = req.file.buffer.toString('base64');
    const mimeType = req.file.mimetype || 'image/jpeg';

    // Dual-path: SlabTrack or BYOK
    const slabTrackCheck = await canUseSlabTrackScan(userId);
    const apiKey = await getUserApiKey(userId);

    if (!slabTrackCheck.canUse && !apiKey) {
      return res.status(400).json({ error: 'No scanning method available. Connect SlabTrack Power/Dealer or add your Anthropic API key.' });
    }

    let setInfo = null;
    let inputTokens = 0, outputTokens = 0, cost = 0;
    let scanMode = 'byok';

    // Try SlabTrack first
    if (slabTrackCheck.canUse) {
      try {
        const imageData = `data:${mimeType};base64,${imageBase64}`;
        const stResponse = await axios.post(`${SLABTRACK_API}/scanner/scan`, {
          backImage: imageData,
          source: 'cardflow_set_identify'
        }, {
          headers: {
            'Content-Type': 'application/json',
            'X-API-Token': slabTrackCheck.token
          },
          timeout: 30000
        });

        if (stResponse.data?.success && stResponse.data.card) {
          const card = stResponse.data.card;
          setInfo = {
            set_name: card.set_name || null,
            year: card.year || null,
            sport: card.sport || null,
            manufacturer: card.manufacturer || null
          };
          scanMode = 'slabtrack';
        }
      } catch (e) {
        console.log('[Set Identify] SlabTrack failed, falling back to BYOK:', e.message);
      }
    }

    // BYOK fallback
    if (!setInfo && apiKey) {
      const Anthropic = require('@anthropic-ai/sdk');
      const anthropic = new Anthropic({ apiKey });

      const response = await anthropic.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 512,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: mimeType, data: imageBase64 } },
            { type: 'text', text: 'This is the BACK of a sports card. Identify the set it belongs to by reading any logos, text, copyright info, or design patterns visible.\n\nReturn ONLY a JSON object (no other text):\n{\n  "set_name": "Full set name (e.g., Topps Chrome, Panini Prizm)",\n  "year": 2024,\n  "sport": "baseball, basketball, football, hockey, or soccer",\n  "manufacturer": "Topps, Panini, Upper Deck, etc."\n}' }
          ]
        }]
      });

      const responseText = response.content[0].text;
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        setInfo = JSON.parse(jsonMatch[0]);
      }

      inputTokens = response.usage?.input_tokens || 0;
      outputTokens = response.usage?.output_tokens || 0;
      cost = (inputTokens * 0.003 + outputTokens * 0.015) / 1000;
    }

    if (!setInfo || !setInfo.set_name) {
      return res.status(422).json({ error: 'Could not identify set from image. Try a clearer photo of the card back.' });
    }

    // Build parallels list (same logic as /api/sets/parallels)
    const parallels = new Set();
    const setLower = setInfo.set_name.toLowerCase();

    // Source 1: Hardcoded known parallels
    for (const [key, values] of Object.entries(KNOWN_SET_PARALLELS)) {
      if (setLower.includes(key) || key.includes(setLower)) {
        values.forEach(v => parallels.add(v));
        break;
      }
    }

    // Source 2: Local DB
    if (dbAvailable) {
      const params = [`%${setInfo.set_name}%`];
      let yearFilter = '';
      if (setInfo.year) {
        yearFilter = `AND card_data->>'year' = $2`;
        params.push(String(setInfo.year));
      }
      const dbResult = await pool.query(`
        SELECT DISTINCT card_data->>'parallel' as parallel
        FROM cards
        WHERE card_data->>'set_name' ILIKE $1
          AND card_data->>'parallel' IS NOT NULL
          AND card_data->>'parallel' != ''
          ${yearFilter}
      `, params);
      for (const row of dbResult.rows) {
        if (row.parallel) parallels.add(row.parallel);
      }
    }

    // Source 3: SCP
    if (SPORTSCARDSPRO_TOKEN) {
      try {
        const searchQ = setInfo.year ? `${setInfo.year} ${setInfo.set_name}` : setInfo.set_name;
        const scpRes = await axios.get(`${SCP_API_BASE}/products`, {
          params: { q: searchQ, t: SPORTSCARDSPRO_TOKEN },
          timeout: 5000
        });
        const products = scpRes.data || [];
        const parallelKeywords = ['Refractor', 'Silver', 'Gold', 'Prizm', 'Holo', 'Chrome', 'Pink', 'Blue', 'Green', 'Red', 'Orange', 'Purple', 'Black', 'Mojo', 'Shimmer', 'Camo', 'Disco', 'Scope', 'Tie-Dye', 'Neon', 'Genesis', 'Fluorescent', 'Velocity', 'Sparkle'];
        for (const product of products) {
          const name = product.name || product.title || '';
          for (const kw of parallelKeywords) {
            if (name.includes(kw)) {
              const regex = new RegExp(`(\\w+\\s+)?${kw}(\\s+\\w+)?`, 'i');
              const match = name.match(regex);
              if (match) parallels.add(match[0].trim());
            }
          }
        }
      } catch (e) {
        console.log('[Set Identify] SCP parallels search failed:', e.message);
      }
    }

    if (parallels.size > 0) parallels.add('Base');
    const sortedParallels = Array.from(parallels).sort((a, b) => {
      if (a === 'Base') return -1;
      if (b === 'Base') return 1;
      return a.localeCompare(b);
    });

    // Track usage
    const metadata = {
      set_identified: setInfo,
      scan_mode: scanMode,
      scanned_at: new Date().toISOString()
    };
    await pool.query(`
      INSERT INTO api_usage (user_id, operation, model_used, tokens_input, tokens_output, cost, metadata)
      VALUES ($1, 'set_identify', $2, $3, $4, $5, $6)
    `, [userId, scanMode === 'slabtrack' ? 'slabtrack_api' : 'sonnet4', inputTokens, outputTokens, cost, JSON.stringify(metadata)]);

    // WebSocket broadcast to desktop
    broadcast({
      type: 'set_context_updated',
      userId,
      setContext: {
        set_name: setInfo.set_name,
        year: setInfo.year,
        sport: setInfo.sport,
        parallels: sortedParallels
      }
    });

    console.log(`[Set Identify] User ${userId}: ${setInfo.year || ''} ${setInfo.set_name} (${sortedParallels.length} parallels) via ${scanMode}`);

    res.json({
      success: true,
      set_name: setInfo.set_name,
      year: setInfo.year,
      sport: setInfo.sport,
      manufacturer: setInfo.manufacturer,
      parallels: sortedParallels
    });

  } catch (e) {
    console.error('[Set Identify] Error:', e.message);
    res.status(500).json({ error: 'Set identification failed: ' + e.message });
  }
});

// ============================================
// ERROR HANDLERS (must be after all routes)
// ============================================

// Sentry error handler (v8 API)
if (process.env.SENTRY_DSN) {
  Sentry.setupExpressErrorHandler(app);
}

// Generic error handler (catches anything Sentry didn't)
app.use((err, req, res, next) => {
  console.error('[Error]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================
// START SERVER
// ============================================

const HOST = process.env.NODE_ENV === 'production' ? '0.0.0.0' : 'localhost';

server.listen(PORT, HOST, () => {
  console.log(`
══════════════════════════════════════════════════
  CARDFLOW v2.0 - Multi-User SaaS (Build 0201m)
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

