# CardFlow

A multi-user SaaS platform for bulk trading card identification and pricing using Claude Vision AI.

## Features

- **AI-Powered Identification**: Uses Claude Vision to identify cards from images
- **Market Pricing**: Fetches current market values from multiple sources
- **Multi-User Support**: JWT authentication with user-scoped data
- **Admin Dashboard**: User management, analytics, and cost tracking
- **Bulk Processing**: Handle hundreds of cards efficiently
- **Real-time Updates**: WebSocket notifications for processing status
- **Export**: Excel/CSV export of card data

## Railway Deployment (Recommended)

Deploy CardFlow to Railway with one click. Railway provides PostgreSQL automatically.

### Quick Deploy

1. **Push to GitHub** (if not already):
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   gh repo create cardflow --private --push
   ```

2. **Deploy to Railway**:
   - Go to [railway.app](https://railway.app)
   - Click "New Project" → "Deploy from GitHub repo"
   - Select your CardFlow repository
   - Railway will auto-detect the Dockerfile

3. **Add PostgreSQL**:
   - In Railway dashboard, click "New" → "Database" → "PostgreSQL"
   - Railway automatically links DATABASE_URL to your app

4. **Set Environment Variables** (in Railway dashboard → Variables):
   ```
   JWT_SECRET=<generate-a-random-64-char-string>
   NODE_ENV=production
   ```

   Generate a secure JWT secret:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

5. **First Deploy**:
   - Railway will build and deploy automatically
   - Migrations run on first start
   - Access your app at the Railway-provided URL

### Post-Deployment

1. **Create Admin User**:
   - Register at `/register`
   - Connect to Railway's PostgreSQL and run:
     ```sql
     UPDATE users SET role = 'admin' WHERE email = 'your-email@example.com';
     ```

2. **Add Anthropic API Key**:
   - Login to your app
   - Go to Settings → API Key
   - Enter your Anthropic API key

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Auto | PostgreSQL connection (Railway provides) |
| `JWT_SECRET` | Yes | Secret for JWT tokens (min 32 chars) |
| `NODE_ENV` | Yes | Set to `production` |
| `PORT` | Auto | Server port (Railway provides) |
| `ANTHROPIC_API_KEY` | No | Can be set per-user in Settings |

## Local Development

For local development without a database, the app falls back to file-based storage.

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

Open http://localhost:3005 in your browser.

### With Local PostgreSQL (Optional)

If you want to use PostgreSQL locally:

```bash
# Create database
createdb cardflow

# Set environment
export DATABASE_URL=postgresql://localhost/cardflow
export JWT_SECRET=dev-secret-key

# Run migrations
npm run migrate

# Start server
npm run dev
```

## Usage

### Web Dashboard

1. **Login/Register**: Create an account or login
2. **Upload Cards**: Drop card images into the upload zone
3. **Processing**: AI identifies and prices each card
4. **Export**: Download results as Excel

### CLI Tools

```bash
# Identify cards from images
npm run identify

# Fetch market prices
npm run price

# Export to Excel
npm run export

# Compare model performance
npm run compare
```

## API Endpoints

### Health Check

- `GET /api/health` - Server health status

### Authentication

- `POST /api/auth/register` - Create account
- `POST /api/auth/login` - Login
- `GET /api/auth/me` - Get current user
- `POST /api/auth/logout` - Logout

### Cards

- `GET /api/cards` - List user's cards
- `POST /api/cards` - Add card(s)
- `PUT /api/cards/:id` - Update card
- `DELETE /api/cards/:id` - Delete card

### Admin

- `GET /api/admin/users` - List all users
- `GET /api/admin/analytics` - Usage analytics
- `PUT /api/admin/users/:id` - Update user

## Architecture

```
cardflow/
├── web/
│   ├── server.js      # Express + WebSocket server
│   ├── index.html     # Main dashboard
│   ├── login.html     # Login page
│   ├── register.html  # Registration
│   └── admin.html     # Admin dashboard
├── scripts/
│   ├── identify.js    # Card identification
│   ├── price.js       # Market pricing
│   ├── export.js      # Excel export
│   └── railway-migrate.js  # Database migrations
├── railway.json       # Railway deployment config
├── Dockerfile         # Container config
└── package.json
```

## Database Schema

- **users**: User accounts with auth and subscription data
- **cards**: Card data stored as JSONB with image paths
- **api_usage**: Token and cost tracking per operation
- **sessions**: Processing session grouping

## Troubleshooting

### Railway Deployment Issues

1. **Build fails**: Check Dockerfile syntax, ensure all dependencies are in package.json
2. **Database not connecting**: Verify PostgreSQL service is added and linked
3. **Migrations fail**: Check DATABASE_URL is set, view logs in Railway dashboard

### Authentication Issues

1. Check JWT_SECRET is set (min 32 characters recommended)
2. Clear browser localStorage and try again
3. Verify user exists in database

### Card Identification Fails

1. Verify ANTHROPIC_API_KEY is valid (in Settings or environment)
2. Check API usage limits on Anthropic console
3. Ensure images are readable (not corrupted)

## License

MIT
