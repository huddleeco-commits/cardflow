# CardFlow - Railway Dockerfile
FROM node:20-slim

# Install dependencies for bcrypt and sharp
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --omit=dev

# Copy application code
COPY . .

# Create uploads directory
RUN mkdir -p uploads

# Expose port (Railway will override with PORT env var)
EXPOSE 3005

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:' + (process.env.PORT || 3005) + '/api/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Start command (Railway overrides this via railway.json)
CMD ["node", "web/server.js"]
