# ============================================
#  TessiHz — Dockerfile
# ============================================

FROM node:20-slim

# Install sqlite3 native deps (better-sqlite3 cần)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files first (cache layer)
COPY package*.json ./
RUN npm install --production=false

# Copy source
COPY server/ ./server/
COPY public/ ./public/

# Create data directory
RUN mkdir -p /app/server/data

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/health', r => process.exit(r.statusCode === 200 ? 0 : 1))"

# Run
CMD ["node", "server/index.js"]
