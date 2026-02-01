# ============================================
# STAGE 1: Build
# ============================================
FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY prisma ./prisma/

# Install dependencies
RUN npm ci --only=production=false

# Copy source
COPY tsconfig.json ./
COPY src ./src

# Generate Prisma client
RUN npm run prisma:generate

# Build TypeScript
RUN npm run build

# ============================================
# STAGE 2: Production
# ============================================
FROM node:20-alpine AS production

# Security: Run as non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY prisma ./prisma/

# Install production dependencies only
RUN npm ci --only=production && npm cache clean --force

# Generate Prisma client
RUN npx prisma generate

# Copy built files from builder
COPY --from=builder /app/dist ./dist

# Copy keys directory (will be mounted in production)
RUN mkdir -p keys && chown nodejs:nodejs keys

# Set ownership
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Environment variables will be loaded from .env file or docker-compose
# No hardcoded values - all configuration via environment

# Expose port (default, can be overridden via PORT env var)
EXPOSE 3000

# Health check using environment variable for port
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT:-3000}/health || exit 1

# Start server
CMD ["node", "dist/server.js"]
