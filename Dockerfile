# ==============================================================================
# Multi-Stage Dockerfile for Carpschool Central Server
# Stage 1: Dependencies Builder (deps)
# Stage 2: Source Compilation Builder (builder)
# Stage 3: Minimal Production Runtime (runner)
# ==============================================================================

# --- Stage 1: Dependencies Builder ---
FROM node:20-alpine AS deps
WORKDIR /app

# Install build dependencies if needed
RUN apk add --no-cache libc6-compat

# Copy package manifests for layer caching
COPY package.json package-lock.json* ./

# Install all dependencies (dev + prod)
RUN npm install

# --- Stage 2: Compilation Builder ---
FROM node:20-alpine AS builder
WORKDIR /app

# Copy dependencies from deps stage
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Compile TypeScript application to /app/dist
RUN npm run build

# Prune development dependencies to keep production footprint minimal
RUN npm prune --omit=dev

# --- Stage 3: Minimal Production Runner ---
FROM node:20-alpine AS runner
WORKDIR /app

# Install dumb-init for proper Linux PID 1 signal forwarding and zombie reaping
RUN apk add --no-cache dumb-init

# Prepare application directory with proper node user permissions for key persistence
RUN mkdir -p /app/.keys && chown -R node:node /app

# Set production environment
ENV NODE_ENV=production
ENV PORT=4000

# Run container as an unprivileged, non-root user for security
USER node

# Copy production node_modules from builder stage
COPY --chown=node:node --from=builder /app/node_modules ./node_modules
# Copy compiled JavaScript output
COPY --chown=node:node --from=builder /app/dist ./dist
# Copy package manifest
COPY --chown=node:node --from=builder /app/package.json ./package.json

EXPOSE 4000

ENTRYPOINT ["dumb-init", "node", "dist/main.js"]
