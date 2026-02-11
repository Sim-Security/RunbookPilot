FROM oven/bun:1 AS base
WORKDIR /app

# Install native build dependencies for better-sqlite3
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

# Install dependencies
FROM base AS deps
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

# Build stage
FROM base AS build
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
COPY . .
RUN bun run typecheck

# Production image
FROM base AS production
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/src ./src
COPY --from=build /app/package.json ./
COPY --from=build /app/playbooks ./playbooks
COPY --from=build /app/docs ./docs

# Create data directory for SQLite
RUN mkdir -p /app/data

ENV NODE_ENV=production
ENV RUNBOOKPILOT_DB_PATH=/app/data/runbookpilot.db
ENV LOG_LEVEL=info

VOLUME ["/app/data", "/app/playbooks"]

ENTRYPOINT ["bun", "run", "src/cli/index.ts"]
