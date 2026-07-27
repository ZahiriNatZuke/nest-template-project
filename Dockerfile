# syntax=docker/dockerfile:1

# Node 22 is the current LTS and satisfies the `node >= 20` engine constraint
# that @nestjs/core declares.
ARG NODE_VERSION=22-alpine

# ---------------------------------------------------------------------------
# deps — install the full dependency tree once, cached on the lockfile
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION} AS deps
RUN corepack enable
WORKDIR /app

# libc6-compat is needed by the Prisma engines on Alpine; the build toolchain
# is needed to compile bcrypt's native addon.
RUN apk add --no-cache libc6-compat python3 make g++

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
	pnpm config set store-dir /pnpm/store && \
	pnpm install --frozen-lockfile

# ---------------------------------------------------------------------------
# build — generate the Prisma client and compile to dist/
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION} AS build
RUN corepack enable
WORKDIR /app

RUN apk add --no-cache libc6-compat

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# `prebuild` runs prisma generate, so the client is emitted into node_modules
# before nest build compiles the sources that import it.
RUN pnpm run build

# Drop dev dependencies from the tree we are about to copy into the runtime.
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
	pnpm config set store-dir /pnpm/store && \
	pnpm prune --prod

# ---------------------------------------------------------------------------
# runtime — slim image, non-root
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION} AS runtime
RUN corepack enable
WORKDIR /app

RUN apk add --no-cache libc6-compat

ENV NODE_ENV=production
ENV ENVIRONMENT=production

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/prisma ./prisma
COPY --from=build /app/prisma.config.ts ./prisma.config.ts

# The app writes rotated logs to ./logs, so that directory has to be owned by
# the unprivileged user rather than by root.
RUN mkdir -p logs && chown -R node:node /app
USER node

EXPOSE 3000

# `start:prod` is preceded by `prestart:prod`, which runs `prisma migrate
# deploy` — so a container start always brings the schema up to date before
# serving traffic.
CMD ["pnpm", "run", "start:prod"]
