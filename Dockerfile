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

# `corepack prepare --activate` resolves the version from package.json's
# `packageManager` field and materialises it now, at build time — which is why
# it has to come after the manifest is in place. Plain `corepack enable` defers
# the decision to first use, so the image would silently pick up whatever pnpm
# was newest: that is how this build came to reject a lockfile that CI installs
# cleanly.
RUN corepack prepare --activate

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
RUN corepack prepare --activate

# `prebuild` runs prisma generate, so the client is emitted into node_modules
# before nest build compiles the sources that import it. It needs no
# DATABASE_URL: prisma.config.ts reads the variable directly instead of through
# the eager `env()` helper, which used to throw here.
RUN pnpm run build

# Drop dev dependencies from the tree we are about to copy into the runtime.
# `--ignore-scripts` because pruning removes husky and then pnpm tries to run
# the `prepare` script that husky owns, failing on a binary it just deleted.
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
	pnpm config set store-dir /pnpm/store && \
	pnpm prune --prod --ignore-scripts

# ---------------------------------------------------------------------------
# runtime — slim image, non-root, no package manager
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION} AS runtime
WORKDIR /app

# No corepack here on purpose: nothing in the runtime path invokes pnpm, so the
# image neither downloads nor resolves a package manager when it starts.
RUN apk add --no-cache libc6-compat

ENV NODE_ENV=production
ENV ENVIRONMENT=production

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/prisma ./prisma
COPY --from=build /app/prisma.config.ts ./prisma.config.ts
COPY --chmod=755 docker-entrypoint.sh ./docker-entrypoint.sh

# The app writes rotated logs to ./logs, so that directory has to be owned by
# the unprivileged user rather than by root.
RUN mkdir -p logs && chown -R node:node /app
USER node

EXPOSE 3000

# The entrypoint applies migrations only when MIGRATE_ON_BOOT=true, then execs
# the command below — so PID 1 is the application and signals reach it.
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["node", "dist/src/main"]
