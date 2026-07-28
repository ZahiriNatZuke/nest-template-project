#!/bin/sh
# Container entrypoint.
#
# The image used to start with `pnpm run start:prod`, which meant corepack
# downloaded a pnpm tarball from the network on every container start, then
# pnpm decided the pruned node_modules was out of date and tried to reinstall
# it — aborting because there was no TTY. The container never reached the
# application. Calling node directly removes pnpm, corepack and the network
# from the startup path entirely.
#
# Migrations are opt-in. `prestart:prod` used to run `prisma migrate deploy` on
# every start, which is convenient for a single container and wrong for several:
# every replica races to migrate the same database. Set MIGRATE_ON_BOOT=true
# when one container owns the schema; leave it unset and run
# `pnpm run migrate:deploy` (or a dedicated job) as a separate deployment step.

set -eu

if [ "${MIGRATE_ON_BOOT:-false}" = "true" ]; then
	echo "[entrypoint] MIGRATE_ON_BOOT=true — applying migrations"
	./node_modules/.bin/prisma migrate deploy
fi

exec "$@"
