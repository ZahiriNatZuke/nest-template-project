import 'dotenv/config';
import { defineConfig } from 'prisma/config';

export default defineConfig({
	schema: 'prisma/schema.prisma',
	datasource: {
		// Read directly rather than through prisma's `env()` helper, which
		// resolves eagerly and throws when the variable is absent — including for
		// `generate` and `validate`, neither of which opens a connection. That
		// took CI down once (#25) and then took the Docker build down again,
		// because both run without a .env file. Commands that really do connect
		// still fail, with Prisma's own message about the datasource URL.
		url: process.env.DATABASE_URL ?? '',
	},
	migrations: {
		path: 'prisma/migrations',
		seed: 'ts-node prisma/seed.ts',
	},
});
