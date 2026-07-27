import { resolve } from 'node:path';
import { config } from 'dotenv';

/**
 * Loads `.env.test` before any application module is imported.
 *
 * This must run in Jest's `setupFiles` (not `setupFilesAfterEnv`): `@app/env`
 * parses `process.env` at import time, so by the time a spec file requires
 * anything that transitively imports it, the variables have to already be
 * there.
 *
 * `override: true` makes the test values win over whatever the developer has
 * exported in their shell. `@app/env` itself runs `import 'dotenv/config'`,
 * which loads `.env`, but dotenv never overwrites variables that are already
 * set — so a local `.env` cannot leak into a test run.
 */
config({
	path: resolve(__dirname, '..', '.env.test'),
	override: true,
	quiet: true,
});
