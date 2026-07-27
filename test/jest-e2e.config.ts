import type { Config } from 'jest';

/**
 * End-to-end configuration.
 *
 * Intentionally standalone rather than importing `../jest.config`: Jest parses
 * a TypeScript config as ESM, where a relative import needs a file extension,
 * while `tsc` rejects an explicit `.ts` extension unless
 * `allowImportingTsExtensions` is on — which the project cannot enable because
 * it emits. Duplicating a dozen lines is cheaper than fighting that.
 *
 * Requires a reachable PostgreSQL at the DATABASE_URL in `.env.test`:
 *
 *   docker compose -f docker-compose.test.yml up -d
 *   pnpm prisma migrate deploy
 *   pnpm test:e2e
 */
const swcOptions = {
	jsc: {
		target: 'es2021',
		parser: {
			syntax: 'typescript',
			decorators: true,
			dynamicImport: true,
		},
		transform: {
			legacyDecorator: true,
			decoratorMetadata: true,
		},
		keepClassNames: true,
	},
	module: {
		type: 'commonjs',
	},
	sourceMaps: true,
};

const config: Config = {
	rootDir: '..',
	testEnvironment: 'node',
	roots: ['<rootDir>/test'],
	testRegex: '.*\\.e2e-spec\\.ts$',
	moduleFileExtensions: ['js', 'json', 'ts'],
	transform: {
		'^.+\\.(t|j)s$': ['@swc/jest', swcOptions],
	},
	// Same rationale as the unit config: these packages are ESM-only and Jest's
	// runtime cannot require() them, so they go through the transformer.
	transformIgnorePatterns: ['node_modules/(?!.*(@scure|@noble|cookie))'],
	moduleNameMapper: {
		'^@app/env$': '<rootDir>/src/config/envs',
		'^@app/(.*)$': '<rootDir>/src/app/$1',
		'^@src/(.*)$': '<rootDir>/src/$1',
		'^@test/(.*)$': '<rootDir>/test/$1',
	},
	setupFiles: ['<rootDir>/test/setup-env.ts'],
	setupFilesAfterEnv: ['<rootDir>/test/setup-tests.ts'],
	clearMocks: true,
	// Every spec file truncates and re-seeds the same database, so they cannot
	// share a worker pool. `test:e2e` also passes --runInBand.
	maxWorkers: 1,
	// Booting the Nest application and applying fixtures costs more than a unit
	// test's few milliseconds.
	testTimeout: 30_000,
};

export default config;
