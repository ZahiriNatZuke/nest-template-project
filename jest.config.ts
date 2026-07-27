import type { Config } from 'jest';

/**
 * SWC options for the test transformer.
 *
 * Kept inline instead of in a `.swcrc` on purpose: a `.swcrc` at the project
 * root would also be picked up by `nest build`/`nest start -b swc`, so the
 * build and the tests would share one config and drift would break both at
 * once.
 *
 * `legacyDecorator` + `decoratorMetadata` + `keepClassNames` are what make
 * NestJS dependency injection work — without them `design:paramtypes` is never
 * emitted and every constructor injection resolves to `undefined`.
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
	rootDir: '.',
	testEnvironment: 'node',
	roots: ['<rootDir>/src'],
	testRegex: '.*\\.spec\\.ts$',
	moduleFileExtensions: ['js', 'json', 'ts'],
	transform: {
		'^.+\\.(t|j)s$': ['@swc/jest', swcOptions],
	},
	// otplib pulls in @scure/base and @noble/hashes, which are ESM-only. Node 22
	// can `require()` those directly, but Jest's runtime cannot — so they have to
	// go through the transformer instead of being skipped like the rest of
	// node_modules. The `.*` before the group is what makes this work under
	// pnpm, where the real path is node_modules/.pnpm/@scure+base@x/node_modules/
	// @scure/base and the plain `/node_modules/` prefix appears twice.
	transformIgnorePatterns: ['node_modules/(?!.*(@scure|@noble))'],
	// Mirrors the `paths` block in tsconfig.json. `@app/env` is listed first
	// because `^@app/(.*)$` would otherwise swallow it.
	moduleNameMapper: {
		'^@app/env$': '<rootDir>/src/config/envs',
		'^@app/(.*)$': '<rootDir>/src/app/$1',
		'^@test/(.*)$': '<rootDir>/test/$1',
	},
	setupFiles: ['<rootDir>/test/setup-env.ts'],
	setupFilesAfterEnv: ['<rootDir>/test/setup-tests.ts'],
	clearMocks: true,
	collectCoverageFrom: [
		'src/**/*.ts',
		'!src/**/*.spec.ts',
		'!src/**/*.module.ts',
		'!src/**/*.dto.ts',
		'!src/main.ts',
		'!src/config/envs.ts',
	],
	coverageDirectory: '<rootDir>/coverage',
	coverageReporters: ['text-summary', 'lcov'],
};

export default config;
