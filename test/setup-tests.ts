import { Logger } from '@nestjs/common';

/**
 * Silences NestJS logging for the whole suite.
 *
 * Several services log at `error` level as part of their normal, tested
 * behaviour (EncryptionService on tampered ciphertext, PolicyEngineService on
 * an inactive policy, ...). Without this, the output of a *passing* run is
 * hundreds of lines of stack traces, which buries real failures.
 *
 * The spies go on `Logger.prototype` rather than using
 * `Logger.overrideLogger()`: services here hold their own instance logger
 * (`private readonly logger = new Logger(Foo.name)`), and neither
 * `overrideLogger(false)` nor `overrideLogger([])` reliably silences those —
 * the instance captures its log levels the first time it is used.
 *
 * `clearMocks` only resets call history, so these implementations survive
 * between tests. A spec that wants to assert on logging can re-spy locally;
 * its spy takes precedence and is restored afterwards.
 */
const SILENCED_METHODS = [
	'log',
	'error',
	'warn',
	'debug',
	'verbose',
	'fatal',
] as const;

for (const method of SILENCED_METHODS) {
	jest.spyOn(Logger.prototype, method).mockImplementation(() => undefined);
}
