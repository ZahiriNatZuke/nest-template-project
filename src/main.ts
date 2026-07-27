import { envs } from '@app/env';
import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import {
	FastifyAdapter,
	NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { Logger as PinoLogger } from 'nestjs-pino';

import { AppModule } from './app.module';
import {
	configureApp,
	GLOBAL_PREFIX,
	getHost,
} from './bootstrap/configure-app';

// Re-exported for backwards compatibility: `getHost` used to live here.
export { getHost };

async function bootstrap() {
	const host = getHost();

	// Create the NestJS application
	const app = await NestFactory.create<NestFastifyApplication>(
		AppModule,
		new FastifyAdapter({
			logger: false,
			routerOptions: {
				ignoreTrailingSlash: true,
				ignoreDuplicateSlashes: true,
			},
		})
	);

	// Add the logger to the application
	app.useLogger(app.get(PinoLogger));

	// Apply every cross-cutting concern — shared with the e2e test harness
	await configureApp(app);

	// Start the application
	await app.listen(envs.PORT || 3000, '0.0.0.0', () =>
		Logger.log(
			`REST API at ${host}/${GLOBAL_PREFIX} & Swagger Doc at ${host}/swagger`
		)
	);
}

bootstrap().then(() => Logger.log('NestJS + Fastify ready to work!'));
