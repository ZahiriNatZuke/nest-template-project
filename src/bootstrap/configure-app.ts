import { HttpExceptionFilter } from '@app/core/filters/http-exception.filter';
import { ZodValidationExceptionFilter } from '@app/core/filters/zod-validation.filter';
import { ZodValidationPipe } from '@app/core/pipes/zod-validation.pipe';
import { envs } from '@app/env';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { LoggerErrorInterceptor } from 'nestjs-pino';

/** Path prefix every route in the API is mounted under. */
export const GLOBAL_PREFIX = 'api/v1';

/** Base URL of the running API, protocol depending on the environment. */
export const getHost = (): string => {
	if (envs.ENVIRONMENT === 'production') return `https://${envs.HOST}`;
	return `http://${envs.HOST}:${envs.PORT}`;
};

/**
 * Applies every cross-cutting concern to a Nest application instance: security
 * plugins, CORS, the global prefix, the Zod pipe and the exception filters.
 *
 * This lives apart from `main.ts` so that end-to-end tests can boot the *same*
 * configuration the production process uses. When it was inline in
 * `bootstrap()`, a test app had none of the filters or the global prefix, so
 * e2e specs would have asserted against a application that did not exist
 * outside the test file.
 *
 * Swagger is opt-out via `withSwagger` because building the OpenAPI document
 * scans every route and is pure overhead in tests.
 */
export async function configureApp(
	app: NestFastifyApplication,
	{ withSwagger = true }: { withSwagger?: boolean } = {}
): Promise<NestFastifyApplication> {
	// Register cookie plugin for Fastify
	await app.register(require('@fastify/cookie'));

	// Enable CORS
	app.enableCors({
		origin: envs.ORIGINS,
		preflightContinue: true,
		// allowed headers
		allowedHeaders: [
			'Content-Type',
			'Origin',
			'X-Requested-With',
			'Accept',
			'Authorization',
			envs.HEADER_KEY_API_KEY,
			'X-CSRF-Token',
		],
		// headers exposed to the client
		exposedHeaders: ['Authorization', 'Set-Cookie'],
		credentials: true, // Enable credentials (cookies, authorization headers) cross-origin
		optionsSuccessStatus: 204,
		maxAge: 86400, // 1 day
		methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
	});

	// Enable the shutdown hooks
	app.enableShutdownHooks();

	// Register the helmet plugin
	await app.register(() => import('@fastify/helmet'), {
		global: true,
		contentSecurityPolicy: {
			directives: {
				defaultSrc: ["'self'"],
				scriptSrc: ["'self'", "'unsafe-inline'"],
				styleSrc: ["'self'", "'unsafe-inline'"],
				imgSrc: ["'self'", 'data:'],
				fontSrc: ["'self'"],
			},
		},
		crossOriginEmbedderPolicy: { policy: 'require-corp' },
		crossOriginOpenerPolicy: { policy: 'same-origin' },
		crossOriginResourcePolicy: { policy: 'same-origin' },
		originAgentCluster: true,
		referrerPolicy: { policy: 'same-origin' },
		xContentTypeOptions: true,
		xDnsPrefetchControl: { allow: true },
		xDownloadOptions: true,
		xFrameOptions: { action: 'sameorigin' },
		xPermittedCrossDomainPolicies: { permittedPolicies: 'none' },
		xXssProtection: true,
		hidePoweredBy: true,
		strictTransportSecurity: {
			maxAge: 63072000, // 2 year
			includeSubDomains: true, // include all subdomains
			preload: true, // enable preload
		},
	});

	// Register the rate limit plugin
	await app.register(() => import('@fastify/rate-limit'), {
		global: true, // default true
		max: envs.RATE_LIMIT_MAX, // default 1000
		ban: 2, // default -1
		timeWindow: envs.RATE_LIMIT_WINDOWS, // default 1000 * 60
		cache: 10000, // default 5000
		allowList: ['127.0.0.1'], // default []
		continueExceeding: true, // default false
		skipOnError: true, // default false
		enableDraftSpec: true, // default false. Uses IEFT draft header standard
		addHeadersOnExceeding: {
			// default show all the response headers when rate limit is not reached
			'x-ratelimit-limit': true,
			'x-ratelimit-remaining': true,
			'x-ratelimit-reset': true,
		},
		addHeaders: {
			// default show all the response headers when rate limit is reached
			'x-ratelimit-limit': true,
			'x-ratelimit-remaining': true,
			'x-ratelimit-reset': true,
			'retry-after': true,
		},
	});

	// Register the validation pipe
	app.useGlobalPipes(new ZodValidationPipe());

	// Register the exception filters
	app.useGlobalFilters(new ZodValidationExceptionFilter());
	app.useGlobalFilters(new HttpExceptionFilter());

	// Set the global prefix
	app.setGlobalPrefix(GLOBAL_PREFIX);

	// Register the error interceptor
	app.useGlobalInterceptors(new LoggerErrorInterceptor());

	if (withSwagger) {
		setupSwagger(app);
	}

	return app;
}

/** Builds and mounts the OpenAPI document at `/swagger`. */
function setupSwagger(app: NestFastifyApplication): void {
	const options = new DocumentBuilder()
		.setTitle(envs.APP_NAME)
		.setVersion(envs.SWAGGER_VERSION)
		.addBearerAuth(
			{
				type: 'http',
				scheme: 'bearer',
				bearerFormat: 'JWT',
				in: 'header',
			},
			'Authorization'
		)
		.addApiKey(
			{
				type: 'apiKey',
				in: 'header',
				name: envs.HEADER_KEY_API_KEY,
			},
			envs.HEADER_KEY_API_KEY
		)
		.setLicense('MIT', 'https://opensource.org/licenses/MIT')
		.addServer(getHost())
		.build();

	const appDocument = SwaggerModule.createDocument(app, options, {
		deepScanRoutes: true,
	});

	SwaggerModule.setup('/swagger', app, appDocument, {
		swaggerOptions: { persistAuthorization: true },
	});
}
