import {
	HttpExceptionFilter,
	ZodValidationExceptionFilter,
} from '@app/core/filters'; // Get the host
import { envs } from '@app/env';
import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import {
	FastifyAdapter,
	NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { LoggerErrorInterceptor, Logger as PinoLogger } from 'nestjs-pino';
import { ZodValidationPipe, patchNestJsSwagger } from 'nestjs-zod';
import { AppModule } from './app.module';

// Get the host
export const getHost = () => {
	if (envs.ENVIRONMENT === 'production') return `https://${envs.HOST}`;
	return `http://${envs.HOST}:${envs.PORT}`;
};

async function bootstrap() {
	// Get the global prefix and host
	const globalPrefix = 'api/v1';
	const host = getHost();

	// Create the NestJS application
	const app = await NestFactory.create<NestFastifyApplication>(
		AppModule,
		new FastifyAdapter({ logger: false })
	);

	// Add the logger to the application
	app.useLogger(app.get(PinoLogger));

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
		],
		// headers exposed to the client
		exposedHeaders: ['Authorization'],
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
	app.setGlobalPrefix(globalPrefix);

	// Register the error interceptor
	app.useGlobalInterceptors(new LoggerErrorInterceptor());

	// Register the Swagger documentation
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
		.addServer(host)
		.build();

	// Patch the NestJS Swagger
	patchNestJsSwagger();

	// Create the Swagger document
	const appDocument = SwaggerModule.createDocument(app, options, {
		deepScanRoutes: true,
	});

	// Set up the Swagger module
	SwaggerModule.setup('/swagger', app, appDocument, {
		swaggerOptions: { persistAuthorization: true },
	});

	// Start the application
	await app.listen(envs.PORT || 3000, '0.0.0.0', () =>
		Logger.log(
			`REST API at ${host}/${globalPrefix} & Swagger Doc at ${host}/swagger`
		)
	);
}

bootstrap().then(() => Logger.log('NestJS + Fastify ready to work!'));
