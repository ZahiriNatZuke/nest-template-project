import { HttpAdapterHost, NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { Logger } from '@nestjs/common';
import {
  PrismaClientExceptionFilter,
} from './app/core/filters/prisma-client-exception/prisma-client-exception.filter';
import { NotFoundExceptionFilter } from './app/core/filters/not-found-exception/not-found-exception.filter';
import { UnauthorizedExceptionFilter } from './app/modules/auth/filters/unauthorized-exception.filter';
import { Logger as PinoLogger, LoggerErrorInterceptor } from 'nestjs-pino';
import { patchNestJsSwagger, ZodValidationPipe } from 'nestjs-zod';

// Get the host
export const getHost = () => {
  if ( process.env[ 'ENVIRONMENT' ] === 'production' )
    return `https://${ process.env[ 'HOST' ] }`;
  else return `http://${ process.env[ 'HOST' ] }:${ process.env[ 'PORT' ] }`;
};

async function bootstrap() {
  // Get the global prefix, port, and host
  const globalPrefix = 'api/v1';
  const port = +process.env[ 'PORT' ]!;
  const host = getHost();

  // Create the NestJS application
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({ logger: false }),
  );

  // Add the logger to the application
  app.useLogger(app.get(PinoLogger));

  // Enable CORS
  app.enableCors({
    credentials: true,
    origin: '*',
    preflightContinue: true,
    optionsSuccessStatus: 204,
  });

  // Enable the shutdown hooks
  app.enableShutdownHooks();

  // Register the helmet plugin
  await app.register(
    import('@fastify/helmet'),
    {
      noSniff: true,
      xssFilter: true,
      hidePoweredBy: true,
      dnsPrefetchControl: { allow: true },
    },
  );

  // Register the rate limit plugin
  await app.register(
    import('@fastify/rate-limit'),
    {
      global: true, // default true
      max: +process.env[ 'RATE_LIMIT_MAX' ]!, // default 1000
      ban: 2, // default -1
      timeWindow: +process.env[ 'RATE_LIMIT_WINDOWS' ]!, // default 1000 * 60
      cache: 10000, // default 5000
      allowList: [ '127.0.0.1' ], // default []
      continueExceeding: true, // default false
      skipOnError: true, // default false
      enableDraftSpec: true, // default false. Uses IEFT draft header standard
      addHeadersOnExceeding: { // default show all the response headers when rate limit is not reached
        'x-ratelimit-limit': true,
        'x-ratelimit-remaining': true,
        'x-ratelimit-reset': true,
      },
      addHeaders: { // default show all the response headers when rate limit is reached
        'x-ratelimit-limit': true,
        'x-ratelimit-remaining': true,
        'x-ratelimit-reset': true,
        'retry-after': true,
      },
    },
  );

  // Set the global prefix
  app.setGlobalPrefix(globalPrefix);

  // Register the validation pipe
  app.useGlobalPipes(new ZodValidationPipe());

  // Register the exception filters
  app.useGlobalFilters(new UnauthorizedExceptionFilter());
  app.useGlobalFilters(new NotFoundExceptionFilter());
  app.useGlobalFilters(new PrismaClientExceptionFilter(app.get(HttpAdapterHost).httpAdapter));

  // Register the error interceptor
  app.useGlobalInterceptors(new LoggerErrorInterceptor());

  // Register the Swagger documentation
  const options = new DocumentBuilder()
    .setTitle(<string>process.env[ 'APP_NAME' ])
    .setVersion(<string>process.env[ 'SWAGGER_VERSION' ])
    .addBearerAuth(
      { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', in: 'header' },
      'Authorization',
    )
    .addApiKey(
      {
        type: 'apiKey',
        in: 'header',
        name: <string>process.env[ 'HEADER_KEY_API_KEY' ],
      },
      <string>process.env[ 'HEADER_KEY_API_KEY' ],
    )
    .setLicense('MIT', 'https://opensource.org/licenses/MIT')
    .addServer(host)
    .build();

  // Patch the NestJS Swagger
  patchNestJsSwagger();

  // Create the Swagger document
  const appDocument = SwaggerModule.createDocument(
    app,
    options,
    { deepScanRoutes: true },
  );

  // Set up the Swagger module
  SwaggerModule.setup('/swagger', app, appDocument, {
    swaggerOptions: { persistAuthorization: true },
  });

  // Start the application
  const initialLog = `REST API at ${ host }/${ globalPrefix } & Swagger Doc at ${ host }/swagger`;
  await app.listen(port || 3000, '0.0.0.0', () => Logger.log(initialLog));
}

bootstrap().then(() => Logger.log('NestJS + Fastify ready to work!'));
