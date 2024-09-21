import { TasksService } from '@app/core/services';
import { envs } from '@app/env';
import { ApiKeyModule } from '@app/modules/api-key';
import { AuthModule } from '@app/modules/auth';
import { RoleModule } from '@app/modules/role';
import { SessionModule } from '@app/modules/session';
import { SettingsModule } from '@app/modules/settings';
import { UserModule } from '@app/modules/user';
import { HttpStatus, Logger, Module } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { LoggerModule } from 'nestjs-pino';
import {
	PrismaModule,
	QueryInfo,
	loggingMiddleware,
	providePrismaClientExceptionFilter,
} from 'nestjs-prisma';
import { createStream } from 'rotating-file-stream';

@Module({
	imports: [
		ScheduleModule.forRoot(),
		PrismaModule,
		LoggerModule.forRoot({
			pinoHttp: [
				{
					level: envs.PINO_LOG_LEVEL || 'info',
					formatters: {
						level: label => {
							return { level: label.toUpperCase() };
						},
						bindings: bindings => {
							return {
								pid: bindings.pid,
								host: bindings.hostname,
								node_version: process.version,
							};
						},
					},
					transport: {
						target: 'pino-pretty',
						options: {
							colorize: true,
							colorizeObjects: true,
							singleLine: true,
							translateTime: 'HH:MM:ss',
						},
					},
					customLevels: {
						emerg: 80,
						alert: 70,
						crit: 60,
						error: 50,
						warn: 40,
						notice: 30,
						info: 20,
						debug: 10,
					},
					useOnlyCustomLevels: true,
				},
				createStream(
					(time: Date, index: number) => {
						const name = envs.APP_NAME.toLowerCase().replace(/ /g, '-');
						if (!time) {
							return `${name}-current.log`;
						}

						let filename = time.toISOString().slice(0, 10);
						if (index > 1) {
							filename += `.${index}`;
						}

						return `${name}-${filename}.log.gz`;
					},
					{
						path: './logs',
						initialRotation: true,
						interval: '1d',
						maxSize: '100M',
						maxFiles: 10,
						compress: 'gzip',
					}
				),
			],
		}),
		PrismaModule.forRoot({
			isGlobal: true,
			prismaServiceOptions: {
				prismaOptions: {
					log: [
						{ emit: 'stdout', level: 'query' },
						{ emit: 'stdout', level: 'info' },
						{ emit: 'stdout', level: 'warn' },
						{ emit: 'stdout', level: 'error' },
					],
				},
				middlewares: [
					loggingMiddleware({
						logger: new Logger('PrismaMiddleware'),
						logLevel: 'log', // default is `debug`
						logMessage: (query: QueryInfo) =>
							`[Prisma Query] ${query.model}.${query.action} - ${query.executionTime}ms`,
					}),
				],
			},
		}),
		AuthModule,
		UserModule,
		SettingsModule,
		RoleModule,
		SessionModule,
		ApiKeyModule,
	],
	providers: [
		TasksService,
		providePrismaClientExceptionFilter({
			// Prisma Error Code: HTTP Status Response
			P2000: HttpStatus.BAD_REQUEST,
			P2001: HttpStatus.NOT_FOUND,
			P2002: HttpStatus.CONFLICT,
			P2003: HttpStatus.BAD_REQUEST,
			P2025: HttpStatus.NOT_FOUND,
		}),
	],
})
export class AppModule {}
