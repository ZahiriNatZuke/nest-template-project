import { ApiKeyValidationMiddleware } from '@app/core/middlewares/api-key-validation.middleware';
import { AuditModule } from '@app/core/services/audit/audit.module';
import { CsrfModule } from '@app/core/services/csrf/csrf.module';
import { LoginAttemptModule } from '@app/core/services/login-attempt/login-attempt.module';
import { PrismaModule } from '@app/core/services/prisma/prisma.module';
import { TasksService } from '@app/core/services/tasks/tasks.service';
import { TokenCleanupService } from '@app/core/services/tasks/token-cleanup.service';
import { envs } from '@app/env';
import { ApiKeyModule } from '@app/modules/api-key/api-key.module';
import { AuthModule } from '@app/modules/auth/auth.module';
import { HealthModule } from '@app/modules/health/health.module';
import { PermissionModule } from '@app/modules/permission/permission.module';
import { RoleModule } from '@app/modules/role/role.module';
import { SessionModule } from '@app/modules/session/session.module';
import { SettingsModule } from '@app/modules/settings/settings.module';
import { UserModule } from '@app/modules/user/user.module';
import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { LoggerModule } from 'nestjs-pino';
import { createStream } from 'rotating-file-stream';

@Module({
	imports: [
		PrismaModule,
		AuditModule,
		CsrfModule,
		LoginAttemptModule,
		ScheduleModule.forRoot(),
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
		AuthModule,
		UserModule,
		SettingsModule,
		RoleModule,
		PermissionModule,
		SessionModule,
		ApiKeyModule,
		HealthModule,
	],
	providers: [TasksService, TokenCleanupService],
	exports: [],
})
export class AppModule implements NestModule {
	configure(consumer: MiddlewareConsumer) {
		consumer.apply(ApiKeyValidationMiddleware).forRoutes('api/v1/*');
	}
}
