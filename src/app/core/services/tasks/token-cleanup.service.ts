import { LoginAttemptService } from '@app/core/services/login-attempt/login-attempt.service';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';

@Injectable()
export class TokenCleanupService {
	private readonly logger = new Logger(TokenCleanupService.name);

	constructor(
		private prisma: PrismaService,
		private loginAttemptService: LoginAttemptService
	) {}

	@Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
	async cleanupExpiredTokens() {
		this.logger.log('Running cleanup of expired tokens in blacklist');

		const now = new Date();
		const result = await this.prisma.tokenBlacklist.deleteMany({
			where: {
				expiresAt: {
					lt: now,
				},
			},
		});

		this.logger.log(`Cleaned up ${result.count} expired tokens from blacklist`);
	}

	@Cron(CronExpression.EVERY_HOUR)
	async cleanupExpiredCsrfTokens() {
		this.logger.log('Running cleanup of expired CSRF tokens');

		const now = new Date();
		const result = await this.prisma.csrfToken.deleteMany({
			where: {
				expiresAt: {
					lt: now,
				},
			},
		});

		this.logger.log(`Cleaned up ${result.count} expired CSRF tokens`);
	}

	@Cron(CronExpression.EVERY_HOUR)
	async cleanupOldLoginAttempts() {
		this.logger.log('Running cleanup of old login attempts');

		const count = await this.loginAttemptService.cleanupOldAttempts();
		this.logger.log(`Cleaned up ${count} old login attempts`);
	}

	@Cron(CronExpression.EVERY_HOUR)
	async cleanupExpiredRolePermissions() {
		this.logger.log(
			'Running cleanup of expired role permissions (2.4 Temporary Permissions)'
		);

		const now = new Date();
		const result = await this.prisma.rolePermission.deleteMany({
			where: {
				expiresAt: {
					lt: now,
					not: null,
				},
			},
		});

		if (result.count > 0) {
			this.logger.log(`Cleaned up ${result.count} expired role permissions`);
		}
	}
}
