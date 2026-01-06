import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';

@Injectable()
export class TokenCleanupService {
	private readonly logger = new Logger(TokenCleanupService.name);

	constructor(private prisma: PrismaService) {}

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
}
