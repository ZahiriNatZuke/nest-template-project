import { randomBytes } from 'node:crypto';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class CsrfService {
	private readonly logger = new Logger(CsrfService.name);

	constructor(private readonly prisma: PrismaService) {}

	async generateToken(): Promise<string> {
		const token = randomBytes(32).toString('hex');
		const expiresAt = new Date(Date.now() + 1000 * 60 * 60); // 1 hour

		try {
			await this.prisma.csrfToken.create({
				data: {
					token,
					expiresAt,
				},
			});

			this.logger.debug(`CSRF token generated: ${token.substring(0, 10)}...`);
			return token;
		} catch (error) {
			this.logger.error('Error generating CSRF token', error);
			throw error;
		}
	}

	async validateToken(token: string): Promise<boolean> {
		try {
			const entry = await this.prisma.csrfToken.findUnique({
				where: { token },
			});

			if (!entry) {
				this.logger.warn(`CSRF token not found: ${token.substring(0, 10)}...`);
				return false;
			}

			const now = new Date();
			if (entry.expiresAt < now) {
				// Token expired, delete it
				await this.invalidateToken(token);
				this.logger.warn(`CSRF token expired: ${token.substring(0, 10)}...`);
				return false;
			}

			this.logger.debug(`CSRF token validated: ${token.substring(0, 10)}...`);
			return true;
		} catch (error) {
			this.logger.error('Error validating CSRF token', error);
			return false;
		}
	}

	async invalidateToken(token: string): Promise<void> {
		try {
			await this.prisma.csrfToken.delete({
				where: { token },
			});
			this.logger.debug(`CSRF token invalidated: ${token.substring(0, 10)}...`);
		} catch {
			// Token might not exist, that's okay
			this.logger.debug(
				`Could not invalidate CSRF token: ${token.substring(0, 10)}...`
			);
		}
	}
}
