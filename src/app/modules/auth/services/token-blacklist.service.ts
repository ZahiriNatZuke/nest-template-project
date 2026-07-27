import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Injectable } from '@nestjs/common';

/**
 * Owns token revocation.
 *
 * Extracted from AuthService because both the session flows and the password
 * flows need it: logging out, rotating a refresh token, changing a password
 * and resetting one all end with the same requirement — the tokens that came
 * before must stop working. Keeping it here means neither of those services
 * has to depend on the other.
 */
@Injectable()
export class TokenBlacklistService {
	constructor(private prisma: PrismaService) {}

	/**
	 * Revokes a token until `expiresInHours` from now.
	 *
	 * The window is per-token-kind rather than global: an access token only has
	 * to outlive its own 15-minute validity, a refresh token a full day.
	 */
	async blacklist(token: string, expiresInHours: number): Promise<void> {
		const expiresAt = new Date();
		expiresAt.setHours(expiresAt.getHours() + expiresInHours);
		await this.prisma.tokenBlacklist.create({
			data: { token, expiresAt },
		});
	}

	/** Revokes both halves of a session's token pair. */
	async blacklistSessionTokens(session: {
		accessToken: string;
		refreshToken: string;
	}): Promise<void> {
		await this.blacklist(session.accessToken, 8);
		await this.blacklist(session.refreshToken, 24);
	}

	/**
	 * A row that exists but has already expired does not count: the entry is
	 * only there until the token would have expired on its own.
	 */
	async isBlacklisted(token: string): Promise<boolean> {
		const entry = await this.prisma.tokenBlacklist.findUnique({
			where: { token },
		});
		if (!entry) return false;
		return entry.expiresAt > new Date();
	}

	/**
	 * Tears down every session a user has, revoking the tokens first so a
	 * request already in flight cannot slip through the gap between the
	 * blacklist write and the session delete.
	 */
	async invalidateAllUserSessions(userId: string): Promise<void> {
		const sessions = await this.prisma.session.findMany({ where: { userId } });
		for (const session of sessions) {
			await this.blacklistSessionTokens(session);
		}
		await this.prisma.session.deleteMany({ where: { userId } });
	}
}
