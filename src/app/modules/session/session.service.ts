import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Injectable, Logger } from '@nestjs/common';
import { Prisma, Session } from '@prisma/client';

@Injectable()
export class SessionService {
	private readonly logger = new Logger(SessionService.name);

	constructor(private prisma: PrismaService) {}

	async findMany(sessionWhereUniqueInput: Prisma.SessionWhereInput) {
		return this.prisma.session.findMany({
			where: sessionWhereUniqueInput,
		});
	}

	async findOne(
		sessionWhereUniqueInput: Prisma.SessionWhereUniqueInput,
		canThrow = false
	): Promise<Session | null> {
		if (canThrow)
			return this.prisma.session.findUniqueOrThrow({
				where: sessionWhereUniqueInput,
			});

		return this.prisma.session.findUnique({
			where: sessionWhereUniqueInput,
		});
	}

	async delete(where: Prisma.SessionWhereUniqueInput): Promise<Session> {
		return this.prisma.session.delete({ where });
	}

	/**
	 * SESSION FIXATION PROTECTION: Invalidate all sessions created before a specific timestamp
	 * This is useful when a user logs in to invalidate all previous sessions.
	 */
	async invalidateSessionsCreatedBefore(
		userId: string,
		timestamp: Date
	): Promise<number> {
		const result = await this.prisma.session.deleteMany({
			where: {
				userId,
				createdAt: {
					lt: timestamp,
				},
			},
		});

		if (result.count > 0) {
			this.logger.log(
				`Invalidated ${result.count} sessions for user ${userId} created before ${timestamp.toISOString()}`
			);
		}

		return result.count;
	}

	/**
	 * Update last activity timestamp for a session
	 */
	async updateLastActivity(sessionId: string): Promise<void> {
		await this.prisma.session.update({
			where: { id: sessionId },
			data: { lastActivityAt: new Date() },
		});
	}

	/**
	 * Get all active sessions for a user
	 */
	async getActiveSessionsByUserId(userId: string): Promise<Session[]> {
		return this.prisma.session.findMany({
			where: { userId },
			orderBy: { lastActivityAt: 'desc' },
		});
	}

	/**
	 * Validate that a session's loginSessionId matches
	 * This prevents session fixation attacks
	 */
	async validateLoginSessionId(
		sessionId: string,
		loginSessionId: string
	): Promise<boolean> {
		const session = await this.findOne({ id: sessionId });
		if (!session) {
			return false;
		}
		return session.loginSessionId === loginSessionId;
	}
}
