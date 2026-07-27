import { randomUUID } from 'node:crypto';
import { LoginAttemptService } from '@app/core/services/login-attempt/login-attempt.service';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { SafeUser, ValidatedUser } from '@app/core/types/app-request';
import { envs } from '@app/env';
import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { UserMapper } from '../user/user.mapper';
import { JWTPayload } from './interface/jwt.payload';
import { TokenBlacklistService } from './services/token-blacklist.service';

/**
 * Session authority: proving who a caller is, issuing their tokens, rotating
 * them and tearing them down.
 *
 * Password changes, recovery and email confirmation live in PasswordService;
 * token revocation lives in TokenBlacklistService.
 */
@Injectable()
export class AuthService {
	private readonly logger = new Logger(AuthService.name);

	constructor(
		private prisma: PrismaService,
		private jwtService: JwtService,
		private userMapper: UserMapper,
		private loginAttemptService: LoginAttemptService,
		private tokenBlacklist: TokenBlacklistService
	) {}

	async validateUser(
		identifier: string,
		pass: string,
		ipAddress?: string,
		userAgent?: string
	): Promise<ValidatedUser> {
		const trackAttempts = Boolean(ipAddress && userAgent);

		try {
			// ✅ BRUTE FORCE PROTECTION: Validar que el usuario/IP no esté bloqueado
			if (trackAttempts) {
				await this.loginAttemptService.validateLoginAttempt(
					identifier,
					ipAddress as string
				);
			}

			const user: User = await this.prisma.user.findFirstOrThrow({
				where: {
					deletedAt: null,
					OR: [{ email: identifier }, { username: identifier }],
				},
				take: 1,
			});

			const passwordMatch = await bcrypt.compare(pass, user.password ?? '');

			if (user.confirmed && !user.blocked && passwordMatch) {
				if (trackAttempts) {
					await this.loginAttemptService.recordSuccessfulAttempt({
						identifier,
						ipAddress: ipAddress as string,
						userAgent,
					});
				}

				return {
					status: true,
					user: this.userMapper.omitDefault(user),
				};
			}

			if (trackAttempts) {
				await this.loginAttemptService.recordFailedAttempt({
					identifier,
					ipAddress: ipAddress as string,
					userAgent,
				});
			}

			if (!user.blocked && !user.confirmed) {
				return {
					status: 'miss_activate',
					user: this.userMapper.omitDefault(user),
				};
			}

			return {
				user: null,
				status: false,
			};
		} catch (error) {
			// A lockout is a 429 and must reach the caller as one, not be
			// flattened into the generic 401 below.
			if (error instanceof HttpException) {
				throw error;
			}

			if (trackAttempts) {
				try {
					await this.loginAttemptService.recordFailedAttempt({
						identifier,
						ipAddress: ipAddress as string,
						userAgent,
					});
				} catch (e) {
					this.logger.error('Error recording failed attempt', e);
				}
			}

			// Deliberately identical to a wrong password: the response must not
			// reveal whether the account exists.
			throw new HttpException(
				{ message: 'Login Failure' },
				HttpStatus.UNAUTHORIZED
			);
		}
	}

	async generateSession(
		user: SafeUser,
		device: string,
		ipAddress?: string,
		userAgent?: string
	) {
		const perm = await this.resolvePermissions(user.id);

		const data: JWTPayload = {
			userId: user.id,
			device,
			email: user.email,
			fullName: user.fullName,
			perm,
		};

		const { accessToken, refreshToken } = this.signTokenPair(data);

		// Check existing session for (userId, device)
		const existing = await this.prisma.session.findUnique({
			where: { userId_device: { userId: user.id, device } },
		});

		// ✅ SESSION FIXATION PROTECTION: Generar nuevo loginSessionId
		const newLoginSessionId = randomUUID();

		if (existing) {
			await this.tokenBlacklist.blacklistSessionTokens(existing);

			// Regenerate session ID y invalidar la sesión anterior
			return this.prisma.session.update({
				where: { id: existing.id },
				data: {
					accessToken,
					refreshToken,
					loginSessionId: newLoginSessionId,
					lastActivityAt: new Date(),
					// Actualizar IP y User-Agent solo si se proporcionan
					...(ipAddress && { ipAddress }),
					...(userAgent && { userAgent }),
				},
			});
		}

		await this.evictOldestSessionIfAtLimit(user.id);

		return this.prisma.session.create({
			data: {
				userId: user.id,
				device,
				accessToken,
				refreshToken,
				loginSessionId: newLoginSessionId,
				lastActivityAt: new Date(),
				ipAddress,
				userAgent,
			},
		});
	}

	async refreshSession(
		refreshToken: string,
		requestIpAddress?: string,
		requestUserAgent?: string
	) {
		try {
			// A refresh token presented after it was rotated means it leaked, so
			// every session for that user goes, not just this one.
			const blacklisted = await this.tokenBlacklist.isBlacklisted(refreshToken);
			if (blacklisted) {
				const session = await this.prisma.session.findUnique({
					where: { refreshToken },
				});
				if (session) {
					await this.tokenBlacklist.invalidateAllUserSessions(session.userId);
				}
				return null;
			}

			const currentSession = await this.prisma.session.findUniqueOrThrow({
				where: { refreshToken },
			});

			if (
				!(await this.matchesSessionContext(
					currentSession,
					requestIpAddress,
					requestUserAgent
				))
			) {
				// Posible session hijacking - invalidar sesión
				await this.closeSession(currentSession.accessToken);
				return null;
			}

			const user = await this.prisma.user.findUniqueOrThrow({
				where: { id: currentSession.userId },
				include: {
					userRoles: {
						include: {
							role: {
								include: { rolePermissions: { include: { permission: true } } },
							},
						},
					},
				},
			});

			const perm = Array.from(
				new Set(
					user.userRoles.flatMap(ur =>
						ur.role.rolePermissions.map(rp => rp.permission.identifier)
					)
				)
			);

			const data: JWTPayload = {
				userId: currentSession.userId,
				device: currentSession.device,
				email: user.email,
				fullName: user.fullName,
				perm,
			};

			const { accessToken, refreshToken: newRefreshToken } =
				this.signTokenPair(data);

			await this.tokenBlacklist.blacklistSessionTokens(currentSession);

			const session = await this.prisma.session.update({
				where: { id: currentSession.id },
				data: {
					accessToken,
					refreshToken: newRefreshToken,
					lastActivityAt: new Date(),
				},
			});

			return { session, user };
		} catch (_) {
			return null;
		}
	}

	async closeSession(accessToken: string) {
		try {
			const session = await this.prisma.session.findUniqueOrThrow({
				where: { accessToken },
			});

			await this.tokenBlacklist.blacklistSessionTokens(session);

			await this.prisma.session.delete({
				where: { id: session.id },
			});

			return true;
		} catch (_) {
			return false;
		}
	}

	async validateApiKey(apikey: string) {
		const allKeys = await this.prisma.apiKey.findMany({
			select: { keyHash: true },
		});

		for (const k of allKeys) {
			if (await bcrypt.compare(apikey, k.keyHash)) {
				return true;
			}
		}
		return false;
	}

	async getUserRolesWithPermissions(userId: string) {
		return this.prisma.userRole.findMany({
			where: { userId },
			include: {
				role: {
					include: {
						rolePermissions: { include: { permission: true } },
					},
				},
			},
		});
	}

	/** Flattens every permission reachable through the user's roles. */
	private async resolvePermissions(userId: string): Promise<string[]> {
		const userRoles = await this.getUserRolesWithPermissions(userId);
		return Array.from(
			new Set(
				userRoles.flatMap(ur =>
					ur.role.rolePermissions.map(rp => rp.permission.identifier)
				)
			)
		);
	}

	private signTokenPair(data: JWTPayload) {
		return {
			accessToken: this.jwtService.sign(data),
			refreshToken: this.jwtService.sign(data, {
				secret: envs.JWT_REFRESH_TOKEN_SECRET,
				expiresIn: '1d',
			}),
		};
	}

	/**
	 * Enforces MAX_CONCURRENT_SESSIONS by dropping the oldest session, so a new
	 * sign-in is never refused — it just costs the least recently created one.
	 */
	private async evictOldestSessionIfAtLimit(userId: string): Promise<void> {
		const activeSessions = await this.prisma.session.count({
			where: { userId },
		});

		if (activeSessions < envs.MAX_CONCURRENT_SESSIONS) return;

		const oldestSession = await this.prisma.session.findFirst({
			where: { userId },
			orderBy: { createdAt: 'asc' },
		});

		if (!oldestSession) return;

		this.logger.warn(
			`User ${userId} reached max concurrent sessions (${envs.MAX_CONCURRENT_SESSIONS}). ` +
				`Removing oldest session: ${oldestSession.device}`
		);

		await this.tokenBlacklist.blacklistSessionTokens(oldestSession);
		await this.prisma.session.delete({ where: { id: oldestSession.id } });
	}

	/**
	 * Compares the request's origin against the one recorded when the session
	 * was created. Sessions stored without that context (older rows, or a
	 * request that carried neither header) skip the check rather than being
	 * rejected outright.
	 */
	private async matchesSessionContext(
		session: { id: string; ipAddress: string | null; userAgent: string | null },
		requestIpAddress?: string,
		requestUserAgent?: string
	): Promise<boolean> {
		if (
			!requestIpAddress ||
			!requestUserAgent ||
			!session.ipAddress ||
			!session.userAgent
		) {
			return true;
		}

		const { isSimilarIP, isSimilarUserAgent } = await import(
			'@app/core/utils/request-info'
		);

		const ipMatch = isSimilarIP(session.ipAddress, requestIpAddress);
		const uaMatch = isSimilarUserAgent(session.userAgent, requestUserAgent);

		if (!ipMatch || !uaMatch) {
			this.logger.warn(
				`Refresh token validation failed for session ${session.id}. ` +
					`IP match: ${ipMatch}, UA match: ${uaMatch}`
			);
			return false;
		}

		return true;
	}
}
