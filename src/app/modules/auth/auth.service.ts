import { LoginAttemptService } from '@app/core/services/login-attempt/login-attempt.service';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { SafeUser, ValidatedUser } from '@app/core/types/app-request';
import { ZodValidationException } from '@app/core/utils/zod';
import { envs } from '@app/env';
import { RecoveryAccountDto } from '@app/modules/auth/dto/recovery-account.dto';
import { RequestRecoveryAccountZodDto } from '@app/modules/auth/dto/request-recovery-account.dto';
import { UpdatePasswordZodDto } from '@app/modules/auth/dto/update-password.dto';
import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { pick } from 'lodash';
import { v4 } from 'uuid';
import { z } from 'zod';
import { UserMapper } from '../user/user.mapper';
import type { UserService } from '../user/user.service';
import { JWTPayload } from './interface/jwt.payload';

@Injectable()
export class AuthService {
	private readonly logger = new Logger(AuthService.name);

	constructor(
		private prisma: PrismaService,
		private jwtService: JwtService,
		private userMapper: UserMapper,
		private moduleRef: ModuleRef,
		private loginAttemptService: LoginAttemptService
	) {}

	async validateUser(
		identifier: string,
		pass: string,
		ipAddress?: string,
		userAgent?: string
	): Promise<ValidatedUser> {
		try {
			// ✅ BRUTE FORCE PROTECTION: Validar que el usuario/IP no esté bloqueado
			if (ipAddress && userAgent) {
				await this.loginAttemptService.validateLoginAttempt(
					identifier,
					ipAddress
				);
			}

			const user: User = await this.prisma.user.findFirstOrThrow({
				where: {
					OR: [{ email: identifier }, { username: identifier }],
				},
				take: 1,
			});

			const passwordMatch = await bcrypt.compare(pass, user.password ?? '');

			if (user.confirmed && !user.blocked && passwordMatch) {
				// ✅ Registrar intento exitoso
				if (ipAddress && userAgent) {
					await this.loginAttemptService.recordSuccessfulAttempt({
						identifier,
						ipAddress,
						userAgent,
					});
				}

				return {
					status: true,
					user: this.userMapper.omitDefault(user),
				};
			}

			// ✅ Registrar intento fallido
			if (ipAddress && userAgent) {
				await this.loginAttemptService.recordFailedAttempt({
					identifier,
					ipAddress,
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
			// Si es error de brute force o bloqueado, re-lanzar
			if (error instanceof HttpException) {
				throw error;
			}

			// Registrar intento fallido antes de lanzar excepción genérica
			if (ipAddress && userAgent) {
				try {
					await this.loginAttemptService.recordFailedAttempt({
						identifier,
						ipAddress,
						userAgent,
					});
				} catch (e) {
					this.logger.error('Error recording failed attempt', e);
				}
			}

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
		// Resolver permisos del usuario
		const userRoles = await this.prisma.userRole.findMany({
			where: { userId: user.id },
			include: {
				role: {
					include: {
						rolePermissions: { include: { permission: true } },
					},
				},
			},
		});
		const perm = Array.from(
			new Set(
				userRoles.flatMap(ur =>
					ur.role.rolePermissions.map(rp => rp.permission.identifier)
				)
			)
		);

		const data: JWTPayload = {
			userId: user.id,
			device,
			email: user.email,
			fullName: user.fullName,
			perm,
		};

		const accessToken = this.jwtService.sign(data);
		const refreshToken = this.jwtService.sign(data, {
			secret: envs.JWT_REFRESH_TOKEN_SECRET,
			expiresIn: '1d',
		});

		// Check existing session for (userId, device)
		const existing = await this.prisma.session.findUnique({
			where: { userId_device: { userId: user.id, device } },
		});

		if (existing) {
			// Blacklist old tokens
			await this.blacklistToken(existing.accessToken, 8);
			await this.blacklistToken(existing.refreshToken, 24);

			return this.prisma.session.update({
				where: { id: existing.id },
				data: {
					accessToken,
					refreshToken,
					// Actualizar IP y User-Agent solo si se proporcionan
					...(ipAddress && { ipAddress }),
					...(userAgent && { userAgent }),
				},
			});
		}

		return this.prisma.session.create({
			data: {
				userId: user.id,
				device,
				accessToken,
				refreshToken,
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
			// Verificar que el token no esté en blacklist
			const blacklisted = await this.isTokenBlacklisted(refreshToken);
			if (blacklisted) {
				// Reuse detection: invalidar todas las sesiones del usuario
				const session = await this.prisma.session.findUnique({
					where: { refreshToken },
				});
				if (session) {
					await this.invalidateAllUserSessions(session.userId);
				}
				return null;
			}

			const currentSession = await this.prisma.session.findUniqueOrThrow({
				where: { refreshToken },
			});

			// Validar IP y User-Agent si están disponibles
			if (
				requestIpAddress &&
				requestUserAgent &&
				currentSession.ipAddress &&
				currentSession.userAgent
			) {
				const { isSimilarIP, isSimilarUserAgent } = await import(
					'@app/core/utils/request-info'
				);

				const ipMatch = isSimilarIP(currentSession.ipAddress, requestIpAddress);
				const uaMatch = isSimilarUserAgent(
					currentSession.userAgent,
					requestUserAgent
				);

				if (!ipMatch || !uaMatch) {
					// Posible session hijacking - invalidar sesión
					Logger.warn(
						`Refresh token validation failed for session ${currentSession.id}. ` +
							`IP match: ${ipMatch}, UA match: ${uaMatch}`,
						'AuthService'
					);

					// Invalidar esta sesión sospechosa
					await this.closeSession(currentSession.accessToken);
					return null;
				}
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

			const newAccessToken = this.jwtService.sign(data);
			const newRefreshToken = this.jwtService.sign(data, {
				secret: envs.JWT_REFRESH_TOKEN_SECRET,
				expiresIn: '1d',
			});

			// Blacklist old tokens
			await this.blacklistToken(currentSession.accessToken, 8);
			await this.blacklistToken(currentSession.refreshToken, 24);

			const session = await this.prisma.session.update({
				where: { id: currentSession.id },
				data: {
					accessToken: newAccessToken,
					refreshToken: newRefreshToken,
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

			// Blacklist both tokens
			await this.blacklistToken(session.accessToken, 8);
			await this.blacklistToken(session.refreshToken, 24);

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

	async updatePassword(dto: UpdatePasswordZodDto, user: User) {
		const userDb = await this.prisma.user.findUniqueOrThrow({
			where: { id: user.id },
		});

		if (!(await bcrypt.compare(dto.current_password, user.password)))
			throw new ZodValidationException(
				new z.ZodError([
					{
						code: 'custom',
						path: [],
						message: 'Current password miss match',
					},
				])
			);

		if (dto.new_password !== dto.confirm_new_password) {
			throw new ZodValidationException(
				new z.ZodError([
					{
						code: 'custom',
						path: [],
						message: 'Passwords not match',
					},
				])
			);
		}

		const newPassword = await bcrypt.hash(
			dto.new_password,
			bcrypt.genSaltSync(16)
		);

		// Invalidar todas las sesiones del usuario
		await this.invalidateAllUserSessions(user.id);

		return this.prisma.user.update({
			where: { id: userDb.id },
			data: { password: newPassword },
		});
	}

	async recoverAccount({
		email,
		newPassword,
		confirmNewPassword,
	}: RecoveryAccountDto) {
		if (newPassword !== confirmNewPassword) {
			throw new ZodValidationException(
				new z.ZodError([
					{
						code: 'custom',
						path: [],
						message: 'Passwords not match',
					},
				])
			);
		}

		try {
			const userDb = await this.prisma.user.findUniqueOrThrow({
				where: { email },
			});

			return this.prisma.user.update({
				where: { id: userDb.id },
				data: {
					password: await bcrypt.hash(newPassword, bcrypt.genSaltSync(16)),
				},
			});
		} catch (_) {
			throw new ZodValidationException(
				new z.ZodError([
					{
						code: 'custom',
						path: [],
						message: 'Recovery account process failure',
					},
				])
			);
		}
	}

	async requestRecoveryAccount(dto: RequestRecoveryAccountZodDto) {
		try {
			// Lazy load UserService only when needed
			const userService = this.moduleRef.get('UserService', {
				strict: false,
			}) as UserService;
			const user = await userService?.findOne({ email: dto.email }, true);

			if (!user) {
				throw new ZodValidationException(
					new z.ZodError([
						{
							code: 'custom',
							path: [],
							message: 'Request for recovery account failure',
						},
					])
				);
			}

			const payload = pick(user, ['name', 'lastname', 'email', 'id']);
			const token = this.jwtService.sign(
				{ ...payload, xhr: v4() },
				{
					secret: envs.JWT_VERIFICATION_TOKEN_SECRET,
					expiresIn: '30m',
				}
			);
			const url = `${envs.RECOVERY_ACCOUNT_URL}?token=${token}&email=${dto.email}`;

			new Logger(AuthService.name).debug(`>> [recovery-url]: ${url}`);
		} catch (_e) {
			throw new ZodValidationException(
				new z.ZodError([
					{
						code: 'custom',
						path: [],
						message: 'Request for recovery account failure',
					},
				])
			);
		}
	}

	async decodeVerificationToken(token: string): Promise<boolean> {
		try {
			const payload = await this.jwtService.verify(token, {
				secret: envs.JWT_VERIFICATION_TOKEN_SECRET,
			});

			return typeof payload === 'object' && 'xhr' in payload;
		} catch (error) {
			if (error?.name === 'TokenExpiredError') {
				throw new ZodValidationException(
					new z.ZodError([
						{
							code: 'custom',
							path: [],
							message: 'Recovered process expired, you must restart process',
						},
					])
				);
			}
			throw new ZodValidationException(
				new z.ZodError([
					{
						code: 'custom',
						path: [],
						message: 'Verification of recovery process failure',
					},
				])
			);
		}
	}

	private async blacklistToken(token: string, expiresInHours: number) {
		const expiresAt = new Date();
		expiresAt.setHours(expiresAt.getHours() + expiresInHours);
		await this.prisma.tokenBlacklist.create({
			data: { token, expiresAt },
		});
	}

	private async isTokenBlacklisted(token: string): Promise<boolean> {
		const entry = await this.prisma.tokenBlacklist.findUnique({
			where: { token },
		});
		if (!entry) return false;
		// Verificar si aún no expiró
		return entry.expiresAt > new Date();
	}

	public async invalidateAllUserSessions(userId: string) {
		const sessions = await this.prisma.session.findMany({
			where: { userId },
		});
		for (const session of sessions) {
			await this.blacklistToken(session.accessToken, 8);
			await this.blacklistToken(session.refreshToken, 24);
		}
		await this.prisma.session.deleteMany({ where: { userId } });
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
}
