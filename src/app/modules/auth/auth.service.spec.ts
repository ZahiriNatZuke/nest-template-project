import { LoginAttemptService } from '@app/core/services/login-attempt/login-attempt.service';
import { NotificationService } from '@app/core/services/notification/notification.service';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { ZodValidationException } from '@app/core/utils/zod';
import { HttpException, HttpStatus } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { buildSession, buildUser } from '@test/utils/factories';
import {
	asPrismaService,
	createPrismaMock,
	type PrismaMock,
} from '@test/utils/prisma-mock';
import * as bcrypt from 'bcrypt';
import { UserMapper } from '../user/user.mapper';
import { AuthService } from './auth.service';

jest.mock('bcrypt', () => ({
	compare: jest.fn(),
	hash: jest.fn(),
	genSaltSync: jest.fn(() => 'salt'),
}));

const mockedBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;

describe('AuthService', () => {
	let service: AuthService;
	let prisma: PrismaMock;
	let jwtService: { sign: jest.Mock; verify: jest.Mock };
	let loginAttempt: {
		validateLoginAttempt: jest.Mock;
		recordSuccessfulAttempt: jest.Mock;
		recordFailedAttempt: jest.Mock;
	};
	let moduleRef: { get: jest.Mock };

	const IP = '203.0.113.10';
	const UA = 'Mozilla/5.0 (jest)';

	beforeEach(async () => {
		prisma = createPrismaMock();
		jwtService = {
			sign: jest.fn((_payload, opts) => (opts ? 'refresh-jwt' : 'access-jwt')),
			verify: jest.fn(),
		};
		loginAttempt = {
			validateLoginAttempt: jest.fn().mockResolvedValue(undefined),
			recordSuccessfulAttempt: jest.fn().mockResolvedValue(undefined),
			recordFailedAttempt: jest.fn().mockResolvedValue(undefined),
		};
		moduleRef = { get: jest.fn() };

		const module: TestingModule = await Test.createTestingModule({
			providers: [
				AuthService,
				UserMapper,
				{ provide: PrismaService, useValue: asPrismaService(prisma) },
				{ provide: JwtService, useValue: jwtService },
				{ provide: ModuleRef, useValue: moduleRef },
				{ provide: LoginAttemptService, useValue: loginAttempt },
				{ provide: NotificationService, useValue: {} },
			],
		}).compile();

		service = module.get<AuthService>(AuthService);

		mockedBcrypt.hash.mockResolvedValue('hashed-password' as never);
		prisma.tokenBlacklist.create.mockResolvedValue({});
	});

	describe('validateUser', () => {
		it('returns the safe user on matching credentials', async () => {
			const user = buildUser();
			prisma.user.findFirstOrThrow.mockResolvedValue(user);
			mockedBcrypt.compare.mockResolvedValue(true as never);

			const result = await service.validateUser('a@b.c', 'pw', IP, UA);

			expect(result.status).toBe(true);
			expect(result.user).toMatchObject({ id: user.id, email: user.email });
		});

		// The mapper strips everything a caller should never see; a regression
		// here leaks the password hash straight into the login response body.
		it('never returns the password or the reset tokens', async () => {
			prisma.user.findFirstOrThrow.mockResolvedValue(
				buildUser({
					resetPasswordToken: 'secret-reset',
					confirmationToken: 'secret-confirm',
				})
			);
			mockedBcrypt.compare.mockResolvedValue(true as never);

			const { user } = await service.validateUser('a@b.c', 'pw', IP, UA);

			expect(user).not.toHaveProperty('password');
			expect(user).not.toHaveProperty('resetPasswordToken');
			expect(user).not.toHaveProperty('confirmationToken');
			expect(user).not.toHaveProperty('deletedAt');
		});

		it('looks the user up by email or username, excluding soft-deleted rows', async () => {
			prisma.user.findFirstOrThrow.mockResolvedValue(buildUser());
			mockedBcrypt.compare.mockResolvedValue(true as never);

			await service.validateUser('someone', 'pw');

			expect(prisma.user.findFirstOrThrow).toHaveBeenCalledWith({
				where: {
					deletedAt: null,
					OR: [{ email: 'someone' }, { username: 'someone' }],
				},
				take: 1,
			});
		});

		it('reports miss_activate for an unconfirmed but unblocked user', async () => {
			prisma.user.findFirstOrThrow.mockResolvedValue(
				buildUser({ confirmed: false, blocked: false })
			);
			mockedBcrypt.compare.mockResolvedValue(true as never);

			const result = await service.validateUser('a@b.c', 'pw', IP, UA);

			expect(result.status).toBe('miss_activate');
		});

		it('denies a blocked user even with the right password', async () => {
			prisma.user.findFirstOrThrow.mockResolvedValue(
				buildUser({ blocked: true })
			);
			mockedBcrypt.compare.mockResolvedValue(true as never);

			const result = await service.validateUser('a@b.c', 'pw', IP, UA);

			expect(result).toEqual({ user: null, status: false });
		});

		it('denies a wrong password', async () => {
			prisma.user.findFirstOrThrow.mockResolvedValue(buildUser());
			mockedBcrypt.compare.mockResolvedValue(false as never);

			const result = await service.validateUser('a@b.c', 'bad', IP, UA);

			expect(result.status).toBe(false);
		});

		it('throws 401 for an unknown user rather than leaking that it is unknown', async () => {
			prisma.user.findFirstOrThrow.mockRejectedValue(new Error('not found'));

			await expect(
				service.validateUser('ghost@b.c', 'pw', IP, UA)
			).rejects.toMatchObject({ status: HttpStatus.UNAUTHORIZED });
		});

		describe('brute force integration', () => {
			it('checks the lockout before touching the database', async () => {
				prisma.user.findFirstOrThrow.mockResolvedValue(buildUser());
				mockedBcrypt.compare.mockResolvedValue(true as never);

				await service.validateUser('a@b.c', 'pw', IP, UA);

				expect(loginAttempt.validateLoginAttempt).toHaveBeenCalledWith(
					'a@b.c',
					IP
				);
			});

			// Re-thrown as-is so the caller sees 429, not a generic 401.
			it('propagates the lockout exception untouched', async () => {
				const lockout = new HttpException(
					{ message: 'blocked' },
					HttpStatus.TOO_MANY_REQUESTS
				);
				loginAttempt.validateLoginAttempt.mockRejectedValue(lockout);

				await expect(service.validateUser('a@b.c', 'pw', IP, UA)).rejects.toBe(
					lockout
				);
			});

			it('records a success on a valid login', async () => {
				prisma.user.findFirstOrThrow.mockResolvedValue(buildUser());
				mockedBcrypt.compare.mockResolvedValue(true as never);

				await service.validateUser('a@b.c', 'pw', IP, UA);

				expect(loginAttempt.recordSuccessfulAttempt).toHaveBeenCalled();
				expect(loginAttempt.recordFailedAttempt).not.toHaveBeenCalled();
			});

			it('records a failure on a bad password', async () => {
				prisma.user.findFirstOrThrow.mockResolvedValue(buildUser());
				mockedBcrypt.compare.mockResolvedValue(false as never);

				await service.validateUser('a@b.c', 'bad', IP, UA);

				expect(loginAttempt.recordFailedAttempt).toHaveBeenCalled();
			});

			it('skips attempt tracking when IP and user agent are absent', async () => {
				prisma.user.findFirstOrThrow.mockResolvedValue(buildUser());
				mockedBcrypt.compare.mockResolvedValue(true as never);

				await service.validateUser('a@b.c', 'pw');

				expect(loginAttempt.validateLoginAttempt).not.toHaveBeenCalled();
				expect(loginAttempt.recordSuccessfulAttempt).not.toHaveBeenCalled();
			});
		});
	});

	describe('generateSession', () => {
		const safeUser = buildUser();

		beforeEach(() => {
			prisma.userRole.findMany.mockResolvedValue([
				{
					role: {
						rolePermissions: [
							{ permission: { identifier: 'users:read' } },
							{ permission: { identifier: 'users:write' } },
						],
					},
				},
			]);
			prisma.session.findUnique.mockResolvedValue(null);
			prisma.session.count.mockResolvedValue(0);
			prisma.session.create.mockResolvedValue(buildSession());
		});

		it('embeds the resolved permissions in the token payload', async () => {
			await service.generateSession(safeUser as never, 'web');

			expect(jwtService.sign).toHaveBeenCalledWith(
				expect.objectContaining({
					userId: safeUser.id,
					device: 'web',
					perm: ['users:read', 'users:write'],
				})
			);
		});

		it('de-duplicates a permission granted through two roles', async () => {
			prisma.userRole.findMany.mockResolvedValue([
				{ role: { rolePermissions: [{ permission: { identifier: 'a' } }] } },
				{ role: { rolePermissions: [{ permission: { identifier: 'a' } }] } },
			]);

			await service.generateSession(safeUser as never, 'web');

			expect(jwtService.sign).toHaveBeenCalledWith(
				expect.objectContaining({ perm: ['a'] })
			);
		});

		it('creates a session with the request context', async () => {
			await service.generateSession(safeUser as never, 'web', IP, UA);

			expect(prisma.session.create).toHaveBeenCalledWith({
				data: expect.objectContaining({
					userId: safeUser.id,
					device: 'web',
					ipAddress: IP,
					userAgent: UA,
					loginSessionId: expect.any(String),
				}),
			});
		});

		describe('session fixation protection', () => {
			it('rotates loginSessionId when reusing an existing device session', async () => {
				const existing = buildSession({ loginSessionId: 'old-login-id' });
				prisma.session.findUnique.mockResolvedValue(existing);
				prisma.session.update.mockResolvedValue(existing);

				await service.generateSession(safeUser as never, 'web');

				const data = prisma.session.update.mock.calls[0][0].data;
				expect(data.loginSessionId).toEqual(expect.any(String));
				expect(data.loginSessionId).not.toBe('old-login-id');
			});

			it('blacklists both previous tokens before reissuing', async () => {
				const existing = buildSession({
					accessToken: 'old-access',
					refreshToken: 'old-refresh',
				});
				prisma.session.findUnique.mockResolvedValue(existing);
				prisma.session.update.mockResolvedValue(existing);

				await service.generateSession(safeUser as never, 'web');

				const blacklisted = prisma.tokenBlacklist.create.mock.calls.map(
					c => c[0].data.token
				);
				expect(blacklisted).toEqual(['old-access', 'old-refresh']);
			});

			it('updates rather than creating a second row for the same device', async () => {
				const existing = buildSession();
				prisma.session.findUnique.mockResolvedValue(existing);
				prisma.session.update.mockResolvedValue(existing);

				await service.generateSession(safeUser as never, 'web');

				expect(prisma.session.update).toHaveBeenCalled();
				expect(prisma.session.create).not.toHaveBeenCalled();
			});
		});

		describe('concurrent session limit', () => {
			// MAX_CONCURRENT_SESSIONS is 5 in .env.test.
			it('evicts the oldest session once the limit is reached', async () => {
				const oldest = buildSession({
					id: 'oldest',
					accessToken: 'oldest-access',
					refreshToken: 'oldest-refresh',
				});
				prisma.session.count.mockResolvedValue(5);
				prisma.session.findFirst.mockResolvedValue(oldest);
				prisma.session.delete.mockResolvedValue(oldest);

				await service.generateSession(safeUser as never, 'web');

				expect(prisma.session.findFirst).toHaveBeenCalledWith({
					where: { userId: safeUser.id },
					orderBy: { createdAt: 'asc' },
				});
				expect(prisma.session.delete).toHaveBeenCalledWith({
					where: { id: 'oldest' },
				});
				expect(
					prisma.tokenBlacklist.create.mock.calls.map(c => c[0].data.token)
				).toEqual(['oldest-access', 'oldest-refresh']);
			});

			it('does not evict below the limit', async () => {
				prisma.session.count.mockResolvedValue(4);

				await service.generateSession(safeUser as never, 'web');

				expect(prisma.session.delete).not.toHaveBeenCalled();
			});
		});
	});

	describe('refreshSession', () => {
		const currentSession = buildSession({
			accessToken: 'current-access',
			refreshToken: 'current-refresh',
			ipAddress: IP,
			userAgent: UA,
		});

		beforeEach(() => {
			prisma.tokenBlacklist.findUnique.mockResolvedValue(null);
			prisma.session.findUniqueOrThrow.mockResolvedValue(currentSession);
			prisma.session.update.mockResolvedValue(currentSession);
			prisma.user.findUniqueOrThrow.mockResolvedValue({
				...buildUser({ id: currentSession.userId }),
				userRoles: [
					{ role: { rolePermissions: [{ permission: { identifier: 'x' } }] } },
				],
			});
		});

		it('issues new tokens and returns the session with its user', async () => {
			const result = await service.refreshSession('current-refresh', IP, UA);

			expect(result).not.toBeNull();
			expect(prisma.session.update).toHaveBeenCalledWith({
				where: { id: currentSession.id },
				data: expect.objectContaining({
					accessToken: 'access-jwt',
					refreshToken: 'refresh-jwt',
				}),
			});
		});

		it('blacklists the tokens it is replacing', async () => {
			await service.refreshSession('current-refresh', IP, UA);

			expect(
				prisma.tokenBlacklist.create.mock.calls.map(c => c[0].data.token)
			).toEqual(['current-access', 'current-refresh']);
		});

		// Presenting an already-rotated refresh token means it leaked, so every
		// session for that user is torn down rather than just this one.
		describe('reuse detection', () => {
			it('invalidates every session of the user and returns null', async () => {
				prisma.tokenBlacklist.findUnique.mockResolvedValue({
					expiresAt: new Date(Date.now() + 3_600_000),
				});
				prisma.session.findUnique.mockResolvedValue(currentSession);
				prisma.session.findMany.mockResolvedValue([
					buildSession({ accessToken: 'a1', refreshToken: 'r1' }),
					buildSession({ accessToken: 'a2', refreshToken: 'r2' }),
				]);
				prisma.session.deleteMany.mockResolvedValue({ count: 2 });

				await expect(
					service.refreshSession('current-refresh', IP, UA)
				).resolves.toBeNull();
				expect(prisma.session.deleteMany).toHaveBeenCalledWith({
					where: { userId: currentSession.userId },
				});
			});

			it('treats an expired blacklist entry as not blacklisted', async () => {
				prisma.tokenBlacklist.findUnique.mockResolvedValue({
					expiresAt: new Date(Date.now() - 1000),
				});

				await expect(
					service.refreshSession('current-refresh', IP, UA)
				).resolves.not.toBeNull();
			});
		});

		describe('hijack detection', () => {
			it('rejects a refresh from a different IP and user agent', async () => {
				prisma.session.delete.mockResolvedValue(currentSession);

				const result = await service.refreshSession(
					'current-refresh',
					'198.51.100.7',
					'curl/8.0'
				);

				expect(result).toBeNull();
			});

			it('skips the check when the stored session has no request context', async () => {
				prisma.session.findUniqueOrThrow.mockResolvedValue(
					buildSession({ ipAddress: null, userAgent: null })
				);

				await expect(
					service.refreshSession('current-refresh', '198.51.100.7', 'curl/8.0')
				).resolves.not.toBeNull();
			});
		});

		it('returns null for an unknown refresh token', async () => {
			prisma.session.findUniqueOrThrow.mockRejectedValue(new Error('none'));

			await expect(service.refreshSession('nope')).resolves.toBeNull();
		});
	});

	describe('closeSession', () => {
		it('blacklists both tokens and deletes the row', async () => {
			const session = buildSession({
				accessToken: 'a',
				refreshToken: 'r',
			});
			prisma.session.findUniqueOrThrow.mockResolvedValue(session);
			prisma.session.delete.mockResolvedValue(session);

			await expect(service.closeSession('a')).resolves.toBe(true);
			expect(
				prisma.tokenBlacklist.create.mock.calls.map(c => c[0].data.token)
			).toEqual(['a', 'r']);
			expect(prisma.session.delete).toHaveBeenCalledWith({
				where: { id: session.id },
			});
		});

		it('returns false for an unknown token instead of throwing', async () => {
			prisma.session.findUniqueOrThrow.mockRejectedValue(new Error('none'));

			await expect(service.closeSession('ghost')).resolves.toBe(false);
		});
	});

	describe('validateApiKey', () => {
		it('accepts a key matching any stored hash', async () => {
			prisma.apiKey.findMany.mockResolvedValue([
				{ keyHash: 'h1' },
				{ keyHash: 'h2' },
			]);
			mockedBcrypt.compare.mockImplementation(
				(async (_k: string, h: string) => h === 'h2') as never
			);

			await expect(service.validateApiKey('key')).resolves.toBe(true);
		});

		it('rejects a key matching nothing', async () => {
			prisma.apiKey.findMany.mockResolvedValue([{ keyHash: 'h1' }]);
			mockedBcrypt.compare.mockResolvedValue(false as never);

			await expect(service.validateApiKey('key')).resolves.toBe(false);
		});

		it('rejects when no API keys exist at all', async () => {
			prisma.apiKey.findMany.mockResolvedValue([]);

			await expect(service.validateApiKey('key')).resolves.toBe(false);
		});
	});

	describe('updatePassword', () => {
		const user = buildUser();
		const dto = {
			current_password: 'old',
			new_password: 'NewPassw0rd!',
			confirm_new_password: 'NewPassw0rd!',
		};

		beforeEach(() => {
			prisma.user.findUniqueOrThrow.mockResolvedValue(user);
			prisma.user.update.mockResolvedValue(user);
			prisma.session.findMany.mockResolvedValue([]);
			prisma.session.deleteMany.mockResolvedValue({ count: 0 });
		});

		it('hashes and stores the new password', async () => {
			mockedBcrypt.compare.mockResolvedValue(true as never);

			await service.updatePassword(dto as never, user as never);

			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: user.id },
				data: { password: 'hashed-password' },
			});
		});

		it('rejects a wrong current password', async () => {
			mockedBcrypt.compare.mockResolvedValue(false as never);

			await expect(
				service.updatePassword(dto as never, user as never)
			).rejects.toBeInstanceOf(ZodValidationException);
			expect(prisma.user.update).not.toHaveBeenCalled();
		});

		it('rejects when the confirmation does not match', async () => {
			mockedBcrypt.compare.mockResolvedValue(true as never);

			await expect(
				service.updatePassword(
					{ ...dto, confirm_new_password: 'Different!' } as never,
					user as never
				)
			).rejects.toBeInstanceOf(ZodValidationException);
			expect(prisma.user.update).not.toHaveBeenCalled();
		});

		// Changing a password has to log every other device out.
		it('invalidates all existing sessions', async () => {
			mockedBcrypt.compare.mockResolvedValue(true as never);
			prisma.session.findMany.mockResolvedValue([
				buildSession({ accessToken: 'a', refreshToken: 'r' }),
			]);

			await service.updatePassword(dto as never, user as never);

			expect(prisma.session.deleteMany).toHaveBeenCalledWith({
				where: { userId: user.id },
			});
			expect(
				prisma.tokenBlacklist.create.mock.calls.map(c => c[0].data.token)
			).toEqual(['a', 'r']);
		});
	});

	describe('forgotPassword', () => {
		it('stores a reset token with a 15 minute expiry', async () => {
			jest.useFakeTimers().setSystemTime(new Date('2026-01-01T12:00:00.000Z'));
			const user = buildUser();
			prisma.user.findFirst.mockResolvedValue(user);
			prisma.user.update.mockResolvedValue(user);

			await service.forgotPassword({ email: user.email } as never);

			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: user.id },
				data: {
					resetPasswordToken: expect.any(String),
					resetPasswordExpiresAt: new Date('2026-01-01T12:15:00.000Z'),
				},
			});
			jest.useRealTimers();
		});

		it('rejects an unknown email', async () => {
			prisma.user.findFirst.mockResolvedValue(null);

			await expect(
				service.forgotPassword({ email: 'ghost@b.c' } as never)
			).rejects.toBeInstanceOf(ZodValidationException);
		});

		it('ignores soft-deleted users', async () => {
			prisma.user.findFirst.mockResolvedValue(null);

			await expect(
				service.forgotPassword({ email: 'gone@b.c' } as never)
			).rejects.toBeInstanceOf(ZodValidationException);
			expect(prisma.user.findFirst).toHaveBeenCalledWith({
				where: { email: 'gone@b.c', deletedAt: null },
			});
		});
	});

	describe('resetPassword', () => {
		const dto = {
			email: 'a@b.c',
			token: 'reset-token',
			newPassword: 'NewPassw0rd!',
		};

		it('requires an unexpired token bound to that email', async () => {
			prisma.user.findFirst.mockResolvedValue(null);

			await expect(service.resetPassword(dto as never)).rejects.toBeInstanceOf(
				ZodValidationException
			);
			expect(prisma.user.findFirst).toHaveBeenCalledWith({
				where: {
					email: dto.email,
					resetPasswordToken: dto.token,
					resetPasswordExpiresAt: { gt: expect.any(Date) },
					deletedAt: null,
				},
			});
		});

		it('stores the new password and clears the token', async () => {
			const user = buildUser();
			prisma.user.findFirst.mockResolvedValue(user);
			prisma.user.update.mockResolvedValue(user);
			prisma.session.findMany.mockResolvedValue([]);
			prisma.session.deleteMany.mockResolvedValue({ count: 0 });

			await service.resetPassword(dto as never);

			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: user.id },
				data: {
					password: 'hashed-password',
					resetPasswordToken: null,
					resetPasswordExpiresAt: null,
				},
			});
		});

		it('invalidates all sessions after a reset', async () => {
			const user = buildUser();
			prisma.user.findFirst.mockResolvedValue(user);
			prisma.user.update.mockResolvedValue(user);
			prisma.session.findMany.mockResolvedValue([]);
			prisma.session.deleteMany.mockResolvedValue({ count: 0 });

			await service.resetPassword(dto as never);

			expect(prisma.session.deleteMany).toHaveBeenCalledWith({
				where: { userId: user.id },
			});
		});
	});

	describe('confirmEmail', () => {
		it('marks the user confirmed and clears the token', async () => {
			const user = buildUser({ confirmed: false });
			prisma.user.findFirst.mockResolvedValue(user);
			prisma.user.update.mockResolvedValue(user);

			await service.confirmEmail({ token: 'confirm-token' } as never);

			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: user.id },
				data: {
					confirmed: true,
					confirmedAt: expect.any(Date),
					confirmationToken: null,
					confirmationTokenExpiresAt: null,
				},
			});
		});

		it('rejects an invalid or expired token', async () => {
			prisma.user.findFirst.mockResolvedValue(null);

			await expect(
				service.confirmEmail({ token: 'bad' } as never)
			).rejects.toBeInstanceOf(ZodValidationException);
		});
	});

	describe('recoverAccount', () => {
		it('rejects mismatched passwords before any lookup', async () => {
			await expect(
				service.recoverAccount({
					email: 'a@b.c',
					newPassword: 'One!',
					confirmNewPassword: 'Two!',
				} as never)
			).rejects.toBeInstanceOf(ZodValidationException);
			expect(prisma.user.findUniqueOrThrow).not.toHaveBeenCalled();
		});

		it('stores the hashed password for a known email', async () => {
			const user = buildUser();
			prisma.user.findUniqueOrThrow.mockResolvedValue(user);
			prisma.user.update.mockResolvedValue(user);

			await service.recoverAccount({
				email: user.email,
				newPassword: 'NewPassw0rd!',
				confirmNewPassword: 'NewPassw0rd!',
			} as never);

			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: user.id },
				data: { password: 'hashed-password' },
			});
		});

		it('reports a generic failure for an unknown email', async () => {
			prisma.user.findUniqueOrThrow.mockRejectedValue(new Error('none'));

			await expect(
				service.recoverAccount({
					email: 'ghost@b.c',
					newPassword: 'NewPassw0rd!',
					confirmNewPassword: 'NewPassw0rd!',
				} as never)
			).rejects.toBeInstanceOf(ZodValidationException);
		});
	});

	describe('decodeVerificationToken', () => {
		it('accepts a payload carrying the xhr claim', async () => {
			jwtService.verify.mockReturnValue({ xhr: 'uuid', email: 'a@b.c' });

			await expect(service.decodeVerificationToken('t')).resolves.toBe(true);
		});

		it('rejects a payload without the xhr claim', async () => {
			jwtService.verify.mockReturnValue({ email: 'a@b.c' });

			await expect(service.decodeVerificationToken('t')).resolves.toBe(false);
		});

		// ZodValidationException's own message is always "Validation failed"; the
		// caller-facing text lives in the wrapped ZodError, so that is what these
		// assert on.
		const issueMessages = async (promise: Promise<unknown>) => {
			try {
				await promise;
			} catch (error) {
				return (error as ZodValidationException).zodError.issues.map(
					i => i.message
				);
			}
			throw new Error('expected the call to reject');
		};

		it('reports expiry distinctly from a malformed token', async () => {
			jwtService.verify.mockImplementation(() => {
				const error = new Error('jwt expired');
				error.name = 'TokenExpiredError';
				throw error;
			});

			await expect(
				issueMessages(service.decodeVerificationToken('t'))
			).resolves.toEqual([
				'Recovered process expired, you must restart process',
			]);
		});

		it('reports a generic failure for a malformed token', async () => {
			jwtService.verify.mockImplementation(() => {
				throw new Error('invalid signature');
			});

			await expect(
				issueMessages(service.decodeVerificationToken('t'))
			).resolves.toEqual(['Verification of recovery process failure']);
		});
	});

	describe('requestRecoveryAccount', () => {
		it('signs a recovery token for a known user', async () => {
			const userService = { findOne: jest.fn().mockResolvedValue(buildUser()) };
			moduleRef.get.mockReturnValue(userService);

			await service.requestRecoveryAccount({ email: 'a@b.c' } as never);

			expect(jwtService.sign).toHaveBeenCalledWith(
				expect.objectContaining({ xhr: expect.any(String) }),
				expect.objectContaining({ expiresIn: '30m' })
			);
		});

		it('reports failure for an unknown user', async () => {
			moduleRef.get.mockReturnValue({
				findOne: jest.fn().mockResolvedValue(null),
			});

			await expect(
				service.requestRecoveryAccount({ email: 'ghost@b.c' } as never)
			).rejects.toBeInstanceOf(ZodValidationException);
		});
	});

	describe('invalidateAllUserSessions', () => {
		it('blacklists every token then deletes every session', async () => {
			prisma.session.findMany.mockResolvedValue([
				buildSession({ accessToken: 'a1', refreshToken: 'r1' }),
				buildSession({ accessToken: 'a2', refreshToken: 'r2' }),
			]);
			prisma.session.deleteMany.mockResolvedValue({ count: 2 });

			await service.invalidateAllUserSessions('user-1');

			expect(
				prisma.tokenBlacklist.create.mock.calls.map(c => c[0].data.token)
			).toEqual(['a1', 'r1', 'a2', 'r2']);
			expect(prisma.session.deleteMany).toHaveBeenCalledWith({
				where: { userId: 'user-1' },
			});
		});

		it('still clears sessions when there are none to blacklist', async () => {
			prisma.session.findMany.mockResolvedValue([]);
			prisma.session.deleteMany.mockResolvedValue({ count: 0 });

			await service.invalidateAllUserSessions('user-1');

			expect(prisma.tokenBlacklist.create).not.toHaveBeenCalled();
			expect(prisma.session.deleteMany).toHaveBeenCalled();
		});
	});

	describe('getUserRolesWithPermissions', () => {
		it('returns the roles with their permissions expanded', async () => {
			const rows = [{ role: { rolePermissions: [] } }];
			prisma.userRole.findMany.mockResolvedValue(rows);

			await expect(service.getUserRolesWithPermissions('user-1')).resolves.toBe(
				rows
			);
			expect(prisma.userRole.findMany).toHaveBeenCalledWith({
				where: { userId: 'user-1' },
				include: {
					role: {
						include: { rolePermissions: { include: { permission: true } } },
					},
				},
			});
		});
	});
});
