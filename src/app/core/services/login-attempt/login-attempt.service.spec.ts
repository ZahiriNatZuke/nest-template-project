import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { HttpStatus } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import {
	asPrismaService,
	createPrismaMock,
	type PrismaMock,
} from '@test/utils/prisma-mock';
import {
	BRUTE_FORCE_CONFIG,
	LoginAttemptService,
} from './login-attempt.service';

describe('LoginAttemptService', () => {
	let service: LoginAttemptService;
	let prisma: PrismaMock;

	const info = {
		identifier: 'user@test.local',
		ipAddress: '203.0.113.10',
		userAgent: 'jest-test-runner',
	};

	beforeEach(async () => {
		prisma = createPrismaMock();

		const module: TestingModule = await Test.createTestingModule({
			providers: [
				LoginAttemptService,
				{ provide: PrismaService, useValue: asPrismaService(prisma) },
			],
		}).compile();

		service = module.get<LoginAttemptService>(LoginAttemptService);
	});

	describe('recordFailedAttempt', () => {
		it('persists the attempt with success = false', async () => {
			prisma.loginAttempt.create.mockResolvedValue({});

			await service.recordFailedAttempt(info);

			expect(prisma.loginAttempt.create).toHaveBeenCalledWith({
				data: {
					identifier: info.identifier,
					ipAddress: info.ipAddress,
					userAgent: info.userAgent,
					success: false,
				},
			});
		});

		// Recording is best-effort: a logging failure must never break a login.
		it('swallows a database error instead of propagating it', async () => {
			prisma.loginAttempt.create.mockRejectedValue(new Error('db is down'));

			await expect(service.recordFailedAttempt(info)).resolves.toBeUndefined();
		});
	});

	describe('recordSuccessfulAttempt', () => {
		it('persists the attempt with success = true', async () => {
			prisma.loginAttempt.create.mockResolvedValue({});

			await service.recordSuccessfulAttempt(info);

			expect(prisma.loginAttempt.create).toHaveBeenCalledWith({
				data: {
					identifier: info.identifier,
					ipAddress: info.ipAddress,
					userAgent: info.userAgent,
					success: true,
				},
			});
		});

		it('swallows a database error instead of propagating it', async () => {
			prisma.loginAttempt.create.mockRejectedValue(new Error('db is down'));

			await expect(
				service.recordSuccessfulAttempt(info)
			).resolves.toBeUndefined();
		});
	});

	describe('isBlocked', () => {
		it('counts only failed attempts inside the configured window', async () => {
			jest.useFakeTimers().setSystemTime(new Date('2026-01-01T12:00:00.000Z'));
			prisma.loginAttempt.count.mockResolvedValue(0);

			await service.isBlocked(info.identifier);

			expect(prisma.loginAttempt.count).toHaveBeenCalledWith({
				where: {
					identifier: info.identifier,
					success: false,
					createdAt: {
						gte: new Date('2026-01-01T11:45:00.000Z'),
					},
				},
			});

			jest.useRealTimers();
		});

		it(`blocks at exactly ${BRUTE_FORCE_CONFIG.MAX_ATTEMPTS} failed attempts`, async () => {
			prisma.loginAttempt.count.mockResolvedValue(
				BRUTE_FORCE_CONFIG.MAX_ATTEMPTS
			);

			await expect(service.isBlocked(info.identifier)).resolves.toBe(true);
		});

		it('does not block one attempt below the threshold', async () => {
			prisma.loginAttempt.count.mockResolvedValue(
				BRUTE_FORCE_CONFIG.MAX_ATTEMPTS - 1
			);

			await expect(service.isBlocked(info.identifier)).resolves.toBe(false);
		});

		// Documented trade-off: availability over strictness. A database outage
		// must not lock every user out of the application.
		it('fails open when the database errors', async () => {
			prisma.loginAttempt.count.mockRejectedValue(new Error('db is down'));

			await expect(service.isBlocked(info.identifier)).resolves.toBe(false);
		});
	});

	describe('isIPBlocked', () => {
		it('counts failed attempts by IP rather than by identifier', async () => {
			jest.useFakeTimers().setSystemTime(new Date('2026-01-01T12:00:00.000Z'));
			prisma.loginAttempt.count.mockResolvedValue(0);

			await service.isIPBlocked(info.ipAddress);

			expect(prisma.loginAttempt.count).toHaveBeenCalledWith({
				where: {
					ipAddress: info.ipAddress,
					success: false,
					createdAt: {
						gte: new Date('2026-01-01T11:45:00.000Z'),
					},
				},
			});

			jest.useRealTimers();
		});

		it(`blocks at ${BRUTE_FORCE_CONFIG.MAX_ATTEMPTS} failed attempts`, async () => {
			prisma.loginAttempt.count.mockResolvedValue(
				BRUTE_FORCE_CONFIG.MAX_ATTEMPTS
			);

			await expect(service.isIPBlocked(info.ipAddress)).resolves.toBe(true);
		});

		it('fails open when the database errors', async () => {
			prisma.loginAttempt.count.mockRejectedValue(new Error('db is down'));

			await expect(service.isIPBlocked(info.ipAddress)).resolves.toBe(false);
		});
	});

	describe('getFailedAttemptCount', () => {
		it('returns the count from the database', async () => {
			prisma.loginAttempt.count.mockResolvedValue(3);

			await expect(
				service.getFailedAttemptCount(info.identifier)
			).resolves.toBe(3);
		});

		it('returns 0 when the database errors', async () => {
			prisma.loginAttempt.count.mockRejectedValue(new Error('db is down'));

			await expect(
				service.getFailedAttemptCount(info.identifier)
			).resolves.toBe(0);
		});
	});

	describe('cleanupOldAttempts', () => {
		it('deletes attempts older than the lockout window and returns the count', async () => {
			jest.useFakeTimers().setSystemTime(new Date('2026-01-01T12:00:00.000Z'));
			prisma.loginAttempt.deleteMany.mockResolvedValue({ count: 42 });

			await expect(service.cleanupOldAttempts()).resolves.toBe(42);
			expect(prisma.loginAttempt.deleteMany).toHaveBeenCalledWith({
				where: {
					createdAt: {
						lt: new Date('2026-01-01T11:30:00.000Z'),
					},
				},
			});

			jest.useRealTimers();
		});

		it('returns 0 when the database errors', async () => {
			prisma.loginAttempt.deleteMany.mockRejectedValue(new Error('db is down'));

			await expect(service.cleanupOldAttempts()).resolves.toBe(0);
		});
	});

	describe('unlockIdentifier', () => {
		it('deletes only the failed attempts for that identifier', async () => {
			prisma.loginAttempt.deleteMany.mockResolvedValue({ count: 5 });

			await service.unlockIdentifier(info.identifier);

			expect(prisma.loginAttempt.deleteMany).toHaveBeenCalledWith({
				where: { identifier: info.identifier, success: false },
			});
		});

		it('swallows a database error instead of propagating it', async () => {
			prisma.loginAttempt.deleteMany.mockRejectedValue(new Error('db is down'));

			await expect(
				service.unlockIdentifier(info.identifier)
			).resolves.toBeUndefined();
		});
	});

	describe('validateLoginAttempt', () => {
		it('resolves when neither the identifier nor the IP is blocked', async () => {
			prisma.loginAttempt.count.mockResolvedValue(0);

			await expect(
				service.validateLoginAttempt(info.identifier, info.ipAddress)
			).resolves.toBeUndefined();
		});

		it('throws 429 naming the identifier when the identifier is blocked', async () => {
			// First call is the identifier check, second is the IP check.
			prisma.loginAttempt.count
				.mockResolvedValueOnce(BRUTE_FORCE_CONFIG.MAX_ATTEMPTS)
				.mockResolvedValueOnce(0);

			await expect(
				service.validateLoginAttempt(info.identifier, info.ipAddress)
			).rejects.toMatchObject({
				status: HttpStatus.TOO_MANY_REQUESTS,
				response: {
					statusCode: HttpStatus.TOO_MANY_REQUESTS,
					message: `Too many failed login attempts. Try again in ${BRUTE_FORCE_CONFIG.LOCKOUT_MINUTES} minutes.`,
				},
			});
		});

		it('throws 429 naming the IP when only the IP is blocked', async () => {
			prisma.loginAttempt.count
				.mockResolvedValueOnce(0)
				.mockResolvedValueOnce(BRUTE_FORCE_CONFIG.MAX_ATTEMPTS);

			await expect(
				service.validateLoginAttempt(info.identifier, info.ipAddress)
			).rejects.toMatchObject({
				status: HttpStatus.TOO_MANY_REQUESTS,
				response: {
					message: `Too many login attempts from your IP. Try again in ${BRUTE_FORCE_CONFIG.LOCKOUT_MINUTES} minutes.`,
				},
			});
		});

		it('reports the identifier block first when both are blocked', async () => {
			prisma.loginAttempt.count.mockResolvedValue(
				BRUTE_FORCE_CONFIG.MAX_ATTEMPTS
			);

			await expect(
				service.validateLoginAttempt(info.identifier, info.ipAddress)
			).rejects.toMatchObject({
				response: {
					message: `Too many failed login attempts. Try again in ${BRUTE_FORCE_CONFIG.LOCKOUT_MINUTES} minutes.`,
				},
			});
		});
	});
});
