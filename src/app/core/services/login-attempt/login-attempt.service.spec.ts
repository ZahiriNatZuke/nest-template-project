import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { HttpException, HttpStatus } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import {
	BRUTE_FORCE_CONFIG,
	LoginAttemptService,
} from './login-attempt.service';

describe('LoginAttemptService', () => {
	let service: LoginAttemptService;
	let _prismaService: PrismaService;

	const mockPrismaService = {
		loginAttempt: {
			create: jest.fn(),
			count: jest.fn(),
			deleteMany: jest.fn(),
		},
	};

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				LoginAttemptService,
				{
					provide: PrismaService,
					useValue: mockPrismaService,
				},
			],
		}).compile();

		service = module.get<LoginAttemptService>(LoginAttemptService);
		_prismaService = module.get<PrismaService>(PrismaService);

		jest.clearAllMocks();
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	describe('recordFailedAttempt', () => {
		it('should record a failed login attempt', async () => {
			mockPrismaService.loginAttempt.create.mockResolvedValue({
				id: '1',
				identifier: 'user@example.com',
				ipAddress: '192.168.1.100',
				userAgent: 'Chrome',
				success: false,
				createdAt: new Date(),
			});

			await service.recordFailedAttempt({
				identifier: 'user@example.com',
				ipAddress: '192.168.1.100',
				userAgent: 'Chrome',
			});

			expect(mockPrismaService.loginAttempt.create).toHaveBeenCalledWith({
				data: {
					identifier: 'user@example.com',
					ipAddress: '192.168.1.100',
					userAgent: 'Chrome',
					success: false,
				},
			});
		});
	});

	describe('recordSuccessfulAttempt', () => {
		it('should record a successful login attempt', async () => {
			mockPrismaService.loginAttempt.create.mockResolvedValue({
				id: '1',
				identifier: 'user@example.com',
				ipAddress: '192.168.1.100',
				success: true,
				createdAt: new Date(),
			});

			await service.recordSuccessfulAttempt({
				identifier: 'user@example.com',
				ipAddress: '192.168.1.100',
			});

			expect(mockPrismaService.loginAttempt.create).toHaveBeenCalledWith({
				data: {
					identifier: 'user@example.com',
					ipAddress: '192.168.1.100',
					userAgent: undefined,
					success: true,
				},
			});
		});
	});

	describe('isBlocked', () => {
		it('should return false if attempts are below threshold', async () => {
			mockPrismaService.loginAttempt.count.mockResolvedValue(2);

			const isBlocked = await service.isBlocked('user@example.com');

			expect(isBlocked).toBe(false);
		});

		it('should return true if attempts exceed threshold', async () => {
			mockPrismaService.loginAttempt.count.mockResolvedValue(
				BRUTE_FORCE_CONFIG.MAX_ATTEMPTS
			);

			const isBlocked = await service.isBlocked('user@example.com');

			expect(isBlocked).toBe(true);
		});

		it('should return true if attempts are at max threshold', async () => {
			mockPrismaService.loginAttempt.count.mockResolvedValue(5);

			const isBlocked = await service.isBlocked('user@example.com');

			expect(isBlocked).toBe(true);
		});

		it('should query with correct time window', async () => {
			mockPrismaService.loginAttempt.count.mockResolvedValue(0);

			await service.isBlocked('user@example.com');

			const callArgs = mockPrismaService.loginAttempt.count.mock.calls[0][0];
			expect(callArgs.where.createdAt.gte).toBeInstanceOf(Date);
		});
	});

	describe('isIPBlocked', () => {
		it('should return false if IP attempts are below threshold', async () => {
			mockPrismaService.loginAttempt.count.mockResolvedValue(2);

			const isBlocked = await service.isIPBlocked('192.168.1.100');

			expect(isBlocked).toBe(false);
		});

		it('should return true if IP attempts exceed threshold', async () => {
			mockPrismaService.loginAttempt.count.mockResolvedValue(
				BRUTE_FORCE_CONFIG.MAX_ATTEMPTS + 1
			);

			const isBlocked = await service.isIPBlocked('192.168.1.100');

			expect(isBlocked).toBe(true);
		});
	});

	describe('getFailedAttemptCount', () => {
		it('should return count of failed attempts', async () => {
			mockPrismaService.loginAttempt.count.mockResolvedValue(3);

			const count = await service.getFailedAttemptCount('user@example.com');

			expect(count).toBe(3);
		});

		it('should return 0 on error', async () => {
			mockPrismaService.loginAttempt.count.mockRejectedValue(
				new Error('DB error')
			);

			const count = await service.getFailedAttemptCount('user@example.com');

			expect(count).toBe(0);
		});
	});

	describe('cleanupOldAttempts', () => {
		it('should delete old attempts', async () => {
			mockPrismaService.loginAttempt.deleteMany.mockResolvedValue({
				count: 10,
			});

			const deletedCount = await service.cleanupOldAttempts();

			expect(deletedCount).toBe(10);
			expect(mockPrismaService.loginAttempt.deleteMany).toHaveBeenCalled();
		});

		it('should return 0 on error', async () => {
			mockPrismaService.loginAttempt.deleteMany.mockRejectedValue(
				new Error('DB error')
			);

			const deletedCount = await service.cleanupOldAttempts();

			expect(deletedCount).toBe(0);
		});
	});

	describe('unlockIdentifier', () => {
		it('should delete failed attempts for identifier', async () => {
			mockPrismaService.loginAttempt.deleteMany.mockResolvedValue({
				count: 5,
			});

			await service.unlockIdentifier('user@example.com');

			expect(mockPrismaService.loginAttempt.deleteMany).toHaveBeenCalledWith({
				where: {
					identifier: 'user@example.com',
					success: false,
				},
			});
		});
	});

	describe('validateLoginAttempt', () => {
		it('should throw if identifier is blocked', async () => {
			mockPrismaService.loginAttempt.count
				.mockResolvedValueOnce(BRUTE_FORCE_CONFIG.MAX_ATTEMPTS) // isBlocked
				.mockResolvedValueOnce(2); // isIPBlocked

			await expect(
				service.validateLoginAttempt('user@example.com', '192.168.1.100')
			).rejects.toThrow(HttpException);
		});

		it('should throw if IP is blocked', async () => {
			mockPrismaService.loginAttempt.count
				.mockResolvedValueOnce(2) // isBlocked
				.mockResolvedValueOnce(BRUTE_FORCE_CONFIG.MAX_ATTEMPTS); // isIPBlocked

			await expect(
				service.validateLoginAttempt('user@example.com', '192.168.1.100')
			).rejects.toThrow(HttpException);
		});

		it('should not throw if both identifier and IP are not blocked', async () => {
			mockPrismaService.loginAttempt.count
				.mockResolvedValueOnce(2) // isBlocked
				.mockResolvedValueOnce(2); // isIPBlocked

			await expect(
				service.validateLoginAttempt('user@example.com', '192.168.1.100')
			).resolves.not.toThrow();
		});

		it('should return TOO_MANY_REQUESTS status', async () => {
			mockPrismaService.loginAttempt.count.mockResolvedValue(
				BRUTE_FORCE_CONFIG.MAX_ATTEMPTS
			);

			try {
				await service.validateLoginAttempt('user@example.com', '192.168.1.100');
				fail('Should have thrown');
			} catch (error) {
				expect(error.getStatus()).toBe(HttpStatus.TOO_MANY_REQUESTS);
			}
		});
	});

	describe('BRUTE_FORCE_CONFIG', () => {
		it('should have appropriate configuration', () => {
			expect(BRUTE_FORCE_CONFIG.MAX_ATTEMPTS).toBe(5);
			expect(BRUTE_FORCE_CONFIG.WINDOW_MINUTES).toBe(15);
			expect(BRUTE_FORCE_CONFIG.LOCKOUT_MINUTES).toBe(30);
		});
	});
});
