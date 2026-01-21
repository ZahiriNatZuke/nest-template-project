import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Test, TestingModule } from '@nestjs/testing';
import { CsrfService } from './csrf.service';

describe('CsrfService', () => {
	let service: CsrfService;
	let _prismaService: PrismaService;

	const mockPrismaService = {
		csrfToken: {
			create: jest.fn(),
			findUnique: jest.fn(),
			delete: jest.fn(),
		},
	};

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				CsrfService,
				{
					provide: PrismaService,
					useValue: mockPrismaService,
				},
			],
		}).compile();

		service = module.get<CsrfService>(CsrfService);
		_prismaService = module.get<PrismaService>(PrismaService);

		// Clear all mocks before each test
		jest.clearAllMocks();
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	describe('generateToken', () => {
		it('should generate a valid CSRF token', async () => {
			const mockToken = 'abc123def456';
			mockPrismaService.csrfToken.create.mockResolvedValue({
				id: '1',
				token: mockToken,
				expiresAt: new Date(Date.now() + 3600000),
				createdAt: new Date(),
			});

			const token = await service.generateToken();

			expect(token).toBeDefined();
			expect(typeof token).toBe('string');
			expect(token.length).toBeGreaterThan(0);
			expect(mockPrismaService.csrfToken.create).toHaveBeenCalledTimes(1);
		});

		it('should create token with correct expiration (1 hour)', async () => {
			const now = Date.now();
			mockPrismaService.csrfToken.create.mockResolvedValue({
				id: '1',
				token: 'test-token',
				expiresAt: new Date(now + 3600000),
				createdAt: new Date(),
			});

			await service.generateToken();

			const createCall = mockPrismaService.csrfToken.create.mock.calls[0][0];
			const expiresAt = createCall.data.expiresAt;
			const expectedExpiry = now + 3600000; // 1 hour

			expect(expiresAt.getTime()).toBeGreaterThanOrEqual(expectedExpiry - 1000);
			expect(expiresAt.getTime()).toBeLessThanOrEqual(expectedExpiry + 1000);
		});

		it('should throw error if database fails', async () => {
			mockPrismaService.csrfToken.create.mockRejectedValue(
				new Error('Database error')
			);

			await expect(service.generateToken()).rejects.toThrow('Database error');
		});
	});

	describe('validateToken', () => {
		it('should return true for valid non-expired token', async () => {
			const token = 'valid-token';
			const futureDate = new Date(Date.now() + 3600000);

			mockPrismaService.csrfToken.findUnique.mockResolvedValue({
				id: '1',
				token,
				expiresAt: futureDate,
				createdAt: new Date(),
			});

			const result = await service.validateToken(token);

			expect(result).toBe(true);
			expect(mockPrismaService.csrfToken.findUnique).toHaveBeenCalledWith({
				where: { token },
			});
		});

		it('should return false for non-existent token', async () => {
			mockPrismaService.csrfToken.findUnique.mockResolvedValue(null);

			const result = await service.validateToken('non-existent-token');

			expect(result).toBe(false);
		});

		it('should return false and delete expired token', async () => {
			const token = 'expired-token';
			const pastDate = new Date(Date.now() - 3600000);

			mockPrismaService.csrfToken.findUnique.mockResolvedValue({
				id: '1',
				token,
				expiresAt: pastDate,
				createdAt: new Date(),
			});

			mockPrismaService.csrfToken.delete.mockResolvedValue({
				id: '1',
				token,
				expiresAt: pastDate,
				createdAt: new Date(),
			});

			const result = await service.validateToken(token);

			expect(result).toBe(false);
			expect(mockPrismaService.csrfToken.delete).toHaveBeenCalledWith({
				where: { token },
			});
		});

		it('should return false on database error', async () => {
			mockPrismaService.csrfToken.findUnique.mockRejectedValue(
				new Error('Database error')
			);

			const result = await service.validateToken('any-token');

			expect(result).toBe(false);
		});
	});

	describe('invalidateToken', () => {
		it('should delete token from database', async () => {
			const token = 'token-to-delete';
			mockPrismaService.csrfToken.delete.mockResolvedValue({
				id: '1',
				token,
				expiresAt: new Date(),
				createdAt: new Date(),
			});

			await service.invalidateToken(token);

			expect(mockPrismaService.csrfToken.delete).toHaveBeenCalledWith({
				where: { token },
			});
		});

		it('should handle deletion of non-existent token gracefully', async () => {
			mockPrismaService.csrfToken.delete.mockRejectedValue(
				new Error('Not found')
			);

			await expect(
				service.invalidateToken('non-existent')
			).resolves.not.toThrow();
		});
	});
});
