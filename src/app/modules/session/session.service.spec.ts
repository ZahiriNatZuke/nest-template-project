import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Test, TestingModule } from '@nestjs/testing';
import { Session } from '@prisma/client';
import { SessionService } from './session.service';

describe('SessionService', () => {
	let service: SessionService;
	let prisma: PrismaService;

	const mockSession: Session = {
		id: 'session-1',
		userId: 'user-1',
		device: 'Chrome/Windows',
		accessToken: 'access-token-1',
		refreshToken: 'refresh-token-1',
		loginSessionId: 'login-session-1',
		ipAddress: '192.168.1.1',
		userAgent: 'Mozilla/5.0',
		lastActivityAt: new Date(),
		createdAt: new Date(),
		updatedAt: new Date(),
	};

	const mockPrismaService = {
		session: {
			findMany: jest.fn(),
			findUnique: jest.fn(),
			findUniqueOrThrow: jest.fn(),
			delete: jest.fn(),
			deleteMany: jest.fn(),
			update: jest.fn(),
		},
	};

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				SessionService,
				{
					provide: PrismaService,
					useValue: mockPrismaService,
				},
			],
		}).compile();

		service = module.get<SessionService>(SessionService);
		prisma = module.get<PrismaService>(PrismaService);
	});

	afterEach(() => {
		jest.clearAllMocks();
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	describe('findMany', () => {
		it('should return sessions matching the criteria', async () => {
			const sessions = [mockSession];
			mockPrismaService.session.findMany.mockResolvedValue(sessions);

			const result = await service.findMany({ userId: 'user-1' });

			expect(result).toEqual(sessions);
			expect(prisma.session.findMany).toHaveBeenCalledWith({
				where: { userId: 'user-1' },
			});
		});
	});

	describe('findOne', () => {
		it('should return a session when found', async () => {
			mockPrismaService.session.findUnique.mockResolvedValue(mockSession);

			const result = await service.findOne({ id: 'session-1' });

			expect(result).toEqual(mockSession);
			expect(prisma.session.findUnique).toHaveBeenCalledWith({
				where: { id: 'session-1' },
			});
		});

		it('should throw when canThrow is true and session not found', async () => {
			mockPrismaService.session.findUniqueOrThrow.mockRejectedValue(
				new Error('Not found')
			);

			await expect(
				service.findOne({ id: 'non-existent' }, true)
			).rejects.toThrow();
		});

		it('should return null when canThrow is false and session not found', async () => {
			mockPrismaService.session.findUnique.mockResolvedValue(null);

			const result = await service.findOne({ id: 'non-existent' });

			expect(result).toBeNull();
		});
	});

	describe('delete', () => {
		it('should delete a session', async () => {
			mockPrismaService.session.delete.mockResolvedValue(mockSession);

			const result = await service.delete({ id: 'session-1' });

			expect(result).toEqual(mockSession);
			expect(prisma.session.delete).toHaveBeenCalledWith({
				where: { id: 'session-1' },
			});
		});
	});

	describe('invalidateSessionsCreatedBefore', () => {
		it('should invalidate sessions created before a specific timestamp', async () => {
			const timestamp = new Date('2026-01-20T00:00:00Z');
			mockPrismaService.session.deleteMany.mockResolvedValue({ count: 3 });

			const result = await service.invalidateSessionsCreatedBefore(
				'user-1',
				timestamp
			);

			expect(result).toBe(3);
			expect(prisma.session.deleteMany).toHaveBeenCalledWith({
				where: {
					userId: 'user-1',
					createdAt: {
						lt: timestamp,
					},
				},
			});
		});

		it('should return 0 when no sessions are invalidated', async () => {
			const timestamp = new Date();
			mockPrismaService.session.deleteMany.mockResolvedValue({ count: 0 });

			const result = await service.invalidateSessionsCreatedBefore(
				'user-1',
				timestamp
			);

			expect(result).toBe(0);
		});
	});

	describe('updateLastActivity', () => {
		it('should update the last activity timestamp', async () => {
			const updatedSession = {
				...mockSession,
				lastActivityAt: new Date(),
			};
			mockPrismaService.session.update.mockResolvedValue(updatedSession);

			await service.updateLastActivity('session-1');

			expect(prisma.session.update).toHaveBeenCalledWith({
				where: { id: 'session-1' },
				data: { lastActivityAt: expect.any(Date) },
			});
		});
	});

	describe('getActiveSessionsByUserId', () => {
		it('should return active sessions ordered by last activity', async () => {
			const sessions = [
				{ ...mockSession, lastActivityAt: new Date('2026-01-22T12:00:00Z') },
				{ ...mockSession, lastActivityAt: new Date('2026-01-22T10:00:00Z') },
			];
			mockPrismaService.session.findMany.mockResolvedValue(sessions);

			const result = await service.getActiveSessionsByUserId('user-1');

			expect(result).toEqual(sessions);
			expect(prisma.session.findMany).toHaveBeenCalledWith({
				where: { userId: 'user-1' },
				orderBy: { lastActivityAt: 'desc' },
			});
		});
	});

	describe('validateLoginSessionId', () => {
		it('should return true when loginSessionId matches', async () => {
			mockPrismaService.session.findUnique.mockResolvedValue(mockSession);

			const result = await service.validateLoginSessionId(
				'session-1',
				'login-session-1'
			);

			expect(result).toBe(true);
		});

		it('should return false when loginSessionId does not match', async () => {
			mockPrismaService.session.findUnique.mockResolvedValue(mockSession);

			const result = await service.validateLoginSessionId(
				'session-1',
				'wrong-login-session-id'
			);

			expect(result).toBe(false);
		});

		it('should return false when session not found', async () => {
			mockPrismaService.session.findUnique.mockResolvedValue(null);

			const result = await service.validateLoginSessionId(
				'non-existent',
				'login-session-1'
			);

			expect(result).toBe(false);
		});
	});
});
