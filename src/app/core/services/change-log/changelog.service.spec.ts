import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Test, TestingModule } from '@nestjs/testing';
import { ChangeLogService } from './changelog.service';

describe('ChangeLogService', () => {
	let service: ChangeLogService;
	let _prismaService: PrismaService;

	const mockPrismaService = {
		auditChangeLog: {
			create: jest.fn(),
			findMany: jest.fn(),
			count: jest.fn(),
		},
		$transaction: jest.fn(),
	};

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				ChangeLogService,
				{
					provide: PrismaService,
					useValue: mockPrismaService,
				},
			],
		}).compile();

		service = module.get<ChangeLogService>(ChangeLogService);
		_prismaService = module.get<PrismaService>(PrismaService);

		jest.clearAllMocks();
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	describe('logChange', () => {
		it('should log a change with before and after states', async () => {
			const changeData = {
				userId: 'user-123',
				action: 'user.update',
				entityType: 'user',
				entityId: 'entity-456',
				before: { name: 'Old Name', email: 'old@example.com' },
				after: { name: 'New Name', email: 'new@example.com' },
			};

			mockPrismaService.auditChangeLog.create.mockResolvedValue({
				id: 'changelog-1',
				...changeData,
				createdAt: new Date(),
			});

			await service.logChange(changeData);

			expect(mockPrismaService.auditChangeLog.create).toHaveBeenCalledWith({
				data: {
					userId: 'user-123',
					action: 'user.update',
					entityType: 'user',
					entityId: 'entity-456',
					before: { name: 'Old Name', email: 'old@example.com' },
					after: { name: 'New Name', email: 'new@example.com' },
				},
			});
		});

		it('should log a change without userId (system action)', async () => {
			const changeData = {
				action: 'system.cleanup',
				entityType: 'session',
				entityId: 'session-789',
				before: null,
				after: null,
			};

			mockPrismaService.auditChangeLog.create.mockResolvedValue({
				id: 'changelog-2',
				userId: null,
				...changeData,
				createdAt: new Date(),
			});

			await service.logChange(changeData);

			expect(mockPrismaService.auditChangeLog.create).toHaveBeenCalledWith({
				data: {
					userId: undefined,
					action: 'system.cleanup',
					entityType: 'session',
					entityId: 'session-789',
					before: undefined,
					after: undefined,
				},
			});
		});

		it('should log a create action with only after state', async () => {
			const changeData = {
				userId: 'user-123',
				action: 'role.create',
				entityType: 'role',
				entityId: 'role-new',
				before: null,
				after: { name: 'Admin', identifier: 'ADMIN_ROLE' },
			};

			mockPrismaService.auditChangeLog.create.mockResolvedValue({
				id: 'changelog-3',
				...changeData,
				createdAt: new Date(),
			});

			await service.logChange(changeData);

			expect(mockPrismaService.auditChangeLog.create).toHaveBeenCalledWith({
				data: {
					userId: 'user-123',
					action: 'role.create',
					entityType: 'role',
					entityId: 'role-new',
					before: undefined,
					after: { name: 'Admin', identifier: 'ADMIN_ROLE' },
				},
			});
		});

		it('should log a delete action with only before state', async () => {
			const changeData = {
				userId: 'user-123',
				action: 'permission.delete',
				entityType: 'permission',
				entityId: 'perm-old',
				before: { resource: 'users', action: 'delete' },
				after: null,
			};

			mockPrismaService.auditChangeLog.create.mockResolvedValue({
				id: 'changelog-4',
				...changeData,
				createdAt: new Date(),
			});

			await service.logChange(changeData);

			expect(mockPrismaService.auditChangeLog.create).toHaveBeenCalledWith({
				data: {
					userId: 'user-123',
					action: 'permission.delete',
					entityType: 'permission',
					entityId: 'perm-old',
					before: { resource: 'users', action: 'delete' },
					after: undefined,
				},
			});
		});

		it('should handle complex nested objects in before/after', async () => {
			const changeData = {
				userId: 'user-123',
				action: 'user.update',
				entityType: 'user',
				entityId: 'user-complex',
				before: {
					id: 'user-complex',
					profile: {
						name: 'John Doe',
						settings: { theme: 'dark', notifications: true },
					},
					roles: ['user', 'editor'],
				},
				after: {
					id: 'user-complex',
					profile: {
						name: 'John Smith',
						settings: { theme: 'light', notifications: false },
					},
					roles: ['user', 'editor', 'admin'],
				},
			};

			mockPrismaService.auditChangeLog.create.mockResolvedValue({
				id: 'changelog-5',
				...changeData,
				createdAt: new Date(),
			});

			await service.logChange(changeData);

			expect(mockPrismaService.auditChangeLog.create).toHaveBeenCalledWith({
				data: expect.objectContaining({
					before: changeData.before,
					after: changeData.after,
				}),
			});
		});

		it('should log soft delete action', async () => {
			const changeData = {
				userId: 'user-123',
				action: 'user.soft_delete',
				entityType: 'user',
				entityId: 'user-to-delete',
				before: { deletedAt: null, email: 'user@example.com' },
				after: { deletedAt: expect.any(Date), email: 'user@example.com' },
			};

			mockPrismaService.auditChangeLog.create.mockResolvedValue({
				id: 'changelog-6',
				userId: 'user-123',
				action: 'user.soft_delete',
				entityType: 'user',
				entityId: 'user-to-delete',
				before: changeData.before,
				after: changeData.after,
				createdAt: new Date(),
			});

			await service.logChange(changeData);

			expect(mockPrismaService.auditChangeLog.create).toHaveBeenCalledWith({
				data: expect.objectContaining({
					action: 'user.soft_delete',
					entityType: 'user',
				}),
			});
		});

		it('should log restore action', async () => {
			const changeData = {
				userId: 'user-123',
				action: 'user.restore',
				entityType: 'user',
				entityId: 'user-to-restore',
				before: { deletedAt: new Date(), email: 'user@example.com' },
				after: { deletedAt: null, email: 'user@example.com' },
			};

			mockPrismaService.auditChangeLog.create.mockResolvedValue({
				id: 'changelog-7',
				...changeData,
				createdAt: new Date(),
			});

			await service.logChange(changeData);

			expect(mockPrismaService.auditChangeLog.create).toHaveBeenCalledWith({
				data: {
					userId: 'user-123',
					action: 'user.restore',
					entityType: 'user',
					entityId: 'user-to-restore',
					before: changeData.before,
					after: changeData.after,
				},
			});
		});
	});
});
