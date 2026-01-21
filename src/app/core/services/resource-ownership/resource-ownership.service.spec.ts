import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { ForbiddenException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { ResourceOwnershipService } from './resource-ownership.service';

describe('ResourceOwnershipService', () => {
	let service: ResourceOwnershipService;
	let _prismaService: PrismaService;

	const mockPrismaService = {
		resourceOwnership: {
			findUnique: jest.fn(),
			findMany: jest.fn(),
			upsert: jest.fn(),
			update: jest.fn(),
			delete: jest.fn(),
			deleteMany: jest.fn(),
		},
	};

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				ResourceOwnershipService,
				{
					provide: PrismaService,
					useValue: mockPrismaService,
				},
			],
		}).compile();

		service = module.get<ResourceOwnershipService>(ResourceOwnershipService);
		_prismaService = module.get<PrismaService>(PrismaService);

		jest.clearAllMocks();
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	describe('isOwner', () => {
		it('should return true if user is owner', async () => {
			const userId = 'user1';
			const resourceType = 'document';
			const resourceId = 'doc1';

			mockPrismaService.resourceOwnership.findUnique.mockResolvedValue({
				userId,
				resourceType,
				resourceId,
				accessLevel: 'owner',
			});

			const result = await service.isOwner(userId, resourceType, resourceId);

			expect(result).toBe(true);
		});

		it('should return false if user is not owner', async () => {
			mockPrismaService.resourceOwnership.findUnique.mockResolvedValue({
				userId: 'user1',
				accessLevel: 'editor',
			});

			const result = await service.isOwner('user1', 'document', 'doc1');

			expect(result).toBe(false);
		});

		it('should return false if no ownership record', async () => {
			mockPrismaService.resourceOwnership.findUnique.mockResolvedValue(null);

			const result = await service.isOwner('user1', 'document', 'doc1');

			expect(result).toBe(false);
		});
	});

	describe('getAccessLevel', () => {
		it('should return access level for user', async () => {
			mockPrismaService.resourceOwnership.findUnique.mockResolvedValue({
				accessLevel: 'editor',
			});

			const result = await service.getAccessLevel('user1', 'document', 'doc1');

			expect(result).toBe('editor');
		});

		it('should return null if no access', async () => {
			mockPrismaService.resourceOwnership.findUnique.mockResolvedValue(null);

			const result = await service.getAccessLevel('user1', 'document', 'doc1');

			expect(result).toBeNull();
		});
	});

	describe('hasAccess', () => {
		it('should return true if user has access', async () => {
			mockPrismaService.resourceOwnership.findUnique.mockResolvedValue({
				accessLevel: 'viewer',
			});

			const result = await service.hasAccess('user1', 'document', 'doc1');

			expect(result).toBe(true);
		});

		it('should return false if user has no access', async () => {
			mockPrismaService.resourceOwnership.findUnique.mockResolvedValue(null);

			const result = await service.hasAccess('user1', 'document', 'doc1');

			expect(result).toBe(false);
		});
	});

	describe('hasAccessLevel', () => {
		it('should allow owner to access resource', async () => {
			mockPrismaService.resourceOwnership.findUnique.mockResolvedValue({
				accessLevel: 'owner',
			});

			const result = await service.hasAccessLevel(
				'user1',
				'document',
				'doc1',
				'editor'
			);

			expect(result).toBe(true);
		});

		it('should deny viewer from editing', async () => {
			mockPrismaService.resourceOwnership.findUnique.mockResolvedValue({
				accessLevel: 'viewer',
			});

			const result = await service.hasAccessLevel(
				'user1',
				'document',
				'doc1',
				'editor'
			);

			expect(result).toBe(false);
		});

		it('should allow editor to view', async () => {
			mockPrismaService.resourceOwnership.findUnique.mockResolvedValue({
				accessLevel: 'editor',
			});

			const result = await service.hasAccessLevel(
				'user1',
				'document',
				'doc1',
				'viewer'
			);

			expect(result).toBe(true);
		});
	});

	describe('assignOwnership', () => {
		it('should create ownership record', async () => {
			const userId = 'user1';
			const resourceType = 'document';
			const resourceId = 'doc1';

			mockPrismaService.resourceOwnership.upsert.mockResolvedValue({
				userId,
				resourceType,
				resourceId,
				accessLevel: 'owner',
			});

			await service.assignOwnership(userId, resourceType, resourceId, 'owner');

			expect(mockPrismaService.resourceOwnership.upsert).toHaveBeenCalledWith({
				where: {
					userId_resourceType_resourceId: {
						userId,
						resourceType,
						resourceId,
					},
				},
				update: { accessLevel: 'owner' },
				create: {
					userId,
					resourceType,
					resourceId,
					accessLevel: 'owner',
				},
			});
		});
	});

	describe('revokeAccess', () => {
		it('should delete ownership record', async () => {
			const userId = 'user1';
			const resourceType = 'document';
			const resourceId = 'doc1';

			mockPrismaService.resourceOwnership.deleteMany.mockResolvedValue({
				count: 1,
			});

			await service.revokeAccess(userId, resourceType, resourceId);

			expect(
				mockPrismaService.resourceOwnership.deleteMany
			).toHaveBeenCalledWith({
				where: {
					userId,
					resourceType,
					resourceId,
				},
			});
		});
	});

	describe('getResourceAccessors', () => {
		it('should return all users with access to resource', async () => {
			const accessors = [
				{ userId: 'user1', accessLevel: 'owner' },
				{ userId: 'user2', accessLevel: 'editor' },
			];

			mockPrismaService.resourceOwnership.findMany.mockResolvedValue(accessors);

			const result = await service.getResourceAccessors('document', 'doc1');

			expect(result).toEqual(accessors);
		});
	});

	describe('getUserResources', () => {
		it('should return all resources accessible by user', async () => {
			const resources = [
				{ resourceType: 'document', resourceId: 'doc1', accessLevel: 'owner' },
				{ resourceType: 'document', resourceId: 'doc2', accessLevel: 'editor' },
			];

			mockPrismaService.resourceOwnership.findMany.mockResolvedValue(resources);

			const result = await service.getUserResources('user1');

			expect(result).toEqual(resources);
		});

		it('should filter by resource type', async () => {
			mockPrismaService.resourceOwnership.findMany.mockResolvedValue([
				{ resourceType: 'document', resourceId: 'doc1', accessLevel: 'owner' },
			]);

			await service.getUserResources('user1', 'document');

			expect(mockPrismaService.resourceOwnership.findMany).toHaveBeenCalledWith(
				{
					where: {
						userId: 'user1',
						resourceType: 'document',
					},
					select: expect.any(Object),
				}
			);
		});
	});

	describe('transferOwnership', () => {
		it('should transfer ownership successfully', async () => {
			const fromUserId = 'user1';
			const toUserId = 'user2';

			// Mock isOwner check
			mockPrismaService.resourceOwnership.findUnique.mockResolvedValueOnce({
				accessLevel: 'owner',
			});

			// Mock deleteMany for revoke
			mockPrismaService.resourceOwnership.deleteMany.mockResolvedValue({
				count: 1,
			});

			// Mock upsert for new owner
			mockPrismaService.resourceOwnership.upsert.mockResolvedValue({
				userId: toUserId,
				accessLevel: 'owner',
			});

			await service.transferOwnership(fromUserId, toUserId, 'document', 'doc1');

			expect(mockPrismaService.resourceOwnership.deleteMany).toHaveBeenCalled();
			expect(mockPrismaService.resourceOwnership.upsert).toHaveBeenCalled();
		});

		it('should reject transfer if not owner', async () => {
			mockPrismaService.resourceOwnership.findUnique.mockResolvedValue({
				accessLevel: 'editor',
			});

			await expect(
				service.transferOwnership('user1', 'user2', 'document', 'doc1')
			).rejects.toThrow(ForbiddenException);
		});
	});

	describe('updateAccessLevel', () => {
		it('should update access level', async () => {
			mockPrismaService.resourceOwnership.findUnique.mockResolvedValue({
				accessLevel: 'editor',
			});

			mockPrismaService.resourceOwnership.update.mockResolvedValue({
				accessLevel: 'viewer',
			});

			await service.updateAccessLevel('user1', 'document', 'doc1', 'viewer');

			expect(mockPrismaService.resourceOwnership.update).toHaveBeenCalled();
		});

		it('should throw error if user has no access', async () => {
			mockPrismaService.resourceOwnership.findUnique.mockResolvedValue(null);

			await expect(
				service.updateAccessLevel('user1', 'document', 'doc1', 'viewer')
			).rejects.toThrow();
		});
	});

	describe('cleanupResourceOwnerships', () => {
		it('should delete all ownership records for resource', async () => {
			mockPrismaService.resourceOwnership.deleteMany.mockResolvedValue({
				count: 2,
			});

			await service.cleanupResourceOwnerships('document', 'doc1');

			expect(
				mockPrismaService.resourceOwnership.deleteMany
			).toHaveBeenCalledWith({
				where: {
					resourceType: 'document',
					resourceId: 'doc1',
				},
			});
		});
	});
});
