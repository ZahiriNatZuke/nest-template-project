import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { ForbiddenException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import {
	asPrismaService,
	createPrismaMock,
	type PrismaMock,
} from '@test/utils/prisma-mock';
import {
	type AccessLevel,
	ResourceOwnershipService,
} from './resource-ownership.service';

describe('ResourceOwnershipService', () => {
	let service: ResourceOwnershipService;
	let prisma: PrismaMock;

	const USER = 'user-1';
	const TYPE = 'project';
	const RESOURCE = 'project-42';

	/** The compound-unique selector the service builds for every point lookup. */
	const compoundWhere = (userId = USER) => ({
		userId_resourceType_resourceId: {
			userId,
			resourceType: TYPE,
			resourceId: RESOURCE,
		},
	});

	beforeEach(async () => {
		prisma = createPrismaMock();

		const module: TestingModule = await Test.createTestingModule({
			providers: [
				ResourceOwnershipService,
				{ provide: PrismaService, useValue: asPrismaService(prisma) },
			],
		}).compile();

		service = module.get<ResourceOwnershipService>(ResourceOwnershipService);
	});

	describe('isOwner', () => {
		it('queries by the compound unique key', async () => {
			prisma.resourceOwnership.findUnique.mockResolvedValue(null);

			await service.isOwner(USER, TYPE, RESOURCE);

			expect(prisma.resourceOwnership.findUnique).toHaveBeenCalledWith({
				where: compoundWhere(),
			});
		});

		it('is true only for the owner level', async () => {
			prisma.resourceOwnership.findUnique.mockResolvedValue({
				accessLevel: 'owner',
			});

			await expect(service.isOwner(USER, TYPE, RESOURCE)).resolves.toBe(true);
		});

		it.each(['editor', 'viewer'])('is false for %s', async accessLevel => {
			prisma.resourceOwnership.findUnique.mockResolvedValue({ accessLevel });

			await expect(service.isOwner(USER, TYPE, RESOURCE)).resolves.toBe(false);
		});

		it('is false when there is no ownership row', async () => {
			prisma.resourceOwnership.findUnique.mockResolvedValue(null);

			await expect(service.isOwner(USER, TYPE, RESOURCE)).resolves.toBe(false);
		});
	});

	describe('getAccessLevel', () => {
		it('returns the stored level', async () => {
			prisma.resourceOwnership.findUnique.mockResolvedValue({
				accessLevel: 'editor',
			});

			await expect(service.getAccessLevel(USER, TYPE, RESOURCE)).resolves.toBe(
				'editor'
			);
		});

		it('returns null when there is no row', async () => {
			prisma.resourceOwnership.findUnique.mockResolvedValue(null);

			await expect(
				service.getAccessLevel(USER, TYPE, RESOURCE)
			).resolves.toBeNull();
		});
	});

	describe('hasAccess', () => {
		it.each(['owner', 'editor', 'viewer'])(
			'grants access at %s level',
			async accessLevel => {
				prisma.resourceOwnership.findUnique.mockResolvedValue({ accessLevel });

				await expect(service.hasAccess(USER, TYPE, RESOURCE)).resolves.toBe(
					true
				);
			}
		);

		it('denies when there is no row', async () => {
			prisma.resourceOwnership.findUnique.mockResolvedValue(null);

			await expect(service.hasAccess(USER, TYPE, RESOURCE)).resolves.toBe(
				false
			);
		});
	});

	describe('hasAccessLevel', () => {
		// The full owner > editor > viewer matrix: rows are what the user has,
		// columns are what the endpoint requires.
		const matrix: Array<[AccessLevel, AccessLevel, boolean]> = [
			['owner', 'owner', true],
			['owner', 'editor', true],
			['owner', 'viewer', true],
			['editor', 'owner', false],
			['editor', 'editor', true],
			['editor', 'viewer', true],
			['viewer', 'owner', false],
			['viewer', 'editor', false],
			['viewer', 'viewer', true],
		];

		it.each(matrix)(
			'a %s meeting a required level of %s -> %s',
			async (actual, required, expected) => {
				prisma.resourceOwnership.findUnique.mockResolvedValue({
					accessLevel: actual,
				});

				await expect(
					service.hasAccessLevel(USER, TYPE, RESOURCE, required)
				).resolves.toBe(expected);
			}
		);

		it('denies when the user has no access at all', async () => {
			prisma.resourceOwnership.findUnique.mockResolvedValue(null);

			await expect(
				service.hasAccessLevel(USER, TYPE, RESOURCE, 'viewer')
			).resolves.toBe(false);
		});
	});

	describe('assignOwnership', () => {
		it('defaults to the owner level', async () => {
			prisma.resourceOwnership.upsert.mockResolvedValue({});

			await service.assignOwnership(USER, TYPE, RESOURCE);

			expect(prisma.resourceOwnership.upsert).toHaveBeenCalledWith({
				where: compoundWhere(),
				update: { accessLevel: 'owner' },
				create: {
					userId: USER,
					resourceType: TYPE,
					resourceId: RESOURCE,
					accessLevel: 'owner',
				},
			});
		});

		// Upsert means re-assigning is idempotent rather than a unique violation.
		it('upgrades an existing row instead of failing', async () => {
			prisma.resourceOwnership.upsert.mockResolvedValue({});

			await service.assignOwnership(USER, TYPE, RESOURCE, 'editor');

			expect(prisma.resourceOwnership.upsert).toHaveBeenCalledWith(
				expect.objectContaining({ update: { accessLevel: 'editor' } })
			);
		});
	});

	describe('revokeAccess', () => {
		it('deletes the row for that user and resource only', async () => {
			prisma.resourceOwnership.deleteMany.mockResolvedValue({ count: 1 });

			await service.revokeAccess(USER, TYPE, RESOURCE);

			expect(prisma.resourceOwnership.deleteMany).toHaveBeenCalledWith({
				where: { userId: USER, resourceType: TYPE, resourceId: RESOURCE },
			});
		});
	});

	describe('getResourceAccessors', () => {
		it('lists every user with access to the resource', async () => {
			const rows = [
				{ userId: 'user-1', accessLevel: 'owner' },
				{ userId: 'user-2', accessLevel: 'viewer' },
			];
			prisma.resourceOwnership.findMany.mockResolvedValue(rows);

			await expect(
				service.getResourceAccessors(TYPE, RESOURCE)
			).resolves.toEqual(rows);
			expect(prisma.resourceOwnership.findMany).toHaveBeenCalledWith({
				where: { resourceType: TYPE, resourceId: RESOURCE },
				select: { userId: true, accessLevel: true },
			});
		});

		it('returns an empty list for a resource nobody can reach', async () => {
			prisma.resourceOwnership.findMany.mockResolvedValue([]);

			await expect(
				service.getResourceAccessors(TYPE, RESOURCE)
			).resolves.toEqual([]);
		});
	});

	describe('getUserResources', () => {
		it('filters by resource type when one is given', async () => {
			prisma.resourceOwnership.findMany.mockResolvedValue([]);

			await service.getUserResources(USER, TYPE);

			expect(prisma.resourceOwnership.findMany).toHaveBeenCalledWith({
				where: { userId: USER, resourceType: TYPE },
				select: { resourceType: true, resourceId: true, accessLevel: true },
			});
		});

		it('omits the type filter when none is given', async () => {
			prisma.resourceOwnership.findMany.mockResolvedValue([]);

			await service.getUserResources(USER);

			expect(prisma.resourceOwnership.findMany).toHaveBeenCalledWith({
				where: { userId: USER },
				select: { resourceType: true, resourceId: true, accessLevel: true },
			});
		});
	});

	describe('transferOwnership', () => {
		it('rejects a transfer by a non-owner without changing anything', async () => {
			prisma.resourceOwnership.findUnique.mockResolvedValue({
				accessLevel: 'editor',
			});

			await expect(
				service.transferOwnership(USER, 'user-2', TYPE, RESOURCE)
			).rejects.toThrow(ForbiddenException);
			expect(prisma.resourceOwnership.deleteMany).not.toHaveBeenCalled();
			expect(prisma.resourceOwnership.upsert).not.toHaveBeenCalled();
		});

		it('rejects a transfer by a user with no access', async () => {
			prisma.resourceOwnership.findUnique.mockResolvedValue(null);

			await expect(
				service.transferOwnership(USER, 'user-2', TYPE, RESOURCE)
			).rejects.toThrow('Only the owner can transfer ownership');
		});

		it('revokes the old owner and grants the new one', async () => {
			prisma.resourceOwnership.findUnique.mockResolvedValue({
				accessLevel: 'owner',
			});
			prisma.resourceOwnership.deleteMany.mockResolvedValue({ count: 1 });
			prisma.resourceOwnership.upsert.mockResolvedValue({});

			await service.transferOwnership(USER, 'user-2', TYPE, RESOURCE);

			expect(prisma.resourceOwnership.deleteMany).toHaveBeenCalledWith({
				where: { userId: USER, resourceType: TYPE, resourceId: RESOURCE },
			});
			expect(prisma.resourceOwnership.upsert).toHaveBeenCalledWith(
				expect.objectContaining({
					where: compoundWhere('user-2'),
					update: { accessLevel: 'owner' },
				})
			);
		});

		// The revoke and the grant are two separate statements, not one
		// transaction: if the grant fails the resource is left with no owner.
		it('leaves the resource unowned if the grant fails after the revoke', async () => {
			prisma.resourceOwnership.findUnique.mockResolvedValue({
				accessLevel: 'owner',
			});
			prisma.resourceOwnership.deleteMany.mockResolvedValue({ count: 1 });
			prisma.resourceOwnership.upsert.mockRejectedValue(
				new Error('db is down')
			);

			await expect(
				service.transferOwnership(USER, 'user-2', TYPE, RESOURCE)
			).rejects.toThrow('db is down');
			expect(prisma.resourceOwnership.deleteMany).toHaveBeenCalled();
			expect(prisma.$transaction).not.toHaveBeenCalled();
		});
	});

	describe('updateAccessLevel', () => {
		it('updates an existing row', async () => {
			prisma.resourceOwnership.findUnique.mockResolvedValue({
				accessLevel: 'viewer',
			});
			prisma.resourceOwnership.update.mockResolvedValue({});

			await service.updateAccessLevel(USER, TYPE, RESOURCE, 'editor');

			expect(prisma.resourceOwnership.update).toHaveBeenCalledWith({
				where: compoundWhere(),
				data: { accessLevel: 'editor' },
			});
		});

		it('throws when the user has no access to update', async () => {
			prisma.resourceOwnership.findUnique.mockResolvedValue(null);

			await expect(
				service.updateAccessLevel(USER, TYPE, RESOURCE, 'editor')
			).rejects.toThrow(
				`User ${USER} does not have access to ${TYPE}/${RESOURCE}`
			);
			expect(prisma.resourceOwnership.update).not.toHaveBeenCalled();
		});
	});

	describe('cleanupResourceOwnerships', () => {
		it('deletes every ownership row for the resource', async () => {
			prisma.resourceOwnership.deleteMany.mockResolvedValue({ count: 3 });

			await service.cleanupResourceOwnerships(TYPE, RESOURCE);

			expect(prisma.resourceOwnership.deleteMany).toHaveBeenCalledWith({
				where: { resourceType: TYPE, resourceId: RESOURCE },
			});
		});
	});
});
