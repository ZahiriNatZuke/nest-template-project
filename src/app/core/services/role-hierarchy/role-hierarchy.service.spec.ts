import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { BadRequestException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { buildRole } from '@test/utils/factories';
import {
	asPrismaService,
	createPrismaMock,
	type PrismaMock,
} from '@test/utils/prisma-mock';
import { RoleHierarchyService } from './role-hierarchy.service';

describe('RoleHierarchyService', () => {
	let service: RoleHierarchyService;
	let prisma: PrismaMock;

	/**
	 * Wires the mock to answer parent lookups and permission lookups from a
	 * plain description of a hierarchy, so each test states only its shape:
	 *
	 *   stubHierarchy({
	 *     admin:   { parent: 'manager', permissions: ['p-admin'] },
	 *     manager: { parent: null,      permissions: ['p-read'] },
	 *   })
	 */
	const stubHierarchy = (
		graph: Record<
			string,
			{
				parent: string | null;
				permissions?: Array<{ permissionId: string; expiresAt?: Date | null }>;
			}
		>
	) => {
		prisma.role.findUnique.mockImplementation(
			async ({ where }: { where: { id: string } }) =>
				graph[where.id] ? { parentRoleId: graph[where.id].parent } : null
		);
		prisma.rolePermission.findMany.mockImplementation(
			async ({ where }: { where: { roleId: string } }) =>
				(graph[where.roleId]?.permissions ?? []).map(p => ({
					permissionId: p.permissionId,
					expiresAt: p.expiresAt ?? null,
				}))
		);
	};

	beforeEach(async () => {
		prisma = createPrismaMock();

		const module: TestingModule = await Test.createTestingModule({
			providers: [
				RoleHierarchyService,
				{ provide: PrismaService, useValue: asPrismaService(prisma) },
			],
		}).compile();

		service = module.get<RoleHierarchyService>(RoleHierarchyService);
	});

	describe('getInheritedPermissions', () => {
		it('returns the direct permissions of a root role', async () => {
			stubHierarchy({
				user: { parent: null, permissions: [{ permissionId: 'p-read' }] },
			});

			await expect(service.getInheritedPermissions('user')).resolves.toEqual(
				new Set(['p-read'])
			);
		});

		it('accumulates permissions up the whole chain', async () => {
			stubHierarchy({
				admin: {
					parent: 'manager',
					permissions: [{ permissionId: 'p-admin' }],
				},
				manager: { parent: 'user', permissions: [{ permissionId: 'p-write' }] },
				user: { parent: null, permissions: [{ permissionId: 'p-read' }] },
			});

			await expect(service.getInheritedPermissions('admin')).resolves.toEqual(
				new Set(['p-admin', 'p-write', 'p-read'])
			);
		});

		it('de-duplicates a permission granted at two levels', async () => {
			stubHierarchy({
				admin: { parent: 'user', permissions: [{ permissionId: 'p-read' }] },
				user: { parent: null, permissions: [{ permissionId: 'p-read' }] },
			});

			await expect(service.getInheritedPermissions('admin')).resolves.toEqual(
				new Set(['p-read'])
			);
		});

		it('returns an empty set for a role with no permissions', async () => {
			stubHierarchy({ empty: { parent: null } });

			await expect(service.getInheritedPermissions('empty')).resolves.toEqual(
				new Set()
			);
		});

		describe('temporary permissions', () => {
			it('includes a permission whose expiry is in the future', async () => {
				stubHierarchy({
					user: {
						parent: null,
						permissions: [
							{
								permissionId: 'p-temp',
								expiresAt: new Date(Date.now() + 60_000),
							},
						],
					},
				});

				await expect(service.getInheritedPermissions('user')).resolves.toEqual(
					new Set(['p-temp'])
				);
			});

			it('drops a permission whose expiry has passed', async () => {
				stubHierarchy({
					user: {
						parent: null,
						permissions: [
							{ permissionId: 'p-kept' },
							{
								permissionId: 'p-expired',
								expiresAt: new Date(Date.now() - 60_000),
							},
						],
					},
				});

				await expect(service.getInheritedPermissions('user')).resolves.toEqual(
					new Set(['p-kept'])
				);
			});

			it('drops an inherited permission that has expired on the parent', async () => {
				stubHierarchy({
					admin: { parent: 'user', permissions: [{ permissionId: 'p-admin' }] },
					user: {
						parent: null,
						permissions: [
							{
								permissionId: 'p-expired',
								expiresAt: new Date(Date.now() - 1_000),
							},
						],
					},
				});

				await expect(service.getInheritedPermissions('admin')).resolves.toEqual(
					new Set(['p-admin'])
				);
			});
		});

		describe('cycle safety', () => {
			// A cycle already present in the database must not hang the resolver.
			it('stops instead of recursing forever on a two-role cycle', async () => {
				stubHierarchy({
					a: { parent: 'b', permissions: [{ permissionId: 'p-a' }] },
					b: { parent: 'a', permissions: [{ permissionId: 'p-b' }] },
				});

				await expect(service.getInheritedPermissions('a')).resolves.toEqual(
					new Set(['p-a', 'p-b'])
				);
			});

			it('stops on a self-referencing role', async () => {
				stubHierarchy({
					a: { parent: 'a', permissions: [{ permissionId: 'p-a' }] },
				});

				await expect(service.getInheritedPermissions('a')).resolves.toEqual(
					new Set(['p-a'])
				);
			});
		});

		describe('caching', () => {
			it('serves a second call from cache without re-querying', async () => {
				stubHierarchy({
					user: { parent: null, permissions: [{ permissionId: 'p-read' }] },
				});

				await service.getInheritedPermissions('user');
				const callsAfterFirst =
					prisma.rolePermission.findMany.mock.calls.length;
				await service.getInheritedPermissions('user');

				expect(prisma.rolePermission.findMany).toHaveBeenCalledTimes(
					callsAfterFirst
				);
			});

			it('re-queries once the TTL has elapsed', async () => {
				jest.useFakeTimers().setSystemTime(new Date('2026-01-01T00:00:00Z'));
				stubHierarchy({
					user: { parent: null, permissions: [{ permissionId: 'p-read' }] },
				});

				await service.getInheritedPermissions('user');
				const callsAfterFirst =
					prisma.rolePermission.findMany.mock.calls.length;

				// TTL is 5 minutes.
				jest.setSystemTime(new Date('2026-01-01T00:05:01Z'));
				await service.getInheritedPermissions('user');

				expect(
					prisma.rolePermission.findMany.mock.calls.length
				).toBeGreaterThan(callsAfterFirst);
				jest.useRealTimers();
			});

			it('re-queries after the cache is invalidated', async () => {
				stubHierarchy({
					user: { parent: null, permissions: [{ permissionId: 'p-read' }] },
				});

				await service.getInheritedPermissions('user');
				const callsAfterFirst =
					prisma.rolePermission.findMany.mock.calls.length;

				service.invalidateCache('user');
				await service.getInheritedPermissions('user');

				expect(
					prisma.rolePermission.findMany.mock.calls.length
				).toBeGreaterThan(callsAfterFirst);
			});
		});
	});

	describe('getRoleHierarchyPath', () => {
		it('walks from the role up to the root', async () => {
			stubHierarchy({
				admin: { parent: 'manager' },
				manager: { parent: 'user' },
				user: { parent: null },
			});

			await expect(service.getRoleHierarchyPath('admin')).resolves.toEqual([
				'admin',
				'manager',
				'user',
			]);
		});

		it('returns just the role itself when it has no parent', async () => {
			stubHierarchy({ user: { parent: null } });

			await expect(service.getRoleHierarchyPath('user')).resolves.toEqual([
				'user',
			]);
		});

		it('returns just the role id when the role does not exist', async () => {
			stubHierarchy({});

			await expect(service.getRoleHierarchyPath('ghost')).resolves.toEqual([
				'ghost',
			]);
		});
	});

	describe('setParentRole', () => {
		it('rejects making a role its own parent', async () => {
			await expect(service.setParentRole('role-a', 'role-a')).rejects.toThrow(
				BadRequestException
			);
			expect(prisma.role.update).not.toHaveBeenCalled();
		});

		it('rejects a parent that is a descendant of the child', async () => {
			// manager already inherits from admin, so making manager the parent of
			// admin would close a loop.
			stubHierarchy({
				manager: { parent: 'admin' },
				admin: { parent: null },
			});

			await expect(service.setParentRole('admin', 'manager')).rejects.toThrow(
				'Setting this parent would create a circular role hierarchy'
			);
			expect(prisma.role.update).not.toHaveBeenCalled();
		});

		it('assigns a valid parent', async () => {
			stubHierarchy({ manager: { parent: null }, admin: { parent: null } });
			prisma.role.update.mockResolvedValue(
				buildRole({ id: 'admin', parentRoleId: 'manager' })
			);

			await service.setParentRole('admin', 'manager');

			expect(prisma.role.update).toHaveBeenCalledWith({
				where: { id: 'admin' },
				data: { parentRoleId: 'manager' },
			});
		});

		it('detaches a role when the parent is null, skipping the cycle check', async () => {
			prisma.role.update.mockResolvedValue(
				buildRole({ id: 'admin', parentRoleId: null })
			);

			await service.setParentRole('admin', null);

			expect(prisma.role.update).toHaveBeenCalledWith({
				where: { id: 'admin' },
				data: { parentRoleId: null },
			});
			expect(prisma.role.findUnique).not.toHaveBeenCalled();
		});

		it('invalidates the cached permissions of the updated role', async () => {
			stubHierarchy({
				admin: { parent: null, permissions: [{ permissionId: 'p-old' }] },
				manager: { parent: null, permissions: [{ permissionId: 'p-new' }] },
			});
			prisma.role.update.mockResolvedValue(buildRole({ id: 'admin' }));

			await service.getInheritedPermissions('admin');
			const callsBefore = prisma.rolePermission.findMany.mock.calls.length;

			await service.setParentRole('admin', 'manager');
			await service.getInheritedPermissions('admin');

			expect(prisma.rolePermission.findMany.mock.calls.length).toBeGreaterThan(
				callsBefore
			);
		});
	});

	describe('invalidateCacheRecursive', () => {
		it('invalidates the role and every descendant', async () => {
			stubHierarchy({
				parent: { parent: null, permissions: [{ permissionId: 'p-1' }] },
				child: { parent: 'parent', permissions: [{ permissionId: 'p-2' }] },
			});
			prisma.role.findMany.mockImplementation(
				async ({ where }: { where: { parentRoleId: string } }) =>
					where.parentRoleId === 'parent' ? [{ id: 'child' }] : []
			);

			await service.getInheritedPermissions('child');
			const callsBefore = prisma.rolePermission.findMany.mock.calls.length;

			await service.invalidateCacheRecursive('parent');
			await service.getInheritedPermissions('child');

			expect(prisma.rolePermission.findMany.mock.calls.length).toBeGreaterThan(
				callsBefore
			);
		});

		it('terminates for a role with no children', async () => {
			prisma.role.findMany.mockResolvedValue([]);

			await expect(
				service.invalidateCacheRecursive('leaf')
			).resolves.toBeUndefined();
		});
	});

	describe('validateHierarchyNoCycles', () => {
		it('accepts an acyclic hierarchy', async () => {
			prisma.role.findMany.mockResolvedValue([
				{ id: 'admin', parentRoleId: 'manager' },
				{ id: 'manager', parentRoleId: 'user' },
				{ id: 'user', parentRoleId: null },
			]);

			await expect(service.validateHierarchyNoCycles()).resolves.toBe(true);
		});

		it('accepts several independent trees', async () => {
			prisma.role.findMany.mockResolvedValue([
				{ id: 'a', parentRoleId: null },
				{ id: 'b', parentRoleId: 'a' },
				{ id: 'c', parentRoleId: null },
			]);

			await expect(service.validateHierarchyNoCycles()).resolves.toBe(true);
		});

		it('rejects a two-role cycle', async () => {
			prisma.role.findMany.mockResolvedValue([
				{ id: 'a', parentRoleId: 'b' },
				{ id: 'b', parentRoleId: 'a' },
			]);

			await expect(service.validateHierarchyNoCycles()).resolves.toBe(false);
		});

		it('rejects a self-referencing role', async () => {
			prisma.role.findMany.mockResolvedValue([{ id: 'a', parentRoleId: 'a' }]);

			await expect(service.validateHierarchyNoCycles()).resolves.toBe(false);
		});

		it('accepts an empty hierarchy', async () => {
			prisma.role.findMany.mockResolvedValue([]);

			await expect(service.validateHierarchyNoCycles()).resolves.toBe(true);
		});
	});
});
