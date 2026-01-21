import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { BadRequestException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { RoleHierarchyService } from './role-hierarchy.service';

describe('RoleHierarchyService', () => {
	let service: RoleHierarchyService;
	let _prismaService: PrismaService;

	const mockPrismaService = {
		role: {
			findUnique: jest.fn(),
			findMany: jest.fn(),
			update: jest.fn(),
		},
		rolePermission: {
			findMany: jest.fn(),
		},
	};

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				RoleHierarchyService,
				{
					provide: PrismaService,
					useValue: mockPrismaService,
				},
			],
		}).compile();

		service = module.get<RoleHierarchyService>(RoleHierarchyService);
		_prismaService = module.get<PrismaService>(PrismaService);

		jest.clearAllMocks();
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	describe('getInheritedPermissions', () => {
		it('should return direct permissions for role without parent', async () => {
			const roleId = 'role1';
			const permissionId = 'perm1';

			mockPrismaService.rolePermission.findMany.mockResolvedValue([
				{
					permissionId,
					expiresAt: null,
				},
			]);

			mockPrismaService.role.findUnique.mockResolvedValue({
				id: roleId,
				parentRoleId: null,
			});

			const permissions = await service.getInheritedPermissions(roleId);

			expect(permissions.has(permissionId)).toBe(true);
			expect(permissions.size).toBe(1);
		});

		it('should inherit permissions from parent role', async () => {
			const roleId = 'role2';
			const parentRoleId = 'role1';
			const childPerm = 'perm2';
			const parentPerm = 'perm1';

			mockPrismaService.rolePermission.findMany
				.mockResolvedValueOnce([{ permissionId: childPerm, expiresAt: null }]) // role2 perms
				.mockResolvedValueOnce([{ permissionId: parentPerm, expiresAt: null }]); // role1 perms

			mockPrismaService.role.findUnique
				.mockResolvedValueOnce({ id: roleId, parentRoleId }) // role2 lookup
				.mockResolvedValueOnce({ id: parentRoleId, parentRoleId: null }); // role1 lookup

			const permissions = await service.getInheritedPermissions(roleId);

			expect(permissions.has(childPerm)).toBe(true);
			expect(permissions.has(parentPerm)).toBe(true);
			expect(permissions.size).toBe(2);
		});

		it('should exclude expired permissions', async () => {
			const roleId = 'role1';
			const activePerm = 'perm1';
			const expiredPerm = 'perm2';
			const expirationTime = new Date(Date.now() - 1000); // 1 segundo atrás

			mockPrismaService.rolePermission.findMany.mockResolvedValue([
				{ permissionId: activePerm, expiresAt: null },
				{ permissionId: expiredPerm, expiresAt: expirationTime },
			]);

			mockPrismaService.role.findUnique.mockResolvedValue({
				id: roleId,
				parentRoleId: null,
			});

			const permissions = await service.getInheritedPermissions(roleId);

			expect(permissions.has(activePerm)).toBe(true);
			expect(permissions.has(expiredPerm)).toBe(false);
		});

		it('should use cache on second call', async () => {
			const roleId = 'role1';

			mockPrismaService.rolePermission.findMany.mockResolvedValue([
				{ permissionId: 'perm1', expiresAt: null },
			]);

			mockPrismaService.role.findUnique.mockResolvedValue({
				id: roleId,
				parentRoleId: null,
			});

			// Primera llamada
			await service.getInheritedPermissions(roleId);
			// Segunda llamada
			await service.getInheritedPermissions(roleId);

			// rolePermission.findMany debe ser llamado solo una vez (caché)
			expect(mockPrismaService.rolePermission.findMany).toHaveBeenCalledTimes(
				1
			);
		});
	});

	describe('getRoleHierarchyPath', () => {
		it('should return single role if no parent', async () => {
			const roleId = 'role1';

			mockPrismaService.role.findUnique.mockResolvedValue({
				id: roleId,
				parentRoleId: null,
			});

			const path = await service.getRoleHierarchyPath(roleId);

			expect(path).toEqual([roleId]);
		});

		it('should return full hierarchy path', async () => {
			const role1 = 'role1';
			const role2 = 'role2';
			const role3 = 'role3';

			mockPrismaService.role.findUnique
				.mockResolvedValueOnce({ id: role3, parentRoleId: role2 })
				.mockResolvedValueOnce({ id: role2, parentRoleId: role1 })
				.mockResolvedValueOnce({ id: role1, parentRoleId: null });

			const path = await service.getRoleHierarchyPath(role3);

			expect(path).toEqual([role3, role2, role1]);
		});
	});

	describe('setParentRole', () => {
		it('should reject setting role as its own parent', async () => {
			const roleId = 'role1';

			await expect(service.setParentRole(roleId, roleId)).rejects.toThrow(
				BadRequestException
			);
		});

		it('should reject circular hierarchy', async () => {
			const role1 = 'role1';
			const role2 = 'role2';

			mockPrismaService.role.findUnique
				.mockResolvedValueOnce({ id: role2, parentRoleId: role1 })
				.mockResolvedValueOnce({ id: role1, parentRoleId: null });

			await expect(service.setParentRole(role1, role2)).rejects.toThrow(
				BadRequestException
			);
		});

		it('should set parent role successfully', async () => {
			const childRoleId = 'role2';
			const parentRoleId = 'role1';

			mockPrismaService.role.findUnique.mockResolvedValue({
				id: parentRoleId,
				parentRoleId: null,
			});

			mockPrismaService.role.update.mockResolvedValue({
				id: childRoleId,
				parentRoleId,
				identifier: 'child',
				name: 'Child Role',
				description: null,
				default: false,
				createdAt: new Date(),
				updatedAt: new Date(),
			});

			const result = await service.setParentRole(childRoleId, parentRoleId);

			expect(result.parentRoleId).toBe(parentRoleId);
			expect(mockPrismaService.role.update).toHaveBeenCalledWith({
				where: { id: childRoleId },
				data: { parentRoleId },
			});
		});

		it('should allow clearing parent role', async () => {
			const childRoleId = 'role2';

			mockPrismaService.role.update.mockResolvedValue({
				id: childRoleId,
				parentRoleId: null,
				identifier: 'child',
				name: 'Child Role',
				description: null,
				default: false,
				createdAt: new Date(),
				updatedAt: new Date(),
			});

			const result = await service.setParentRole(childRoleId, null);

			expect(result.parentRoleId).toBeNull();
		});
	});

	describe('invalidateCache', () => {
		it('should remove role from cache', async () => {
			const roleId = 'role1';

			// Poblar caché
			mockPrismaService.rolePermission.findMany.mockResolvedValue([
				{ permissionId: 'perm1', expiresAt: null },
			]);
			mockPrismaService.role.findUnique.mockResolvedValue({
				id: roleId,
				parentRoleId: null,
			});

			await service.getInheritedPermissions(roleId);
			service.invalidateCache(roleId);

			// Segunda llamada debería hacer query nuevamente
			mockPrismaService.rolePermission.findMany.mockClear();
			mockPrismaService.role.findUnique.mockClear();

			mockPrismaService.rolePermission.findMany.mockResolvedValue([
				{ permissionId: 'perm1', expiresAt: null },
			]);
			mockPrismaService.role.findUnique.mockResolvedValue({
				id: roleId,
				parentRoleId: null,
			});

			await service.getInheritedPermissions(roleId);

			expect(mockPrismaService.rolePermission.findMany).toHaveBeenCalled();
		});
	});

	describe('validateHierarchyNoCycles', () => {
		it('should return true for valid hierarchy', async () => {
			mockPrismaService.role.findMany.mockResolvedValue([
				{ id: 'role1', parentRoleId: null },
				{ id: 'role2', parentRoleId: 'role1' },
				{ id: 'role3', parentRoleId: 'role2' },
			]);

			const isValid = await service.validateHierarchyNoCycles();

			expect(isValid).toBe(true);
		});

		it('should return false for circular hierarchy', async () => {
			mockPrismaService.role.findMany.mockResolvedValue([
				{ id: 'role1', parentRoleId: 'role3' },
				{ id: 'role2', parentRoleId: 'role1' },
				{ id: 'role3', parentRoleId: 'role2' },
			]);

			const isValid = await service.validateHierarchyNoCycles();

			expect(isValid).toBe(false);
		});
	});
});
