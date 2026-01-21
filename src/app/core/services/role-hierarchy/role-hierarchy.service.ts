import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { Role } from '@prisma/client';

/**
 * Servicio para gestionar jerarquía de roles (2.1 - Roles Jerárquicos)
 * Permite que roles hereden permisos de otros roles (e.g., Admin > Manager > User)
 */
@Injectable()
export class RoleHierarchyService {
	private readonly logger = new Logger(RoleHierarchyService.name);
	private permissionCache = new Map<string, Set<string>>(); // roleId -> Set<permissionId>
	private readonly CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutos
	private cacheTimestamps = new Map<string, number>();

	constructor(private prisma: PrismaService) {}

	/**
	 * Obtiene todos los permisos de un rol incluyendo herencia
	 * Usa caché para optimizar queries frecuentes
	 */
	async getInheritedPermissions(roleId: string): Promise<Set<string>> {
		// Verificar caché
		const now = Date.now();
		const cachedTime = this.cacheTimestamps.get(roleId);

		if (
			this.permissionCache.has(roleId) &&
			cachedTime &&
			now - cachedTime < this.CACHE_TTL_MS
		) {
			this.logger.debug(`Using cached permissions for role ${roleId}`);
			const cached = this.permissionCache.get(roleId);
			if (cached) return cached;
		}

		// Resolver permisos
		const permissions = await this.resolvePermissionsRecursive(
			roleId,
			new Set()
		);
		this.permissionCache.set(roleId, permissions);
		this.cacheTimestamps.set(roleId, now);

		return permissions;
	}

	/**
	 * Resuelve permisos recursivamente a través de la jerarquía
	 */
	private async resolvePermissionsRecursive(
		roleId: string,
		visited: Set<string>
	): Promise<Set<string>> {
		// Evitar ciclos infinitos
		if (visited.has(roleId)) {
			this.logger.warn(`Cycle detected in role hierarchy at role ${roleId}`);
			return new Set();
		}
		visited.add(roleId);

		// Obtener permisos directos de este rol
		const directPermissions = await this.prisma.rolePermission.findMany({
			where: { roleId },
			select: { permissionId: true, expiresAt: true },
		});

		const allPermissions = new Set<string>();

		// Agregar permisos válidos (no expirados)
		const now = new Date();
		for (const rp of directPermissions) {
			if (!rp.expiresAt || rp.expiresAt > now) {
				allPermissions.add(rp.permissionId);
			}
		}

		// Obtener rol padre y resolver sus permisos recursivamente
		const role = await this.prisma.role.findUnique({
			where: { id: roleId },
			select: { parentRoleId: true },
		});

		if (role?.parentRoleId) {
			const parentPermissions = await this.resolvePermissionsRecursive(
				role.parentRoleId,
				visited
			);
			parentPermissions.forEach(p => {
				allPermissions.add(p);
			});
		}

		return allPermissions;
	}

	/**
	 * Obtiene la jerarquía completa de un rol
	 */
	async getRoleHierarchyPath(roleId: string): Promise<string[]> {
		const path: string[] = [roleId];
		let currentId: string | null = roleId;

		while (currentId) {
			const role = await this.prisma.role.findUnique({
				where: { id: currentId },
				select: { parentRoleId: true },
			});

			if (role?.parentRoleId) {
				path.push(role.parentRoleId);
				currentId = role.parentRoleId;
			} else {
				currentId = null;
			}
		}

		return path;
	}

	/**
	 * Asigna un rol padre a un rol (crear relación de herencia)
	 * Valida que no haya ciclos
	 */
	async setParentRole(
		childRoleId: string,
		parentRoleId: string | null
	): Promise<Role> {
		// Validar que no sea el mismo rol
		if (childRoleId === parentRoleId) {
			throw new BadRequestException('A role cannot be its own parent');
		}

		// Validar que no haya ciclos (parentRoleId no debe ser descendiente de childRoleId)
		if (parentRoleId) {
			const parentPath = await this.getRoleHierarchyPath(parentRoleId);
			if (parentPath.includes(childRoleId)) {
				throw new BadRequestException(
					'Setting this parent would create a circular role hierarchy'
				);
			}
		}

		const updated = await this.prisma.role.update({
			where: { id: childRoleId },
			data: { parentRoleId },
		});

		// Invalidar caché
		this.permissionCache.delete(childRoleId);
		this.cacheTimestamps.delete(childRoleId);
		this.logger.log(
			`Parent role updated for role ${childRoleId}. Cache invalidated.`
		);

		return updated;
	}

	/**
	 * Invalida el caché de un rol
	 */
	invalidateCache(roleId: string): void {
		this.permissionCache.delete(roleId);
		this.cacheTimestamps.delete(roleId);
	}

	/**
	 * Invalida el caché de un rol y sus descendientes
	 */
	async invalidateCacheRecursive(roleId: string): Promise<void> {
		this.invalidateCache(roleId);

		// Encontrar todos los roles que tienen este como padre
		const children = await this.prisma.role.findMany({
			where: { parentRoleId: roleId },
			select: { id: true },
		});

		for (const child of children) {
			await this.invalidateCacheRecursive(child.id);
		}
	}

	/**
	 * Detecta ciclos en la jerarquía de roles
	 */
	async validateHierarchyNoCycles(): Promise<boolean> {
		const allRoles = await this.prisma.role.findMany({
			select: { id: true, parentRoleId: true },
		});

		const visited = new Set<string>();
		const recursionStack = new Set<string>();

		for (const role of allRoles) {
			if (!visited.has(role.id)) {
				if (this.hasCycleDFS(role.id, visited, recursionStack, allRoles)) {
					return false;
				}
			}
		}

		return true;
	}

	private hasCycleDFS(
		roleId: string,
		visited: Set<string>,
		recursionStack: Set<string>,
		allRoles: Array<{ id: string; parentRoleId: string | null }>
	): boolean {
		visited.add(roleId);
		recursionStack.add(roleId);

		const parentId = allRoles.find(r => r.id === roleId)?.parentRoleId;
		if (parentId) {
			if (!visited.has(parentId)) {
				if (this.hasCycleDFS(parentId, visited, recursionStack, allRoles)) {
					return true;
				}
			} else if (recursionStack.has(parentId)) {
				return true;
			}
		}

		recursionStack.delete(roleId);
		return false;
	}
}
