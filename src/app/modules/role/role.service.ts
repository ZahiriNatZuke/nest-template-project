import { AuditService } from '@app/core/services/audit/audit.service';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { ZodValidationException } from '@app/core/utils/zod';
import { CreateRoleZodDto } from '@app/modules/role/dto/create-role.dto';
import { UpdateRoleZodDto } from '@app/modules/role/dto/update-role.dto';
import { Injectable, NotFoundException } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { Prisma, Role } from '@prisma/client';
import { z } from 'zod';
import type { TokenBlacklistService } from '../auth/services/token-blacklist.service';

@Injectable()
export class RoleService {
	constructor(
		private prisma: PrismaService,
		private auditService: AuditService,
		private moduleRef: ModuleRef
	) {}

	async findMany() {
		return this.prisma.role.findMany();
	}

	async findOne(
		roleWhereUniqueInput: Prisma.RoleWhereUniqueInput,
		canThrow = false
	): Promise<Role | null> {
		if (canThrow)
			return this.prisma.role.findUniqueOrThrow({
				where: roleWhereUniqueInput,
				include: { userRoles: { include: { user: true } } },
			});

		return this.prisma.role.findUnique({
			where: roleWhereUniqueInput,
			include: { userRoles: { include: { user: true } } },
		});
	}

	async create(data: CreateRoleZodDto): Promise<Role> {
		try {
			return this.prisma.role.create({ data });
		} catch (_e) {
			throw new ZodValidationException(
				new z.ZodError([
					{
						code: 'custom',
						path: [],
						message: 'Create role failure',
					},
				])
			);
		}
	}

	async update(params: {
		where: Prisma.RoleWhereUniqueInput;
		data: UpdateRoleZodDto;
	}): Promise<Role> {
		const { where, data } = params;
		await this.prisma.role.update({
			where,
			data,
		});

		return this.prisma.role.findUniqueOrThrow({
			where,
			include: { userRoles: { include: { user: true } } },
		});
	}

	async delete(where: Prisma.RoleWhereUniqueInput): Promise<Role> {
		return this.prisma.role.delete({ where });
	}

	/**
	 * Resolves a role for the two routes that take `:id` with no pipe in front
	 * of them.
	 *
	 * The uuid is checked here rather than left to the database: Postgres
	 * rejects a malformed uuid with a driver error, and neither that nor
	 * `findUniqueOrThrow`'s rejection is an HttpException — the global filter
	 * can only render either as 500. A genuine database failure still
	 * propagates, which is why this validates instead of catching.
	 */
	private async findRoleOrThrow(roleId: string): Promise<{ id: string }> {
		if (!z.uuid().safeParse(roleId).success)
			throw new NotFoundException('Role not found');

		const role = await this.prisma.role.findUnique({
			where: { id: roleId },
			select: { id: true },
		});
		if (!role) throw new NotFoundException('Role not found');
		return role;
	}

	/** Same, for the permission side of the join. */
	private async findPermissionOrThrow(
		permissionId: string
	): Promise<{ id: string }> {
		if (!z.uuid().safeParse(permissionId).success)
			throw new NotFoundException('Permission not found');

		const permission = await this.prisma.permission.findUnique({
			where: { id: permissionId },
			select: { id: true },
		});
		if (!permission) throw new NotFoundException('Permission not found');
		return permission;
	}

	async assignPermission(roleId: string, permissionId: string): Promise<Role> {
		// Verificar que el rol existe
		await this.findRoleOrThrow(roleId);

		// Verificar que el permiso exists
		await this.findPermissionOrThrow(permissionId);

		// Crear la relación si no existe
		await this.prisma.rolePermission.upsert({
			where: {
				roleId_permissionId: {
					roleId,
					permissionId,
				},
			},
			create: {
				roleId,
				permissionId,
			},
			update: {},
		});

		// Audit log
		await this.auditService.log({
			action: 'role.permission.assign',
			entityType: 'role',
			entityId: roleId,
			metadata: { permissionId },
		});

		// Invalidar sesiones de todos los usuarios con este rol
		await this.invalidateUsersWithRole(roleId);

		return this.prisma.role.findUniqueOrThrow({ where: { id: roleId } });
	}

	async removePermission(roleId: string, permissionId: string): Promise<Role> {
		// Verificar que el rol existe
		await this.findRoleOrThrow(roleId);
		await this.findPermissionOrThrow(permissionId);

		// Que el permiso exista no implica que este rol lo tenga, y borrar una
		// fila ausente es el mismo 500 que todo lo demás.
		const assignment = await this.prisma.rolePermission.findUnique({
			where: { roleId_permissionId: { roleId, permissionId } },
		});
		if (!assignment)
			throw new NotFoundException('Role does not hold that permission');

		// Eliminar la relación
		await this.prisma.rolePermission.delete({
			where: {
				roleId_permissionId: {
					roleId,
					permissionId,
				},
			},
		});

		// Audit log
		await this.auditService.log({
			action: 'role.permission.remove',
			entityType: 'role',
			entityId: roleId,
			metadata: { permissionId },
		});

		// Invalidar sesiones de todos los usuarios con este rol
		await this.invalidateUsersWithRole(roleId);

		return this.prisma.role.findUniqueOrThrow({ where: { id: roleId } });
	}

	private async invalidateUsersWithRole(roleId: string) {
		const userRoles = await this.prisma.userRole.findMany({
			where: { roleId },
			select: { userId: true },
		});
		const tokenBlacklist = this.moduleRef.get('TokenBlacklistService', {
			strict: false,
		}) as TokenBlacklistService;
		for (const ur of userRoles) {
			await tokenBlacklist?.invalidateAllUserSessions(ur.userId);
		}
	}
}
