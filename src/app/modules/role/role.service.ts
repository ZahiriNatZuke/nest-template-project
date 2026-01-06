import { AuditService } from '@app/core/services/audit/audit.service';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { ZodValidationException } from '@app/core/utils/zod';
import { CreateRoleZodDto } from '@app/modules/role/dto/create-role.dto';
import { UpdateRoleZodDto } from '@app/modules/role/dto/update-role.dto';
import { Injectable } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { Prisma, Role } from '@prisma/client';
import { z } from 'zod';
import type { AuthService } from '../auth/auth.service';

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

	async assignPermission(roleId: string, permissionId: string): Promise<Role> {
		// Verificar que el rol existe
		await this.prisma.role.findUniqueOrThrow({
			where: { id: roleId },
		});

		// Verificar que el permiso exists
		await this.prisma.permission.findUniqueOrThrow({
			where: { id: permissionId },
		});

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
		await this.prisma.role.findUniqueOrThrow({ where: { id: roleId } });

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
		const authService = this.moduleRef.get('AuthService', {
			strict: false,
		}) as AuthService;
		for (const ur of userRoles) {
			await (authService as AuthService).invalidateAllUserSessions(ur.userId);
		}
	}
}
