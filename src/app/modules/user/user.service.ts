import { AuditService } from '@app/core/services/audit/audit.service';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { ZodValidationException } from '@app/core/utils/zod';
import { CreateUserZodDto } from '@app/modules/user/dto/create-user.dto';
import { UpdateUserZodDto } from '@app/modules/user/dto/update-user.dto';
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { Prisma, User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { z } from 'zod';
import type { AuthService } from '../auth/auth.service';

export interface UserPagination {
	skip?: number;
	take?: number;
	where?: Prisma.UserWhereInput;
	orderBy?: Prisma.UserOrderByWithRelationInput;
}

@Injectable()
export class UserService {
	constructor(
		private prisma: PrismaService,
		private auditService: AuditService,
		private moduleRef: ModuleRef
	) {}

	async findOne(
		userWhereUniqueInput: Prisma.UserWhereUniqueInput,
		canThrow = false
	): Promise<User | null> {
		if (canThrow)
			return this.prisma.user.findUniqueOrThrow({
				where: userWhereUniqueInput,
				include: { userRoles: { include: { role: true } } },
			});

		return this.prisma.user.findUnique({
			where: userWhereUniqueInput,
			include: { userRoles: { include: { role: true } } },
		});
	}

	async findMany(params: UserPagination): Promise<[number, User[]]> {
		const { skip, take, where, orderBy } = params;
		return this.prisma.$transaction([
			this.prisma.user.count({
				where,
				orderBy,
			}),
			this.prisma.user.findMany({
				skip,
				take,
				where,
				orderBy,
				include: { userRoles: { include: { role: true } } },
			}),
		]);
	}

	async create(data: CreateUserZodDto): Promise<User> {
		return this.createUser(data);
	}

	async update(params: {
		where: Prisma.UserWhereUniqueInput;
		data: UpdateUserZodDto;
	}): Promise<User> {
		const { where, data } = params;
		await this.prisma.user.update({
			where,
			data,
		});

		return this.prisma.user.findUniqueOrThrow({
			where,
			include: { userRoles: { include: { role: true } } },
		});
	}

	async delete(where: Prisma.UserWhereUniqueInput): Promise<User> {
		return this.prisma.user.delete({
			where,
		});
	}

	private async createUser(payload: CreateUserZodDto) {
		const { password, ...input } = payload;
		const pwd = await bcrypt.hash(password, bcrypt.genSaltSync(16));
		const userRole = await this.prisma.role.findUniqueOrThrow({
			where: { identifier: 'USER_ROLE' },
		});

		if (userRole) {
			try {
				const user = await this.prisma.user.create({
					data: {
						...input,
						password: pwd,
						confirmed: true,
						userRoles: {
							create: {
								roleId: userRole.id,
							},
						},
					},
				});

				return this.prisma.user.findUniqueOrThrow({
					where: { id: user.id },
					include: { userRoles: { include: { role: true } } },
				});
			} catch (_e) {
				throw new ZodValidationException(
					new z.ZodError([
						{
							code: 'custom',
							path: [],
							message: 'Create user failure',
						},
					])
				);
			}
		} else {
			throw new HttpException(
				{ message: 'Default Role not found' },
				HttpStatus.NOT_FOUND
			);
		}
	}

	async assignRole(userId: string, roleId: string): Promise<User> {
		// Verificar que el usuario existe
		await this.prisma.user.findUniqueOrThrow({ where: { id: userId } });

		// Verificar que el rol existe
		await this.prisma.role.findUniqueOrThrow({ where: { id: roleId } });

		// Crear la relación si no existe
		await this.prisma.userRole.upsert({
			where: {
				userId_roleId: {
					userId,
					roleId,
				},
			},
			create: {
				userId,
				roleId,
			},
			update: {},
		});

		// Audit log
		await this.auditService.log({
			action: 'user.role.assign',
			entityType: 'user',
			entityId: userId,
			metadata: { roleId },
		});

		// Invalidar sesiones para refrescar permisos
		const authService = this.moduleRef.get('AuthService', {
			strict: false,
		}) as AuthService;
		if (authService) {
			await (authService as AuthService).invalidateAllUserSessions(userId);
		}

		return this.prisma.user.findUniqueOrThrow({
			where: { id: userId },
			include: { userRoles: { include: { role: true } } },
		});
	}

	async removeRole(userId: string, roleId: string): Promise<User> {
		// Verificar que el usuario existe
		await this.prisma.user.findUniqueOrThrow({ where: { id: userId } });

		// Eliminar la relación
		await this.prisma.userRole.delete({
			where: {
				userId_roleId: {
					userId,
					roleId,
				},
			},
		});

		// Audit log
		await this.auditService.log({
			action: 'user.role.remove',
			entityType: 'user',
			entityId: userId,
			metadata: { roleId },
		});

		// Invalidar sesiones para refrescar permisos
		const authService = this.moduleRef.get('AuthService', {
			strict: false,
		}) as AuthService;
		if (authService) {
			await (authService as AuthService).invalidateAllUserSessions(userId);
		}

		return this.prisma.user.findUniqueOrThrow({
			where: { id: userId },
			include: { userRoles: { include: { role: true } } },
		});
	}
}
