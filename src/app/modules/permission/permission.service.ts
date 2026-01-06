import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Injectable } from '@nestjs/common';
import { Permission, Prisma } from '@prisma/client';

@Injectable()
export class PermissionService {
	constructor(private prisma: PrismaService) {}

	async findMany(): Promise<Permission[]> {
		return this.prisma.permission.findMany({
			orderBy: [{ resource: 'asc' }, { action: 'asc' }],
		});
	}

	async findOne(
		where: Prisma.PermissionWhereUniqueInput
	): Promise<Permission | null> {
		return this.prisma.permission.findUnique({ where });
	}

	async create(data: {
		resource: string;
		action: string;
		description?: string;
	}): Promise<Permission> {
		const identifier = `${data.resource}:${data.action}`;
		return this.prisma.permission.create({
			data: {
				resource: data.resource,
				action: data.action,
				description: data.description,
				identifier,
			},
		});
	}

	async update(params: {
		where: Prisma.PermissionWhereUniqueInput;
		data: Prisma.PermissionUpdateInput;
	}): Promise<Permission> {
		const { where, data } = params;
		return this.prisma.permission.update({ where, data });
	}

	async delete(where: Prisma.PermissionWhereUniqueInput): Promise<Permission> {
		return this.prisma.permission.delete({ where });
	}
}
