import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

@Injectable()
export class AuditService {
	constructor(private prisma: PrismaService) {}

	async log(params: {
		userId?: string;
		action: string;
		entityType: string;
		entityId?: string;
		metadata?: Record<string, string | number | boolean>;
		ipAddress?: string;
		userAgent?: string;
	}) {
		const {
			userId,
			action,
			entityType,
			entityId,
			metadata,
			ipAddress,
			userAgent,
		} = params;

		await this.prisma.auditLog.create({
			data: {
				userId,
				action,
				entityType,
				entityId,
				metadata: metadata ? (metadata as Prisma.InputJsonValue) : undefined,
				ipAddress,
				userAgent,
			},
		});
	}

	async findAll(params?: {
		userId?: string;
		action?: string;
		entityType?: string;
		skip?: number;
		take?: number;
	}) {
		const { userId, action, entityType, skip, take } = params || {};

		return this.prisma.auditLog.findMany({
			where: {
				userId,
				action,
				entityType,
			},
			orderBy: { createdAt: 'desc' },
			skip,
			take,
		});
	}

	async findManyPaged(params: {
		userId?: string;
		action?: string;
		entityType?: string;
		skip?: number;
		take?: number;
	}) {
		const { userId, action, entityType, skip, take } = params;
		return this.prisma.$transaction([
			this.prisma.auditLog.count({
				where: { userId, action, entityType },
			}),
			this.prisma.auditLog.findMany({
				where: { userId, action, entityType },
				orderBy: { createdAt: 'desc' },
				skip,
				take,
			}),
		]);
	}
}
