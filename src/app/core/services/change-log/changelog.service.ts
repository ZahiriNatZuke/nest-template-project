import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

@Injectable()
export class ChangeLogService {
	constructor(private prisma: PrismaService) {}

	async logChange(params: {
		userId?: string;
		action: string;
		entityType: string;
		entityId?: string;
		before?: Record<string, unknown> | null;
		after?: Record<string, unknown> | null;
	}) {
		const { userId, action, entityType, entityId, before, after } = params;
		await this.prisma.auditChangeLog.create({
			data: {
				userId,
				action,
				entityType,
				entityId,
				before: before ? (before as Prisma.InputJsonValue) : undefined,
				after: after ? (after as Prisma.InputJsonValue) : undefined,
			},
		});
	}
}
