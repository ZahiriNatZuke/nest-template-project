import { EncryptionService } from '@app/core/services/encryption/encryption.service';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Injectable, Logger } from '@nestjs/common';
import { Prisma } from '@prisma/client';

@Injectable()
export class AuditService {
	private readonly logger = new Logger(AuditService.name);

	constructor(
		private prisma: PrismaService,
		private encryptionService: EncryptionService
	) {}

	async log(params: {
		userId?: string;
		action: string;
		entityType: string;
		entityId?: string;
		metadata?: Record<string, string | number | boolean>;
		ipAddress?: string;
		userAgent?: string;
		encryptMetadata?: boolean; // New parameter to control encryption
	}) {
		const {
			userId,
			action,
			entityType,
			entityId,
			metadata,
			ipAddress,
			userAgent,
			encryptMetadata = false,
		} = params;

		// Encrypt metadata if requested and metadata exists
		let finalMetadata: Prisma.InputJsonValue | undefined;
		if (metadata) {
			if (encryptMetadata) {
				try {
					const encryptedData =
						await this.encryptionService.encryptObject(metadata);
					finalMetadata = { encrypted: encryptedData } as Prisma.InputJsonValue;
				} catch (error) {
					this.logger.error('Failed to encrypt audit metadata', error);
					// Fallback to unencrypted metadata
					finalMetadata = metadata as Prisma.InputJsonValue;
				}
			} else {
				finalMetadata = metadata as Prisma.InputJsonValue;
			}
		}

		await this.prisma.auditLog.create({
			data: {
				userId,
				action,
				entityType,
				entityId,
				metadata: finalMetadata,
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

	/**
	 * Decrypt metadata from an audit log entry
	 * Returns the original metadata if it's not encrypted
	 */
	async decryptMetadata(
		metadata: Prisma.JsonValue
	): Promise<Record<string, unknown> | null> {
		if (!metadata) {
			return null;
		}

		// Check if metadata is encrypted
		const metadataObj = metadata as Record<string, unknown>;
		if (
			typeof metadataObj === 'object' &&
			'encrypted' in metadataObj &&
			typeof metadataObj.encrypted === 'string'
		) {
			try {
				return await this.encryptionService.decryptObject(
					metadataObj.encrypted
				);
			} catch (error) {
				this.logger.error('Failed to decrypt audit metadata', error);
				return null;
			}
		}

		// Return unencrypted metadata
		return metadataObj;
	}
}
