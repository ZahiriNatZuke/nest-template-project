import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { ForbiddenException, Injectable, Logger } from '@nestjs/common';

/**
 * Niveles de acceso para recursos
 */
export type AccessLevel = 'owner' | 'editor' | 'viewer';

/**
 * Servicio para gestionar ownership de recursos (2.2 - Resource-Level Authorization)
 * Permite control de acceso basado en propiedad del recurso
 */
@Injectable()
export class ResourceOwnershipService {
	private readonly logger = new Logger(ResourceOwnershipService.name);

	constructor(private prisma: PrismaService) {}

	/**
	 * Verifica si un usuario es propietario de un recurso
	 */
	async isOwner(
		userId: string,
		resourceType: string,
		resourceId: string
	): Promise<boolean> {
		const ownership = await this.prisma.resourceOwnership.findUnique({
			where: {
				userId_resourceType_resourceId: {
					userId,
					resourceType,
					resourceId,
				},
			},
		});

		return ownership?.accessLevel === 'owner';
	}

	/**
	 * Obtiene el nivel de acceso que tiene un usuario sobre un recurso
	 */
	async getAccessLevel(
		userId: string,
		resourceType: string,
		resourceId: string
	): Promise<AccessLevel | null> {
		const ownership = await this.prisma.resourceOwnership.findUnique({
			where: {
				userId_resourceType_resourceId: {
					userId,
					resourceType,
					resourceId,
				},
			},
		});

		return (ownership?.accessLevel as AccessLevel) || null;
	}

	/**
	 * Verifica si un usuario tiene acceso a un recurso (de cualquier nivel)
	 */
	async hasAccess(
		userId: string,
		resourceType: string,
		resourceId: string
	): Promise<boolean> {
		const level = await this.getAccessLevel(userId, resourceType, resourceId);
		return level !== null;
	}

	/**
	 * Verifica si un usuario tiene al menos el nivel de acceso especificado
	 * Jerarquía: owner > editor > viewer
	 */
	async hasAccessLevel(
		userId: string,
		resourceType: string,
		resourceId: string,
		requiredLevel: AccessLevel
	): Promise<boolean> {
		const level = await this.getAccessLevel(userId, resourceType, resourceId);

		if (!level) {
			return false;
		}

		const hierarchy: Record<AccessLevel, number> = {
			owner: 3,
			editor: 2,
			viewer: 1,
		};

		return hierarchy[level] >= hierarchy[requiredLevel];
	}

	/**
	 * Asigna ownership de un recurso a un usuario
	 */
	async assignOwnership(
		userId: string,
		resourceType: string,
		resourceId: string,
		accessLevel: AccessLevel = 'owner'
	): Promise<void> {
		await this.prisma.resourceOwnership.upsert({
			where: {
				userId_resourceType_resourceId: {
					userId,
					resourceType,
					resourceId,
				},
			},
			update: { accessLevel },
			create: {
				userId,
				resourceType,
				resourceId,
				accessLevel,
			},
		});

		this.logger.log(
			`Assigned ${accessLevel} access to user ${userId} for ${resourceType}/${resourceId}`
		);
	}

	/**
	 * Revoca acceso de un usuario a un recurso
	 */
	async revokeAccess(
		userId: string,
		resourceType: string,
		resourceId: string
	): Promise<void> {
		await this.prisma.resourceOwnership.deleteMany({
			where: {
				userId,
				resourceType,
				resourceId,
			},
		});

		this.logger.log(
			`Revoked access from user ${userId} for ${resourceType}/${resourceId}`
		);
	}

	/**
	 * Obtiene todos los usuarios que tienen acceso a un recurso
	 */
	async getResourceAccessors(
		resourceType: string,
		resourceId: string
	): Promise<
		Array<{
			userId: string;
			accessLevel: AccessLevel;
		}>
	> {
		const ownerships = await this.prisma.resourceOwnership.findMany({
			where: {
				resourceType,
				resourceId,
			},
			select: {
				userId: true,
				accessLevel: true,
			},
		});

		return ownerships as Array<{
			userId: string;
			accessLevel: AccessLevel;
		}>;
	}

	/**
	 * Obtiene todos los recursos a los que tiene acceso un usuario
	 */
	async getUserResources(
		userId: string,
		resourceType?: string
	): Promise<
		Array<{
			resourceType: string;
			resourceId: string;
			accessLevel: AccessLevel;
		}>
	> {
		const ownerships = await this.prisma.resourceOwnership.findMany({
			where: {
				userId,
				...(resourceType && { resourceType }),
			},
			select: {
				resourceType: true,
				resourceId: true,
				accessLevel: true,
			},
		});

		return ownerships as Array<{
			resourceType: string;
			resourceId: string;
			accessLevel: AccessLevel;
		}>;
	}

	/**
	 * Transfiere la propiedad de un recurso de un usuario a otro
	 */
	async transferOwnership(
		fromUserId: string,
		toUserId: string,
		resourceType: string,
		resourceId: string
	): Promise<void> {
		// Verificar que el usuario actual es propietario
		const isOwner = await this.isOwner(fromUserId, resourceType, resourceId);
		if (!isOwner) {
			throw new ForbiddenException('Only the owner can transfer ownership');
		}

		// Revocar acceso del usuario anterior
		await this.revokeAccess(fromUserId, resourceType, resourceId);

		// Asignar ownership al nuevo usuario
		await this.assignOwnership(toUserId, resourceType, resourceId, 'owner');

		this.logger.log(
			`Transferred ownership of ${resourceType}/${resourceId} from ${fromUserId} to ${toUserId}`
		);
	}

	/**
	 * Cambiar nivel de acceso de un usuario para un recurso
	 */
	async updateAccessLevel(
		userId: string,
		resourceType: string,
		resourceId: string,
		newLevel: AccessLevel
	): Promise<void> {
		const existing = await this.prisma.resourceOwnership.findUnique({
			where: {
				userId_resourceType_resourceId: {
					userId,
					resourceType,
					resourceId,
				},
			},
		});

		if (!existing) {
			throw new Error(
				`User ${userId} does not have access to ${resourceType}/${resourceId}`
			);
		}

		await this.prisma.resourceOwnership.update({
			where: {
				userId_resourceType_resourceId: {
					userId,
					resourceType,
					resourceId,
				},
			},
			data: { accessLevel: newLevel },
		});

		this.logger.log(
			`Updated access level for user ${userId} on ${resourceType}/${resourceId} to ${newLevel}`
		);
	}

	/**
	 * Elimina todos los recursos de un tipo específico cuando se elimina
	 */
	async cleanupResourceOwnerships(
		resourceType: string,
		resourceId: string
	): Promise<void> {
		await this.prisma.resourceOwnership.deleteMany({
			where: {
				resourceType,
				resourceId,
			},
		});

		this.logger.log(
			`Cleaned up ownership records for ${resourceType}/${resourceId}`
		);
	}
}
