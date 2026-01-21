import { ResourceOwnershipService } from '@app/core/services/resource-ownership/resource-ownership.service';
import { AppRequest } from '@app/core/types/app-request';
import {
	BadRequestException,
	CanActivate,
	ExecutionContext,
	ForbiddenException,
	Injectable,
	Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { User } from '@prisma/client';

export const RESOURCE_OWNER_METADATA_KEY = 'resource_owner';

export interface ResourceOwnerMetadata {
	resourceType: string; // tipo de recurso (e.g., 'user', 'document')
	resourceIdParam?: string; // nombre del parámetro que contiene el ID (ej: 'id')
	accessLevel?: 'viewer' | 'editor' | 'owner'; // nivel mínimo de acceso (default: 'owner')
}

/**
 * Guard para validar ownership de recursos (2.2 - Resource-Level Authorization)
 * Uso: @UseGuards(ResourceOwnerGuard) @Authz('users:read')
 * 		@RequireOwnership({resourceType: 'user', resourceIdParam: 'id', accessLevel: 'owner'})
 */
@Injectable()
export class ResourceOwnerGuard implements CanActivate {
	private readonly logger = new Logger(ResourceOwnerGuard.name);

	constructor(
		private reflector: Reflector,
		private resourceOwnershipService: ResourceOwnershipService
	) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const metadata = this.reflector.get<ResourceOwnerMetadata>(
			RESOURCE_OWNER_METADATA_KEY,
			context.getHandler()
		);

		// Si no hay metadata, permitir
		if (!metadata) {
			return true;
		}

		const request: AppRequest = context.switchToHttp().getRequest();
		const user = request.user as Partial<User>;

		if (!user?.id) {
			throw new ForbiddenException('Unauthorized principal');
		}

		// Obtener ID del recurso desde parámetros o body
		const resourceId = this.getResourceId(request, metadata.resourceIdParam);
		if (!resourceId) {
			throw new BadRequestException(
				`Resource ID not found. Expected parameter: ${metadata.resourceIdParam || 'id'}`
			);
		}

		// Validar acceso
		const accessLevel = metadata.accessLevel || 'owner';
		const hasAccess = await this.resourceOwnershipService.hasAccessLevel(
			user.id,
			metadata.resourceType,
			resourceId,
			accessLevel
		);

		if (!hasAccess) {
			this.logger.warn(
				`User ${user.id} denied resource access: ${metadata.resourceType}/${resourceId} (required: ${accessLevel})`
			);
			throw new ForbiddenException(
				`Insufficient access level. Required: ${accessLevel}`
			);
		}

		// Agregar información del recurso al request para uso posterior
		request.resourceOwnership = {
			resourceType: metadata.resourceType,
			resourceId,
			accessLevel,
		};

		return true;
	}

	private getResourceId(
		request: AppRequest,
		resourceIdParam?: string
	): string | undefined {
		const paramName = resourceIdParam || 'id';

		// Intentar obtener del path params
		if (request.params?.[paramName]) {
			return request.params[paramName];
		}

		// Intentar obtener del body
		if (request.body?.[paramName]) {
			return request.body[paramName];
		}

		// Intentar obtener del query
		if (request.query?.[paramName]) {
			return String(request.query[paramName]);
		}

		return undefined;
	}
}
