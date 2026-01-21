import { SetMetadata } from '@nestjs/common';
import {
	RESOURCE_OWNER_METADATA_KEY,
	ResourceOwnerMetadata,
} from '../guards/resource-owner.guard';

/**
 * Decorador para requerir ownership de un recurso
 * Uso:
 * @Patch(':id')
 * @RequireOwnership({resourceType: 'user', resourceIdParam: 'id', accessLevel: 'owner'})
 * async updateUser(@Param('id') id: string) { ... }
 */
export const RequireOwnership = (metadata: ResourceOwnerMetadata) =>
	SetMetadata(RESOURCE_OWNER_METADATA_KEY, metadata);
