import { SetMetadata } from '@nestjs/common';
import { ABAC_METADATA_KEY, AbacMetadata } from '../guards/abac.guard';

/**
 * Decorador para requerir cumplimiento de una política ABAC
 * Uso:
 * @Patch(':id')
 * @RequirePolicy({
 *   policyIdentifier: 'can_edit_active_users',
 *   contextBuilder: (req, user) => ({
 *     userId: user.id,
 *     userStatus: 'active'
 *   })
 * })
 * async updateUser(@Param('id') id: string) { ... }
 */
export const RequirePolicy = (metadata: AbacMetadata) =>
	SetMetadata(ABAC_METADATA_KEY, metadata);
