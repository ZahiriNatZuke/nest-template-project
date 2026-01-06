import { JwtAuthGuard } from '@app/modules/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from '@app/modules/auth/guards/permissions.guard';
import { VerifyJwtGuard } from '@app/modules/auth/guards/verify-jwt.guard';
import { applyDecorators, UseGuards } from '@nestjs/common';
import {
	ApiBearerAuth,
	ApiForbiddenResponse,
	ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { RequirePermissions } from './permissions.decorator';

export function Authz(...permissions: string[]) {
	return applyDecorators(
		RequirePermissions(...permissions),
		UseGuards(VerifyJwtGuard, JwtAuthGuard, PermissionsGuard),
		ApiBearerAuth('Authorization'),
		ApiUnauthorizedResponse({ description: 'Unauthorized' }),
		ApiForbiddenResponse({ description: 'Forbidden' })
	);
}
