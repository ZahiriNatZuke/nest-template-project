import { Roles } from '@app/modules/auth/decorators';
import {
	JwtAuthGuard,
	RoleGuard,
	VerifyJwtGuard,
} from '@app/modules/auth/guards';
import { HttpStatus, UseGuards, applyDecorators } from '@nestjs/common';
import { ApiBearerAuth, ApiUnauthorizedResponse } from '@nestjs/swagger';
import { AuthRole } from '../enums/auth-role';

export function Auth(roles: AuthRole[]) {
	return applyDecorators(
		Roles(roles),
		UseGuards(VerifyJwtGuard, JwtAuthGuard, RoleGuard),
		ApiBearerAuth('Authorization'),
		ApiUnauthorizedResponse({
			description: 'Unauthorized',
			status: HttpStatus.UNAUTHORIZED,
		})
	);
}
