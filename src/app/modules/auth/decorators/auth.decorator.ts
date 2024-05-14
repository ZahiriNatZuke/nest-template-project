import { applyDecorators, HttpStatus, UseGuards } from '@nestjs/common';
import { AuthRole } from '../enums/auth-role';
import { Roles } from './role.decorator';
import { VerifyJwtGuard } from '../guards/verify-jwt.guard';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RoleGuard } from '../guards/role.guard';
import { ApiBearerAuth, ApiUnauthorizedResponse } from '@nestjs/swagger';

export function Auth(roles: AuthRole[]) {
  return applyDecorators(
    Roles(roles),
    UseGuards(VerifyJwtGuard, JwtAuthGuard, RoleGuard),
    ApiBearerAuth('Authorization'),
    ApiUnauthorizedResponse({
      description: 'Unauthorized',
      status: HttpStatus.UNAUTHORIZED,
    }),
  );
}
