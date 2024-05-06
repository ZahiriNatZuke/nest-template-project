import { applyDecorators } from '@nestjs/common';
import { AuthRole } from '../enums/auth-role';

export function Auth(roles: AuthRole[]) {
  return applyDecorators(
    // Roles(roles),
    // UseGuards(VerifyJwtGuard, JwtAuthGuard, RoleGuard),
    // ApiBearerAuth('Authorization'),
    // ApiUnauthorizedResponse({
    //   description: 'Unauthorized',
    //   statusCode: HttpStatus.UNAUTHORIZED,
    // }),
  );
}
