import { applyDecorators, SetMetadata } from '@nestjs/common';
import { AuthRole } from '../enums/auth-role';

export const Roles = (roles: AuthRole[]) =>
  applyDecorators(SetMetadata('roles', roles));
