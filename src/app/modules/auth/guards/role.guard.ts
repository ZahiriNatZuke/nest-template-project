import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { User } from '@prisma/client';
import { AuthRole } from '../enums/auth-role';
import { PrismaService } from '../../../core/modules/prisma/prisma.service';
import { FastifyRequest } from 'fastify';

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(private reflector: Reflector, private prisma: PrismaService) {
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const authRoles: AuthRole[] = this.reflector.get<AuthRole[]>(
      'roles',
      context.getHandler(),
    );
    if ( !authRoles ) return true;
    const request: FastifyRequest & { user: User } = context.switchToHttp().getRequest();
    const user: User = request.user;
    const roleModel = await this.prisma.role.findUniqueOrThrow({
      where: { id: user.roleId },
    });
    return authRoles.includes(<AuthRole>roleModel.identifier);
  }
}
