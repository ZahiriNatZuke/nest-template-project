import { AuthRequest } from '@app/core/types';
import { AuthRole } from '@app/modules/auth/enums';
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PrismaService } from 'nestjs-prisma';

@Injectable()
export class RoleGuard implements CanActivate {
	constructor(
		private reflector: Reflector,
		private prisma: PrismaService
	) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const authRoles: AuthRole[] = this.reflector.get<AuthRole[]>(
			'roles',
			context.getHandler()
		);
		if (!authRoles) return true;
		const request: AuthRequest = context.switchToHttp().getRequest();
		const user = request.user;
		const roleModel = await this.prisma.role.findUniqueOrThrow({
			where: { id: user.roleId },
		});
		return authRoles.includes(<AuthRole>roleModel.identifier);
	}
}
