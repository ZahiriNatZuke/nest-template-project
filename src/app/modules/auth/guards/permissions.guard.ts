import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { RoleHierarchyService } from '@app/core/services/role-hierarchy/role-hierarchy.service';
import { AuthRequest } from '@app/core/types/app-request';
import {
	CanActivate,
	ExecutionContext,
	ForbiddenException,
	Injectable,
	Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { User } from '@prisma/client';

export const PERMISSIONS_METADATA_KEY = 'permissions';

function matchesWildcard(granted: string, required: string): boolean {
	// soporta 'resource:all' y 'resource:*'
	const [grRes, grAct] = granted.split(':');
	const [reqRes, reqAct] = required.split(':');
	if (grRes !== reqRes) return false;
	return grAct === reqAct || grAct === 'all' || grAct === '*';
}

@Injectable()
export class PermissionsGuard implements CanActivate {
	private readonly logger = new Logger(PermissionsGuard.name);

	constructor(
		private reflector: Reflector,
		private prisma: PrismaService,
		private roleHierarchyService: RoleHierarchyService
	) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const required: string[] =
			this.reflector.get<string[]>(
				PERMISSIONS_METADATA_KEY,
				context.getHandler()
			) || [];
		if (required.length === 0) return true;

		const request: AuthRequest = context.switchToHttp().getRequest();
		const user = request.user as Partial<User> & { perm?: string[] };
		if (!user?.id) throw new ForbiddenException('Unauthorized principal');

		// Usar permisos cacheados del JWT si están presentes
		let granted: string[] | null = Array.isArray(user?.perm) ? user.perm : null;

		if (!granted) {
			// Fallback: consultar DB y resolver herencia
			const userRoles = await this.prisma.userRole.findMany({
				where: { userId: user.id },
				select: { roleId: true },
			});

			const grantedSet = new Set<string>();

			// Para cada rol, resolver permisos incluyendo herencia (2.1)
			for (const ur of userRoles) {
				const inheritedPermissions =
					await this.roleHierarchyService.getInheritedPermissions(ur.roleId);
				for (const permId of inheritedPermissions) {
					grantedSet.add(permId);
				}
			}

			// Obtener identifiers de permisos
			const permissionIds = Array.from(grantedSet);
			const permissions = await this.prisma.permission.findMany({
				where: { id: { in: permissionIds } },
				select: { identifier: true },
			});

			granted = permissions.map(p => p.identifier);
		}

		const grantedArr = granted ?? [];
		const ok = required.every(perm =>
			grantedArr.some(g => g === perm || matchesWildcard(g, perm))
		);

		if (!ok) {
			this.logger.warn(
				`User ${user.id} denied access. Required: ${required.join(', ')}, Granted: ${grantedArr.join(', ')}`
			);
			throw new ForbiddenException('Insufficient permissions');
		}

		return true;
	}
}
