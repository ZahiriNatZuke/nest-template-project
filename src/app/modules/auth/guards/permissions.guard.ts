import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { AuthRequest } from '@app/core/types/app-request';
import {
	CanActivate,
	ExecutionContext,
	ForbiddenException,
	Injectable,
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
	constructor(
		private reflector: Reflector,
		private prisma: PrismaService
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
			// Fallback: consultar DB
			const userRoles = await this.prisma.userRole.findMany({
				where: { userId: user.id },
				include: {
					role: {
						include: {
							rolePermissions: {
								include: { permission: true },
							},
						},
					},
				},
			});
			const grantedSet = new Set<string>();
			for (const ur of userRoles) {
				for (const rp of ur.role.rolePermissions) {
					grantedSet.add(rp.permission.identifier);
				}
			}
			granted = Array.from(grantedSet);
		}

		const grantedArr = granted ?? [];
		const ok = required.every(perm =>
			grantedArr.some(g => g === perm || matchesWildcard(g, perm))
		);
		if (!ok) {
			throw new ForbiddenException('Insufficient permissions');
		}
		return true;
	}
}
