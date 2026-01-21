import {
	PolicyContext,
	PolicyEngineService,
} from '@app/core/services/policy-engine/policy-engine.service';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
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

export const ABAC_METADATA_KEY = 'abac_policy';

export interface AbacMetadata {
	policyIdentifier: string; // ID de la política a evaluar
	contextBuilder?: (req: AuthRequest, user: User) => PolicyContext; // función para construir contexto
}

/**
 * Guard para validar control de acceso basado en atributos (2.3 - ABAC)
 * Uso:
 * @Patch(':id')
 * @Authz('users:write')
 * @RequirePolicy({policyIdentifier: 'can_edit_active_users'})
 * async updateUser(@Param('id') id: string) { ... }
 */
@Injectable()
export class AbacGuard implements CanActivate {
	private readonly logger = new Logger(AbacGuard.name);

	constructor(
		private reflector: Reflector,
		private policyEngine: PolicyEngineService,
		private prisma: PrismaService
	) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const metadata = this.reflector.get<AbacMetadata>(
			ABAC_METADATA_KEY,
			context.getHandler()
		);

		// Si no hay metadata, permitir
		if (!metadata) {
			return true;
		}

		const request: AuthRequest = context.switchToHttp().getRequest();
		const user = request.user as Partial<User>;

		if (!user?.id) {
			throw new ForbiddenException('Unauthorized principal');
		}

		// Obtener roles del usuario
		const userRoles = await this.prisma.userRole.findMany({
			where: { userId: user.id },
			select: { roleId: true },
		});

		if (userRoles.length === 0) {
			throw new ForbiddenException('User has no roles');
		}

		// Construir contexto de políticas
		const policyContext =
			metadata.contextBuilder?.(request, user as User) ||
			this.buildDefaultContext(request, user as User);

		// Verificar si alguno de los roles del usuario cumple la política
		for (const ur of userRoles) {
			const hasPolicy = await this.policyEngine.hasPolicy(
				ur.roleId,
				metadata.policyIdentifier,
				policyContext
			);

			if (hasPolicy) {
				this.logger.debug(
					`User ${user.id} authorized by policy ${metadata.policyIdentifier}`
				);
				return true;
			}
		}

		this.logger.warn(
			`User ${user.id} denied by policy ${metadata.policyIdentifier}. Context: ${JSON.stringify(policyContext)}`
		);
		throw new ForbiddenException(
			`Access denied by policy: ${metadata.policyIdentifier}`
		);
	}

	private buildDefaultContext(request: AuthRequest, user: User): PolicyContext {
		return {
			userId: user.id,
			userStatus: user.confirmed ? 'active' : 'pending',
			userBlocked: user.blocked,
			timestamp: new Date().toISOString(),
			ipAddress: request.ip,
			userAgent: request.headers['user-agent'],
		};
	}
}
