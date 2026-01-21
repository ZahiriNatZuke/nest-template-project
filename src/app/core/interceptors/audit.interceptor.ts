import {
	AUDIT_METADATA_KEY,
	AuditMetadata,
} from '@app/core/decorators/log-audit.decorator';
import { AuditService } from '@app/core/services/audit/audit.service';
import {
	CallHandler,
	ExecutionContext,
	Injectable,
	NestInterceptor,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable, tap } from 'rxjs';

@Injectable()
export class AuditInterceptor implements NestInterceptor {
	constructor(
		private reflector: Reflector,
		private auditService: AuditService
	) {}

	intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
		const auditMeta = this.reflector.get<AuditMetadata | undefined>(
			AUDIT_METADATA_KEY,
			context.getHandler()
		);

		if (!auditMeta) return next.handle();

		const req = context.switchToHttp().getRequest<{
			user?: { id?: string };
			params?: Record<string, string>;
			body?: Record<string, unknown>;
			requestContext?: { ipAddress?: string; userAgent?: string };
		}>();

		const userId = req.user?.id;
		const ipAddress = req.requestContext?.ipAddress;
		const userAgent = req.requestContext?.userAgent;
		const entityId = auditMeta.entityIdParam
			? req.params?.[auditMeta.entityIdParam]
			: (req.params?.id as string | undefined) ||
				((req.body?.id as string) ?? undefined);
		const metadata = auditMeta.omitBody
			? undefined
			: (req.body as Record<string, string | number | boolean> | undefined);

		return next.handle().pipe(
			tap(async () => {
				await this.auditService.log({
					userId,
					action: auditMeta.action,
					entityType: auditMeta.entityType,
					entityId,
					metadata,
					ipAddress,
					userAgent,
				});
			})
		);
	}
}
