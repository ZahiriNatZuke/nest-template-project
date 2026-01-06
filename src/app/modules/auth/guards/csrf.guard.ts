import { CsrfService } from '@app/core/services/csrf/csrf.service';
import {
	CanActivate,
	ExecutionContext,
	HttpException,
	HttpStatus,
	Injectable,
} from '@nestjs/common';
import { FastifyRequest } from 'fastify';

@Injectable()
export class CsrfGuard implements CanActivate {
	constructor(private csrfService: CsrfService) {}

	canActivate(context: ExecutionContext): boolean {
		const request: FastifyRequest = context.switchToHttp().getRequest();
		const method = request.method;

		// Solo validar en mutaciones
		if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
			return true;
		}

		const csrfToken = request.headers['x-csrf-token'] as string | undefined;

		if (!csrfToken) {
			throw new HttpException(
				{ error: 'CSRF token invalid', code: 'CSRF_INVALID' },
				HttpStatus.FORBIDDEN
			);
		}

		if (!this.csrfService.validateToken(csrfToken)) {
			throw new HttpException(
				{ error: 'CSRF token invalid', code: 'CSRF_INVALID' },
				HttpStatus.FORBIDDEN
			);
		}

		return true;
	}
}
