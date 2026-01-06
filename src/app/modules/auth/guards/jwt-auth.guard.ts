import { AppRequest } from '@app/core/types/app-request';
import {
	CanActivate,
	ExecutionContext,
	HttpException,
	HttpStatus,
	Injectable,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JwtAuthGuard implements CanActivate {
	constructor(private jwtService: JwtService) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const request = context.switchToHttp().getRequest<AppRequest>();
		const token = request.cookies?.accessToken;

		if (!token) {
			throw new HttpException(
				{ error: 'Unauthorized', code: 'TOKEN_MISSING' },
				HttpStatus.UNAUTHORIZED
			);
		}

		try {
			request.user = this.jwtService.verify(token);
			return true;
		} catch (_e) {
			throw new HttpException(
				{ error: 'Unauthorized', code: 'TOKEN_EXPIRED' },
				HttpStatus.UNAUTHORIZED
			);
		}
	}
}
