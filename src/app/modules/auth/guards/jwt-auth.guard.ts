import { AppRequest, JwtPrincipal } from '@app/core/types/app-request';
import {
	CanActivate,
	ExecutionContext,
	HttpException,
	HttpStatus,
	Injectable,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JWTPayload } from '../interface/jwt.payload';

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
			const payload: JWTPayload = this.jwtService.verify(token);

			// The token names the subject `userId`, but every consumer downstream —
			// PermissionsGuard, the 2FA controller, the profile controller — reads
			// `id`, which is also what passport's JwtStrategy attaches. Without this
			// alias `user.id` is undefined and PermissionsGuard rejects every
			// request with "Unauthorized principal", including a fully authorised
			// one.
			// AppRequest.user is typed for the local-strategy shape; this guard
			// attaches the JWT principal instead.
			const principal: JwtPrincipal = { ...payload, id: payload.userId };
			request.user = principal as unknown as AppRequest['user'];
			return true;
		} catch (_e) {
			throw new HttpException(
				{ error: 'Unauthorized', code: 'TOKEN_EXPIRED' },
				HttpStatus.UNAUTHORIZED
			);
		}
	}
}
