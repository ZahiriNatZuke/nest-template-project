import { extractRequestInfo } from '@app/core/utils/request-info';
import { AuthService } from '@app/modules/auth/auth.service';
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
	constructor(private authService: AuthService) {
		super({
			usernameField: 'identifier',
			passwordField: 'password',
			passReqToCallback: true, // ✅ Pasar request al validate
		});
	}

	async validate(req: any, identifier: string, password: string) {
		// ✅ Extraer IP y User-Agent del request
		const { ipAddress, userAgent } = extractRequestInfo(req);

		// ✅ Pasar información adicional al validateUser
		const data = await this.authService.validateUser(
			identifier,
			password,
			ipAddress,
			userAgent
		);

		if (data.status) return data;
		throw new HttpException(
			{ message: 'Login Failure' },
			HttpStatus.UNAUTHORIZED
		);
	}
}
