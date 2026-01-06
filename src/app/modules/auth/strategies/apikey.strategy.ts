import { envs } from '@app/env';
import { AuthService } from '@app/modules/auth/auth.service';
import { HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { HeaderAPIKeyStrategy } from 'passport-headerapikey';

@Injectable()
export class ApiKeyStrategy extends PassportStrategy(
	HeaderAPIKeyStrategy,
	'ApiKey'
) {
	constructor(private authService: AuthService) {
		super(
			{
				header: envs.HEADER_KEY_API_KEY,
				prefix: '',
			},
			false // passReqToCallback
		);
	}

	async validate(apiKey: string): Promise<Record<string, unknown>> {
		const isValid = await this.authService.validateApiKey(apiKey);
		if (!isValid) {
			throw new UnauthorizedException({
				statusCode: HttpStatus.UNAUTHORIZED,
				message: 'Api Key Failure',
			});
		}
		return { apiKey };
	}
}
