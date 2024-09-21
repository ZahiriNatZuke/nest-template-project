import { envs } from '@app/env';
import { AuthService } from '@app/modules/auth/auth.service';
import { HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { HeaderAPIKeyStrategy } from 'passport-headerapikey';

declare type doneFn = (err: Error | null, user?: unknown) => void;

@Injectable()
export class ApiKeyStrategy extends PassportStrategy(
	HeaderAPIKeyStrategy,
	'ApiKey'
) {
	constructor(private authService: AuthService) {
		super(
			{ header: envs.HEADER_KEY_API_KEY, prefix: '' },
			true,
			async (apiKey: string, done: doneFn) => this.validate(apiKey, done)
		);
	}

	async validate(apiKey: string, done: doneFn) {
		(await this.authService.validateApiKey(apiKey))
			? done(null, true)
			: done(
					new UnauthorizedException({
						statusCode: HttpStatus.UNAUTHORIZED,
						message: 'Api Key Failure',
					}),
					null
				);
	}
}
