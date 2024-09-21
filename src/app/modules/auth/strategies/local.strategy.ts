import { AuthService } from '@app/modules/auth/auth.service';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
	constructor(private authService: AuthService) {
		super({ usernameField: 'identifier', passwordField: 'password' });
	}

	async validate(identifier: string, password: string) {
		const data = await this.authService.validateUser(identifier, password);
		if (data.status) return data;
		throw new UnauthorizedException('Login Failure');
	}
}
