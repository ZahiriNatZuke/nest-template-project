import {
	CanActivate,
	ExecutionContext,
	HttpException,
	HttpStatus,
	Injectable,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { FastifyRequest } from 'fastify';
import { ExtractJwt } from 'passport-jwt';
import { Observable } from 'rxjs';

@Injectable()
export class VerifyJwtGuard implements CanActivate {
	constructor(private jwtService: JwtService) {}

	canActivate(
		context: ExecutionContext
	): boolean | Promise<boolean> | Observable<boolean> {
		const request: FastifyRequest = context.switchToHttp().getRequest();
		const jwt = ExtractJwt.fromAuthHeaderAsBearerToken()(request);
		try {
			this.jwtService.verify(jwt ?? '');
			return true;
		} catch (e) {
			throw new HttpException({ message: e.message }, HttpStatus.UNAUTHORIZED);
		}
	}
}
