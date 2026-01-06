import { PrismaService } from '@app/core/services/prisma/prisma.service';
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

@Injectable()
export class VerifyJwtGuard implements CanActivate {
	constructor(
		private jwtService: JwtService,
		private prisma: PrismaService
	) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const request: FastifyRequest = context.switchToHttp().getRequest();
		const jwt = ExtractJwt.fromAuthHeaderAsBearerToken()(request);

		if (!jwt) {
			throw new HttpException(
				{ message: 'Missing token' },
				HttpStatus.UNAUTHORIZED
			);
		}

		try {
			this.jwtService.verify(jwt);
		} catch (e) {
			throw new HttpException({ message: e.message }, HttpStatus.UNAUTHORIZED);
		}

		// Check blacklist
		const blacklisted = await this.prisma.tokenBlacklist.findUnique({
			where: { token: jwt },
		});

		if (blacklisted && blacklisted.expiresAt > new Date()) {
			throw new HttpException(
				{ message: 'Token has been revoked' },
				HttpStatus.UNAUTHORIZED
			);
		}

		return true;
	}
}
