import { PrismaService } from '@app/core/services/prisma/prisma.service';
import {
	extractRequestInfo,
	isSimilarIP,
	isSimilarUserAgent,
} from '@app/core/utils/request-info';
import {
	CanActivate,
	ExecutionContext,
	HttpException,
	HttpStatus,
	Injectable,
	Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { FastifyRequest } from 'fastify';
import { ExtractJwt } from 'passport-jwt';

@Injectable()
export class VerifyJwtGuard implements CanActivate {
	private readonly logger = new Logger(VerifyJwtGuard.name);

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

		// Validar IP y User-Agent para prevenir session hijacking
		const session = await this.prisma.session.findUnique({
			where: { accessToken: jwt },
		});

		if (session?.ipAddress && session?.userAgent) {
			const { ipAddress, userAgent } = extractRequestInfo(request);

			const ipMatch = isSimilarIP(session.ipAddress, ipAddress);
			const uaMatch = isSimilarUserAgent(session.userAgent, userAgent);

			if (!ipMatch || !uaMatch) {
				this.logger.warn(
					`Session validation failed for user ${session.userId}. ` +
						`IP match: ${ipMatch} (${session.ipAddress} vs ${ipAddress}), ` +
						`UA match: ${uaMatch}`
				);

				throw new HttpException(
					{
						message:
							'Session validation failed. IP or device mismatch detected.',
					},
					HttpStatus.UNAUTHORIZED
				);
			}
		}

		return true;
	}
}
