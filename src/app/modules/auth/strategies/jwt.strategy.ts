import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { envs } from '@app/env';
import { JWTPayload } from '@app/modules/auth/interface/jwt.payload';
import { UserMapper } from '@app/modules/user/user.mapper';
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Session, User } from '@prisma/client';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
	constructor(
		private prisma: PrismaService,
		private userMapper: UserMapper
	) {
		super({
			secretOrKey: envs.JWT_SECRET,
			jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
			ignoreExpiration: false,
		});
	}

	async validate(
		payload: JWTPayload
	): Promise<Partial<User> & { perm?: string[] }> {
		const { device, userId, perm } = payload;
		const session: Session = await this.prisma.session.findUniqueOrThrow({
			where: { userId_device: { userId, device } },
		});
		if (session) {
			const user: User = await this.prisma.user.findUniqueOrThrow({
				where: { id: userId },
			});
			if (user) {
				const safe = this.userMapper.omitDefault(user) as Partial<User> & {
					perm?: string[];
				};
				safe.perm = perm;
				return safe;
			}
			throw new HttpException(
				{ message: 'JWT Failure' },
				HttpStatus.UNAUTHORIZED
			);
		}
		throw new HttpException(
			{ message: 'Session Failure' },
			HttpStatus.UNAUTHORIZED
		);
	}
}
