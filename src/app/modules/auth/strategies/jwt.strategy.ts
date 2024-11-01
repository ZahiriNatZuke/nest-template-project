import { envs } from '@app/env';
import { JWTPayload } from '@app/modules/auth/interface';
import { UserMapper } from '@app/modules/user/user.mapper';
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Session, User } from '@prisma/client';
import { PrismaService } from 'nestjs-prisma';
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

	async validate(payload: JWTPayload): Promise<Partial<User>> {
		const { device, userId } = payload;
		const session: Session = await this.prisma.session.findUniqueOrThrow({
			where: { device },
		});
		if (session) {
			const user: User = await this.prisma.user.findUniqueOrThrow({
				where: { id: userId },
			});
			if (user) {
				return this.userMapper.omitDefault(user);
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
