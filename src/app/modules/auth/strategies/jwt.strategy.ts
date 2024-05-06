import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JWTPayload } from '../interface/jwt.payload';
import { Session, User } from '@prisma/client';
import { UserMapper } from '../../user/user.mapper';
import { PrismaService } from '../../../core/modules/prisma/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private prisma: PrismaService,
    private userMapper: UserMapper,
  ) {
    super({
      secretOrKey: process.env[ 'JWT_SECRET' ],
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
    });
  }

  async validate(payload: JWTPayload): Promise<Partial<User>> {
    const { device, userId } = payload;
    const session: Session = await this.prisma.session.findUniqueOrThrow({
      where: { device },
    });
    if ( session ) {
      const user: User = await this.prisma.user.findUniqueOrThrow({
        where: { id: userId },
      });
      if ( user ) {
        return this.userMapper.omitDefault(user);
      } else {
        throw new UnauthorizedException('JWT Failure');
      }
    } else {
      throw new UnauthorizedException('Session Failure');
    }
  }
}
