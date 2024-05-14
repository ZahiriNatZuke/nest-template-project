import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UserModule } from '../user/user.module';
import { AuthController } from './auth.controller';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt.strategy';
import { ApiKeyStrategy } from './strategies/apikey.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { PrismaModule } from '../../core/modules/prisma/prisma.module';
import { envs } from '../../../config/envs';

@Module({
  providers: [ AuthService, ApiKeyStrategy, LocalStrategy, JwtStrategy ],
  imports: [
    UserModule,
    PrismaModule,
    PassportModule,
    JwtModule.register({
      secret: envs.JWT_SECRET,
      signOptions: {
        expiresIn: envs.EXPIRESIN_ACCESS,
      },
    }),
  ],
  controllers: [ AuthController ],
  exports: [ PassportModule, JwtModule, AuthService ],
})
export class AuthModule {
}
