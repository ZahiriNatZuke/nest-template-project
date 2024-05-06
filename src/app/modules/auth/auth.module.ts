import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UserModule } from '../user/user.module';
import { AuthController } from './auth.controller';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt.strategy';
import { ApiKeyStrategy } from './strategies/apikey.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PrismaModule } from '../../core/modules/prisma/prisma.module';

@Module({
  providers: [ AuthService, ApiKeyStrategy, LocalStrategy, JwtStrategy ],
  imports: [
    UserModule,
    PrismaModule,
    PassportModule,
    JwtModule.registerAsync({
      imports: [ ConfigModule ],
      useFactory: async (configService: ConfigService) => ( {
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('EXPIRESIN_ACCESS'),
        },
      } ),
      inject: [ ConfigService ],
    }),
  ],
  controllers: [ AuthController ],
  exports: [ PassportModule, JwtModule, AuthService ],
})
export class AuthModule {
}
