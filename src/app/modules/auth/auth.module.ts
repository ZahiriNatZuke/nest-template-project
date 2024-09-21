import { UserModule } from '@app/modules/user';
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

import { envs } from '@app/env';
import {
	ApiKeyStrategy,
	JwtStrategy,
	LocalStrategy,
} from '@app/modules/auth/strategies';
import { PrismaModule } from 'nestjs-prisma';

@Module({
	providers: [AuthService, ApiKeyStrategy, LocalStrategy, JwtStrategy],
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
	controllers: [AuthController],
	exports: [PassportModule, JwtModule, AuthService],
})
export class AuthModule {}
