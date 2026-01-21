import { LoginAttemptModule } from '@app/core/services/login-attempt/login-attempt.module';
import { envs } from '@app/env';
import { JwtStrategy } from '@app/modules/auth/strategies/jwt.strategy';
import { LocalStrategy } from '@app/modules/auth/strategies/local.strategy';
import { UserModule } from '@app/modules/user/user.module';
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PermissionsGuard } from './guards/permissions.guard';
import { VerifyJwtGuard } from './guards/verify-jwt.guard';

@Module({
	providers: [
		AuthService,
		LocalStrategy,
		JwtStrategy,
		PermissionsGuard,
		VerifyJwtGuard,
	],
	imports: [
		UserModule,
		LoginAttemptModule,
		PassportModule,
		JwtModule.register({
			secret: envs.JWT_SECRET,
			signOptions: {
				expiresIn: '8h',
			},
		}),
	],
	controllers: [AuthController],
	exports: [PassportModule, JwtModule, AuthService, VerifyJwtGuard],
})
export class AuthModule {}
