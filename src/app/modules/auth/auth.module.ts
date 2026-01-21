import { LoginAttemptModule } from '@app/core/services/login-attempt/login-attempt.module';
import { PolicyEngineService } from '@app/core/services/policy-engine/policy-engine.service';
import { ResourceOwnershipService } from '@app/core/services/resource-ownership/resource-ownership.service';
import { RoleHierarchyService } from '@app/core/services/role-hierarchy/role-hierarchy.service';
import { envs } from '@app/env';
import { JwtStrategy } from '@app/modules/auth/strategies/jwt.strategy';
import { LocalStrategy } from '@app/modules/auth/strategies/local.strategy';
import { UserModule } from '@app/modules/user/user.module';
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AbacGuard } from './guards/abac.guard';
import { PermissionsGuard } from './guards/permissions.guard';
import { ResourceOwnerGuard } from './guards/resource-owner.guard';
import { VerifyJwtGuard } from './guards/verify-jwt.guard';

@Module({
	providers: [
		// Auth strategies & guards
		AuthService,
		LocalStrategy,
		JwtStrategy,
		PermissionsGuard,
		VerifyJwtGuard,
		// RBAC Advanced: 2.1, 2.2, 2.3
		RoleHierarchyService,
		ResourceOwnerGuard,
		ResourceOwnershipService,
		AbacGuard,
		PolicyEngineService,
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
	exports: [
		PassportModule,
		JwtModule,
		AuthService,
		VerifyJwtGuard,
		PermissionsGuard,
		// Exportar nuevos servicios y guards para uso en otros módulos
		RoleHierarchyService,
		ResourceOwnerGuard,
		ResourceOwnershipService,
		AbacGuard,
		PolicyEngineService,
	],
})
export class AuthModule {}
