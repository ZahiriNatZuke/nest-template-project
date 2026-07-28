import { ChangelogModule } from '@app/core/services/change-log/changelog.module';
import { AuthModule } from '@app/modules/auth/auth.module';
import { UserController } from '@app/modules/user/user.controller';
import { UserMapper } from '@app/modules/user/user.mapper';
import { UserService } from '@app/modules/user/user.service';
import { forwardRef, Module } from '@nestjs/common';

/**
 * `'UserService'` is registered as a string alias alongside the class.
 *
 * PasswordService resolves this service lazily with
 * `moduleRef.get('UserService', { strict: false })` to sidestep the circular
 * dependency between auth and user. That string was never a registered token,
 * so the lookup threw — and because the call sits inside a try/catch that
 * reports a generic failure, `request-recovery-account` answered "failure" for
 * every address, including ones that exist.
 *
 * Aliasing keeps the lazy lookup working without importing the class into a
 * cycle. `useExisting` shares the same instance rather than constructing a
 * second one.
 */
@Module({
	providers: [
		UserService,
		UserMapper,
		{ provide: 'UserService', useExisting: UserService },
	],
	exports: [UserService, UserMapper, 'UserService'],
	imports: [forwardRef(() => AuthModule), ChangelogModule],
	controllers: [UserController],
})
export class UserModule {}
