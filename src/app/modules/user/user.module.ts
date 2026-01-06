import { AuthModule } from '@app/modules/auth/auth.module';
import { UserController } from '@app/modules/user/user.controller';
import { UserMapper } from '@app/modules/user/user.mapper';
import { UserService } from '@app/modules/user/user.service';
import { forwardRef, Module } from '@nestjs/common';

@Module({
	providers: [UserService, UserMapper],
	exports: [UserService, UserMapper],
	imports: [forwardRef(() => AuthModule)],
	controllers: [UserController],
})
export class UserModule {}
