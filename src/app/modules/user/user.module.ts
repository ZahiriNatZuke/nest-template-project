import { AuthModule } from '@app/modules/auth';
import { UserController } from '@app/modules/user/user.controller';
import { UserMapper } from '@app/modules/user/user.mapper';
import { UserService } from '@app/modules/user/user.service';
import { Module, forwardRef } from '@nestjs/common';
import { PrismaModule } from 'nestjs-prisma';

@Module({
	providers: [UserService, UserMapper],
	exports: [UserService, UserMapper],
	imports: [PrismaModule, forwardRef(() => AuthModule)],
	controllers: [UserController],
})
export class UserModule {}
