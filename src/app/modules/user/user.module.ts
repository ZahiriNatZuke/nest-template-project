import { forwardRef, Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { UserMapper } from './user.mapper';
import { AuthModule } from '../auth/auth.module';
import { PrismaModule } from '../../core/modules/prisma/prisma.module';

@Module({
  providers: [ UserService, UserMapper ],
  exports: [ UserService, UserMapper ],
  imports: [ PrismaModule, forwardRef(() => AuthModule) ],
  controllers: [ UserController ],
})
export class UserModule {
}
