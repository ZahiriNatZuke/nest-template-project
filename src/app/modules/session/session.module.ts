import { Module } from '@nestjs/common';
import { SessionService } from './session.service';
import { SessionController } from './session.controller';
import { AuthModule } from '../auth/auth.module';
import { UserModule } from '../user/user.module';
import { PrismaModule } from '../../core/modules/prisma/prisma.module';

@Module({
  controllers: [ SessionController ],
  providers: [ SessionService ],
  exports: [ SessionService ],
  imports: [
    PrismaModule,
    AuthModule,
    UserModule,
  ],
})
export class SessionModule {
}
