import { Module } from '@nestjs/common';
import { RoleService } from './role.service';
import { RoleController } from './role.controller';
import { AuthModule } from '../auth/auth.module';
import { PrismaModule } from '../../core/modules/prisma/prisma.module';

@Module({
  controllers: [ RoleController ],
  providers: [ RoleService ],
  exports: [ RoleService ],
  imports: [
    PrismaModule,
    AuthModule,
  ],
})
export class RoleModule {
}
