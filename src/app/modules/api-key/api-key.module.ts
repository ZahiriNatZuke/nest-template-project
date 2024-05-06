import { Module } from '@nestjs/common';
import { ApiKeyService } from './api-key.service';
import { ApiKeyController } from './api-key.controller';
import { AuthModule } from '../auth/auth.module';
import { PrismaModule } from '../../core/modules/prisma/prisma.module';

@Module({
  controllers: [ ApiKeyController ],
  providers: [ ApiKeyService ],
  exports: [ ApiKeyService ],
  imports: [
    PrismaModule,
    AuthModule,
  ],
})
export class ApiKeyModule {
}
