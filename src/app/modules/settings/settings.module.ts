import { forwardRef, Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { SettingsController } from './settings.controller';
import { SettingsService } from './settings.service';
import { PrismaModule } from '../../core/modules/prisma/prisma.module';

@Module({
  providers: [ SettingsService ],
  controllers: [ SettingsController ],
  imports: [ PrismaModule, forwardRef(() => AuthModule) ],
  exports: [ SettingsService ],
})
export class SettingsModule {
}
