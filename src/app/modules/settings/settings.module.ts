import { AuthModule } from '@app/modules/auth/auth.module';
import { SettingsController } from '@app/modules/settings/settings.controller';
import { SettingsService } from '@app/modules/settings/settings.service';
import { forwardRef, Module } from '@nestjs/common';

@Module({
	providers: [SettingsService],
	controllers: [SettingsController],
	imports: [forwardRef(() => AuthModule)],
	exports: [SettingsService],
})
export class SettingsModule {}
