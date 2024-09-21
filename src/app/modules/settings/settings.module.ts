import { AuthModule } from '@app/modules/auth';
import { SettingsController } from '@app/modules/settings/settings.controller';
import { SettingsService } from '@app/modules/settings/settings.service';
import { Module, forwardRef } from '@nestjs/common';
import { PrismaModule } from 'nestjs-prisma';

@Module({
	providers: [SettingsService],
	controllers: [SettingsController],
	imports: [PrismaModule, forwardRef(() => AuthModule)],
	exports: [SettingsService],
})
export class SettingsModule {}
