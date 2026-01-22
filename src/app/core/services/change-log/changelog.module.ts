import { ChangeLogService } from '@app/core/services/change-log/changelog.service';
import { Global, Module } from '@nestjs/common';

@Global()
@Module({
	providers: [ChangeLogService],
	exports: [ChangeLogService],
})
export class ChangelogModule {}
