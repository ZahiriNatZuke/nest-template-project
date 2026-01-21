import { AuditModule as AuditCoreModule } from '@app/core/services/audit/audit.module';
import { AuditService } from '@app/core/services/audit/audit.service';
import { Module } from '@nestjs/common';
import { AuditLogController } from './audit-log.controller';

@Module({
	imports: [AuditCoreModule],
	controllers: [AuditLogController],
	providers: [AuditService],
})
export class AuditLogModule {}
