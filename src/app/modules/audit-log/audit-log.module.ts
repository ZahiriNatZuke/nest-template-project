import { AuditModule as AuditCoreModule } from '@app/core/services/audit/audit.module';
import { AuditService } from '@app/core/services/audit/audit.service';
import { EncryptionModule } from '@app/core/services/encryption/encryption.module';
import { AuthModule } from '@app/modules/auth/auth.module';
import { Module } from '@nestjs/common';
import { AuditLogController } from './audit-log.controller';

@Module({
	imports: [AuthModule, AuditCoreModule, EncryptionModule],
	controllers: [AuditLogController],
	providers: [AuditService],
})
export class AuditLogModule {}
