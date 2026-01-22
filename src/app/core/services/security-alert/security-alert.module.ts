import { Global, Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { NotificationModule } from '../notification/notification.module';
import { SecurityAlertService } from './security-alert.service';

@Global()
@Module({
	imports: [NotificationModule, AuditModule],
	providers: [SecurityAlertService],
	exports: [SecurityAlertService],
})
export class SecurityAlertModule {}
