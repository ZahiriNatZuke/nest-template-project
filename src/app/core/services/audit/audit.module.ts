import { Global, Module } from '@nestjs/common';
import { EncryptionModule } from '../encryption/encryption.module';
import { AuditService } from './audit.service';

@Global()
@Module({
	imports: [EncryptionModule],
	providers: [AuditService],
	exports: [AuditService],
})
export class AuditModule {}
