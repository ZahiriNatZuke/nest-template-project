import { EncryptionModule } from '@app/core/services/encryption/encryption.module';
import { Global, Module } from '@nestjs/common';
import { TwoFactorService } from './two-factor.service';

@Global()
@Module({
	// TOTP secrets are encrypted at rest, so the service needs EncryptionService.
	imports: [EncryptionModule],
	providers: [TwoFactorService],
	exports: [TwoFactorService],
})
export class TwoFactorModule {}
