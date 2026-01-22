import { Global, Module } from '@nestjs/common';
import { TwoFactorService } from './two-factor.service';

@Global()
@Module({
	providers: [TwoFactorService],
	exports: [TwoFactorService],
})
export class TwoFactorModule {}
