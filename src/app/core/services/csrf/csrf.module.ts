import { Global, Module } from '@nestjs/common';
import { CsrfService } from './csrf.service';

@Global()
@Module({
	providers: [CsrfService],
	exports: [CsrfService],
})
export class CsrfModule {}
