import { ApiKeyController } from '@app/modules/api-key/api-key.controller';
import { ApiKeyService } from '@app/modules/api-key/api-key.service';
import { AuthModule } from '@app/modules/auth/auth.module';
import { Module } from '@nestjs/common';

@Module({
	controllers: [ApiKeyController],
	providers: [ApiKeyService],
	exports: [ApiKeyService],
	imports: [AuthModule],
})
export class ApiKeyModule {}
