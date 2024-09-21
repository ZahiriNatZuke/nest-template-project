import { ApiKeyController } from '@app/modules/api-key/api-key.controller';
import { ApiKeyService } from '@app/modules/api-key/api-key.service';
import { AuthModule } from '@app/modules/auth';
import { Module } from '@nestjs/common';
import { PrismaModule } from 'nestjs-prisma';

@Module({
	controllers: [ApiKeyController],
	providers: [ApiKeyService],
	exports: [ApiKeyService],
	imports: [PrismaModule, AuthModule],
})
export class ApiKeyModule {}
