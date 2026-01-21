import { PrismaModule } from '@app/core/services/prisma/prisma.module';
import { Module } from '@nestjs/common';
import { TerminusModule } from '@nestjs/terminus';
import { HealthController } from './health.controller';

@Module({
	imports: [TerminusModule, PrismaModule],
	controllers: [HealthController],
})
export class HealthModule {}
