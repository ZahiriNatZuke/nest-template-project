import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Module } from '@nestjs/common';
import { LoginAttemptService } from './login-attempt.service';

@Module({
	providers: [LoginAttemptService, PrismaService],
	exports: [LoginAttemptService],
})
export class LoginAttemptModule {}
