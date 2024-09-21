import { AuthModule } from '@app/modules/auth';
import { SessionController } from '@app/modules/session/session.controller';
import { SessionService } from '@app/modules/session/session.service';
import { UserModule } from '@app/modules/user';
import { Module } from '@nestjs/common';
import { PrismaModule } from 'nestjs-prisma';

@Module({
	controllers: [SessionController],
	providers: [SessionService],
	exports: [SessionService],
	imports: [PrismaModule, AuthModule, UserModule],
})
export class SessionModule {}
