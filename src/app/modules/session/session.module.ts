import { AuthModule } from '@app/modules/auth/auth.module';
import { SessionController } from '@app/modules/session/session.controller';
import { SessionService } from '@app/modules/session/session.service';
import { UserModule } from '@app/modules/user/user.module';
import { Module } from '@nestjs/common';

@Module({
	controllers: [SessionController],
	providers: [SessionService],
	exports: [SessionService],
	imports: [AuthModule, UserModule],
})
export class SessionModule {}
