import { AuthModule } from '@app/modules/auth/auth.module';
import { Module } from '@nestjs/common';
import { PermissionController } from './permission.controller';
import { PermissionService } from './permission.service';

@Module({
	imports: [AuthModule],
	controllers: [PermissionController],
	providers: [PermissionService],
	exports: [PermissionService],
})
export class PermissionModule {}
