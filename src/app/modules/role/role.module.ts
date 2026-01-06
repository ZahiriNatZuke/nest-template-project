import { AuthModule } from '@app/modules/auth/auth.module';
import { RoleController } from '@app/modules/role/role.controller';
import { RoleService } from '@app/modules/role/role.service';
import { Module } from '@nestjs/common';

@Module({
	controllers: [RoleController],
	providers: [RoleService],
	exports: [RoleService],
	imports: [AuthModule],
})
export class RoleModule {}
