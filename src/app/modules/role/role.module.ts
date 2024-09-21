import { AuthModule } from '@app/modules/auth';
import { RoleController } from '@app/modules/role/role.controller';
import { RoleService } from '@app/modules/role/role.service';
import { Module } from '@nestjs/common';
import { PrismaModule } from 'nestjs-prisma';

@Module({
	controllers: [RoleController],
	providers: [RoleService],
	exports: [RoleService],
	imports: [PrismaModule, AuthModule],
})
export class RoleModule {}
