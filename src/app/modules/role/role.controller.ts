import { AppController } from '@app/core/decorators/app-controller.decorator';
import { ZodValidationException } from '@app/core/utils/zod';
import { Authz } from '@app/modules/auth/decorators/authz.decorator';
import { AssignPermissionZodDto } from '@app/modules/role/dto/assign-permission.dto';
import { CreateRoleZodDto } from '@app/modules/role/dto/create-role.dto';
import { UpdateRoleZodDto } from '@app/modules/role/dto/update-role.dto';
import { FindRoleByIdPipe } from '@app/modules/role/pipes/find-role-by-id.pipe';
import { RoleService } from '@app/modules/role/role.service';
import {
	Body,
	Delete,
	Get,
	HttpStatus,
	Param,
	Patch,
	Post,
	Res,
} from '@nestjs/common';
import { ApiParam } from '@nestjs/swagger';
import { Role } from '@prisma/client';
import { FastifyReply } from 'fastify';
import { isNil, omitBy } from 'lodash';
import { z } from 'zod';

@AppController('role')
export class RoleController {
	constructor(private roleService: RoleService) {}

	@Post()
	@Authz('roles:write')
	async create(@Res() res: FastifyReply, @Body() payload: CreateRoleZodDto) {
		const role = await this.roleService.create(payload);
		return res.code(HttpStatus.CREATED).send({
			statusCode: 201,
			data: role,
			message: 'Role created',
		});
	}

	@Get()
	@Authz('roles:read')
	async findMany(@Res() res: FastifyReply) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: await this.roleService.findMany(),
		});
	}

	@Get(':id')
	@ApiParam({ name: 'id', type: 'string', required: true })
	@Authz('roles:read')
	async findOne(
		@Res() res: FastifyReply,
		@Param('id', FindRoleByIdPipe) role: Role
	) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: role,
		});
	}

	@Patch(':id')
	@Authz('roles:write')
	@ApiParam({ name: 'id', type: 'string', required: true })
	async update(
		@Res() res: FastifyReply,
		@Param('id', FindRoleByIdPipe) { id }: Role,
		@Body() payload: UpdateRoleZodDto
	) {
		const role = await this.roleService.update({
			where: { id },
			data: omitBy(payload, isNil),
		});
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: role,
			message: 'Role updated',
		});
	}

	@Delete(':id')
	@Authz('roles:delete')
	@ApiParam({ name: 'id', type: 'string', required: true })
	async delete(
		@Res() res: FastifyReply,
		@Param('id', FindRoleByIdPipe) role: Role
	) {
		if (role.default) {
			throw new ZodValidationException(
				new z.ZodError([
					{
						code: 'custom',
						path: [],
						message: 'You cannot delete the default role',
					},
				])
			);
		}
		const roleDeleted = await this.roleService.delete({ id: role.id });
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: roleDeleted,
			message: 'Role deleted',
		});
	}

	@Post(':id/permissions')
	@Authz('roles:write')
	@ApiParam({ name: 'id', type: String })
	async assignPermission(
		@Res() res: FastifyReply,
		@Param('id') roleId: string,
		@Body() payload: AssignPermissionZodDto
	) {
		const role = await this.roleService.assignPermission(
			roleId,
			payload.permissionId
		);
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: role,
			message: 'Permission assigned to role',
		});
	}

	@Delete(':id/permissions/:permissionId')
	@Authz('roles:write')
	@ApiParam({ name: 'id', type: String })
	@ApiParam({ name: 'permissionId', type: String })
	async removePermission(
		@Res() res: FastifyReply,
		@Param('id') roleId: string,
		@Param('permissionId') permissionId: string
	) {
		const role = await this.roleService.removePermission(roleId, permissionId);
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: role,
			message: 'Permission removed from role',
		});
	}
}
