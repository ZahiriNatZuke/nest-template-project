import { AppController } from '@app/core/decorators/app-controller/app-controller.decorator';
import { Authz } from '@app/modules/auth/decorators/authz.decorator';
import { CreatePermissionZodDto } from '@app/modules/permission/dto/create-permission.dto';
import { UpdatePermissionZodDto } from '@app/modules/permission/dto/update-permission.dto';
import { PermissionService } from '@app/modules/permission/permission.service';
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
import { FastifyReply } from 'fastify';
import { isNil, omitBy } from 'lodash';

@AppController('permission')
export class PermissionController {
	constructor(private permissionService: PermissionService) {}

	@Post()
	@Authz('permissions:write')
	async create(
		@Res() res: FastifyReply,
		@Body() payload: CreatePermissionZodDto
	) {
		const permission = await this.permissionService.create(payload);
		return res.code(HttpStatus.CREATED).send({
			statusCode: 201,
			data: permission,
			message: 'Permission created',
		});
	}

	@Get()
	@Authz('permissions:read')
	async findMany(@Res() res: FastifyReply) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: await this.permissionService.findMany(),
		});
	}

	@Get(':id')
	@ApiParam({ name: 'id', type: 'string', required: true })
	@Authz('permissions:read')
	async findOne(@Res() res: FastifyReply, @Param('id') id: string) {
		const permission = await this.permissionService.findOne({ id });
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: permission,
		});
	}

	@Patch(':id')
	@Authz('permissions:write')
	@ApiParam({ name: 'id', type: 'string', required: true })
	async update(
		@Res() res: FastifyReply,
		@Param('id') id: string,
		@Body() payload: UpdatePermissionZodDto
	) {
		const permission = await this.permissionService.update({
			where: { id },
			data: omitBy(payload, isNil),
		});
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: permission,
			message: 'Permission updated',
		});
	}

	@Delete(':id')
	@Authz('permissions:delete')
	@ApiParam({ name: 'id', type: 'string', required: true })
	async delete(@Res() res: FastifyReply, @Param('id') id: string) {
		const permissionDeleted = await this.permissionService.delete({ id });
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: permissionDeleted,
			message: 'Permission deleted',
		});
	}
}
