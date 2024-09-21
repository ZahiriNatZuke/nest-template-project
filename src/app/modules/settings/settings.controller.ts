import { AppController } from '@app/core/decorators';
import { Auth } from '@app/modules/auth/decorators';
import { AuthRole } from '@app/modules/auth/enums';
import {
	CreateSettingsZodDto,
	UpdateManySettingsZodDto,
	UpdateSettingsZodDto,
} from '@app/modules/settings/dto';
import { FindSettingByKeyPipe } from '@app/modules/settings/pipes';
import { SettingsService } from '@app/modules/settings/settings.service';
import { Body, Get, HttpStatus, Param, Patch, Post, Res } from '@nestjs/common';
import { ApiParam } from '@nestjs/swagger';
import { Settings } from '@prisma/client';
import { FastifyReply } from 'fastify';

@AppController('settings')
export class SettingsController {
	constructor(private settingsService: SettingsService) {}

	@Post()
	@Auth([AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE])
	async create(
		@Res() res: FastifyReply,
		@Body() payload: CreateSettingsZodDto
	) {
		const settings = await this.settingsService.create(payload);
		return res.code(HttpStatus.CREATED).send({
			statusCode: 201,
			data: settings,
			message: 'Settings created',
		});
	}

	@Get()
	@Auth([AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE])
	async findMany(@Res() res: FastifyReply) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: await this.settingsService.findMany(),
		});
	}

	@Get('/:key')
	@Auth([AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE])
	@ApiParam({ name: 'key', type: 'string', required: true })
	async findOne(
		@Res() res: FastifyReply,
		@Param('key', FindSettingByKeyPipe) setting: Settings
	) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: setting,
		});
	}

	@Patch('/:key')
	@Auth([AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE])
	@ApiParam({ name: 'key', type: 'string', required: true })
	async update(
		@Res() res: FastifyReply,
		@Body() { value }: UpdateSettingsZodDto,
		@Param('key', FindSettingByKeyPipe) { key }: Settings
	) {
		const settings = await this.settingsService.update({
			where: { key },
			data: { value },
		});

		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: settings,
			message: 'Setting updated',
		});
	}

	@Patch()
	@Auth([AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE])
	async updateMany(
		@Res() res: FastifyReply,
		@Body() data: UpdateManySettingsZodDto
	) {
		const settings = await this.settingsService.updateMany(data);

		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: settings,
			message: 'Settings updated',
		});
	}
}
