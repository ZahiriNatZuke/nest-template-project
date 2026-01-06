import { AppController } from '@app/core/decorators/app-controller/app-controller.decorator';
import { Authz } from '@app/modules/auth/decorators/authz.decorator';
import { CreateSettingsZodDto } from '@app/modules/settings/dto/create-settings.dto';
import { UpdateManySettingsZodDto } from '@app/modules/settings/dto/update-many-settings.dto';
import { UpdateSettingsZodDto } from '@app/modules/settings/dto/update-settings.dto';
import { FindSettingByKeyPipe } from '@app/modules/settings/pipes/find-setting-by-key.pipe';
import { SettingsService } from '@app/modules/settings/settings.service';
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
import { Settings } from '@prisma/client';
import { FastifyReply } from 'fastify';

@AppController('settings')
export class SettingsController {
	constructor(private settingsService: SettingsService) {}

	@Post()
	@Authz('settings:write')
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
	@Authz('settings:read')
	async findMany(@Res() res: FastifyReply) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: await this.settingsService.findMany(),
		});
	}

	@Get('/:key')
	@Authz('settings:read')
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
	@Authz('settings:write')
	@ApiParam({ name: 'key', type: 'string', required: true })
	async update(
		@Res() res: FastifyReply,
		@Body() body: UpdateSettingsZodDto,
		@Param('key', FindSettingByKeyPipe) { key }: Settings
	) {
		const { value } = body;
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
	@Authz('settings:write')
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

	@Delete('/:key')
	@Authz('settings:delete')
	@ApiParam({ name: 'key', type: 'string', required: true })
	async remove(
		@Res() res: FastifyReply,
		@Param('key', FindSettingByKeyPipe) setting: Settings
	) {
		// Eliminar la configuración mediante el servicio
		await this.settingsService.delete({ key: setting.key });

		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			message: 'Setting deleted',
		});
	}
}
