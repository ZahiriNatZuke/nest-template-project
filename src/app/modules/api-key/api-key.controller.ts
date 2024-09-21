import { AppController } from '@app/core/decorators';
import {
	CreateApiKeyZodDto,
	UpdateApiKeyZodDto,
} from '@app/modules/api-key/dto';
import { FindApiKeyByIdPipe } from '@app/modules/api-key/pipes';
import { Auth } from '@app/modules/auth/decorators';
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
import { ApiKey } from '@prisma/client';
import { FastifyReply } from 'fastify';
import { ZodValidationException } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';
import { AuthRole } from '../auth/enums/auth-role';
import { ApiKeyService } from './api-key.service';

@AppController('api-key')
export class ApiKeyController {
	constructor(private apiKeyService: ApiKeyService) {}

	@Post()
	@Auth([AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE])
	async create(@Res() res: FastifyReply, @Body() payload: CreateApiKeyZodDto) {
		const apiKey = await this.apiKeyService.create(payload);
		return res.code(HttpStatus.CREATED).send({
			statusCode: 201,
			data: apiKey,
			message: 'Api key created',
		});
	}

	@Get()
	@Auth([AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE])
	async findMany(@Res() res: FastifyReply) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: await this.apiKeyService.findMany(),
		});
	}

	@Get('/get-key/:id')
	@ApiParam({ name: 'id', type: 'string', required: true })
	@Auth([AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE])
	async getKey(
		@Res() res: FastifyReply,
		@Param('id', FindApiKeyByIdPipe) { id }: ApiKey
	) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: await this.apiKeyService.getKey(id),
		});
	}

	@Get('/:id')
	@ApiParam({ name: 'id', type: 'string', required: true })
	@Auth([AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE])
	async findOne(
		@Res() res: FastifyReply,
		@Param('id', FindApiKeyByIdPipe) apiKey: ApiKey
	) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: apiKey,
		});
	}

	@Patch('/:id')
	@Auth([AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE])
	@ApiParam({ name: 'id', type: 'string', required: true })
	async update(
		@Res() res: FastifyReply,
		@Param('id', FindApiKeyByIdPipe) { id }: ApiKey,
		@Body() payload: UpdateApiKeyZodDto
	) {
		const apiKey = await this.apiKeyService.update({
			where: { id },
			data: payload,
		});
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: apiKey,
			message: 'Api key updated',
		});
	}

	@Delete('/:id')
	@Auth([AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE])
	@ApiParam({ name: 'id', type: 'string', required: true })
	async delete(
		@Res() res: FastifyReply,
		@Param('id', FindApiKeyByIdPipe) apiKey: ApiKey
	) {
		if (apiKey.default) {
			throw new ZodValidationException(
				z.ZodError.create([
					{
						code: 'custom',
						path: [],
						message: 'You cannot delete the default api key',
					},
				])
			);
		}
		const apiKeyDeleted = await this.apiKeyService.delete({ id: apiKey.id });
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: apiKeyDeleted,
			message: 'Api key deleted',
		});
	}
}
