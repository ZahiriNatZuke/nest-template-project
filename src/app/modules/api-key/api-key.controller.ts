import { AppController } from '@app/core/decorators/app-controller.decorator';
import { ZodValidationException } from '@app/core/utils/zod';
import { CreateApiKeyZodDto } from '@app/modules/api-key/dto/create-api-key.dto';
import { FindApiKeyByIdPipe } from '@app/modules/api-key/pipes/find-api-key-by-id.pipe';
import { Authz } from '@app/modules/auth/decorators/authz.decorator';
import {
	Body,
	Delete,
	Get,
	HttpStatus,
	Param,
	Post,
	Res,
} from '@nestjs/common';
import { ApiParam } from '@nestjs/swagger';
import { ApiKey } from '@prisma/client';
import { FastifyReply } from 'fastify';
import { z } from 'zod';
import { ApiKeyService } from './api-key.service';

@AppController('api-key')
export class ApiKeyController {
	constructor(private apiKeyService: ApiKeyService) {}

	@Post()
	@Authz('api-keys:write')
	async create(@Res() res: FastifyReply, @Body() payload: CreateApiKeyZodDto) {
		const result = await this.apiKeyService.create(payload);
		return res.code(HttpStatus.CREATED).send({
			statusCode: 201,
			data: result.apiKey,
			plainKey: result.plainKey, // Only revealed once on creation
			message:
				'Api key created - save the plainKey, it will not be shown again',
		});
	}

	@Get()
	@Authz('api-keys:read')
	async findMany(@Res() res: FastifyReply) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: await this.apiKeyService.findMany(),
		});
	}

	@Get(':id')
	@ApiParam({ name: 'id', type: 'string', required: true })
	@Authz('api-keys:read')
	async findOne(
		@Res() res: FastifyReply,
		@Param('id', FindApiKeyByIdPipe) apiKey: ApiKey
	) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: apiKey,
		});
	}

	@Delete(':id')
	@Authz('api-keys:delete')
	@ApiParam({ name: 'id', type: 'string', required: true })
	async delete(
		@Res() res: FastifyReply,
		@Param('id', FindApiKeyByIdPipe) apiKey: ApiKey
	) {
		if (apiKey.default) {
			throw new ZodValidationException(
				new z.ZodError([
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
