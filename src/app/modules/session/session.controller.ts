import { Delete, Get, HttpStatus, Param, Res } from '@nestjs/common';

import { ApiParam } from '@nestjs/swagger';
import { Session, User } from '@prisma/client';

import { AppController } from '@app/core/decorators';
import { Auth } from '@app/modules/auth/decorators';
import { AuthRole } from '@app/modules/auth/enums';
import { FindSessionByIdPipe } from '@app/modules/session/pipes';
import { SessionService } from '@app/modules/session/session.service';
import { FindUserByIdPipe } from '@app/modules/user/pipes';
import { FastifyReply } from 'fastify';

@AppController('session')
export class SessionController {
	constructor(private sessionService: SessionService) {}

	@Get('/:userId')
	@Auth([AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE])
	async findMany(
		@Res() res: FastifyReply,
		@Param('userId', FindUserByIdPipe) { id }: User
	) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: await this.sessionService.findMany({ userId: id }),
		});
	}

	@Delete('/:id')
	@Auth([AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE])
	@ApiParam({ name: 'id', type: 'string', required: true })
	async delete(
		@Res() res: FastifyReply,
		@Param('id', FindSessionByIdPipe) { id }: Session
	) {
		await this.sessionService.delete({ id });
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: null,
			message: 'Session deleted',
		});
	}
}
