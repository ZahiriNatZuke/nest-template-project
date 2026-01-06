import { AppController } from '@app/core/decorators/app-controller/app-controller.decorator';
import { Authz } from '@app/modules/auth/decorators/authz.decorator';
import { FindSessionByIdPipe } from '@app/modules/session/pipes/find-session-by-id.pipe';
import { SessionService } from '@app/modules/session/session.service';
import { FindUserByIdPipe } from '@app/modules/user/pipes/find-user-by-id.pipe';
import { Delete, Get, HttpStatus, Param, Res } from '@nestjs/common';
import { ApiParam } from '@nestjs/swagger';
import { Session, User } from '@prisma/client';
import { FastifyReply } from 'fastify';

@AppController('session')
export class SessionController {
	constructor(private sessionService: SessionService) {}

	@Get()
	@Authz('sessions:read')
	async findMany(
		@Res() res: FastifyReply,
		@Param('userId', FindUserByIdPipe) { id }: User
	) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: await this.sessionService.findMany({ userId: id }),
		});
	}

	@Get(':id')
	@Authz('sessions:read')
	@ApiParam({ name: 'id', type: 'string', required: true })
	async findOne(
		@Res() res: FastifyReply,
		@Param('id', FindSessionByIdPipe) { id }: Session
	) {
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: await this.sessionService.findOne({ id }),
		});
	}

	@Delete(':id')
	@Authz('sessions:delete')
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
