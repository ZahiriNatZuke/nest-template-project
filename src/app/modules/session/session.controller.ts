import { AppController } from '@app/core/decorators/app-controller.decorator';
import { AuthRequest } from '@app/core/types/app-request';
import { Authz } from '@app/modules/auth/decorators/authz.decorator';
import { FindSessionByIdPipe } from '@app/modules/session/pipes/find-session-by-id.pipe';
import { SessionService } from '@app/modules/session/session.service';
import { Delete, Get, HttpStatus, Param, Req, Res } from '@nestjs/common';
import { ApiParam } from '@nestjs/swagger';
import { Session } from '@prisma/client';
import { FastifyReply } from 'fastify';

@AppController('session')
export class SessionController {
	constructor(private sessionService: SessionService) {}

	@Get()
	@Authz('sessions:read')
	async findMany(@Res() res: FastifyReply, @Req() req: AuthRequest) {
		// Reads the caller from the token, not from a route parameter. The route
		// is `/session` and declares no `:userId`, yet this used to resolve
		// `@Param('userId', FindUserByIdPipe)` — so the pipe was handed
		// `undefined`, failed its UUID check and answered 404 to every request.
		return res.code(HttpStatus.OK).send({
			statusCode: 200,
			data: await this.sessionService.findMany({ userId: req.user.id }),
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
