import { Delete, Get, HttpStatus, Param, Res } from '@nestjs/common';
import { Auth } from '../auth/decorators/auth.decorator';
import { AuthRole } from '../auth/enums/auth-role';
import { ApiParam } from '@nestjs/swagger';
import { Session, User } from '@prisma/client';
import { SessionService } from './session.service';
import { FindUserByIdPipe } from '../user/pipes/find-user-by-id.pipe';
import { FindSessionByIdPipe } from './pipes/find-session-by-id/find-session-by-id.pipe';
import { SetController } from '../../core/decorators/set-controller.decorator';
import { FastifyReply } from 'fastify';

@SetController('session')
export class SessionController {

  constructor(private sessionService: SessionService) {
  }

  @Get('/:userId')
  @Auth([ AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE ])
  async findMany(
    @Res() res: FastifyReply,
    @Param('userId', FindUserByIdPipe) { id }: User,
  ) {
    return res.code(HttpStatus.OK).send({
      statusCode: 200,
      data: await this.sessionService.findMany({ userId: id }),
    });
  }

  @Delete('/:id')
  @Auth([ AuthRole.ROOT_ROLE, AuthRole.ADMIN_ROLE ])
  @ApiParam({ name: 'id', type: 'string', required: true })
  async delete(
    @Res() res: FastifyReply,
    @Param('id', FindSessionByIdPipe) { id }: Session,
  ) {
    await this.sessionService.delete({ id });
    return res.code(HttpStatus.OK).send({
      statusCode: 200,
      data: null,
      message: 'Session deleted',
    });
  }

}
