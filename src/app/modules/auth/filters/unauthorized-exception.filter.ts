import { ArgumentsHost, Catch, ExceptionFilter, HttpStatus, Logger, UnauthorizedException } from '@nestjs/common';
import { FastifyReply } from 'fastify';

@Catch(UnauthorizedException)
export class UnauthorizedExceptionFilter implements ExceptionFilter {
  readonly #logger = new Logger(UnauthorizedExceptionFilter.name);

  public catch(
    exception: UnauthorizedException,
    host: ArgumentsHost,
  ): FastifyReply {
    const ctx = host.switchToHttp();
    const response: FastifyReply = ctx.getResponse();
    this.#logger.error(exception.message);
    return response.code(HttpStatus.UNAUTHORIZED).send({
      statusCode: 403,
      message: exception.message,
    });
  }
}
