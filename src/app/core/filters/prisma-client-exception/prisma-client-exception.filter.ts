import { ArgumentsHost, Catch, HttpStatus, Logger } from '@nestjs/common';
import { BaseExceptionFilter } from '@nestjs/core';
import { Prisma } from '@prisma/client';

@Catch(Prisma.PrismaClientKnownRequestError)
export class PrismaClientExceptionFilter extends BaseExceptionFilter {
  readonly #logger = new Logger(PrismaClientExceptionFilter.name);

  catch(exception: Prisma.PrismaClientKnownRequestError, host: ArgumentsHost) {
    this.#logger.error(exception.code, exception.message);
    this.#logger.error(exception.meta);

    const response = host.switchToHttp().getResponse();

    switch ( exception.code ) {
      case 'P2002': {
        response.code(HttpStatus.BAD_REQUEST).send({
          statusCode: 400,
          message: 'Error on validating of information, possible conflict of data',
          error: exception.name,
        });
        break;
      }
      default:
        // default 500 error code
        super.catch(exception, host);
        break;
    }
  }
}
