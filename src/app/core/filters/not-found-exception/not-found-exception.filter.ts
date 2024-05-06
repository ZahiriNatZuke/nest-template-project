import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpStatus,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';

@Catch(NotFoundException)
export class NotFoundExceptionFilter implements ExceptionFilter {
  readonly #logger = new Logger(NotFoundExceptionFilter.name);

  public catch(
    exception: UnauthorizedException,
    host: ArgumentsHost,
  ): Response {
    const response = host.switchToHttp().getResponse();
    const res: any = exception.getResponse();
    this.#logger.error(`${ res.message }`);
    this.#logger.error(`${ res.error }`);
    return response.code(HttpStatus.NOT_FOUND).send({
      statusCode: 404,
      message: res.message,
      error: res.error,
    });
  }
}
