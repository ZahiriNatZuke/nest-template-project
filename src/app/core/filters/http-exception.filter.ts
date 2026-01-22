import {
	ArgumentsHost,
	Catch,
	ExceptionFilter,
	HttpException,
} from '@nestjs/common';
import { FastifyReply } from 'fastify';

@Catch(HttpException)
export class HttpExceptionFilter<T extends HttpException>
	implements ExceptionFilter
{
	catch(exception: T, host: ArgumentsHost) {
		const ctx = host.switchToHttp();
		const response = ctx.getResponse<FastifyReply>();

		const status = exception.getStatus();
		const exceptionResponse = exception.getResponse();

		const error =
			typeof response === 'string'
				? { message: exceptionResponse }
				: (exceptionResponse as object);

		response.status(status).send({
			statusCode: status,
			status: 'error',
			...error,
			timestamp: new Date().toISOString(),
		});
	}
}
