import { ArgumentsHost, Catch, ExceptionFilter } from '@nestjs/common';
import { FastifyReply } from 'fastify';
import { ZodValidationException } from '../utils/zod';

@Catch(ZodValidationException)
export class ZodValidationExceptionFilter implements ExceptionFilter {
	catch(exception: ZodValidationException, host: ArgumentsHost) {
		const ctx = host.switchToHttp();
		const response = ctx.getResponse<FastifyReply>();

		const issues =
			exception.zodError.issues?.map(issue => ({
				path: issue.path,
				message: issue.message,
				code: issue.code,
			})) ?? [];

		response.status(400).send({
			statusCode: 400,
			message: exception.message,
			errors: issues,
		});
	}
}
