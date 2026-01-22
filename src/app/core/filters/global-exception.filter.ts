import {
	ArgumentsHost,
	Catch,
	ExceptionFilter,
	HttpException,
	HttpStatus,
	Logger,
} from '@nestjs/common';
import { FastifyReply } from 'fastify';
import { AppException } from '../exceptions/app.exception';
import { ErrorCode } from '../types/error-codes';

/**
 * Global exception filter that catches all exceptions and formats them consistently
 */
@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
	private readonly logger = new Logger(GlobalExceptionFilter.name);

	catch(exception: unknown, host: ArgumentsHost) {
		const ctx = host.switchToHttp();
		const response = ctx.getResponse<FastifyReply>();
		const request = ctx.getRequest();

		let statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
		let errorResponse: {
			statusCode: number;
			code?: ErrorCode;
			message: string;
			details?: Record<string, unknown>;
			timestamp: string;
			path?: string;
		};

		// Handle AppException (our custom exception)
		if (exception instanceof AppException) {
			statusCode = exception.getStatus();
			const exceptionResponse = exception.getResponse() as {
				statusCode: number;
				code: ErrorCode;
				message: string;
				details?: Record<string, unknown>;
				timestamp: string;
			};

			errorResponse = {
				...exceptionResponse,
				path: request.url,
			};

			// Log based on severity
			if (statusCode >= 500) {
				this.logger.error(
					`[${exceptionResponse.code}] ${exceptionResponse.message}`,
					exception.stack
				);
			} else if (statusCode >= 400) {
				this.logger.warn(
					`[${exceptionResponse.code}] ${exceptionResponse.message}`
				);
			}
		}
		// Handle NestJS HttpException
		else if (exception instanceof HttpException) {
			statusCode = exception.getStatus();
			const exceptionResponse = exception.getResponse();

			if (typeof exceptionResponse === 'object') {
				errorResponse = {
					statusCode,
					message:
						(exceptionResponse as { message?: string }).message ||
						'An error occurred',
					timestamp: new Date().toISOString(),
					path: request.url,
					...(exceptionResponse as Record<string, unknown>),
				};
			} else {
				errorResponse = {
					statusCode,
					message: exceptionResponse as string,
					timestamp: new Date().toISOString(),
					path: request.url,
				};
			}

			if (statusCode >= 500) {
				this.logger.error(errorResponse.message, exception.stack);
			} else if (statusCode >= 400) {
				this.logger.warn(errorResponse.message);
			}
		}
		// Handle unknown errors
		else {
			const error = exception as Error;
			errorResponse = {
				statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
				code: ErrorCode.SYSTEM_INTERNAL_ERROR,
				message: 'Internal server error',
				timestamp: new Date().toISOString(),
				path: request.url,
			};

			this.logger.error(
				`Unhandled exception: ${error.message}`,
				error.stack || ''
			);
		}

		// Send response
		response.status(statusCode).send(errorResponse);
	}
}
