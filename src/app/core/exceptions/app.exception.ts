import { HttpException, HttpStatus } from '@nestjs/common';
import {
	ErrorCode,
	ErrorCodeToHttpStatus,
	ErrorMessages,
} from '../types/error-codes';

export interface AppErrorOptions {
	code: ErrorCode;
	message?: string;
	details?: Record<string, unknown>;
	statusCode?: number;
}

/**
 * Custom application exception with standardized error codes
 */
export class AppException extends HttpException {
	public readonly code: ErrorCode;
	public readonly details?: Record<string, unknown>;

	constructor(options: AppErrorOptions) {
		const { code, message, details, statusCode } = options;

		// Use custom message or default message for the error code
		const errorMessage = message || ErrorMessages[code];

		// Use custom status code or default status code for the error code
		const httpStatus =
			statusCode ||
			ErrorCodeToHttpStatus[code] ||
			HttpStatus.INTERNAL_SERVER_ERROR;

		// Create response object
		const response = {
			statusCode: httpStatus,
			code,
			message: errorMessage,
			...(details && { details }),
			timestamp: new Date().toISOString(),
		};

		super(response, httpStatus);

		this.code = code;
		this.details = details;
	}

	/**
	 * Factory methods for common errors
	 */

	static invalidCredentials(message?: string): AppException {
		return new AppException({
			code: ErrorCode.AUTH_INVALID_CREDENTIALS,
			message,
		});
	}

	static accountNotActivated(message?: string): AppException {
		return new AppException({
			code: ErrorCode.AUTH_ACCOUNT_NOT_ACTIVATED,
			message,
		});
	}

	static accountBlocked(message?: string): AppException {
		return new AppException({
			code: ErrorCode.AUTH_ACCOUNT_BLOCKED,
			message,
		});
	}

	static tokenExpired(message?: string): AppException {
		return new AppException({
			code: ErrorCode.AUTH_TOKEN_EXPIRED,
			message,
		});
	}

	static tokenInvalid(message?: string): AppException {
		return new AppException({
			code: ErrorCode.AUTH_TOKEN_INVALID,
			message,
		});
	}

	static permissionDenied(resource?: string, action?: string): AppException {
		return new AppException({
			code: ErrorCode.AUTHZ_PERMISSION_DENIED,
			details: { resource, action },
		});
	}

	static resourceNotFound(resource: string, id?: string): AppException {
		return new AppException({
			code: ErrorCode.RESOURCE_NOT_FOUND,
			message: `${resource} not found`,
			details: { resource, id },
		});
	}

	static userNotFound(identifier?: string): AppException {
		return new AppException({
			code: ErrorCode.USER_NOT_FOUND,
			details: { identifier },
		});
	}

	static validationFailed(errors: Record<string, unknown>): AppException {
		return new AppException({
			code: ErrorCode.VALIDATION_FAILED,
			details: { errors },
		});
	}

	static rateLimitExceeded(retryAfter?: number): AppException {
		return new AppException({
			code: ErrorCode.RATE_LIMIT_EXCEEDED,
			details: { retryAfter },
		});
	}

	static bruteForceDetected(
		identifier: string,
		lockDuration?: number
	): AppException {
		return new AppException({
			code: ErrorCode.SECURITY_BRUTE_FORCE_DETECTED,
			details: { identifier, lockDuration },
		});
	}

	static internalError(
		message?: string,
		details?: Record<string, unknown>
	): AppException {
		return new AppException({
			code: ErrorCode.SYSTEM_INTERNAL_ERROR,
			message,
			details,
		});
	}
}
