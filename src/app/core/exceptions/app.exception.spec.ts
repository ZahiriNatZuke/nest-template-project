import { HttpStatus } from '@nestjs/common';
import { ErrorCode } from '../types/error-codes';
import { AppException } from './app.exception';

describe('AppException', () => {
	describe('constructor', () => {
		it('should create exception with error code and default message', () => {
			const exception = new AppException({
				code: ErrorCode.AUTH_INVALID_CREDENTIALS,
			});

			expect(exception.code).toBe(ErrorCode.AUTH_INVALID_CREDENTIALS);
			expect(exception.getStatus()).toBe(HttpStatus.UNAUTHORIZED);
			expect(exception.message).toContain('Invalid username or password');
		});

		it('should create exception with custom message', () => {
			const customMessage = 'Custom error message';
			const exception = new AppException({
				code: ErrorCode.USER_NOT_FOUND,
				message: customMessage,
			});

			expect(exception.message).toContain(customMessage);
		});

		it('should create exception with details', () => {
			const details = { userId: '123', reason: 'test' };
			const exception = new AppException({
				code: ErrorCode.RESOURCE_NOT_FOUND,
				details,
			});

			expect(exception.details).toEqual(details);
		});

		it('should use custom status code if provided', () => {
			const exception = new AppException({
				code: ErrorCode.SYSTEM_INTERNAL_ERROR,
				statusCode: HttpStatus.SERVICE_UNAVAILABLE,
			});

			expect(exception.getStatus()).toBe(HttpStatus.SERVICE_UNAVAILABLE);
		});
	});

	describe('factory methods', () => {
		it('should create invalidCredentials exception', () => {
			const exception = AppException.invalidCredentials();
			expect(exception.code).toBe(ErrorCode.AUTH_INVALID_CREDENTIALS);
			expect(exception.getStatus()).toBe(HttpStatus.UNAUTHORIZED);
		});

		it('should create accountNotActivated exception', () => {
			const exception = AppException.accountNotActivated();
			expect(exception.code).toBe(ErrorCode.AUTH_ACCOUNT_NOT_ACTIVATED);
		});

		it('should create accountBlocked exception', () => {
			const exception = AppException.accountBlocked();
			expect(exception.code).toBe(ErrorCode.AUTH_ACCOUNT_BLOCKED);
			expect(exception.getStatus()).toBe(HttpStatus.FORBIDDEN);
		});

		it('should create tokenExpired exception', () => {
			const exception = AppException.tokenExpired();
			expect(exception.code).toBe(ErrorCode.AUTH_TOKEN_EXPIRED);
		});

		it('should create tokenInvalid exception', () => {
			const exception = AppException.tokenInvalid();
			expect(exception.code).toBe(ErrorCode.AUTH_TOKEN_INVALID);
		});

		it('should create permissionDenied exception with details', () => {
			const exception = AppException.permissionDenied('users', 'delete');
			expect(exception.code).toBe(ErrorCode.AUTHZ_PERMISSION_DENIED);
			expect(exception.details).toEqual({
				resource: 'users',
				action: 'delete',
			});
			expect(exception.getStatus()).toBe(HttpStatus.FORBIDDEN);
		});

		it('should create resourceNotFound exception with details', () => {
			const exception = AppException.resourceNotFound('User', '123');
			expect(exception.code).toBe(ErrorCode.RESOURCE_NOT_FOUND);
			expect(exception.details).toEqual({ resource: 'User', id: '123' });
			expect(exception.getStatus()).toBe(HttpStatus.NOT_FOUND);
		});

		it('should create userNotFound exception', () => {
			const exception = AppException.userNotFound('user@example.com');
			expect(exception.code).toBe(ErrorCode.USER_NOT_FOUND);
			expect(exception.details).toEqual({ identifier: 'user@example.com' });
		});

		it('should create validationFailed exception', () => {
			const errors = { email: 'Invalid email format' };
			const exception = AppException.validationFailed(errors);
			expect(exception.code).toBe(ErrorCode.VALIDATION_FAILED);
			expect(exception.details).toEqual({ errors });
			expect(exception.getStatus()).toBe(HttpStatus.BAD_REQUEST);
		});

		it('should create rateLimitExceeded exception', () => {
			const exception = AppException.rateLimitExceeded(60);
			expect(exception.code).toBe(ErrorCode.RATE_LIMIT_EXCEEDED);
			expect(exception.details).toEqual({ retryAfter: 60 });
			expect(exception.getStatus()).toBe(429);
		});

		it('should create bruteForceDetected exception', () => {
			const exception = AppException.bruteForceDetected(
				'user@example.com',
				300
			);
			expect(exception.code).toBe(ErrorCode.SECURITY_BRUTE_FORCE_DETECTED);
			expect(exception.details).toEqual({
				identifier: 'user@example.com',
				lockDuration: 300,
			});
			expect(exception.getStatus()).toBe(429);
		});

		it('should create internalError exception', () => {
			const exception = AppException.internalError(
				'Database connection failed'
			);
			expect(exception.code).toBe(ErrorCode.SYSTEM_INTERNAL_ERROR);
			expect(exception.getStatus()).toBe(HttpStatus.INTERNAL_SERVER_ERROR);
		});
	});

	describe('response structure', () => {
		it('should include all required fields in response', () => {
			const exception = new AppException({
				code: ErrorCode.USER_NOT_FOUND,
				details: { userId: '123' },
			});

			const response = exception.getResponse() as Record<string, unknown>;

			expect(response).toHaveProperty('statusCode');
			expect(response).toHaveProperty('code');
			expect(response).toHaveProperty('message');
			expect(response).toHaveProperty('details');
			expect(response).toHaveProperty('timestamp');
		});

		it('should not include details if not provided', () => {
			const exception = new AppException({
				code: ErrorCode.AUTH_TOKEN_EXPIRED,
			});

			const response = exception.getResponse() as Record<string, unknown>;

			expect(response).not.toHaveProperty('details');
		});
	});
});
