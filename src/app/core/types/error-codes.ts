/**
 * Standardized error codes for the application
 * Format: CATEGORY_SPECIFIC_ERROR
 */
export enum ErrorCode {
	// Authentication errors (1000-1999)
	AUTH_INVALID_CREDENTIALS = 'AUTH_INVALID_CREDENTIALS',
	AUTH_ACCOUNT_NOT_ACTIVATED = 'AUTH_ACCOUNT_NOT_ACTIVATED',
	AUTH_ACCOUNT_BLOCKED = 'AUTH_ACCOUNT_BLOCKED',
	AUTH_TOKEN_EXPIRED = 'AUTH_TOKEN_EXPIRED',
	AUTH_TOKEN_INVALID = 'AUTH_TOKEN_INVALID',
	AUTH_TOKEN_BLACKLISTED = 'AUTH_TOKEN_BLACKLISTED',
	AUTH_REFRESH_TOKEN_INVALID = 'AUTH_REFRESH_TOKEN_INVALID',
	AUTH_SESSION_NOT_FOUND = 'AUTH_SESSION_NOT_FOUND',
	AUTH_CSRF_TOKEN_INVALID = 'AUTH_CSRF_TOKEN_INVALID',
	AUTH_2FA_REQUIRED = 'AUTH_2FA_REQUIRED',
	AUTH_2FA_INVALID = 'AUTH_2FA_INVALID',

	// Authorization errors (2000-2999)
	AUTHZ_PERMISSION_DENIED = 'AUTHZ_PERMISSION_DENIED',
	AUTHZ_ROLE_NOT_FOUND = 'AUTHZ_ROLE_NOT_FOUND',
	AUTHZ_RESOURCE_ACCESS_DENIED = 'AUTHZ_RESOURCE_ACCESS_DENIED',
	AUTHZ_POLICY_VIOLATION = 'AUTHZ_POLICY_VIOLATION',

	// User errors (3000-3999)
	USER_NOT_FOUND = 'USER_NOT_FOUND',
	USER_ALREADY_EXISTS = 'USER_ALREADY_EXISTS',
	USER_EMAIL_ALREADY_EXISTS = 'USER_EMAIL_ALREADY_EXISTS',
	USER_USERNAME_ALREADY_EXISTS = 'USER_USERNAME_ALREADY_EXISTS',
	USER_INVALID_PASSWORD = 'USER_INVALID_PASSWORD',
	USER_PASSWORD_TOO_WEAK = 'USER_PASSWORD_TOO_WEAK',
	USER_PROFILE_UPDATE_FAILED = 'USER_PROFILE_UPDATE_FAILED',

	// Validation errors (4000-4999)
	VALIDATION_FAILED = 'VALIDATION_FAILED',
	VALIDATION_INVALID_INPUT = 'VALIDATION_INVALID_INPUT',
	VALIDATION_REQUIRED_FIELD = 'VALIDATION_REQUIRED_FIELD',
	VALIDATION_INVALID_FORMAT = 'VALIDATION_INVALID_FORMAT',
	VALIDATION_OUT_OF_RANGE = 'VALIDATION_OUT_OF_RANGE',

	// Rate limiting errors (5000-5999)
	RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
	RATE_LIMIT_TOO_MANY_REQUESTS = 'RATE_LIMIT_TOO_MANY_REQUESTS',
	RATE_LIMIT_ACCOUNT_LOCKED = 'RATE_LIMIT_ACCOUNT_LOCKED',
	RATE_LIMIT_IP_BLOCKED = 'RATE_LIMIT_IP_BLOCKED',

	// Resource errors (6000-6999)
	RESOURCE_NOT_FOUND = 'RESOURCE_NOT_FOUND',
	RESOURCE_ALREADY_EXISTS = 'RESOURCE_ALREADY_EXISTS',
	RESOURCE_CONFLICT = 'RESOURCE_CONFLICT',
	RESOURCE_DELETED = 'RESOURCE_DELETED',

	// Security errors (7000-7999)
	SECURITY_BRUTE_FORCE_DETECTED = 'SECURITY_BRUTE_FORCE_DETECTED',
	SECURITY_SUSPICIOUS_ACTIVITY = 'SECURITY_SUSPICIOUS_ACTIVITY',
	SECURITY_SESSION_HIJACK = 'SECURITY_SESSION_HIJACK',
	SECURITY_ENCRYPTION_FAILED = 'SECURITY_ENCRYPTION_FAILED',
	SECURITY_DECRYPTION_FAILED = 'SECURITY_DECRYPTION_FAILED',

	// System errors (8000-8999)
	SYSTEM_INTERNAL_ERROR = 'SYSTEM_INTERNAL_ERROR',
	SYSTEM_DATABASE_ERROR = 'SYSTEM_DATABASE_ERROR',
	SYSTEM_SERVICE_UNAVAILABLE = 'SYSTEM_SERVICE_UNAVAILABLE',
	SYSTEM_MAINTENANCE = 'SYSTEM_MAINTENANCE',

	// API errors (9000-9999)
	API_KEY_INVALID = 'API_KEY_INVALID',
	API_KEY_EXPIRED = 'API_KEY_EXPIRED',
	API_KEY_REVOKED = 'API_KEY_REVOKED',
	API_VERSION_NOT_SUPPORTED = 'API_VERSION_NOT_SUPPORTED',
	API_ENDPOINT_NOT_FOUND = 'API_ENDPOINT_NOT_FOUND',
}

/**
 * Error code to HTTP status mapping
 */
export const ErrorCodeToHttpStatus: Record<ErrorCode, number> = {
	// Authentication errors -> 401
	[ErrorCode.AUTH_INVALID_CREDENTIALS]: 401,
	[ErrorCode.AUTH_ACCOUNT_NOT_ACTIVATED]: 401,
	[ErrorCode.AUTH_ACCOUNT_BLOCKED]: 403,
	[ErrorCode.AUTH_TOKEN_EXPIRED]: 401,
	[ErrorCode.AUTH_TOKEN_INVALID]: 401,
	[ErrorCode.AUTH_TOKEN_BLACKLISTED]: 401,
	[ErrorCode.AUTH_REFRESH_TOKEN_INVALID]: 401,
	[ErrorCode.AUTH_SESSION_NOT_FOUND]: 401,
	[ErrorCode.AUTH_CSRF_TOKEN_INVALID]: 403,
	[ErrorCode.AUTH_2FA_REQUIRED]: 401,
	[ErrorCode.AUTH_2FA_INVALID]: 401,

	// Authorization errors -> 403
	[ErrorCode.AUTHZ_PERMISSION_DENIED]: 403,
	[ErrorCode.AUTHZ_ROLE_NOT_FOUND]: 404,
	[ErrorCode.AUTHZ_RESOURCE_ACCESS_DENIED]: 403,
	[ErrorCode.AUTHZ_POLICY_VIOLATION]: 403,

	// User errors -> 400/404/409
	[ErrorCode.USER_NOT_FOUND]: 404,
	[ErrorCode.USER_ALREADY_EXISTS]: 409,
	[ErrorCode.USER_EMAIL_ALREADY_EXISTS]: 409,
	[ErrorCode.USER_USERNAME_ALREADY_EXISTS]: 409,
	[ErrorCode.USER_INVALID_PASSWORD]: 400,
	[ErrorCode.USER_PASSWORD_TOO_WEAK]: 400,
	[ErrorCode.USER_PROFILE_UPDATE_FAILED]: 400,

	// Validation errors -> 400
	[ErrorCode.VALIDATION_FAILED]: 400,
	[ErrorCode.VALIDATION_INVALID_INPUT]: 400,
	[ErrorCode.VALIDATION_REQUIRED_FIELD]: 400,
	[ErrorCode.VALIDATION_INVALID_FORMAT]: 400,
	[ErrorCode.VALIDATION_OUT_OF_RANGE]: 400,

	// Rate limiting errors -> 429
	[ErrorCode.RATE_LIMIT_EXCEEDED]: 429,
	[ErrorCode.RATE_LIMIT_TOO_MANY_REQUESTS]: 429,
	[ErrorCode.RATE_LIMIT_ACCOUNT_LOCKED]: 429,
	[ErrorCode.RATE_LIMIT_IP_BLOCKED]: 429,

	// Resource errors -> 404/409/410
	[ErrorCode.RESOURCE_NOT_FOUND]: 404,
	[ErrorCode.RESOURCE_ALREADY_EXISTS]: 409,
	[ErrorCode.RESOURCE_CONFLICT]: 409,
	[ErrorCode.RESOURCE_DELETED]: 410,

	// Security errors -> 403/500
	[ErrorCode.SECURITY_BRUTE_FORCE_DETECTED]: 429,
	[ErrorCode.SECURITY_SUSPICIOUS_ACTIVITY]: 403,
	[ErrorCode.SECURITY_SESSION_HIJACK]: 403,
	[ErrorCode.SECURITY_ENCRYPTION_FAILED]: 500,
	[ErrorCode.SECURITY_DECRYPTION_FAILED]: 500,

	// System errors -> 500/503
	[ErrorCode.SYSTEM_INTERNAL_ERROR]: 500,
	[ErrorCode.SYSTEM_DATABASE_ERROR]: 500,
	[ErrorCode.SYSTEM_SERVICE_UNAVAILABLE]: 503,
	[ErrorCode.SYSTEM_MAINTENANCE]: 503,

	// API errors -> 401/404/410
	[ErrorCode.API_KEY_INVALID]: 401,
	[ErrorCode.API_KEY_EXPIRED]: 401,
	[ErrorCode.API_KEY_REVOKED]: 401,
	[ErrorCode.API_VERSION_NOT_SUPPORTED]: 404,
	[ErrorCode.API_ENDPOINT_NOT_FOUND]: 404,
};

/**
 * Human-readable error messages
 */
export const ErrorMessages: Record<ErrorCode, string> = {
	// Authentication errors
	[ErrorCode.AUTH_INVALID_CREDENTIALS]: 'Invalid username or password',
	[ErrorCode.AUTH_ACCOUNT_NOT_ACTIVATED]: 'Account not activated',
	[ErrorCode.AUTH_ACCOUNT_BLOCKED]: 'Account has been blocked',
	[ErrorCode.AUTH_TOKEN_EXPIRED]: 'Authentication token has expired',
	[ErrorCode.AUTH_TOKEN_INVALID]: 'Invalid authentication token',
	[ErrorCode.AUTH_TOKEN_BLACKLISTED]: 'Token has been revoked',
	[ErrorCode.AUTH_REFRESH_TOKEN_INVALID]: 'Invalid refresh token',
	[ErrorCode.AUTH_SESSION_NOT_FOUND]: 'Session not found',
	[ErrorCode.AUTH_CSRF_TOKEN_INVALID]: 'Invalid CSRF token',
	[ErrorCode.AUTH_2FA_REQUIRED]: 'Two-factor authentication required',
	[ErrorCode.AUTH_2FA_INVALID]: 'Invalid 2FA code',

	// Authorization errors
	[ErrorCode.AUTHZ_PERMISSION_DENIED]: 'Permission denied',
	[ErrorCode.AUTHZ_ROLE_NOT_FOUND]: 'Role not found',
	[ErrorCode.AUTHZ_RESOURCE_ACCESS_DENIED]: 'Access denied to this resource',
	[ErrorCode.AUTHZ_POLICY_VIOLATION]: 'Policy violation detected',

	// User errors
	[ErrorCode.USER_NOT_FOUND]: 'User not found',
	[ErrorCode.USER_ALREADY_EXISTS]: 'User already exists',
	[ErrorCode.USER_EMAIL_ALREADY_EXISTS]: 'Email already registered',
	[ErrorCode.USER_USERNAME_ALREADY_EXISTS]: 'Username already taken',
	[ErrorCode.USER_INVALID_PASSWORD]: 'Current password is incorrect',
	[ErrorCode.USER_PASSWORD_TOO_WEAK]:
		'Password does not meet security requirements',
	[ErrorCode.USER_PROFILE_UPDATE_FAILED]: 'Failed to update user profile',

	// Validation errors
	[ErrorCode.VALIDATION_FAILED]: 'Validation failed',
	[ErrorCode.VALIDATION_INVALID_INPUT]: 'Invalid input provided',
	[ErrorCode.VALIDATION_REQUIRED_FIELD]: 'Required field is missing',
	[ErrorCode.VALIDATION_INVALID_FORMAT]: 'Invalid format',
	[ErrorCode.VALIDATION_OUT_OF_RANGE]: 'Value is out of acceptable range',

	// Rate limiting errors
	[ErrorCode.RATE_LIMIT_EXCEEDED]: 'Rate limit exceeded',
	[ErrorCode.RATE_LIMIT_TOO_MANY_REQUESTS]: 'Too many requests',
	[ErrorCode.RATE_LIMIT_ACCOUNT_LOCKED]:
		'Account temporarily locked due to too many attempts',
	[ErrorCode.RATE_LIMIT_IP_BLOCKED]: 'IP address temporarily blocked',

	// Resource errors
	[ErrorCode.RESOURCE_NOT_FOUND]: 'Resource not found',
	[ErrorCode.RESOURCE_ALREADY_EXISTS]: 'Resource already exists',
	[ErrorCode.RESOURCE_CONFLICT]: 'Resource conflict detected',
	[ErrorCode.RESOURCE_DELETED]: 'Resource has been deleted',

	// Security errors
	[ErrorCode.SECURITY_BRUTE_FORCE_DETECTED]: 'Brute force attack detected',
	[ErrorCode.SECURITY_SUSPICIOUS_ACTIVITY]: 'Suspicious activity detected',
	[ErrorCode.SECURITY_SESSION_HIJACK]: 'Session hijack attempt detected',
	[ErrorCode.SECURITY_ENCRYPTION_FAILED]: 'Encryption operation failed',
	[ErrorCode.SECURITY_DECRYPTION_FAILED]: 'Decryption operation failed',

	// System errors
	[ErrorCode.SYSTEM_INTERNAL_ERROR]: 'Internal server error',
	[ErrorCode.SYSTEM_DATABASE_ERROR]: 'Database operation failed',
	[ErrorCode.SYSTEM_SERVICE_UNAVAILABLE]: 'Service temporarily unavailable',
	[ErrorCode.SYSTEM_MAINTENANCE]: 'System under maintenance',

	// API errors
	[ErrorCode.API_KEY_INVALID]: 'Invalid API key',
	[ErrorCode.API_KEY_EXPIRED]: 'API key has expired',
	[ErrorCode.API_KEY_REVOKED]: 'API key has been revoked',
	[ErrorCode.API_VERSION_NOT_SUPPORTED]: 'API version not supported',
	[ErrorCode.API_ENDPOINT_NOT_FOUND]: 'API endpoint not found',
};
