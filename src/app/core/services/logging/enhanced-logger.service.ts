import { Injectable, Logger } from '@nestjs/common';

export interface LogContext {
	correlationId?: string;
	userId?: string;
	username?: string;
	ipAddress?: string;
	userAgent?: string;
	requestMethod?: string;
	requestUrl?: string;
	[key: string]: unknown;
}

/**
 * Enhanced logging service with structured logging support
 * Includes correlation ID and user context
 */
@Injectable()
export class EnhancedLoggerService {
	private logger: Logger;
	private context: LogContext = {};

	constructor() {
		this.logger = new Logger();
	}

	/**
	 * Set the logger context name
	 */
	setContext(contextName: string): void {
		this.logger = new Logger(contextName);
	}

	/**
	 * Set logging context (correlation ID, user info, etc.)
	 */
	setLogContext(context: LogContext): void {
		this.context = { ...this.context, ...context };
	}

	/**
	 * Clear logging context
	 */
	clearContext(): void {
		this.context = {};
	}

	/**
	 * Format message with context
	 */
	private formatMessage(message: string): string {
		const contextParts: string[] = [];

		if (this.context.correlationId) {
			contextParts.push(`[${this.context.correlationId}]`);
		}

		if (this.context.userId) {
			contextParts.push(
				`[User: ${this.context.username || this.context.userId}]`
			);
		}

		if (this.context.requestMethod && this.context.requestUrl) {
			contextParts.push(
				`[${this.context.requestMethod} ${this.context.requestUrl}]`
			);
		}

		return contextParts.length > 0
			? `${contextParts.join(' ')} ${message}`
			: message;
	}

	/**
	 * Get structured context object
	 */
	private getStructuredContext(): Record<string, unknown> {
		return {
			...this.context,
			timestamp: new Date().toISOString(),
		};
	}

	/**
	 * Log at info level
	 */
	log(message: string, context?: Record<string, unknown>): void {
		const formattedMessage = this.formatMessage(message);
		const structuredContext = {
			...this.getStructuredContext(),
			...context,
		};

		this.logger.log(formattedMessage, JSON.stringify(structuredContext));
	}

	/**
	 * Log at error level
	 */
	error(
		message: string,
		trace?: string,
		context?: Record<string, unknown>
	): void {
		const formattedMessage = this.formatMessage(message);
		const structuredContext = {
			...this.getStructuredContext(),
			...context,
			...(trace && { trace }),
		};

		this.logger.error(
			formattedMessage,
			trace || '',
			JSON.stringify(structuredContext)
		);
	}

	/**
	 * Log at warn level
	 */
	warn(message: string, context?: Record<string, unknown>): void {
		const formattedMessage = this.formatMessage(message);
		const structuredContext = {
			...this.getStructuredContext(),
			...context,
		};

		this.logger.warn(formattedMessage, JSON.stringify(structuredContext));
	}

	/**
	 * Log at debug level
	 */
	debug(message: string, context?: Record<string, unknown>): void {
		const formattedMessage = this.formatMessage(message);
		const structuredContext = {
			...this.getStructuredContext(),
			...context,
		};

		this.logger.debug(formattedMessage, JSON.stringify(structuredContext));
	}

	/**
	 * Log at verbose level
	 */
	verbose(message: string, context?: Record<string, unknown>): void {
		const formattedMessage = this.formatMessage(message);
		const structuredContext = {
			...this.getStructuredContext(),
			...context,
		};

		this.logger.verbose(formattedMessage, JSON.stringify(structuredContext));
	}

	/**
	 * Log security event
	 */
	security(
		event: string,
		severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
		context?: Record<string, unknown>
	): void {
		const message = `[SECURITY-${severity}] ${event}`;
		const structuredContext = {
			...this.getStructuredContext(),
			...context,
			securityEvent: true,
			severity,
		};

		if (severity === 'CRITICAL' || severity === 'HIGH') {
			this.error(message, undefined, structuredContext);
		} else if (severity === 'MEDIUM') {
			this.warn(message, structuredContext);
		} else {
			this.log(message, structuredContext);
		}
	}

	/**
	 * Log audit event
	 */
	audit(
		action: string,
		entityType: string,
		entityId?: string,
		context?: Record<string, unknown>
	): void {
		const message = `[AUDIT] ${action} on ${entityType}${entityId ? ` (${entityId})` : ''}`;
		const structuredContext = {
			...this.getStructuredContext(),
			...context,
			auditEvent: true,
			action,
			entityType,
			entityId,
		};

		this.log(message, structuredContext);
	}
}
