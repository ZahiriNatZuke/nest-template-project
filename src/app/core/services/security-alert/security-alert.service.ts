import { Injectable, Logger } from '@nestjs/common';
import { AuditService } from '../audit/audit.service';
import { NotificationService } from '../notification/notification.service';

export enum SecurityAlertType {
	BRUTE_FORCE_ATTEMPT = 'BRUTE_FORCE_ATTEMPT',
	ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
	SUSPICIOUS_LOGIN = 'SUSPICIOUS_LOGIN',
	PASSWORD_CHANGE = 'PASSWORD_CHANGE',
	SESSION_HIJACK_ATTEMPT = 'SESSION_HIJACK_ATTEMPT',
	UNAUTHORIZED_ACCESS_ATTEMPT = 'UNAUTHORIZED_ACCESS_ATTEMPT',
	MULTIPLE_FAILED_2FA = 'MULTIPLE_FAILED_2FA',
	DATA_BREACH_ATTEMPT = 'DATA_BREACH_ATTEMPT',
}

export interface SecurityAlertParams {
	type: SecurityAlertType;
	userId?: string;
	email?: string;
	severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
	message: string;
	metadata?: Record<string, unknown>;
	ipAddress?: string;
	userAgent?: string;
	timestamp?: Date;
}

/**
 * Security Alert Service
 *
 * Handles security-related alerts and integrates with:
 * - Notification service (email/SMS/push)
 * - Audit logging
 * - TODO: Webhook notifications for external systems (e.g., SIEM, Slack, PagerDuty)
 */
@Injectable()
export class SecurityAlertService {
	private readonly logger = new Logger(SecurityAlertService.name);

	constructor(
		private notificationService: NotificationService,
		private auditService: AuditService
	) {}

	/**
	 * Trigger a security alert
	 * @param params - Alert parameters
	 */
	async triggerAlert(params: SecurityAlertParams): Promise<void> {
		const { type, userId, severity, message, metadata, ipAddress, userAgent } =
			params;

		// Log the alert
		this.logAlert(severity, type, message, metadata);

		// Store in audit log with encryption for sensitive data
		await this.auditService.log({
			userId,
			action: 'SECURITY_ALERT',
			entityType: 'security',
			metadata: {
				alertType: type,
				severity,
				message,
				...metadata,
			},
			ipAddress,
			userAgent,
			encryptMetadata: true, // Encrypt sensitive security alert data
		});

		// Send notifications based on severity
		await this.sendNotifications(params);

		// TODO: Send to external monitoring systems (webhooks)
		// await this.sendToWebhook(params);
	}

	/**
	 * Alert for brute force attempts
	 */
	async alertBruteForceAttempt(params: {
		identifier: string;
		email?: string;
		ipAddress: string;
		attemptCount: number;
	}): Promise<void> {
		await this.triggerAlert({
			type: SecurityAlertType.BRUTE_FORCE_ATTEMPT,
			email: params.email,
			severity: 'HIGH',
			message: `Brute force attempt detected for ${params.identifier}`,
			metadata: {
				identifier: params.identifier,
				attemptCount: params.attemptCount,
			},
			ipAddress: params.ipAddress,
		});
	}

	/**
	 * Alert for account locked
	 */
	async alertAccountLocked(params: {
		userId: string;
		email: string;
		reason: string;
		unlockTime?: Date;
	}): Promise<void> {
		await this.triggerAlert({
			type: SecurityAlertType.ACCOUNT_LOCKED,
			userId: params.userId,
			email: params.email,
			severity: 'HIGH',
			message: `Account locked: ${params.reason}`,
			metadata: {
				reason: params.reason,
				unlockTime: params.unlockTime?.toISOString(),
			},
		});

		// Send notification to user
		await this.notificationService.notifyAccountLocked(params);
	}

	/**
	 * Alert for suspicious login
	 */
	async alertSuspiciousLogin(params: {
		userId: string;
		email: string;
		reason: string;
		ipAddress?: string;
		userAgent?: string;
	}): Promise<void> {
		await this.triggerAlert({
			type: SecurityAlertType.SUSPICIOUS_LOGIN,
			userId: params.userId,
			email: params.email,
			severity: 'MEDIUM',
			message: `Suspicious login attempt: ${params.reason}`,
			metadata: {
				reason: params.reason,
			},
			ipAddress: params.ipAddress,
			userAgent: params.userAgent,
		});

		// Send notification to user
		await this.notificationService.notifySuspiciousLogin({
			...params,
			timestamp: new Date(),
		});
	}

	/**
	 * Alert for password change
	 */
	async alertPasswordChange(params: {
		userId: string;
		email: string;
	}): Promise<void> {
		await this.triggerAlert({
			type: SecurityAlertType.PASSWORD_CHANGE,
			userId: params.userId,
			email: params.email,
			severity: 'MEDIUM',
			message: 'Password changed successfully',
		});

		// Send notification to user
		await this.notificationService.notifyPasswordChange({
			...params,
			timestamp: new Date(),
		});
	}

	/**
	 * Alert for session hijack attempt
	 */
	async alertSessionHijackAttempt(params: {
		userId: string;
		email?: string;
		reason: string;
		ipAddress?: string;
		userAgent?: string;
	}): Promise<void> {
		await this.triggerAlert({
			type: SecurityAlertType.SESSION_HIJACK_ATTEMPT,
			userId: params.userId,
			email: params.email,
			severity: 'CRITICAL',
			message: `Session hijack attempt detected: ${params.reason}`,
			metadata: {
				reason: params.reason,
			},
			ipAddress: params.ipAddress,
			userAgent: params.userAgent,
		});
	}

	/**
	 * Alert for unauthorized access attempt
	 */
	async alertUnauthorizedAccess(params: {
		userId?: string;
		email?: string;
		resource: string;
		action: string;
		ipAddress?: string;
		userAgent?: string;
	}): Promise<void> {
		await this.triggerAlert({
			type: SecurityAlertType.UNAUTHORIZED_ACCESS_ATTEMPT,
			userId: params.userId,
			email: params.email,
			severity: 'MEDIUM',
			message: `Unauthorized access attempt to ${params.resource}`,
			metadata: {
				resource: params.resource,
				action: params.action,
			},
			ipAddress: params.ipAddress,
			userAgent: params.userAgent,
		});
	}

	/**
	 * Log alert based on severity
	 */
	private logAlert(
		severity: string,
		type: SecurityAlertType,
		message: string,
		metadata?: Record<string, unknown>
	): void {
		const logMessage = `[${severity}] ${type}: ${message}`;
		const context = metadata ? JSON.stringify(metadata) : '';

		switch (severity) {
			case 'CRITICAL':
			case 'HIGH':
				this.logger.error(logMessage, context);
				break;
			case 'MEDIUM':
				this.logger.warn(logMessage, context);
				break;
			default:
				this.logger.log(logMessage, context);
		}
	}

	/**
	 * Send notifications based on severity
	 */
	private async sendNotifications(params: SecurityAlertParams): Promise<void> {
		const { severity, email, type } = params;

		// Only send notifications for MEDIUM, HIGH, and CRITICAL alerts
		if (severity === 'LOW' || !email) {
			return;
		}

		// Notifications are handled by specific alert methods
		// This is a placeholder for additional notification logic
		this.logger.log(
			`TODO: Send ${severity} security alert notification for ${type} to ${email}`
		);

		// TODO: Implement webhook notifications
		// if (severity === 'CRITICAL' || severity === 'HIGH') {
		//   await this.sendToWebhook(params);
		// }
	}

	/**
	 * TODO: Send alert to external webhook (e.g., Slack, PagerDuty, SIEM)
	 */
	// private async sendToWebhook(params: SecurityAlertParams): Promise<void> {
	//   // Implementation would depend on the external system
	//   // Example: POST to Slack webhook
	// }
}
