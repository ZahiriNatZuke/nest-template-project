import { Injectable, Logger } from '@nestjs/common';

/**
 * Notification Service for sending alerts to users
 *
 * TODO: Implement notification service when using this template
 * This service should be extended to support:
 * - Email notifications
 * - SMS notifications
 * - Push notifications
 * - In-app notifications
 *
 * Integration points:
 * - Email: nodemailer, sendgrid, ses, etc.
 * - SMS: twilio, vonage, aws sns, etc.
 * - Push: firebase, onesignal, etc.
 */
@Injectable()
export class NotificationService {
	private readonly logger = new Logger(NotificationService.name);

	/**
	 * Send notification about new session login
	 * @param params - User and session information
	 *
	 * TODO: Implement actual notification sending logic
	 */
	async notifyNewSession(params: {
		userId: string;
		email: string;
		device: string;
		ipAddress?: string;
		userAgent?: string;
		location?: string;
		timestamp: Date;
	}): Promise<void> {
		const { userId, email, device, ipAddress, userAgent, location, timestamp } =
			params;

		this.logger.log(
			`[TODO] Send new session notification to user ${userId} (${email})`
		);
		this.logger.log(`Device: ${device}`);
		this.logger.log(`IP Address: ${ipAddress || 'unknown'}`);
		this.logger.log(`User Agent: ${userAgent || 'unknown'}`);
		this.logger.log(`Location: ${location || 'unknown'}`);
		this.logger.log(`Timestamp: ${timestamp.toISOString()}`);

		// TODO: Implement email notification
		// Example structure:
		// await this.emailService.send({
		//   to: email,
		//   subject: 'New login detected',
		//   template: 'new-session',
		//   context: {
		//     device,
		//     ipAddress,
		//     userAgent,
		//     location,
		//     timestamp,
		//   },
		// });
	}

	/**
	 * Send notification about suspicious login attempt
	 * @param params - User and attempt information
	 *
	 * TODO: Implement actual notification sending logic
	 */
	async notifySuspiciousLogin(params: {
		userId: string;
		email: string;
		reason: string;
		ipAddress?: string;
		userAgent?: string;
		timestamp: Date;
	}): Promise<void> {
		const { userId, email, reason, ipAddress, userAgent, timestamp } = params;

		this.logger.warn(
			`[TODO] Send suspicious login notification to user ${userId} (${email})`
		);
		this.logger.warn(`Reason: ${reason}`);
		this.logger.warn(`IP Address: ${ipAddress || 'unknown'}`);
		this.logger.warn(`User Agent: ${userAgent || 'unknown'}`);
		this.logger.warn(`Timestamp: ${timestamp.toISOString()}`);

		// TODO: Implement email/SMS notification for security alerts
	}

	/**
	 * Send notification about password change
	 * @param params - User information
	 *
	 * TODO: Implement actual notification sending logic
	 */
	async notifyPasswordChange(params: {
		userId: string;
		email: string;
		timestamp: Date;
	}): Promise<void> {
		const { userId, email, timestamp } = params;

		this.logger.log(
			`[TODO] Send password change notification to user ${userId} (${email})`
		);
		this.logger.log(`Timestamp: ${timestamp.toISOString()}`);

		// TODO: Implement email notification
	}

	/**
	 * Send notification about account locked due to failed login attempts
	 * @param params - User information
	 *
	 * TODO: Implement actual notification sending logic
	 */
	async notifyAccountLocked(params: {
		userId: string;
		email: string;
		reason: string;
		unlockTime?: Date;
	}): Promise<void> {
		const { userId, email, reason, unlockTime } = params;

		this.logger.warn(
			`[TODO] Send account locked notification to user ${userId} (${email})`
		);
		this.logger.warn(`Reason: ${reason}`);
		if (unlockTime) {
			this.logger.warn(`Unlock time: ${unlockTime.toISOString()}`);
		}

		// TODO: Implement email/SMS notification for security alerts
	}

	/**
	 * Send notification about session termination
	 * @param params - User and session information
	 *
	 * TODO: Implement actual notification sending logic
	 */
	async notifySessionTerminated(params: {
		userId: string;
		email: string;
		reason: string;
		device: string;
	}): Promise<void> {
		const { userId, email, reason, device } = params;

		this.logger.log(
			`[TODO] Send session terminated notification to user ${userId} (${email})`
		);
		this.logger.log(`Device: ${device}`);
		this.logger.log(`Reason: ${reason}`);

		// TODO: Implement email notification
	}
}
