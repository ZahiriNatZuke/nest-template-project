import { Injectable, Logger } from '@nestjs/common';
import {
	type AccountLockedNotification,
	type NewSessionNotification,
	NotificationPort,
	type PasswordChangeNotification,
	type SessionTerminatedNotification,
	type SuspiciousLoginNotification,
} from './notification.port';

/**
 * Default NotificationPort implementation: writes what *would* have been sent
 * to the log and returns.
 *
 * This is what makes the template runnable without picking an email or SMS
 * provider for the reader. It is not a stub in the sense of being unfinished —
 * it is a deliberate null object, so the security paths that notify can be
 * exercised end to end before a provider exists.
 *
 * Replace the binding in NotificationModule when you wire up a real one.
 */
@Injectable()
export class LoggingNotificationAdapter extends NotificationPort {
	private readonly logger = new Logger(LoggingNotificationAdapter.name);

	async notifyNewSession(n: NewSessionNotification): Promise<void> {
		this.logger.log(
			`[notification:new-session] user=${n.userId} email=${n.email} ` +
				`device=${n.device} ip=${n.ipAddress ?? 'unknown'} ` +
				`location=${n.location ?? 'unknown'} at=${n.timestamp.toISOString()}`
		);
	}

	async notifySuspiciousLogin(n: SuspiciousLoginNotification): Promise<void> {
		this.logger.warn(
			`[notification:suspicious-login] user=${n.userId} email=${n.email} ` +
				`reason=${n.reason} ip=${n.ipAddress ?? 'unknown'} ` +
				`ua=${n.userAgent ?? 'unknown'} at=${n.timestamp.toISOString()}`
		);
	}

	async notifyPasswordChange(n: PasswordChangeNotification): Promise<void> {
		this.logger.log(
			`[notification:password-change] user=${n.userId} email=${n.email} ` +
				`at=${n.timestamp.toISOString()}`
		);
	}

	async notifyAccountLocked(n: AccountLockedNotification): Promise<void> {
		this.logger.warn(
			`[notification:account-locked] user=${n.userId} email=${n.email} ` +
				`reason=${n.reason} unlockAt=${n.unlockTime?.toISOString() ?? 'n/a'}`
		);
	}

	async notifySessionTerminated(
		n: SessionTerminatedNotification
	): Promise<void> {
		this.logger.log(
			`[notification:session-terminated] user=${n.userId} email=${n.email} ` +
				`device=${n.device} reason=${n.reason}`
		);
	}
}
