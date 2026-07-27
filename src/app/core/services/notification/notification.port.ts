/**
 * The contract the application relies on for outbound user notifications.
 *
 * Declared as an abstract class rather than a TypeScript `interface` because
 * Nest needs a runtime value to use as an injection token — an interface
 * disappears at compile time. Consumers inject `NotificationPort`; the module
 * decides which implementation answers.
 *
 * To plug in a real provider, implement this class and swap the binding in
 * NotificationModule. Nothing else in the codebase has to change:
 *
 *   @Injectable()
 *   export class SesNotificationAdapter extends NotificationPort { ... }
 *
 *   { provide: NotificationPort, useClass: SesNotificationAdapter }
 *
 * Implementations must not throw. These calls sit on security-sensitive paths
 * (a lockout, a suspicious login) and a failing mail provider must never be
 * the reason a user cannot sign in. Swallow and log instead.
 */

/** A user signed in from a device or location. */
export interface NewSessionNotification {
	userId: string;
	email: string;
	device: string;
	ipAddress?: string;
	userAgent?: string;
	location?: string;
	timestamp: Date;
}

/** A sign-in looked wrong enough to tell the account owner about. */
export interface SuspiciousLoginNotification {
	userId: string;
	email: string;
	reason: string;
	ipAddress?: string;
	userAgent?: string;
	timestamp: Date;
}

/** The account's password was changed. */
export interface PasswordChangeNotification {
	userId: string;
	email: string;
	timestamp: Date;
}

/** The account was locked, usually by brute-force protection. */
export interface AccountLockedNotification {
	userId: string;
	email: string;
	reason: string;
	unlockTime?: Date;
}

/** A session was ended by something other than the user's own logout. */
export interface SessionTerminatedNotification {
	userId: string;
	email: string;
	reason: string;
	device: string;
}

export abstract class NotificationPort {
	abstract notifyNewSession(
		notification: NewSessionNotification
	): Promise<void>;

	abstract notifySuspiciousLogin(
		notification: SuspiciousLoginNotification
	): Promise<void>;

	abstract notifyPasswordChange(
		notification: PasswordChangeNotification
	): Promise<void>;

	abstract notifyAccountLocked(
		notification: AccountLockedNotification
	): Promise<void>;

	abstract notifySessionTerminated(
		notification: SessionTerminatedNotification
	): Promise<void>;
}
