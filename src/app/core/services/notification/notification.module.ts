import { Global, Module } from '@nestjs/common';
import { LoggingNotificationAdapter } from './logging-notification.adapter';
import { NotificationPort } from './notification.port';

/**
 * Binds the notification contract to its implementation.
 *
 * This is the single line to change when adopting the template: point
 * `useClass` at your own NotificationPort implementation and every consumer
 * picks it up, because they all inject the abstract port rather than a
 * concrete service.
 */
@Global()
@Module({
	providers: [
		{
			provide: NotificationPort,
			useClass: LoggingNotificationAdapter,
		},
	],
	exports: [NotificationPort],
})
export class NotificationModule {}
