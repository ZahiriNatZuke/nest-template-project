import { Logger } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { LoggingNotificationAdapter } from './logging-notification.adapter';
import { NotificationPort } from './notification.port';

describe('LoggingNotificationAdapter', () => {
	let adapter: LoggingNotificationAdapter;

	const AT = new Date('2026-01-01T12:00:00.000Z');

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				{ provide: NotificationPort, useClass: LoggingNotificationAdapter },
			],
		}).compile();

		adapter = module.get<LoggingNotificationAdapter>(NotificationPort);
	});

	it('satisfies the port contract', () => {
		expect(adapter).toBeInstanceOf(NotificationPort);
	});

	// Consumers call these on security-sensitive paths and do not guard them, so
	// the default implementation resolving cleanly is the contract.
	it.each([
		[
			'notifyNewSession',
			{ userId: 'u1', email: 'a@b.c', device: 'web', timestamp: AT },
		],
		[
			'notifySuspiciousLogin',
			{ userId: 'u1', email: 'a@b.c', reason: 'new country', timestamp: AT },
		],
		['notifyPasswordChange', { userId: 'u1', email: 'a@b.c', timestamp: AT }],
		[
			'notifyAccountLocked',
			{ userId: 'u1', email: 'a@b.c', reason: 'brute force' },
		],
		[
			'notifySessionTerminated',
			{ userId: 'u1', email: 'a@b.c', reason: 'limit', device: 'web' },
		],
	])('%s resolves without throwing', async (method, payload) => {
		await expect(
			(
				adapter[method as keyof LoggingNotificationAdapter] as (
					p: unknown
				) => Promise<void>
			).call(adapter, payload)
		).resolves.toBeUndefined();
	});

	describe('what it records', () => {
		it('logs the new session with its device and location', async () => {
			const log = jest.spyOn(Logger.prototype, 'log');

			await adapter.notifyNewSession({
				userId: 'u1',
				email: 'a@b.c',
				device: 'web',
				ipAddress: '203.0.113.10',
				location: 'Madrid',
				timestamp: AT,
			});

			expect(log).toHaveBeenCalledWith(
				expect.stringContaining('[notification:new-session]')
			);
			expect(log).toHaveBeenCalledWith(expect.stringContaining('device=web'));
			expect(log).toHaveBeenCalledWith(expect.stringContaining('Madrid'));
		});

		it('reports optional fields as unknown rather than undefined', async () => {
			const log = jest.spyOn(Logger.prototype, 'log');

			await adapter.notifyNewSession({
				userId: 'u1',
				email: 'a@b.c',
				device: 'web',
				timestamp: AT,
			});

			expect(log).toHaveBeenCalledWith(expect.stringContaining('ip=unknown'));
			expect(log).not.toHaveBeenCalledWith(
				expect.stringContaining('undefined')
			);
		});

		// Security events go to warn so they survive a production log level that
		// filters out `log`.
		it.each([
			[
				'notifySuspiciousLogin',
				{ userId: 'u1', email: 'a@b.c', reason: 'r', timestamp: AT },
			],
			[
				'notifyAccountLocked',
				{ userId: 'u1', email: 'a@b.c', reason: 'brute force' },
			],
		])('%s logs at warn level', async (method, payload) => {
			const warn = jest.spyOn(Logger.prototype, 'warn');

			await (
				adapter[method as keyof LoggingNotificationAdapter] as (
					p: unknown
				) => Promise<void>
			).call(adapter, payload);

			expect(warn).toHaveBeenCalled();
		});
	});
});
