import { Test, TestingModule } from '@nestjs/testing';
import { NotificationService } from './notification.service';

describe('NotificationService', () => {
	let service: NotificationService;

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [NotificationService],
		}).compile();

		service = module.get<NotificationService>(NotificationService);
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	describe('notifyNewSession', () => {
		it('should log new session notification (TODO implementation)', async () => {
			const logSpy = jest.spyOn(service.logger, 'log');

			await service.notifyNewSession({
				userId: 'user-1',
				email: 'user@example.com',
				device: 'Chrome/Windows',
				ipAddress: '192.168.1.1',
				userAgent: 'Mozilla/5.0',
				location: 'New York, US',
				timestamp: new Date(),
			});

			expect(logSpy).toHaveBeenCalled();
		});
	});

	describe('notifySuspiciousLogin', () => {
		it('should log suspicious login notification (TODO implementation)', async () => {
			const warnSpy = jest.spyOn(service.logger, 'warn');

			await service.notifySuspiciousLogin({
				userId: 'user-1',
				email: 'user@example.com',
				reason: 'Multiple failed login attempts',
				ipAddress: '192.168.1.1',
				userAgent: 'Mozilla/5.0',
				timestamp: new Date(),
			});

			expect(warnSpy).toHaveBeenCalled();
		});
	});

	describe('notifyPasswordChange', () => {
		it('should log password change notification (TODO implementation)', async () => {
			const logSpy = jest.spyOn(service.logger, 'log');

			await service.notifyPasswordChange({
				userId: 'user-1',
				email: 'user@example.com',
				timestamp: new Date(),
			});

			expect(logSpy).toHaveBeenCalled();
		});
	});

	describe('notifyAccountLocked', () => {
		it('should log account locked notification (TODO implementation)', async () => {
			const warnSpy = jest.spyOn(service.logger, 'warn');

			await service.notifyAccountLocked({
				userId: 'user-1',
				email: 'user@example.com',
				reason: 'Too many failed login attempts',
				unlockTime: new Date(Date.now() + 3600000),
			});

			expect(warnSpy).toHaveBeenCalled();
		});
	});

	describe('notifySessionTerminated', () => {
		it('should log session terminated notification (TODO implementation)', async () => {
			const logSpy = jest.spyOn(service.logger, 'log');

			await service.notifySessionTerminated({
				userId: 'user-1',
				email: 'user@example.com',
				reason: 'Security policy violation',
				device: 'Chrome/Windows',
			});

			expect(logSpy).toHaveBeenCalled();
		});
	});
});
