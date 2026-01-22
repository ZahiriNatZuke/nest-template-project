import { Test, TestingModule } from '@nestjs/testing';
import { AuditService } from '../audit/audit.service';
import { NotificationService } from '../notification/notification.service';
import {
	SecurityAlertService,
	SecurityAlertType,
} from './security-alert.service';

describe('SecurityAlertService', () => {
	let service: SecurityAlertService;
	let notificationService: NotificationService;
	let auditService: AuditService;

	const mockNotificationService = {
		notifyAccountLocked: jest.fn(),
		notifySuspiciousLogin: jest.fn(),
		notifyPasswordChange: jest.fn(),
	};

	const mockAuditService = {
		log: jest.fn(),
	};

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				SecurityAlertService,
				{
					provide: NotificationService,
					useValue: mockNotificationService,
				},
				{
					provide: AuditService,
					useValue: mockAuditService,
				},
			],
		}).compile();

		service = module.get<SecurityAlertService>(SecurityAlertService);
		notificationService = module.get<NotificationService>(NotificationService);
		auditService = module.get<AuditService>(AuditService);
	});

	afterEach(() => {
		jest.clearAllMocks();
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	describe('triggerAlert', () => {
		it('should log alert and store in audit log', async () => {
			const logSpy = jest.spyOn(service.logger, 'error');

			await service.triggerAlert({
				type: SecurityAlertType.BRUTE_FORCE_ATTEMPT,
				userId: 'user-1',
				email: 'user@example.com',
				severity: 'HIGH',
				message: 'Brute force detected',
				metadata: { attemptCount: 5 },
				ipAddress: '192.168.1.1',
				userAgent: 'Mozilla/5.0',
			});

			expect(logSpy).toHaveBeenCalled();
			expect(auditService.log).toHaveBeenCalledWith({
				userId: 'user-1',
				action: 'SECURITY_ALERT',
				entityType: 'security',
				metadata: expect.objectContaining({
					alertType: SecurityAlertType.BRUTE_FORCE_ATTEMPT,
					severity: 'HIGH',
					message: 'Brute force detected',
					attemptCount: 5,
				}),
				ipAddress: '192.168.1.1',
				userAgent: 'Mozilla/5.0',
				encryptMetadata: true,
			});
		});
	});

	describe('alertBruteForceAttempt', () => {
		it('should trigger brute force alert', async () => {
			const triggerAlertSpy = jest.spyOn(service, 'triggerAlert');

			await service.alertBruteForceAttempt({
				identifier: 'user@example.com',
				email: 'user@example.com',
				ipAddress: '192.168.1.1',
				attemptCount: 5,
			});

			expect(triggerAlertSpy).toHaveBeenCalledWith(
				expect.objectContaining({
					type: SecurityAlertType.BRUTE_FORCE_ATTEMPT,
					severity: 'HIGH',
				})
			);
		});
	});

	describe('alertAccountLocked', () => {
		it('should trigger account locked alert and send notification', async () => {
			const params = {
				userId: 'user-1',
				email: 'user@example.com',
				reason: 'Too many failed attempts',
				unlockTime: new Date(Date.now() + 3600000),
			};

			await service.alertAccountLocked(params);

			expect(auditService.log).toHaveBeenCalled();
			expect(notificationService.notifyAccountLocked).toHaveBeenCalledWith(
				params
			);
		});
	});

	describe('alertSuspiciousLogin', () => {
		it('should trigger suspicious login alert and send notification', async () => {
			const params = {
				userId: 'user-1',
				email: 'user@example.com',
				reason: 'Login from unusual location',
				ipAddress: '192.168.1.1',
				userAgent: 'Mozilla/5.0',
			};

			await service.alertSuspiciousLogin(params);

			expect(auditService.log).toHaveBeenCalled();
			expect(notificationService.notifySuspiciousLogin).toHaveBeenCalledWith(
				expect.objectContaining({
					userId: 'user-1',
					email: 'user@example.com',
					reason: 'Login from unusual location',
				})
			);
		});
	});

	describe('alertPasswordChange', () => {
		it('should trigger password change alert and send notification', async () => {
			const params = {
				userId: 'user-1',
				email: 'user@example.com',
			};

			await service.alertPasswordChange(params);

			expect(auditService.log).toHaveBeenCalled();
			expect(notificationService.notifyPasswordChange).toHaveBeenCalledWith(
				expect.objectContaining({
					userId: 'user-1',
					email: 'user@example.com',
				})
			);
		});
	});

	describe('alertSessionHijackAttempt', () => {
		it('should trigger session hijack alert with CRITICAL severity', async () => {
			const logSpy = jest.spyOn(service.logger, 'error');

			await service.alertSessionHijackAttempt({
				userId: 'user-1',
				email: 'user@example.com',
				reason: 'Token reuse detected',
				ipAddress: '192.168.1.1',
				userAgent: 'Mozilla/5.0',
			});

			expect(logSpy).toHaveBeenCalled();
			expect(auditService.log).toHaveBeenCalledWith(
				expect.objectContaining({
					action: 'SECURITY_ALERT',
					metadata: expect.objectContaining({
						alertType: SecurityAlertType.SESSION_HIJACK_ATTEMPT,
						severity: 'CRITICAL',
					}),
				})
			);
		});
	});

	describe('alertUnauthorizedAccess', () => {
		it('should trigger unauthorized access alert', async () => {
			await service.alertUnauthorizedAccess({
				userId: 'user-1',
				email: 'user@example.com',
				resource: 'admin-panel',
				action: 'read',
				ipAddress: '192.168.1.1',
				userAgent: 'Mozilla/5.0',
			});

			expect(auditService.log).toHaveBeenCalledWith(
				expect.objectContaining({
					action: 'SECURITY_ALERT',
					metadata: expect.objectContaining({
						alertType: SecurityAlertType.UNAUTHORIZED_ACCESS_ATTEMPT,
						resource: 'admin-panel',
						action: 'read',
					}),
				})
			);
		});
	});

	describe('logAlert', () => {
		it('should log CRITICAL alerts as error', () => {
			const errorSpy = jest.spyOn(service.logger, 'error');

			service.logAlert(
				'CRITICAL',
				SecurityAlertType.SESSION_HIJACK_ATTEMPT,
				'Test message',
				{}
			);

			expect(errorSpy).toHaveBeenCalled();
		});

		it('should log MEDIUM alerts as warning', () => {
			const warnSpy = jest.spyOn(service.logger, 'warn');

			service.logAlert(
				'MEDIUM',
				SecurityAlertType.SUSPICIOUS_LOGIN,
				'Test message',
				{}
			);

			expect(warnSpy).toHaveBeenCalled();
		});

		it('should log LOW alerts as log', () => {
			const logSpy = jest.spyOn(service.logger, 'log');

			service.logAlert(
				'LOW',
				SecurityAlertType.PASSWORD_CHANGE,
				'Test message',
				{}
			);

			expect(logSpy).toHaveBeenCalled();
		});
	});
});
