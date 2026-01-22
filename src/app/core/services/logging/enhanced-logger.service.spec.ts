import { Test, TestingModule } from '@nestjs/testing';
import { EnhancedLoggerService } from './enhanced-logger.service';

describe('EnhancedLoggerService', () => {
	let service: EnhancedLoggerService;

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [EnhancedLoggerService],
		}).compile();

		service = module.get<EnhancedLoggerService>(EnhancedLoggerService);
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	describe('setLogContext', () => {
		it('should set logging context', () => {
			const context = {
				correlationId: 'test-correlation-id',
				userId: 'user-123',
				username: 'testuser',
			};

			service.setLogContext(context);
			expect(service.context).toEqual(context);
		});

		it('should merge context when called multiple times', () => {
			service.setLogContext({ correlationId: 'test-id' });
			service.setLogContext({ userId: 'user-123' });

			expect(service.context).toEqual({
				correlationId: 'test-id',
				userId: 'user-123',
			});
		});
	});

	describe('clearContext', () => {
		it('should clear logging context', () => {
			service.setLogContext({ correlationId: 'test-id' });
			service.clearContext();

			expect(service.context).toEqual({});
		});
	});

	describe('formatMessage', () => {
		it('should format message with correlation ID', () => {
			service.setLogContext({ correlationId: 'test-id' });
			const formatted = service.formatMessage('Test message');

			expect(formatted).toContain('[test-id]');
			expect(formatted).toContain('Test message');
		});

		it('should format message with user info', () => {
			service.setLogContext({ userId: 'user-123', username: 'testuser' });
			const formatted = service.formatMessage('Test message');

			expect(formatted).toContain('[User: testuser]');
		});

		it('should format message with request info', () => {
			service.setLogContext({
				requestMethod: 'GET',
				requestUrl: '/api/users',
			});
			const formatted = service.formatMessage('Test message');

			expect(formatted).toContain('[GET /api/users]');
		});

		it('should return plain message when no context', () => {
			const formatted = service.formatMessage('Test message');
			expect(formatted).toBe('Test message');
		});
	});

	describe('log methods', () => {
		beforeEach(() => {
			jest.spyOn(service.logger, 'log').mockImplementation();
			jest.spyOn(service.logger, 'error').mockImplementation();
			jest.spyOn(service.logger, 'warn').mockImplementation();
			jest.spyOn(service.logger, 'debug').mockImplementation();
			jest.spyOn(service.logger, 'verbose').mockImplementation();
		});

		it('should log at info level', () => {
			service.log('Test message');
			expect(service.logger.log).toHaveBeenCalled();
		});

		it('should log at error level', () => {
			service.error('Error message', 'stack trace');
			expect(service.logger.error).toHaveBeenCalled();
		});

		it('should log at warn level', () => {
			service.warn('Warning message');
			expect(service.logger.warn).toHaveBeenCalled();
		});

		it('should log at debug level', () => {
			service.debug('Debug message');
			expect(service.logger.debug).toHaveBeenCalled();
		});

		it('should log at verbose level', () => {
			service.verbose('Verbose message');
			expect(service.logger.verbose).toHaveBeenCalled();
		});
	});

	describe('security', () => {
		beforeEach(() => {
			jest.spyOn(service.logger, 'log').mockImplementation();
			jest.spyOn(service.logger, 'error').mockImplementation();
			jest.spyOn(service.logger, 'warn').mockImplementation();
		});

		it('should log CRITICAL security events as error', () => {
			service.security('Unauthorized access', 'CRITICAL');
			expect(service.logger.error).toHaveBeenCalled();
		});

		it('should log HIGH security events as error', () => {
			service.security('Brute force detected', 'HIGH');
			expect(service.logger.error).toHaveBeenCalled();
		});

		it('should log MEDIUM security events as warning', () => {
			service.security('Suspicious activity', 'MEDIUM');
			expect(service.logger.warn).toHaveBeenCalled();
		});

		it('should log LOW security events as info', () => {
			service.security('Password changed', 'LOW');
			expect(service.logger.log).toHaveBeenCalled();
		});
	});

	describe('audit', () => {
		beforeEach(() => {
			jest.spyOn(service.logger, 'log').mockImplementation();
		});

		it('should log audit events', () => {
			service.audit('CREATE', 'User', 'user-123');
			expect(service.logger.log).toHaveBeenCalled();
		});

		it('should format audit message correctly', () => {
			const logSpy = jest.spyOn(service.logger, 'log');
			service.audit('UPDATE', 'Role', 'role-456');

			expect(logSpy).toHaveBeenCalledWith(
				expect.stringContaining('[AUDIT] UPDATE on Role (role-456)'),
				expect.any(String)
			);
		});
	});
});
