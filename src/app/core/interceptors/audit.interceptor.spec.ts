import { AUDIT_METADATA_KEY } from '@app/core/decorators/log-audit.decorator';
import { AuditService } from '@app/core/services/audit/audit.service';
import { CallHandler, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Test, TestingModule } from '@nestjs/testing';
import { of } from 'rxjs';
import { AuditInterceptor } from './audit.interceptor';

describe('AuditInterceptor', () => {
	let interceptor: AuditInterceptor;
	let reflector: Reflector;
	let auditService: AuditService;

	const mockAuditService = {
		log: jest.fn(),
	};

	const mockReflector = {
		get: jest.fn(),
	};

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				AuditInterceptor,
				{
					provide: Reflector,
					useValue: mockReflector,
				},
				{
					provide: AuditService,
					useValue: mockAuditService,
				},
			],
		}).compile();

		interceptor = module.get<AuditInterceptor>(AuditInterceptor);
		reflector = module.get<Reflector>(Reflector);
		auditService = module.get<AuditService>(AuditService);

		jest.clearAllMocks();
	});

	it('should be defined', () => {
		expect(interceptor).toBeDefined();
	});

	describe('intercept', () => {
		it('should skip audit if no metadata is found', async () => {
			mockReflector.get.mockReturnValue(undefined);

			const mockExecutionContext = {
				getHandler: jest.fn(),
				switchToHttp: jest.fn(),
			} as unknown as ExecutionContext;

			const mockCallHandler: CallHandler = {
				handle: jest.fn(() => of('result')),
			};

			const result = await interceptor
				.intercept(mockExecutionContext, mockCallHandler)
				.toPromise();

			expect(result).toBe('result');
			expect(auditService.log).not.toHaveBeenCalled();
		});

		it('should log audit with full context', async () => {
			const auditMetadata = {
				action: 'user.update',
				entityType: 'user',
				entityIdParam: 'userId',
			};

			mockReflector.get.mockReturnValue(auditMetadata);

			const mockRequest = {
				user: { id: 'user-123' },
				params: { userId: 'target-user-456' },
				body: { email: 'new@example.com', fullName: 'John Doe' },
				requestContext: {
					ipAddress: '192.168.1.1',
					userAgent: 'Mozilla/5.0',
				},
			};

			const mockExecutionContext = {
				getHandler: jest.fn(),
				switchToHttp: jest.fn(() => ({
					getRequest: () => mockRequest,
				})),
			} as unknown as ExecutionContext;

			const mockCallHandler: CallHandler = {
				handle: jest.fn(() => of('success')),
			};

			mockAuditService.log.mockResolvedValue(undefined);

			const result = await interceptor
				.intercept(mockExecutionContext, mockCallHandler)
				.toPromise();

			expect(result).toBe('success');
			expect(auditService.log).toHaveBeenCalledWith({
				userId: 'user-123',
				action: 'user.update',
				entityType: 'user',
				entityId: 'target-user-456',
				metadata: { email: 'new@example.com', fullName: 'John Doe' },
				ipAddress: '192.168.1.1',
				userAgent: 'Mozilla/5.0',
			});
		});

		it('should use default entityId from params.id if no custom param', async () => {
			const auditMetadata = {
				action: 'role.delete',
				entityType: 'role',
			};

			mockReflector.get.mockReturnValue(auditMetadata);

			const mockRequest = {
				user: { id: 'admin-user' },
				params: { id: 'role-789' },
				body: {},
				requestContext: {
					ipAddress: '10.0.0.1',
					userAgent: 'PostmanRuntime/7.26.8',
				},
			};

			const mockExecutionContext = {
				getHandler: jest.fn(),
				switchToHttp: jest.fn(() => ({
					getRequest: () => mockRequest,
				})),
			} as unknown as ExecutionContext;

			const mockCallHandler: CallHandler = {
				handle: jest.fn(() => of({ deleted: true })),
			};

			mockAuditService.log.mockResolvedValue(undefined);

			await interceptor
				.intercept(mockExecutionContext, mockCallHandler)
				.toPromise();

			expect(auditService.log).toHaveBeenCalledWith(
				expect.objectContaining({
					entityId: 'role-789',
				})
			);
		});

		it('should use entityId from body if not in params', async () => {
			const auditMetadata = {
				action: 'permission.create',
				entityType: 'permission',
			};

			mockReflector.get.mockReturnValue(auditMetadata);

			const mockRequest = {
				user: { id: 'admin-user' },
				params: {},
				body: { id: 'new-perm-123', resource: 'users', action: 'write' },
				requestContext: {},
			};

			const mockExecutionContext = {
				getHandler: jest.fn(),
				switchToHttp: jest.fn(() => ({
					getRequest: () => mockRequest,
				})),
			} as unknown as ExecutionContext;

			const mockCallHandler: CallHandler = {
				handle: jest.fn(() => of({ created: true })),
			};

			mockAuditService.log.mockResolvedValue(undefined);

			await interceptor
				.intercept(mockExecutionContext, mockCallHandler)
				.toPromise();

			expect(auditService.log).toHaveBeenCalledWith(
				expect.objectContaining({
					entityId: 'new-perm-123',
				})
			);
		});

		it('should omit body metadata if omitBody is true', async () => {
			const auditMetadata = {
				action: 'auth.login',
				entityType: 'session',
				omitBody: true,
			};

			mockReflector.get.mockReturnValue(auditMetadata);

			const mockRequest = {
				user: { id: 'user-123' },
				params: {},
				body: { username: 'admin', password: 'secret123' },
				requestContext: {
					ipAddress: '192.168.1.1',
					userAgent: 'Mozilla/5.0',
				},
			};

			const mockExecutionContext = {
				getHandler: jest.fn(),
				switchToHttp: jest.fn(() => ({
					getRequest: () => mockRequest,
				})),
			} as unknown as ExecutionContext;

			const mockCallHandler: CallHandler = {
				handle: jest.fn(() => of({ token: 'jwt-token' })),
			};

			mockAuditService.log.mockResolvedValue(undefined);

			await interceptor
				.intercept(mockExecutionContext, mockCallHandler)
				.toPromise();

			expect(auditService.log).toHaveBeenCalledWith(
				expect.objectContaining({
					metadata: undefined,
				})
			);
		});

		it('should handle missing user context', async () => {
			const auditMetadata = {
				action: 'public.access',
				entityType: 'resource',
			};

			mockReflector.get.mockReturnValue(auditMetadata);

			const mockRequest = {
				params: { id: 'resource-123' },
				body: {},
				requestContext: {
					ipAddress: '8.8.8.8',
					userAgent: 'curl/7.68.0',
				},
			};

			const mockExecutionContext = {
				getHandler: jest.fn(),
				switchToHttp: jest.fn(() => ({
					getRequest: () => mockRequest,
				})),
			} as unknown as ExecutionContext;

			const mockCallHandler: CallHandler = {
				handle: jest.fn(() => of('public data')),
			};

			mockAuditService.log.mockResolvedValue(undefined);

			await interceptor
				.intercept(mockExecutionContext, mockCallHandler)
				.toPromise();

			expect(auditService.log).toHaveBeenCalledWith(
				expect.objectContaining({
					userId: undefined,
					ipAddress: '8.8.8.8',
					userAgent: 'curl/7.68.0',
				})
			);
		});

		it('should handle missing requestContext', async () => {
			const auditMetadata = {
				action: 'system.task',
				entityType: 'task',
			};

			mockReflector.get.mockReturnValue(auditMetadata);

			const mockRequest = {
				user: { id: 'system' },
				params: {},
				body: {},
			};

			const mockExecutionContext = {
				getHandler: jest.fn(),
				switchToHttp: jest.fn(() => ({
					getRequest: () => mockRequest,
				})),
			} as unknown as ExecutionContext;

			const mockCallHandler: CallHandler = {
				handle: jest.fn(() => of('task completed')),
			};

			mockAuditService.log.mockResolvedValue(undefined);

			await interceptor
				.intercept(mockExecutionContext, mockCallHandler)
				.toPromise();

			expect(auditService.log).toHaveBeenCalledWith(
				expect.objectContaining({
					ipAddress: undefined,
					userAgent: undefined,
				})
			);
		});

		it('should verify AUDIT_METADATA_KEY is used correctly', async () => {
			mockReflector.get.mockReturnValue(undefined);

			const mockExecutionContext = {
				getHandler: jest.fn(),
				switchToHttp: jest.fn(() => ({
					getRequest: () => ({}),
				})),
			} as unknown as ExecutionContext;

			const mockCallHandler: CallHandler = {
				handle: jest.fn(() => of('result')),
			};

			await interceptor
				.intercept(mockExecutionContext, mockCallHandler)
				.toPromise();

			expect(reflector.get).toHaveBeenCalledWith(
				AUDIT_METADATA_KEY,
				mockExecutionContext.getHandler()
			);
		});
	});
});
