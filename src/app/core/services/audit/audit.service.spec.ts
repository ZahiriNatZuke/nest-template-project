import { EncryptionService } from '@app/core/services/encryption/encryption.service';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Test, TestingModule } from '@nestjs/testing';
import { Prisma } from '@prisma/client';
import { AuditService } from './audit.service';

describe('AuditService', () => {
	let service: AuditService;
	let prisma: PrismaService;
	let encryption: EncryptionService;

	const mockPrismaService = {
		auditLog: {
			create: jest.fn(),
			findMany: jest.fn(),
			count: jest.fn(),
		},
		$transaction: jest.fn(),
	};

	const mockEncryptionService = {
		encryptObject: jest.fn(),
		decryptObject: jest.fn(),
	};

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				AuditService,
				{
					provide: PrismaService,
					useValue: mockPrismaService,
				},
				{
					provide: EncryptionService,
					useValue: mockEncryptionService,
				},
			],
		}).compile();

		service = module.get<AuditService>(AuditService);
		prisma = module.get<PrismaService>(PrismaService);
		encryption = module.get<EncryptionService>(EncryptionService);
	});

	afterEach(() => {
		jest.clearAllMocks();
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	describe('log', () => {
		it('should log without encryption', async () => {
			const logParams = {
				userId: 'user-1',
				action: 'CREATE',
				entityType: 'user',
				entityId: 'entity-1',
				metadata: { key: 'value' },
				ipAddress: '192.168.1.1',
				userAgent: 'Mozilla/5.0',
			};

			mockPrismaService.auditLog.create.mockResolvedValue({
				id: 'audit-1',
				...logParams,
			});

			await service.log(logParams);

			expect(prisma.auditLog.create).toHaveBeenCalledWith({
				data: {
					userId: 'user-1',
					action: 'CREATE',
					entityType: 'user',
					entityId: 'entity-1',
					metadata: { key: 'value' },
					ipAddress: '192.168.1.1',
					userAgent: 'Mozilla/5.0',
				},
			});
		});

		it('should log with encryption when encryptMetadata is true', async () => {
			const metadata = { sensitiveKey: 'sensitiveValue' };
			const encryptedData = 'encrypted-string';

			mockEncryptionService.encryptObject.mockResolvedValue(encryptedData);
			mockPrismaService.auditLog.create.mockResolvedValue({
				id: 'audit-1',
			});

			await service.log({
				userId: 'user-1',
				action: 'UPDATE',
				entityType: 'user',
				metadata,
				encryptMetadata: true,
			});

			expect(encryption.encryptObject).toHaveBeenCalledWith(metadata);
			expect(prisma.auditLog.create).toHaveBeenCalledWith({
				data: {
					userId: 'user-1',
					action: 'UPDATE',
					entityType: 'user',
					entityId: undefined,
					metadata: { encrypted: encryptedData },
					ipAddress: undefined,
					userAgent: undefined,
				},
			});
		});

		it('should fallback to unencrypted metadata if encryption fails', async () => {
			const metadata = { key: 'value' };

			mockEncryptionService.encryptObject.mockRejectedValue(
				new Error('Encryption failed')
			);
			mockPrismaService.auditLog.create.mockResolvedValue({
				id: 'audit-1',
			});

			await service.log({
				userId: 'user-1',
				action: 'UPDATE',
				entityType: 'user',
				metadata,
				encryptMetadata: true,
			});

			expect(prisma.auditLog.create).toHaveBeenCalledWith({
				data: expect.objectContaining({
					metadata,
				}),
			});
		});

		it('should handle undefined metadata', async () => {
			mockPrismaService.auditLog.create.mockResolvedValue({
				id: 'audit-1',
			});

			await service.log({
				userId: 'user-1',
				action: 'DELETE',
				entityType: 'user',
			});

			expect(prisma.auditLog.create).toHaveBeenCalledWith({
				data: {
					userId: 'user-1',
					action: 'DELETE',
					entityType: 'user',
					entityId: undefined,
					metadata: undefined,
					ipAddress: undefined,
					userAgent: undefined,
				},
			});
		});
	});

	describe('findAll', () => {
		it('should find all audit logs with filters', async () => {
			const mockLogs = [
				{ id: 'log-1', action: 'CREATE' },
				{ id: 'log-2', action: 'UPDATE' },
			];

			mockPrismaService.auditLog.findMany.mockResolvedValue(mockLogs);

			const result = await service.findAll({
				userId: 'user-1',
				action: 'CREATE',
				skip: 0,
				take: 10,
			});

			expect(result).toEqual(mockLogs);
			expect(prisma.auditLog.findMany).toHaveBeenCalledWith({
				where: {
					userId: 'user-1',
					action: 'CREATE',
					entityType: undefined,
				},
				orderBy: { createdAt: 'desc' },
				skip: 0,
				take: 10,
			});
		});
	});

	describe('findManyPaged', () => {
		it('should return paginated results with count', async () => {
			const mockLogs = [{ id: 'log-1' }, { id: 'log-2' }];
			mockPrismaService.$transaction.mockResolvedValue([2, mockLogs]);

			const result = await service.findManyPaged({
				userId: 'user-1',
				skip: 0,
				take: 10,
			});

			expect(result).toEqual([2, mockLogs]);
		});
	});

	describe('decryptMetadata', () => {
		it('should return null for null metadata', async () => {
			const result = await service.decryptMetadata(null);
			expect(result).toBeNull();
		});

		it('should decrypt encrypted metadata', async () => {
			const encryptedMetadata = {
				encrypted: 'encrypted-string',
			};
			const decryptedData = { key: 'value' };

			mockEncryptionService.decryptObject.mockResolvedValue(decryptedData);

			const result = await service.decryptMetadata(
				encryptedMetadata as Prisma.JsonValue
			);

			expect(result).toEqual(decryptedData);
			expect(encryption.decryptObject).toHaveBeenCalledWith('encrypted-string');
		});

		it('should return unencrypted metadata as-is', async () => {
			const metadata = { key: 'value' };

			const result = await service.decryptMetadata(
				metadata as Prisma.JsonValue
			);

			expect(result).toEqual(metadata);
			expect(encryption.decryptObject).not.toHaveBeenCalled();
		});

		it('should return null if decryption fails', async () => {
			const encryptedMetadata = {
				encrypted: 'invalid-encrypted-string',
			};

			mockEncryptionService.decryptObject.mockRejectedValue(
				new Error('Decryption failed')
			);

			const result = await service.decryptMetadata(
				encryptedMetadata as Prisma.JsonValue
			);

			expect(result).toBeNull();
		});
	});
});
