import { Test, TestingModule } from '@nestjs/testing';
import { EncryptionService } from './encryption.service';

// Mock envs
jest.mock('@app/env', () => ({
	envs: {
		ENCRYPTION_SECRET: 'test-encryption-secret-key-32-chars-long-minimum',
	},
}));

describe('EncryptionService', () => {
	let service: EncryptionService;

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [EncryptionService],
		}).compile();

		service = module.get<EncryptionService>(EncryptionService);
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	describe('encrypt and decrypt', () => {
		it('should encrypt and decrypt a string', async () => {
			const originalData = 'sensitive user data';

			const encrypted = await service.encrypt(originalData);
			expect(encrypted).toBeDefined();
			expect(encrypted).not.toBe(originalData);
			expect(encrypted.split(':').length).toBe(4); // salt:iv:tag:data

			const decrypted = await service.decrypt(encrypted);
			expect(decrypted).toBe(originalData);
		});

		it('should encrypt and decrypt an object', async () => {
			const originalData = {
				email: 'user@example.com',
				ipAddress: '192.168.1.1',
				userAgent: 'Mozilla/5.0',
			};

			const encrypted = await service.encryptObject(originalData);
			expect(encrypted).toBeDefined();
			expect(encrypted).not.toContain('user@example.com');

			const decrypted = await service.decryptObject(encrypted);
			expect(decrypted).toEqual(originalData);
		});

		it('should produce different ciphertext for same input', async () => {
			const data = 'test data';

			const encrypted1 = await service.encrypt(data);
			const encrypted2 = await service.encrypt(data);

			expect(encrypted1).not.toBe(encrypted2);

			const decrypted1 = await service.decrypt(encrypted1);
			const decrypted2 = await service.decrypt(encrypted2);

			expect(decrypted1).toBe(data);
			expect(decrypted2).toBe(data);
		});

		it('should fail to decrypt tampered data', async () => {
			const data = 'secret data';
			const encrypted = await service.encrypt(data);

			// Tamper with the encrypted data
			const parts = encrypted.split(':');
			parts[3] = `${parts[3].slice(0, -1)}X`; // Modify last character
			const tampered = parts.join(':');

			await expect(service.decrypt(tampered)).rejects.toThrow(
				'Failed to decrypt data'
			);
		});

		it('should fail to decrypt invalid format', async () => {
			await expect(service.decrypt('invalid-format')).rejects.toThrow(
				'Failed to decrypt data'
			);
		});
	});

	describe('isEncrypted', () => {
		it('should return true for encrypted data', async () => {
			const encrypted = await service.encrypt('test');
			expect(service.isEncrypted(encrypted)).toBe(true);
		});

		it('should return false for non-encrypted data', () => {
			expect(service.isEncrypted('plain text')).toBe(false);
			expect(service.isEncrypted('one:two:three')).toBe(false);
		});
	});

	describe('encryptObject and decryptObject', () => {
		it('should handle complex nested objects', async () => {
			const complexObject = {
				user: {
					id: '123',
					name: 'John Doe',
					roles: ['admin', 'user'],
				},
				metadata: {
					ipAddress: '192.168.1.1',
					userAgent: 'Mozilla/5.0',
					timestamp: new Date().toISOString(),
				},
			};

			const encrypted = await service.encryptObject(complexObject);
			const decrypted = await service.decryptObject(encrypted);

			expect(decrypted).toEqual(complexObject);
		});

		it('should handle arrays', async () => {
			const array = ['item1', 'item2', 'item3'];

			const encrypted = await service.encryptObject(array);
			const decrypted = await service.decryptObject<string[]>(encrypted);

			expect(decrypted).toEqual(array);
		});

		it('should handle null and undefined values in objects', async () => {
			const obj = {
				nullValue: null,
				undefinedValue: undefined,
				normalValue: 'test',
			};

			const encrypted = await service.encryptObject(obj);
			const decrypted = await service.decryptObject(encrypted);

			// undefined gets removed in JSON serialization
			expect(decrypted).toEqual({
				nullValue: null,
				normalValue: 'test',
			});
		});
	});
});
