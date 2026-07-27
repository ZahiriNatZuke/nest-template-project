import { Test, TestingModule } from '@nestjs/testing';
import { EncryptionService } from './encryption.service';

describe('EncryptionService', () => {
	let service: EncryptionService;

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [EncryptionService],
		}).compile();

		service = module.get<EncryptionService>(EncryptionService);
	});

	describe('encrypt / decrypt round trip', () => {
		it('recovers the original string', async () => {
			const plaintext = 'JBSWY3DPEHPK3PXP';

			const encrypted = await service.encrypt(plaintext);

			expect(encrypted).not.toContain(plaintext);
			await expect(service.decrypt(encrypted)).resolves.toBe(plaintext);
		});

		it('recovers an object serialized on the way in', async () => {
			const payload = { secret: 'JBSWY3DPEHPK3PXP', codes: ['a1b2', 'c3d4'] };

			const encrypted = await service.encrypt(payload);

			await expect(service.decrypt(encrypted)).resolves.toBe(
				JSON.stringify(payload)
			);
		});

		it('round trips an empty string', async () => {
			const encrypted = await service.encrypt('');

			await expect(service.decrypt(encrypted)).resolves.toBe('');
		});

		it('round trips multi-byte unicode', async () => {
			const plaintext = 'contraseña — 🔐 秘密';

			const encrypted = await service.encrypt(plaintext);

			await expect(service.decrypt(encrypted)).resolves.toBe(plaintext);
		});
	});

	describe('ciphertext shape', () => {
		it('emits salt:iv:tag:data as four base64 segments', async () => {
			const encrypted = await service.encrypt('payload');
			const parts = encrypted.split(':');

			expect(parts).toHaveLength(4);
			// Salt is 16 bytes and IV is 16 bytes; the GCM tag is 16 bytes.
			expect(Buffer.from(parts[0], 'base64')).toHaveLength(16);
			expect(Buffer.from(parts[1], 'base64')).toHaveLength(16);
			expect(Buffer.from(parts[2], 'base64')).toHaveLength(16);
		});

		// A fresh random salt and IV per call is what stops an attacker from
		// spotting that two users share a 2FA secret.
		it('produces different ciphertext for the same input on every call', async () => {
			const [first, second] = await Promise.all([
				service.encrypt('same input'),
				service.encrypt('same input'),
			]);

			expect(first).not.toBe(second);
			await expect(service.decrypt(first)).resolves.toBe('same input');
			await expect(service.decrypt(second)).resolves.toBe('same input');
		});
	});

	describe('tamper resistance', () => {
		it('rejects ciphertext whose payload was modified', async () => {
			const encrypted = await service.encrypt('sensitive');
			const [salt, iv, tag, data] = encrypted.split(':');
			const flipped = Buffer.from(data, 'base64');
			flipped[0] ^= 0xff;

			const tampered = `${salt}:${iv}:${tag}:${flipped.toString('base64')}`;

			await expect(service.decrypt(tampered)).rejects.toThrow(
				'Failed to decrypt data'
			);
		});

		it('rejects ciphertext whose auth tag was replaced', async () => {
			const encrypted = await service.encrypt('sensitive');
			const [salt, iv, , data] = encrypted.split(':');
			const forgedTag = Buffer.alloc(16, 0).toString('base64');

			await expect(
				service.decrypt(`${salt}:${iv}:${forgedTag}:${data}`)
			).rejects.toThrow('Failed to decrypt data');
		});

		it('rejects ciphertext encrypted under a different salt', async () => {
			const encrypted = await service.encrypt('sensitive');
			const [, iv, tag, data] = encrypted.split(':');
			const otherSalt = Buffer.alloc(16, 7).toString('base64');

			await expect(
				service.decrypt(`${otherSalt}:${iv}:${tag}:${data}`)
			).rejects.toThrow('Failed to decrypt data');
		});

		it.each([
			['no separators', 'not-encrypted-at-all'],
			['too few segments', 'a:b:c'],
			['too many segments', 'a:b:c:d:e'],
			['empty string', ''],
		])('rejects malformed input (%s)', async (_label, input) => {
			await expect(service.decrypt(input)).rejects.toThrow(
				'Failed to decrypt data'
			);
		});
	});

	describe('encryptObject / decryptObject', () => {
		it('round trips a nested object back to a deep-equal value', async () => {
			const payload = {
				secret: 'JBSWY3DPEHPK3PXP',
				backupCodes: ['aaa', 'bbb'],
				meta: { enabled: true, attempts: 0 },
			};

			const encrypted = await service.encryptObject(payload);

			await expect(service.decryptObject(encrypted)).resolves.toEqual(payload);
		});

		it('round trips an array', async () => {
			const codes = ['code-1', 'code-2', 'code-3'];

			const encrypted = await service.encryptObject(codes);

			await expect(service.decryptObject(encrypted)).resolves.toEqual(codes);
		});
	});

	describe('isEncrypted', () => {
		it('accepts output produced by encrypt', async () => {
			const encrypted = await service.encrypt('payload');

			expect(service.isEncrypted(encrypted)).toBe(true);
		});

		it.each([
			['plain text', 'plain text'],
			['too few segments', 'a:b:c'],
			['too many segments', 'a:b:c:d:e'],
		])('rejects %s', (_label, input) => {
			expect(service.isEncrypted(input)).toBe(false);
		});
	});
});
