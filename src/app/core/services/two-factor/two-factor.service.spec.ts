import { EncryptionService } from '@app/core/services/encryption/encryption.service';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Test, TestingModule } from '@nestjs/testing';
import { Prisma } from '@prisma/client';
import { buildUser } from '@test/utils/factories';
import {
	asPrismaService,
	createPrismaMock,
	type PrismaMock,
} from '@test/utils/prisma-mock';
import * as bcrypt from 'bcrypt';
import { TwoFactorService } from './two-factor.service';

// bcrypt at cost 10 over 10 backup codes dominates the runtime of this suite
// and tells us nothing about the service's own logic, so it is stubbed.
jest.mock('bcrypt', () => ({
	hash: jest.fn(),
	compare: jest.fn(),
}));

const mockedBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;

describe('TwoFactorService', () => {
	let service: TwoFactorService;
	let prisma: PrismaMock;

	const USER_ID = 'user-0001';

	beforeEach(async () => {
		prisma = createPrismaMock();

		// The real EncryptionService, not a stub: these specs assert that a
		// secret round-trips through it, which a stub would make vacuous. It
		// reads ENCRYPTION_SECRET from .env.test and touches nothing external.
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				TwoFactorService,
				EncryptionService,
				{ provide: PrismaService, useValue: asPrismaService(prisma) },
			],
		}).compile();

		service = module.get<TwoFactorService>(TwoFactorService);

		mockedBcrypt.hash.mockImplementation(
			(async (data: string) => `hashed:${data}`) as never
		);
	});

	describe('generateSecret', () => {
		it('returns a non-empty base32 secret', () => {
			const secret = service.generateSecret();

			expect(secret).toEqual(expect.any(String));
			expect(secret.length).toBeGreaterThan(0);
			expect(secret).toMatch(/^[A-Z2-7]+$/);
		});

		it('returns a different secret on each call', () => {
			expect(service.generateSecret()).not.toBe(service.generateSecret());
		});
	});

	describe('generateQRCode', () => {
		it('produces a PNG data URL', async () => {
			const secret = service.generateSecret();

			const dataUrl = await service.generateQRCode('user@test.local', secret);

			expect(dataUrl).toMatch(/^data:image\/png;base64,/);
		});

		it('encodes different otpauth URIs for different emails', async () => {
			const secret = service.generateSecret();

			const [first, second] = await Promise.all([
				service.generateQRCode('a@test.local', secret),
				service.generateQRCode('b@test.local', secret),
			]);

			expect(first).not.toBe(second);
		});
	});

	describe('verifyToken', () => {
		/** Generates a live TOTP via the same otplib instance the service verifies with. */
		const currentToken = (secret: string): Promise<string> =>
			(
				service as unknown as {
					otp: { generate(input: { secret: string }): Promise<string> };
				}
			).otp.generate({ secret });

		it('accepts a token generated from the same secret', async () => {
			const secret = service.generateSecret();
			const token = await currentToken(secret);

			await expect(service.verifyToken(token, secret)).resolves.toBe(true);
		});

		it('rejects a token generated from a different secret', async () => {
			const secret = service.generateSecret();
			const token = await currentToken(service.generateSecret());

			await expect(service.verifyToken(token, secret)).resolves.toBe(false);
		});

		it.each([
			['non-numeric', 'abcdef'],
			['empty', ''],
			['wrong length', '1'],
		])(
			'returns false for a %s token instead of throwing',
			async (_l, token) => {
				const secret = service.generateSecret();

				await expect(service.verifyToken(token, secret)).resolves.toBe(false);
			}
		);

		it('returns false rather than throwing on a malformed secret', async () => {
			await expect(service.verifyToken('123456', 'not-base32!!')).resolves.toBe(
				false
			);
		});
	});

	describe('enable2FA', () => {
		it('encrypts the secret and hashes every backup code', async () => {
			prisma.user.update.mockResolvedValue(buildUser());

			await service.enable2FA({
				userId: USER_ID,
				secret: 'SECRET123',
				backupCodes: ['AAAA1111', 'BBBB2222'],
			});

			expect(mockedBcrypt.hash).toHaveBeenCalledTimes(2);
			expect(mockedBcrypt.hash).toHaveBeenCalledWith('AAAA1111', 10);

			const data = prisma.user.update.mock.calls[0][0].data;
			expect(data.twoFactorEnabled).toBe(true);
			expect(data.twoFactorBackupCodes).toEqual([
				'hashed:AAAA1111',
				'hashed:BBBB2222',
			]);
			// Ciphertext, not the secret. The value is salted per call, so it can
			// only be checked by shape and by decrypting it back.
			expect(data.twoFactorSecret).not.toBe('SECRET123');
			await expect(
				service.resolveSecret(data.twoFactorSecret as string)
			).resolves.toBe('SECRET123');
		});

		it('never persists the secret in plaintext', async () => {
			prisma.user.update.mockResolvedValue(buildUser());

			await service.enable2FA({
				userId: USER_ID,
				secret: 'PLAINTEXTSECRET',
				backupCodes: [],
			});

			const persisted = JSON.stringify(
				prisma.user.update.mock.calls[0][0].data
			);
			expect(persisted).not.toContain('PLAINTEXTSECRET');
		});

		it('never persists a backup code in plaintext', async () => {
			prisma.user.update.mockResolvedValue(buildUser());

			await service.enable2FA({
				userId: USER_ID,
				secret: 'SECRET123',
				backupCodes: ['PLAINTEXT'],
			});

			const persisted = JSON.stringify(
				prisma.user.update.mock.calls[0][0].data.twoFactorBackupCodes
			);
			expect(persisted).not.toContain('"PLAINTEXT"');
		});
	});

	describe('disable2FA', () => {
		it('clears the secret and the backup codes with a JSON null', async () => {
			prisma.user.update.mockResolvedValue(buildUser());

			await service.disable2FA(USER_ID);

			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: USER_ID },
				data: {
					twoFactorEnabled: false,
					twoFactorSecret: null,
					// Prisma.DbNull writes a SQL NULL into the Json column; a plain
					// `null` would store the JSON value `null` instead.
					twoFactorBackupCodes: Prisma.DbNull,
				},
			});
		});
	});

	describe('require2FA / make2FAOptional', () => {
		it('sets twoFactorRequired to true', async () => {
			prisma.user.update.mockResolvedValue(buildUser());

			await service.require2FA(USER_ID);

			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: USER_ID },
				data: { twoFactorRequired: true },
			});
		});

		it('sets twoFactorRequired to false', async () => {
			prisma.user.update.mockResolvedValue(buildUser());

			await service.make2FAOptional(USER_ID);

			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: USER_ID },
				data: { twoFactorRequired: false },
			});
		});
	});

	describe('is2FARequired', () => {
		it('returns the stored flag', async () => {
			prisma.user.findUnique.mockResolvedValue({ twoFactorRequired: true });

			await expect(service.is2FARequired(USER_ID)).resolves.toBe(true);
		});

		it('defaults to false for an unknown user', async () => {
			prisma.user.findUnique.mockResolvedValue(null);

			await expect(service.is2FARequired(USER_ID)).resolves.toBe(false);
		});
	});

	describe('generateBackupCodes', () => {
		it('generates ten codes by default', () => {
			expect(service.generateBackupCodes()).toHaveLength(10);
		});

		it('honours an explicit count', () => {
			expect(service.generateBackupCodes(3)).toHaveLength(3);
		});

		it('returns an empty array for a count of zero', () => {
			expect(service.generateBackupCodes(0)).toEqual([]);
		});

		it('generates uppercase alphanumeric codes', () => {
			for (const code of service.generateBackupCodes(20)) {
				expect(code).toMatch(/^[0-9A-Z]+$/);
			}
		});

		// The previous implementation sliced `Math.random().toString(36)`, which
		// yielded a shorter code whenever the float's base-36 expansion was
		// short — about twice in every hundred thousand.
		it('always produces codes of exactly eight characters', () => {
			for (const code of service.generateBackupCodes(200)) {
				expect(code).toHaveLength(8);
			}
		});

		// These codes bypass the second factor, so the alphabet is fixed
		// deliberately: no 0/O and no 1/I/L, which get misread off a printout.
		it('omits the characters that are confused when copied by hand', () => {
			for (const code of service.generateBackupCodes(200)) {
				expect(code).not.toMatch(/[01OIL]/);
			}
		});

		it('never repeats a code within one batch', () => {
			const codes = service.generateBackupCodes(50);
			expect(new Set(codes).size).toBe(codes.length);
		});
	});

	describe('secrets at rest', () => {
		/** Generates a live TOTP via the same otplib instance the service verifies with. */
		const currentToken = (secret: string): Promise<string> =>
			(
				service as unknown as {
					otp: { generate(input: { secret: string }): Promise<string> };
				}
			).otp.generate({ secret });

		it('round-trips an encrypted secret', async () => {
			const secret = service.generateSecret();
			prisma.user.update.mockResolvedValue(buildUser());

			await service.enable2FA({ userId: USER_ID, secret, backupCodes: [] });
			const stored = prisma.user.update.mock.calls[0][0].data
				.twoFactorSecret as string;

			await expect(service.resolveSecret(stored)).resolves.toBe(secret);
		});

		// Rows written before encryption existed are still plaintext. Refusing
		// them would lock every one of those users out of their own account.
		it('reads a legacy plaintext secret unchanged', async () => {
			const secret = service.generateSecret();

			await expect(service.resolveSecret(secret)).resolves.toBe(secret);
		});

		it('verifies a token against an encrypted secret', async () => {
			const secret = service.generateSecret();
			prisma.user.update.mockResolvedValue(buildUser());

			await service.enable2FA({ userId: USER_ID, secret, backupCodes: [] });
			const stored = prisma.user.update.mock.calls[0][0].data
				.twoFactorSecret as string;

			await expect(
				service.verifyStoredToken(await currentToken(secret), stored)
			).resolves.toBe(true);
		});

		it('verifies a token against a legacy plaintext secret', async () => {
			const secret = service.generateSecret();

			await expect(
				service.verifyStoredToken(await currentToken(secret), secret)
			).resolves.toBe(true);
		});

		it('rewrites a plaintext secret as ciphertext', async () => {
			const secret = service.generateSecret();
			prisma.user.update.mockResolvedValue(buildUser());

			await service.reencryptSecretIfPlaintext(USER_ID, secret);

			const written = prisma.user.update.mock.calls[0][0].data
				.twoFactorSecret as string;
			expect(written).not.toBe(secret);
			await expect(service.resolveSecret(written)).resolves.toBe(secret);
		});

		it('leaves an already encrypted secret alone', async () => {
			prisma.user.update.mockResolvedValue(buildUser());
			await service.enable2FA({
				userId: USER_ID,
				secret: 'SECRET123',
				backupCodes: [],
			});
			const stored = prisma.user.update.mock.calls[0][0].data
				.twoFactorSecret as string;
			prisma.user.update.mockClear();

			await service.reencryptSecretIfPlaintext(USER_ID, stored);

			// A second write would re-salt the value for no reason and cost a
			// query on every single verification.
			expect(prisma.user.update).not.toHaveBeenCalled();
		});

		// The user is authenticated by the time this runs, so a failure here must
		// not surface as a failed login.
		it('swallows a write failure while migrating', async () => {
			const secret = service.generateSecret();
			prisma.user.update.mockRejectedValue(new Error('database is down'));

			await expect(
				service.reencryptSecretIfPlaintext(USER_ID, secret)
			).resolves.toBeUndefined();
		});
	});

	describe('verifyBackupCode', () => {
		it('returns false when the user has no backup codes', async () => {
			prisma.user.findUnique.mockResolvedValue({ twoFactorBackupCodes: null });

			await expect(service.verifyBackupCode(USER_ID, 'AAAA1111')).resolves.toBe(
				false
			);
			expect(prisma.user.update).not.toHaveBeenCalled();
		});

		it('returns false for an unknown user', async () => {
			prisma.user.findUnique.mockResolvedValue(null);

			await expect(service.verifyBackupCode(USER_ID, 'AAAA1111')).resolves.toBe(
				false
			);
		});

		it('returns false when the stored value is not an array', async () => {
			prisma.user.findUnique.mockResolvedValue({
				twoFactorBackupCodes: { not: 'an array' },
			});

			await expect(service.verifyBackupCode(USER_ID, 'AAAA1111')).resolves.toBe(
				false
			);
		});

		it('returns false when no stored code matches', async () => {
			prisma.user.findUnique.mockResolvedValue({
				twoFactorBackupCodes: ['hash-a', 'hash-b'],
			});
			mockedBcrypt.compare.mockResolvedValue(false as never);

			await expect(service.verifyBackupCode(USER_ID, 'NOPE')).resolves.toBe(
				false
			);
			expect(mockedBcrypt.compare).toHaveBeenCalledTimes(2);
			expect(prisma.user.update).not.toHaveBeenCalled();
		});

		// Single-use is the whole point of a backup code.
		it('consumes the matching code and leaves the others intact', async () => {
			prisma.user.findUnique.mockResolvedValue({
				twoFactorBackupCodes: ['hash-a', 'hash-b', 'hash-c'],
			});
			mockedBcrypt.compare.mockImplementation(
				(async (_code: string, hash: string) => hash === 'hash-b') as never
			);
			prisma.user.update.mockResolvedValue(buildUser());

			await expect(
				service.verifyBackupCode(USER_ID, 'MATCHES-B')
			).resolves.toBe(true);
			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: USER_ID },
				data: { twoFactorBackupCodes: ['hash-a', 'hash-c'] },
			});
		});

		it('stops comparing once a code matches', async () => {
			prisma.user.findUnique.mockResolvedValue({
				twoFactorBackupCodes: ['hash-a', 'hash-b', 'hash-c'],
			});
			mockedBcrypt.compare.mockResolvedValue(true as never);
			prisma.user.update.mockResolvedValue(buildUser());

			await service.verifyBackupCode(USER_ID, 'MATCHES-FIRST');

			expect(mockedBcrypt.compare).toHaveBeenCalledTimes(1);
		});
	});

	describe('recordAttempt', () => {
		it('persists the attempt with its request context', async () => {
			prisma.twoFactorAttempt.create.mockResolvedValue({});

			await service.recordAttempt({
				userId: USER_ID,
				success: false,
				ipAddress: '203.0.113.10',
				userAgent: 'jest',
			});

			expect(prisma.twoFactorAttempt.create).toHaveBeenCalledWith({
				data: {
					userId: USER_ID,
					success: false,
					ipAddress: '203.0.113.10',
					userAgent: 'jest',
				},
			});
		});
	});

	describe('checkFailedAttempts', () => {
		it('counts only failed attempts inside the window', async () => {
			jest.useFakeTimers().setSystemTime(new Date('2026-01-01T12:00:00.000Z'));
			prisma.twoFactorAttempt.count.mockResolvedValue(2);

			const result = await service.checkFailedAttempts(USER_ID);

			expect(prisma.twoFactorAttempt.count).toHaveBeenCalledWith({
				where: {
					userId: USER_ID,
					success: false,
					createdAt: { gte: new Date('2026-01-01T11:45:00.000Z') },
				},
			});
			expect(result).toEqual({ exceeded: false, count: 2 });

			jest.useRealTimers();
		});

		it('reports exceeded at exactly the maximum', async () => {
			prisma.twoFactorAttempt.count.mockResolvedValue(5);

			await expect(service.checkFailedAttempts(USER_ID)).resolves.toEqual({
				exceeded: true,
				count: 5,
			});
		});

		it('honours custom thresholds and windows', async () => {
			jest.useFakeTimers().setSystemTime(new Date('2026-01-01T12:00:00.000Z'));
			prisma.twoFactorAttempt.count.mockResolvedValue(3);

			const result = await service.checkFailedAttempts(USER_ID, 3, 60);

			expect(prisma.twoFactorAttempt.count).toHaveBeenCalledWith({
				where: {
					userId: USER_ID,
					success: false,
					createdAt: { gte: new Date('2026-01-01T11:00:00.000Z') },
				},
			});
			expect(result.exceeded).toBe(true);

			jest.useRealTimers();
		});
	});

	describe('getRemainingBackupCodesCount', () => {
		it('returns the number of stored codes', async () => {
			prisma.user.findUnique.mockResolvedValue({
				twoFactorBackupCodes: ['a', 'b', 'c'],
			});

			await expect(service.getRemainingBackupCodesCount(USER_ID)).resolves.toBe(
				3
			);
		});

		it.each([
			['an unknown user', null],
			['no codes', { twoFactorBackupCodes: null }],
			['a non-array value', { twoFactorBackupCodes: 'oops' }],
		])('returns 0 for %s', async (_label, stored) => {
			prisma.user.findUnique.mockResolvedValue(stored);

			await expect(service.getRemainingBackupCodesCount(USER_ID)).resolves.toBe(
				0
			);
		});
	});

	describe('regenerateBackupCodes', () => {
		it('returns plaintext codes but persists only hashes', async () => {
			prisma.user.update.mockResolvedValue(buildUser());

			const codes = await service.regenerateBackupCodes(USER_ID);

			expect(codes).toHaveLength(10);
			const persisted = prisma.user.update.mock.calls[0][0].data
				.twoFactorBackupCodes as string[];
			expect(persisted).toHaveLength(10);
			for (const code of codes) {
				expect(persisted).not.toContain(code);
				expect(persisted).toContain(`hashed:${code}`);
			}
		});

		it('replaces the previous codes wholesale', async () => {
			prisma.user.update.mockResolvedValue(buildUser());

			await service.regenerateBackupCodes(USER_ID);

			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: USER_ID },
				data: { twoFactorBackupCodes: expect.any(Array) },
			});
			expect(prisma.user.findUnique).not.toHaveBeenCalled();
		});
	});
});
