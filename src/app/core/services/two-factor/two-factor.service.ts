import { randomInt } from 'node:crypto';
import { EncryptionService } from '@app/core/services/encryption/encryption.service';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { envs } from '@app/env';
import { Injectable, Logger } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { generateSecret, OTP } from 'otplib';
import * as qrcode from 'qrcode';

/** Excludes 0/O and 1/I/L, which are misread when a code is copied by hand. */
const BACKUP_CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const BACKUP_CODE_LENGTH = 8;

@Injectable()
export class TwoFactorService {
	private readonly logger = new Logger(TwoFactorService.name);
	private readonly appName = envs.APP_NAME || 'NestApp';
	private readonly otp = new OTP();

	constructor(
		private prisma: PrismaService,
		private encryption: EncryptionService
	) {}

	/**
	 * Turns a stored `twoFactorSecret` back into the base32 secret otplib needs.
	 *
	 * Secrets used to be written in plaintext, so rows predating encryption stay
	 * readable: `isEncrypted` tells them apart by shape, and a base32 secret
	 * never contains the `:` separator the ciphertext format uses. That makes
	 * this backwards compatible without a migration script — see
	 * `reencryptSecretIfPlaintext`, which upgrades a row once its owner has
	 * successfully authenticated.
	 */
	async resolveSecret(storedSecret: string): Promise<string> {
		if (!this.encryption.isEncrypted(storedSecret)) {
			return storedSecret;
		}
		return this.encryption.decrypt(storedSecret);
	}

	/**
	 * Verifies a TOTP token against the secret as stored on the user row,
	 * decrypting it first when needed.
	 *
	 * Prefer this over `verifyToken` from anything holding a database row:
	 * handing the raw column to `verifyToken` silently fails once the value is
	 * encrypted, and nothing in the type system would say so.
	 */
	async verifyStoredToken(
		token: string,
		storedSecret: string
	): Promise<boolean> {
		return this.verifyToken(token, await this.resolveSecret(storedSecret));
	}

	/**
	 * Rewrites a legacy plaintext secret as ciphertext.
	 *
	 * Called after a successful verification, so the migration only happens on a
	 * path that has just proved the secret works and a failure to encrypt can
	 * never lock someone out of their own account.
	 */
	async reencryptSecretIfPlaintext(
		userId: string,
		storedSecret: string
	): Promise<void> {
		if (this.encryption.isEncrypted(storedSecret)) return;

		try {
			await this.prisma.user.update({
				where: { id: userId },
				data: { twoFactorSecret: await this.encryption.encrypt(storedSecret) },
			});
			this.logger.log(`2FA secret encrypted at rest for user ${userId}`);
		} catch (error) {
			// Best effort: the user is authenticated either way, and the next
			// verification will try again.
			this.logger.error(
				`Failed to encrypt the 2FA secret of user ${userId}`,
				error
			);
		}
	}

	/**
	 * Generate a new 2FA secret for a user
	 */
	generateSecret(): string {
		return generateSecret();
	}

	/**
	 * Generate QR code data URL for setting up 2FA
	 */
	async generateQRCode(email: string, secret: string): Promise<string> {
		const otpauthUrl = this.otp.generateURI({
			issuer: this.appName,
			label: email,
			secret,
		});
		return qrcode.toDataURL(otpauthUrl);
	}

	/**
	 * Verify a TOTP token against a secret
	 */
	async verifyToken(token: string, secret: string): Promise<boolean> {
		try {
			const result = await this.otp.verify({ token, secret });
			return result.valid;
		} catch (error) {
			this.logger.error('Failed to verify TOTP token', error);
			return false;
		}
	}

	/**
	 * Enable 2FA for a user
	 */
	async enable2FA(params: {
		userId: string;
		secret: string;
		backupCodes: string[];
	}): Promise<void> {
		const { userId, secret, backupCodes } = params;

		// Hash backup codes before storing
		const hashedBackupCodes = await Promise.all(
			backupCodes.map(code => bcrypt.hash(code, 10))
		);

		// Encrypted rather than hashed: TOTP verification needs the original value
		// back, so a one-way function is not an option. Left in plaintext, a
		// leaked database would let anyone mint valid codes for every account
		// with 2FA on — precisely the attack 2FA exists to stop.
		await this.prisma.user.update({
			where: { id: userId },
			data: {
				twoFactorEnabled: true,
				twoFactorSecret: await this.encryption.encrypt(secret),
				twoFactorBackupCodes: hashedBackupCodes,
			},
		});

		this.logger.log(`2FA enabled for user ${userId}`);
	}

	/**
	 * Disable 2FA for a user
	 */
	async disable2FA(userId: string): Promise<void> {
		await this.prisma.user.update({
			where: { id: userId },
			data: {
				twoFactorEnabled: false,
				twoFactorSecret: null,
				twoFactorBackupCodes: Prisma.DbNull,
			},
		});

		this.logger.log(`2FA disabled for user ${userId}`);
	}

	/**
	 * Mark 2FA as required for a user
	 */
	async require2FA(userId: string): Promise<void> {
		await this.prisma.user.update({
			where: { id: userId },
			data: {
				twoFactorRequired: true,
			},
		});

		this.logger.log(`2FA marked as required for user ${userId}`);
	}

	/**
	 * Mark 2FA as optional for a user
	 */
	async make2FAOptional(userId: string): Promise<void> {
		await this.prisma.user.update({
			where: { id: userId },
			data: {
				twoFactorRequired: false,
			},
		});

		this.logger.log(`2FA marked as optional for user ${userId}`);
	}

	/**
	 * Check if 2FA is required for a user
	 */
	async is2FARequired(userId: string): Promise<boolean> {
		const user = await this.prisma.user.findUnique({
			where: { id: userId },
			select: { twoFactorRequired: true },
		});

		return user?.twoFactorRequired ?? false;
	}

	/**
	 * Generate backup codes
	 */
	generateBackupCodes(count = 10): string[] {
		// A backup code bypasses the second factor outright, so it has to come
		// from a CSPRNG. This used to be
		// `Math.random().toString(36).substring(2, 10)`, which is neither: V8's
		// generator is predictable from enough observed output, and slicing a
		// float's base-36 expansion also produced codes shorter than 8
		// characters when the expansion happened to be short.
		//
		// `randomInt` is rejection-sampled, so indexing a 32-character alphabet
		// with it stays uniform — 40 bits per code. The alphabet drops the
		// characters people confuse when copying a code down by hand: 0/O, 1/I/L.
		const codes = new Set<string>();

		while (codes.size < count) {
			let code = '';
			for (let i = 0; i < BACKUP_CODE_LENGTH; i++) {
				code += BACKUP_CODE_ALPHABET[randomInt(BACKUP_CODE_ALPHABET.length)];
			}
			// A repeat would be one fewer usable code than the caller asked for.
			codes.add(code);
		}

		return Array.from(codes);
	}

	/**
	 * Verify a backup code
	 */
	async verifyBackupCode(userId: string, code: string): Promise<boolean> {
		const user = await this.prisma.user.findUnique({
			where: { id: userId },
			select: { twoFactorBackupCodes: true },
		});

		if (
			!user?.twoFactorBackupCodes ||
			!Array.isArray(user.twoFactorBackupCodes)
		) {
			return false;
		}

		// Check if any backup code matches
		for (let i = 0; i < user.twoFactorBackupCodes.length; i++) {
			const hashedCode = user.twoFactorBackupCodes[i] as string;
			const isMatch = await bcrypt.compare(code, hashedCode);

			if (isMatch) {
				// Remove the used backup code
				const remainingCodes = user.twoFactorBackupCodes.filter(
					(_, index) => index !== i
				);

				await this.prisma.user.update({
					where: { id: userId },
					data: { twoFactorBackupCodes: remainingCodes },
				});

				this.logger.log(`Backup code used for user ${userId}`);
				return true;
			}
		}

		return false;
	}

	/**
	 * Record a 2FA attempt (success or failure)
	 */
	async recordAttempt(params: {
		userId: string;
		success: boolean;
		ipAddress?: string;
		userAgent?: string;
	}): Promise<void> {
		const { userId, success, ipAddress, userAgent } = params;

		await this.prisma.twoFactorAttempt.create({
			data: {
				userId,
				success,
				ipAddress,
				userAgent,
			},
		});
	}

	/**
	 * Check if user has exceeded failed 2FA attempts
	 */
	async checkFailedAttempts(
		userId: string,
		maxAttempts = 5,
		windowMinutes = 15
	): Promise<{
		exceeded: boolean;
		count: number;
	}> {
		const since = new Date(Date.now() - windowMinutes * 60 * 1000);

		const failedAttempts = await this.prisma.twoFactorAttempt.count({
			where: {
				userId,
				success: false,
				createdAt: { gte: since },
			},
		});

		return {
			exceeded: failedAttempts >= maxAttempts,
			count: failedAttempts,
		};
	}

	/**
	 * Get remaining backup codes count
	 */
	async getRemainingBackupCodesCount(userId: string): Promise<number> {
		const user = await this.prisma.user.findUnique({
			where: { id: userId },
			select: { twoFactorBackupCodes: true },
		});

		if (
			!user?.twoFactorBackupCodes ||
			!Array.isArray(user.twoFactorBackupCodes)
		) {
			return 0;
		}

		return user.twoFactorBackupCodes.length;
	}

	/**
	 * Regenerate backup codes
	 */
	async regenerateBackupCodes(userId: string): Promise<string[]> {
		const newCodes = this.generateBackupCodes();
		const hashedCodes = await Promise.all(
			newCodes.map(code => bcrypt.hash(code, 10))
		);

		await this.prisma.user.update({
			where: { id: userId },
			data: { twoFactorBackupCodes: hashedCodes },
		});

		this.logger.log(`Backup codes regenerated for user ${userId}`);
		return newCodes;
	}
}
