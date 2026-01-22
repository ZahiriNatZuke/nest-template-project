import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { envs } from '@app/env';
import { Injectable, Logger } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { generateSecret, OTP } from 'otplib';
import * as qrcode from 'qrcode';

@Injectable()
export class TwoFactorService {
	private readonly logger = new Logger(TwoFactorService.name);
	private readonly appName = envs.APP_NAME || 'NestApp';
	private readonly otp = new OTP();

	constructor(private prisma: PrismaService) {}

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

		await this.prisma.user.update({
			where: { id: userId },
			data: {
				twoFactorEnabled: true,
				twoFactorSecret: secret,
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
		const codes: string[] = [];
		for (let i = 0; i < count; i++) {
			// Generate 8-character alphanumeric codes
			const code = Math.random().toString(36).substring(2, 10).toUpperCase();
			codes.push(code);
		}
		return codes;
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
