import { randomUUID } from 'node:crypto';
import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { ZodValidationException } from '@app/core/utils/zod';
import { envs } from '@app/env';
import { ConfirmEmailZodDto } from '@app/modules/auth/dto/confirm-email.dto';
import { ForgotPasswordZodDto } from '@app/modules/auth/dto/forgot-password.dto';
import { RecoveryAccountDto } from '@app/modules/auth/dto/recovery-account.dto';
import { RequestRecoveryAccountZodDto } from '@app/modules/auth/dto/request-recovery-account.dto';
import { ResetPasswordZodDto } from '@app/modules/auth/dto/reset-password.dto';
import { UpdatePasswordZodDto } from '@app/modules/auth/dto/update-password.dto';
import { Injectable, Logger } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { pick } from 'lodash';
import { z } from 'zod';
import type { UserService } from '../../user/user.service';
import { TokenBlacklistService } from './token-blacklist.service';

/** Single place to build the validation error these flows report. */
const validationError = (message: string) =>
	new ZodValidationException(
		new z.ZodError([{ code: 'custom', path: [], message }])
	);

/**
 * Everything that changes or recovers a password, plus email confirmation.
 *
 * Split out of AuthService, which had grown to 673 lines covering two
 * unrelated concerns. This half mirrors ProfileController.updatePassword and
 * the whole of PasswordRecoveryController.
 */
@Injectable()
export class PasswordService {
	private readonly logger = new Logger(PasswordService.name);

	constructor(
		private prisma: PrismaService,
		private jwtService: JwtService,
		private moduleRef: ModuleRef,
		private tokenBlacklist: TokenBlacklistService
	) {}

	/**
	 * Changes the password of an authenticated user.
	 *
	 * Every other session is torn down afterwards: a password change is the
	 * usual response to a suspected compromise, so leaving other devices signed
	 * in would defeat the point.
	 */
	async updatePassword(dto: UpdatePasswordZodDto, user: { id: string }) {
		const userDb = await this.prisma.user.findUniqueOrThrow({
			where: { id: user.id },
		});

		// Compare against the row, never against the principal hanging off the
		// request. Under JwtAuthGuard that principal is the token payload and has
		// no `password` at all, so this used to hand bcrypt `undefined` and no
		// caller could ever change their password. Taking only `{ id }` here
		// keeps the next caller from reintroducing the same mistake.
		if (!(await bcrypt.compare(dto.current_password, userDb.password))) {
			throw validationError('Current password miss match');
		}

		if (dto.new_password !== dto.confirm_new_password) {
			throw validationError('Passwords not match');
		}

		const newPassword = await bcrypt.hash(
			dto.new_password,
			bcrypt.genSaltSync(16)
		);

		await this.tokenBlacklist.invalidateAllUserSessions(user.id);

		return this.prisma.user.update({
			where: { id: userDb.id },
			data: { password: newPassword },
		});
	}

	async recoverAccount({
		email,
		newPassword,
		confirmNewPassword,
	}: RecoveryAccountDto) {
		if (newPassword !== confirmNewPassword) {
			throw validationError('Passwords not match');
		}

		try {
			const userDb = await this.prisma.user.findUniqueOrThrow({
				where: { email },
			});

			return this.prisma.user.update({
				where: { id: userDb.id },
				data: {
					password: await bcrypt.hash(newPassword, bcrypt.genSaltSync(16)),
				},
			});
		} catch (_) {
			// Deliberately generic: a distinct "no such email" would let anyone
			// enumerate registered addresses.
			throw validationError('Recovery account process failure');
		}
	}

	async requestRecoveryAccount(dto: RequestRecoveryAccountZodDto) {
		try {
			// Lazy load UserService only when needed
			const userService = this.moduleRef.get('UserService', {
				strict: false,
			}) as UserService;
			const user = await userService?.findOne({ email: dto.email }, true);

			if (!user) {
				throw validationError('Request for recovery account failure');
			}

			const payload = pick(user, ['name', 'lastname', 'email', 'id']);
			const token = this.jwtService.sign(
				{ ...payload, xhr: randomUUID() },
				{
					secret: envs.JWT_VERIFICATION_TOKEN_SECRET,
					expiresIn: '30m',
				}
			);
			const url = `${envs.RECOVERY_ACCOUNT_URL}?token=${token}&email=${dto.email}`;

			// TODO: hand this to NotificationPort once a provider is wired up.
			this.logger.debug(`>> [recovery-url]: ${url}`);
		} catch (_e) {
			throw validationError('Request for recovery account failure');
		}
	}

	async decodeVerificationToken(token: string): Promise<boolean> {
		try {
			const payload = await this.jwtService.verify(token, {
				secret: envs.JWT_VERIFICATION_TOKEN_SECRET,
			});

			return typeof payload === 'object' && 'xhr' in payload;
		} catch (error) {
			// Expiry is reported distinctly so the client can offer a restart
			// rather than a generic failure.
			if (error?.name === 'TokenExpiredError') {
				throw validationError(
					'Recovered process expired, you must restart process'
				);
			}
			throw validationError('Verification of recovery process failure');
		}
	}

	async forgotPassword(dto: ForgotPasswordZodDto) {
		const user = await this.prisma.user.findFirst({
			where: { email: dto.email, deletedAt: null },
		});
		if (!user) {
			throw validationError('User not found');
		}

		const token = randomUUID();
		const expires = new Date(Date.now() + 15 * 60 * 1000); // 15m
		await this.prisma.user.update({
			where: { id: user.id },
			data: {
				resetPasswordToken: token,
				resetPasswordExpiresAt: expires,
			},
		});

		// TODO: send notification/email with reset link
		this.logger.warn(
			`TODO: send reset password email to ${user.email} with token ${token}`
		);
	}

	async resetPassword(dto: ResetPasswordZodDto) {
		const user = await this.prisma.user.findFirst({
			where: {
				email: dto.email,
				resetPasswordToken: dto.token,
				resetPasswordExpiresAt: { gt: new Date() },
				deletedAt: null,
			},
		});

		if (!user) {
			throw validationError('Invalid or expired reset token');
		}

		const newPassword = await bcrypt.hash(
			dto.newPassword,
			bcrypt.genSaltSync(16)
		);

		await this.prisma.user.update({
			where: { id: user.id },
			data: {
				password: newPassword,
				resetPasswordToken: null,
				resetPasswordExpiresAt: null,
			},
		});

		await this.tokenBlacklist.invalidateAllUserSessions(user.id);
	}

	async confirmEmail(dto: ConfirmEmailZodDto) {
		const user = await this.prisma.user.findFirst({
			where: {
				confirmationToken: dto.token,
				confirmationTokenExpiresAt: { gt: new Date() },
				deletedAt: null,
			},
		});

		if (!user) {
			throw validationError('Invalid or expired confirmation token');
		}

		await this.prisma.user.update({
			where: { id: user.id },
			data: {
				confirmed: true,
				confirmedAt: new Date(),
				confirmationToken: null,
				confirmationTokenExpiresAt: null,
			},
		});
	}
}
