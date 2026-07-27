import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { ZodValidationException } from '@app/core/utils/zod';
import { ModuleRef } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { buildSession, buildUser } from '@test/utils/factories';
import {
	asPrismaService,
	createPrismaMock,
	type PrismaMock,
} from '@test/utils/prisma-mock';
import * as bcrypt from 'bcrypt';
import { PasswordService } from './password.service';
import { TokenBlacklistService } from './token-blacklist.service';

jest.mock('bcrypt', () => ({
	compare: jest.fn(),
	hash: jest.fn(),
	genSaltSync: jest.fn(() => 'salt'),
}));

const mockedBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;

describe('PasswordService', () => {
	let service: PasswordService;
	let prisma: PrismaMock;
	let jwtService: { sign: jest.Mock; verify: jest.Mock };
	let moduleRef: { get: jest.Mock };

	beforeEach(async () => {
		prisma = createPrismaMock();
		jwtService = {
			sign: jest.fn(() => 'signed-jwt'),
			verify: jest.fn(),
		};
		moduleRef = { get: jest.fn() };

		const module: TestingModule = await Test.createTestingModule({
			providers: [
				PasswordService,
				TokenBlacklistService,
				{ provide: PrismaService, useValue: asPrismaService(prisma) },
				{ provide: JwtService, useValue: jwtService },
				{ provide: ModuleRef, useValue: moduleRef },
			],
		}).compile();

		service = module.get<PasswordService>(PasswordService);

		mockedBcrypt.hash.mockResolvedValue('hashed-password' as never);
		prisma.tokenBlacklist.create.mockResolvedValue({});
	});

	describe('updatePassword', () => {
		const user = buildUser();
		const dto = {
			current_password: 'old',
			new_password: 'NewPassw0rd!',
			confirm_new_password: 'NewPassw0rd!',
		};

		beforeEach(() => {
			prisma.user.findUniqueOrThrow.mockResolvedValue(user);
			prisma.user.update.mockResolvedValue(user);
			prisma.session.findMany.mockResolvedValue([]);
			prisma.session.deleteMany.mockResolvedValue({ count: 0 });
		});

		it('hashes and stores the new password', async () => {
			mockedBcrypt.compare.mockResolvedValue(true as never);

			await service.updatePassword(dto as never, user as never);

			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: user.id },
				data: { password: 'hashed-password' },
			});
		});

		it('rejects a wrong current password', async () => {
			mockedBcrypt.compare.mockResolvedValue(false as never);

			await expect(
				service.updatePassword(dto as never, user as never)
			).rejects.toBeInstanceOf(ZodValidationException);
			expect(prisma.user.update).not.toHaveBeenCalled();
		});

		it('rejects when the confirmation does not match', async () => {
			mockedBcrypt.compare.mockResolvedValue(true as never);

			await expect(
				service.updatePassword(
					{ ...dto, confirm_new_password: 'Different!' } as never,
					user as never
				)
			).rejects.toBeInstanceOf(ZodValidationException);
			expect(prisma.user.update).not.toHaveBeenCalled();
		});

		// Changing a password has to log every other device out.
		it('invalidates all existing sessions', async () => {
			mockedBcrypt.compare.mockResolvedValue(true as never);
			prisma.session.findMany.mockResolvedValue([
				buildSession({ accessToken: 'a', refreshToken: 'r' }),
			]);

			await service.updatePassword(dto as never, user as never);

			expect(prisma.session.deleteMany).toHaveBeenCalledWith({
				where: { userId: user.id },
			});
			expect(
				prisma.tokenBlacklist.create.mock.calls.map(c => c[0].data.token)
			).toEqual(['a', 'r']);
		});
	});

	describe('recoverAccount', () => {
		it('rejects mismatched passwords before any lookup', async () => {
			await expect(
				service.recoverAccount({
					email: 'a@b.c',
					newPassword: 'One!',
					confirmNewPassword: 'Two!',
				} as never)
			).rejects.toBeInstanceOf(ZodValidationException);
			expect(prisma.user.findUniqueOrThrow).not.toHaveBeenCalled();
		});

		it('stores the hashed password for a known email', async () => {
			const user = buildUser();
			prisma.user.findUniqueOrThrow.mockResolvedValue(user);
			prisma.user.update.mockResolvedValue(user);

			await service.recoverAccount({
				email: user.email,
				newPassword: 'NewPassw0rd!',
				confirmNewPassword: 'NewPassw0rd!',
			} as never);

			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: user.id },
				data: { password: 'hashed-password' },
			});
		});

		it('reports a generic failure for an unknown email', async () => {
			prisma.user.findUniqueOrThrow.mockRejectedValue(new Error('none'));

			await expect(
				service.recoverAccount({
					email: 'ghost@b.c',
					newPassword: 'NewPassw0rd!',
					confirmNewPassword: 'NewPassw0rd!',
				} as never)
			).rejects.toBeInstanceOf(ZodValidationException);
		});
	});

	describe('requestRecoveryAccount', () => {
		it('signs a recovery token for a known user', async () => {
			const userService = { findOne: jest.fn().mockResolvedValue(buildUser()) };
			moduleRef.get.mockReturnValue(userService);

			await service.requestRecoveryAccount({ email: 'a@b.c' } as never);

			expect(jwtService.sign).toHaveBeenCalledWith(
				expect.objectContaining({ xhr: expect.any(String) }),
				expect.objectContaining({ expiresIn: '30m' })
			);
		});

		it('reports failure for an unknown user', async () => {
			moduleRef.get.mockReturnValue({
				findOne: jest.fn().mockResolvedValue(null),
			});

			await expect(
				service.requestRecoveryAccount({ email: 'ghost@b.c' } as never)
			).rejects.toBeInstanceOf(ZodValidationException);
		});
	});

	describe('decodeVerificationToken', () => {
		it('accepts a payload carrying the xhr claim', async () => {
			jwtService.verify.mockReturnValue({ xhr: 'uuid', email: 'a@b.c' });

			await expect(service.decodeVerificationToken('t')).resolves.toBe(true);
		});

		it('rejects a payload without the xhr claim', async () => {
			jwtService.verify.mockReturnValue({ email: 'a@b.c' });

			await expect(service.decodeVerificationToken('t')).resolves.toBe(false);
		});

		// ZodValidationException's own message is always "Validation failed"; the
		// caller-facing text lives in the wrapped ZodError, so that is what these
		// assert on.
		const issueMessages = async (promise: Promise<unknown>) => {
			try {
				await promise;
			} catch (error) {
				return (error as ZodValidationException).zodError.issues.map(
					i => i.message
				);
			}
			throw new Error('expected the call to reject');
		};

		it('reports expiry distinctly from a malformed token', async () => {
			jwtService.verify.mockImplementation(() => {
				const error = new Error('jwt expired');
				error.name = 'TokenExpiredError';
				throw error;
			});

			await expect(
				issueMessages(service.decodeVerificationToken('t'))
			).resolves.toEqual([
				'Recovered process expired, you must restart process',
			]);
		});

		it('reports a generic failure for a malformed token', async () => {
			jwtService.verify.mockImplementation(() => {
				throw new Error('invalid signature');
			});

			await expect(
				issueMessages(service.decodeVerificationToken('t'))
			).resolves.toEqual(['Verification of recovery process failure']);
		});
	});

	describe('forgotPassword', () => {
		it('stores a reset token with a 15 minute expiry', async () => {
			jest.useFakeTimers().setSystemTime(new Date('2026-01-01T12:00:00.000Z'));
			const user = buildUser();
			prisma.user.findFirst.mockResolvedValue(user);
			prisma.user.update.mockResolvedValue(user);

			await service.forgotPassword({ email: user.email } as never);

			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: user.id },
				data: {
					resetPasswordToken: expect.any(String),
					resetPasswordExpiresAt: new Date('2026-01-01T12:15:00.000Z'),
				},
			});
			jest.useRealTimers();
		});

		it('rejects an unknown email', async () => {
			prisma.user.findFirst.mockResolvedValue(null);

			await expect(
				service.forgotPassword({ email: 'ghost@b.c' } as never)
			).rejects.toBeInstanceOf(ZodValidationException);
		});

		it('ignores soft-deleted users', async () => {
			prisma.user.findFirst.mockResolvedValue(null);

			await expect(
				service.forgotPassword({ email: 'gone@b.c' } as never)
			).rejects.toBeInstanceOf(ZodValidationException);
			expect(prisma.user.findFirst).toHaveBeenCalledWith({
				where: { email: 'gone@b.c', deletedAt: null },
			});
		});
	});

	describe('resetPassword', () => {
		const dto = {
			email: 'a@b.c',
			token: 'reset-token',
			newPassword: 'NewPassw0rd!',
		};

		it('requires an unexpired token bound to that email', async () => {
			prisma.user.findFirst.mockResolvedValue(null);

			await expect(service.resetPassword(dto as never)).rejects.toBeInstanceOf(
				ZodValidationException
			);
			expect(prisma.user.findFirst).toHaveBeenCalledWith({
				where: {
					email: dto.email,
					resetPasswordToken: dto.token,
					resetPasswordExpiresAt: { gt: expect.any(Date) },
					deletedAt: null,
				},
			});
		});

		it('stores the new password and clears the token', async () => {
			const user = buildUser();
			prisma.user.findFirst.mockResolvedValue(user);
			prisma.user.update.mockResolvedValue(user);
			prisma.session.findMany.mockResolvedValue([]);
			prisma.session.deleteMany.mockResolvedValue({ count: 0 });

			await service.resetPassword(dto as never);

			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: user.id },
				data: {
					password: 'hashed-password',
					resetPasswordToken: null,
					resetPasswordExpiresAt: null,
				},
			});
		});

		it('invalidates all sessions after a reset', async () => {
			const user = buildUser();
			prisma.user.findFirst.mockResolvedValue(user);
			prisma.user.update.mockResolvedValue(user);
			prisma.session.findMany.mockResolvedValue([]);
			prisma.session.deleteMany.mockResolvedValue({ count: 0 });

			await service.resetPassword(dto as never);

			expect(prisma.session.deleteMany).toHaveBeenCalledWith({
				where: { userId: user.id },
			});
		});
	});

	describe('confirmEmail', () => {
		it('marks the user confirmed and clears the token', async () => {
			const user = buildUser({ confirmed: false });
			prisma.user.findFirst.mockResolvedValue(user);
			prisma.user.update.mockResolvedValue(user);

			await service.confirmEmail({ token: 'confirm-token' } as never);

			expect(prisma.user.update).toHaveBeenCalledWith({
				where: { id: user.id },
				data: {
					confirmed: true,
					confirmedAt: expect.any(Date),
					confirmationToken: null,
					confirmationTokenExpiresAt: null,
				},
			});
		});

		it('rejects an invalid or expired token', async () => {
			prisma.user.findFirst.mockResolvedValue(null);

			await expect(
				service.confirmEmail({ token: 'bad' } as never)
			).rejects.toBeInstanceOf(ZodValidationException);
		});
	});
});
