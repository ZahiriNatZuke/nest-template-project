import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Test, TestingModule } from '@nestjs/testing';
import { buildSession } from '@test/utils/factories';
import {
	asPrismaService,
	createPrismaMock,
	type PrismaMock,
} from '@test/utils/prisma-mock';
import { TokenBlacklistService } from './token-blacklist.service';

describe('TokenBlacklistService', () => {
	let service: TokenBlacklistService;
	let prisma: PrismaMock;

	beforeEach(async () => {
		prisma = createPrismaMock();
		prisma.tokenBlacklist.create.mockResolvedValue({});

		const module: TestingModule = await Test.createTestingModule({
			providers: [
				TokenBlacklistService,
				{ provide: PrismaService, useValue: asPrismaService(prisma) },
			],
		}).compile();

		service = module.get<TokenBlacklistService>(TokenBlacklistService);
	});

	describe('blacklist', () => {
		it('stores the token with an expiry the given number of hours out', async () => {
			jest.useFakeTimers().setSystemTime(new Date('2026-01-01T12:00:00.000Z'));

			await service.blacklist('a-token', 8);

			expect(prisma.tokenBlacklist.create).toHaveBeenCalledWith({
				data: {
					token: 'a-token',
					expiresAt: new Date('2026-01-01T20:00:00.000Z'),
				},
			});
			jest.useRealTimers();
		});
	});

	describe('blacklistSessionTokens', () => {
		// The windows differ on purpose: an access token only has to outlive its
		// own short validity, a refresh token a full day.
		it('revokes the access token for 8 hours and the refresh token for 24', async () => {
			jest.useFakeTimers().setSystemTime(new Date('2026-01-01T12:00:00.000Z'));

			await service.blacklistSessionTokens({
				accessToken: 'access',
				refreshToken: 'refresh',
			});

			expect(
				prisma.tokenBlacklist.create.mock.calls.map(c => c[0].data)
			).toEqual([
				{
					token: 'access',
					expiresAt: new Date('2026-01-01T20:00:00.000Z'),
				},
				{
					token: 'refresh',
					expiresAt: new Date('2026-01-02T12:00:00.000Z'),
				},
			]);
			jest.useRealTimers();
		});
	});

	describe('isBlacklisted', () => {
		it('is false when the token was never revoked', async () => {
			prisma.tokenBlacklist.findUnique.mockResolvedValue(null);

			await expect(service.isBlacklisted('t')).resolves.toBe(false);
		});

		it('is true for a live entry', async () => {
			prisma.tokenBlacklist.findUnique.mockResolvedValue({
				expiresAt: new Date(Date.now() + 60_000),
			});

			await expect(service.isBlacklisted('t')).resolves.toBe(true);
		});

		// The row only exists until the token would have expired anyway, so a
		// stale entry must not keep reporting a revocation forever.
		it('is false once the entry itself has expired', async () => {
			prisma.tokenBlacklist.findUnique.mockResolvedValue({
				expiresAt: new Date(Date.now() - 1_000),
			});

			await expect(service.isBlacklisted('t')).resolves.toBe(false);
		});
	});

	describe('invalidateAllUserSessions', () => {
		it('revokes every token before deleting the sessions', async () => {
			prisma.session.findMany.mockResolvedValue([
				buildSession({ accessToken: 'a1', refreshToken: 'r1' }),
				buildSession({ accessToken: 'a2', refreshToken: 'r2' }),
			]);
			prisma.session.deleteMany.mockResolvedValue({ count: 2 });

			await service.invalidateAllUserSessions('user-1');

			expect(
				prisma.tokenBlacklist.create.mock.calls.map(c => c[0].data.token)
			).toEqual(['a1', 'r1', 'a2', 'r2']);
			expect(prisma.session.deleteMany).toHaveBeenCalledWith({
				where: { userId: 'user-1' },
			});
		});

		it('still clears sessions when there is nothing to revoke', async () => {
			prisma.session.findMany.mockResolvedValue([]);
			prisma.session.deleteMany.mockResolvedValue({ count: 0 });

			await service.invalidateAllUserSessions('user-1');

			expect(prisma.tokenBlacklist.create).not.toHaveBeenCalled();
			expect(prisma.session.deleteMany).toHaveBeenCalled();
		});
	});
});
