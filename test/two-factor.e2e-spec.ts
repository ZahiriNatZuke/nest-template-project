import type { PrismaService } from '@app/core/services/prisma/prisma.service';
import {
	API,
	type AuthContext,
	apiKeyHeader,
	authenticate,
	createE2EApp,
	type E2EContext,
	resetDatabase,
	type SeededFixtures,
	seedFixtures,
} from '@test/utils/e2e-app';
import { OTP } from 'otplib';
import request from 'supertest';

/**
 * The 2FA enrolment and verification flow through the real HTTP stack.
 *
 * TOTP codes are generated with a live otplib instance against the same secret
 * the endpoint just handed out, so these exercise real verification rather
 * than a stub.
 */
describe('Two-factor authentication (e2e)', () => {
	let ctx: E2EContext;
	let prisma: PrismaService;
	let fixtures: SeededFixtures;
	let auth: AuthContext;

	const otp = new OTP();
	const http = () => request(ctx.server as never);

	beforeAll(async () => {
		ctx = await createE2EApp();
		prisma = ctx.prisma;
	});

	afterAll(async () => {
		await resetDatabase(prisma);
		await ctx.close();
	});

	beforeEach(async () => {
		await resetDatabase(prisma);
		fixtures = await seedFixtures(prisma);
		auth = await authenticate(
			http() as never,
			fixtures.adminUser.email,
			fixtures.password
		);
	});

	/** Authenticated request helper: 2FA routes need both credentials. */
	const authed = (method: 'get' | 'post', path: string) =>
		http()
			[method](`${API}${path}`)
			.set(auth.headers)
			.set('Cookie', auth.cookie);

	const currentToken = (secret: string) => otp.generate({ secret });

	/** Runs setup and enable, returning the secret and backup codes. */
	const enrol = async () => {
		const setup = await authed('get', '/auth/2fa/setup').expect(200);
		const { secret, backupCodes } = setup.body.data;

		await authed('post', '/auth/2fa/enable')
			.send({ token: await currentToken(secret), secret, backupCodes })
			.expect(200);

		return { secret, backupCodes } as {
			secret: string;
			backupCodes: string[];
		};
	};

	describe('GET /auth/2fa/setup', () => {
		it('returns a QR code, a secret and backup codes', async () => {
			const res = await authed('get', '/auth/2fa/setup').expect(200);

			expect(res.body.data.qrCode).toMatch(/^data:image\/png;base64,/);
			expect(res.body.data.secret).toMatch(/^[A-Z2-7]+$/);
			expect(res.body.data.backupCodes).toHaveLength(10);
		});

		// Setup only hands out material; nothing is persisted until enable.
		it('does not enable 2FA on its own', async () => {
			await authed('get', '/auth/2fa/setup').expect(200);

			const user = await prisma.user.findUniqueOrThrow({
				where: { id: fixtures.adminUser.id },
			});
			expect(user.twoFactorEnabled).toBe(false);
			expect(user.twoFactorSecret).toBeNull();
		});

		it('rejects setup once 2FA is already enabled', async () => {
			await enrol();

			await authed('get', '/auth/2fa/setup').expect(400);
		});

		it('requires authentication', async () => {
			await http().get(`${API}/auth/2fa/setup`).set(apiKeyHeader()).expect(401);
		});
	});

	describe('POST /auth/2fa/enable', () => {
		it('enables 2FA for a valid TOTP token', async () => {
			const setup = await authed('get', '/auth/2fa/setup').expect(200);
			const { secret, backupCodes } = setup.body.data;

			await authed('post', '/auth/2fa/enable')
				.send({ token: await currentToken(secret), secret, backupCodes })
				.expect(200);

			const user = await prisma.user.findUniqueOrThrow({
				where: { id: fixtures.adminUser.id },
			});
			expect(user.twoFactorEnabled).toBe(true);
			expect(user.twoFactorSecret).toBe(secret);
		});

		// Note the asymmetry: enrolment treats a bad token as invalid input (400)
		// while `verify` treats it as failed authentication (401). Pinned as-is
		// because both readings are defensible, but a client has to handle both.
		it('rejects a token that does not match the secret', async () => {
			const setup = await authed('get', '/auth/2fa/setup').expect(200);
			const { secret, backupCodes } = setup.body.data;

			const res = await authed('post', '/auth/2fa/enable').send({
				token: '000000',
				secret,
				backupCodes,
			});

			expect(res.status).toBe(400);
			const user = await prisma.user.findUniqueOrThrow({
				where: { id: fixtures.adminUser.id },
			});
			expect(user.twoFactorEnabled).toBe(false);
		});

		it('stores backup codes hashed, never in plaintext', async () => {
			const { backupCodes } = await enrol();

			const user = await prisma.user.findUniqueOrThrow({
				where: { id: fixtures.adminUser.id },
			});
			const stored = JSON.stringify(user.twoFactorBackupCodes);
			for (const code of backupCodes) {
				expect(stored).not.toContain(`"${code}"`);
			}
			expect(user.twoFactorBackupCodes).toHaveLength(10);
		});
	});

	describe('POST /auth/2fa/verify', () => {
		it('accepts a current TOTP token', async () => {
			const { secret } = await enrol();

			await authed('post', '/auth/2fa/verify')
				.send({ token: await currentToken(secret) })
				.expect(200);
		});

		it('rejects an incorrect token', async () => {
			await enrol();

			await authed('post', '/auth/2fa/verify')
				.send({ token: '000000' })
				.expect(401);
		});

		it('rejects verification when 2FA was never enabled', async () => {
			await authed('post', '/auth/2fa/verify')
				.send({ token: '000000' })
				.expect(400);
		});

		it('records both successful and failed attempts', async () => {
			const { secret } = await enrol();

			await authed('post', '/auth/2fa/verify').send({ token: '000000' });
			await authed('post', '/auth/2fa/verify').send({
				token: await currentToken(secret),
			});

			const attempts = await prisma.twoFactorAttempt.findMany({
				where: { userId: fixtures.adminUser.id },
			});
			expect(attempts.map(a => a.success).sort()).toEqual([false, true]);
		});

		describe('backup codes', () => {
			it('accepts a backup code in place of a TOTP token', async () => {
				const { backupCodes } = await enrol();

				await authed('post', '/auth/2fa/verify')
					.send({ token: backupCodes[0] })
					.expect(200);
			});

			// Single use is the entire point of a backup code.
			it('consumes the code so it cannot be replayed', async () => {
				const { backupCodes } = await enrol();

				await authed('post', '/auth/2fa/verify')
					.send({ token: backupCodes[0] })
					.expect(200);
				await authed('post', '/auth/2fa/verify')
					.send({ token: backupCodes[0] })
					.expect(401);
			});

			it('leaves the other codes usable', async () => {
				const { backupCodes } = await enrol();

				await authed('post', '/auth/2fa/verify')
					.send({ token: backupCodes[0] })
					.expect(200);
				await authed('post', '/auth/2fa/verify')
					.send({ token: backupCodes[1] })
					.expect(200);

				const user = await prisma.user.findUniqueOrThrow({
					where: { id: fixtures.adminUser.id },
				});
				expect(user.twoFactorBackupCodes).toHaveLength(8);
			});
		});

		describe('lockout', () => {
			// Five failures inside the window locks verification, so a stolen
			// password cannot be paired with brute-forcing the six-digit code.
			it('answers 429 after five failed attempts', async () => {
				await enrol();

				for (let i = 0; i < 5; i++) {
					await authed('post', '/auth/2fa/verify').send({ token: '000000' });
				}

				await authed('post', '/auth/2fa/verify')
					.send({ token: '000000' })
					.expect(429);
			});

			it('locks out even a correct token once the limit is hit', async () => {
				const { secret } = await enrol();

				for (let i = 0; i < 5; i++) {
					await authed('post', '/auth/2fa/verify').send({ token: '000000' });
				}

				await authed('post', '/auth/2fa/verify')
					.send({ token: await currentToken(secret) })
					.expect(429);
			});
		});
	});

	describe('POST /auth/2fa/regenerate-backup-codes', () => {
		it('replaces the previous codes', async () => {
			const { backupCodes } = await enrol();

			const res = await authed(
				'post',
				'/auth/2fa/regenerate-backup-codes'
			).expect(200);
			const fresh = res.body.data.backupCodes as string[];

			expect(fresh).toHaveLength(10);
			expect(fresh).not.toEqual(backupCodes);
			// An old code must stop working.
			await authed('post', '/auth/2fa/verify')
				.send({ token: backupCodes[0] })
				.expect(401);
		});
	});

	describe('POST /auth/2fa/disable', () => {
		it('clears the secret and the codes', async () => {
			await enrol();

			await authed('post', '/auth/2fa/disable').expect(200);

			const user = await prisma.user.findUniqueOrThrow({
				where: { id: fixtures.adminUser.id },
			});
			expect(user.twoFactorEnabled).toBe(false);
			expect(user.twoFactorSecret).toBeNull();
			expect(user.twoFactorBackupCodes).toBeNull();
		});

		it('rejects disabling when 2FA is not enabled', async () => {
			await authed('post', '/auth/2fa/disable').expect(400);
		});
	});

	describe('POST /auth/2fa/require and /optional', () => {
		it('refuses to require 2FA before it is enabled', async () => {
			await authed('post', '/auth/2fa/require').expect(400);
		});

		it('marks 2FA as required once enabled', async () => {
			await enrol();

			await authed('post', '/auth/2fa/require').expect(200);

			const user = await prisma.user.findUniqueOrThrow({
				where: { id: fixtures.adminUser.id },
			});
			expect(user.twoFactorRequired).toBe(true);
		});

		it('marks 2FA back as optional', async () => {
			await enrol();
			await authed('post', '/auth/2fa/require').expect(200);

			await authed('post', '/auth/2fa/optional').expect(200);

			const user = await prisma.user.findUniqueOrThrow({
				where: { id: fixtures.adminUser.id },
			});
			expect(user.twoFactorRequired).toBe(false);
		});
	});

	describe('login when 2FA is required', () => {
		it('withholds the session and asks for verification', async () => {
			await enrol();
			await authed('post', '/auth/2fa/require').expect(200);

			const csrfRes = await http().get(`${API}/auth/csrf`).expect(200);
			const loginRes = await http()
				.post(`${API}/auth/login`)
				.set(apiKeyHeader())
				.set('x-csrf-token', csrfRes.body.csrfToken)
				.send({
					identifier: fixtures.adminUser.email,
					password: fixtures.password,
					device: 'second-device',
				});

			expect(loginRes.status).toBe(200);
			expect(loginRes.body).toMatchObject({ requiresTwoFactor: true });

			// The usable access cookie is withheld; only a short-lived temporary
			// one is issued until verification completes.
			const cookies = (loginRes.headers['set-cookie'] ??
				[]) as unknown as string[];
			expect(cookies.some(c => c.startsWith('accessToken='))).toBe(false);
			expect(cookies.some(c => c.startsWith('tempAccessToken='))).toBe(true);
		});

		it('issues a normal session when 2FA is enabled but not required', async () => {
			await enrol();

			const csrfRes = await http().get(`${API}/auth/csrf`).expect(200);
			const loginRes = await http()
				.post(`${API}/auth/login`)
				.set(apiKeyHeader())
				.set('x-csrf-token', csrfRes.body.csrfToken)
				.send({
					identifier: fixtures.adminUser.email,
					password: fixtures.password,
					device: 'second-device',
				});

			expect(loginRes.body).toMatchObject({ requiresTwoFactor: false });
			const cookies = (loginRes.headers['set-cookie'] ??
				[]) as unknown as string[];
			expect(cookies.some(c => c.startsWith('accessToken='))).toBe(true);
		});
	});
});
