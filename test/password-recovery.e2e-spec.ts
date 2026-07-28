import type { PrismaService } from '@app/core/services/prisma/prisma.service';
import {
	API,
	apiKeyHeader,
	authenticate,
	createE2EApp,
	type E2EContext,
	resetDatabase,
	type SeededFixtures,
	seedFixtures,
} from '@test/utils/e2e-app';
import request from 'supertest';

/**
 * Password recovery from end to end: forgot → token → reset → log in.
 *
 * The last step is the one that matters. Every stage before it can report
 * success while the account is left exactly as it was, so a spec that stops at
 * a 200 proves nothing.
 */
describe('Password recovery (e2e)', () => {
	let ctx: E2EContext;
	let prisma: PrismaService;
	let fixtures: SeededFixtures;

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
	});

	const newPassword = 'R3coveredPassw0rd!Strong';

	/** Mutating routes still go through the API key and CSRF guards. */
	const csrf = async (): Promise<Record<string, string>> => {
		const res = await http().get(`${API}/auth/csrf`);
		return {
			...apiKeyHeader(),
			'x-csrf-token': res.body.csrfToken as string,
		};
	};

	describe('POST /auth/forgot-password', () => {
		it('stores a reset token against the account', async () => {
			await http()
				.post(`${API}/auth/forgot-password`)
				.set(await csrf())
				.send({ email: fixtures.adminUser.email })
				.expect(200);

			const user = await prisma.user.findUniqueOrThrow({
				where: { id: fixtures.adminUser.id },
			});
			expect(user.resetPasswordToken).toEqual(expect.any(String));
			expect(user.resetPasswordExpiresAt).toBeInstanceOf(Date);
			expect(user.resetPasswordExpiresAt?.getTime()).toBeGreaterThan(
				Date.now()
			);
		});
	});

	describe('POST /auth/reset-password', () => {
		/** Runs forgot-password and returns the token it stored. */
		const requestToken = async (): Promise<string> => {
			await http()
				.post(`${API}/auth/forgot-password`)
				.set(await csrf())
				.send({ email: fixtures.adminUser.email })
				.expect(200);

			const user = await prisma.user.findUniqueOrThrow({
				where: { id: fixtures.adminUser.id },
			});
			return user.resetPasswordToken as string;
		};

		it('accepts the token that forgot-password issued', async () => {
			const token = await requestToken();

			await http()
				.post(`${API}/auth/reset-password`)
				.set(await csrf())
				.send({
					token,
					email: fixtures.adminUser.email,
					newPassword,
					confirmNewPassword: newPassword,
				})
				.expect(200);
		});

		it('lets the user log in with the new password', async () => {
			const token = await requestToken();

			await http()
				.post(`${API}/auth/reset-password`)
				.set(await csrf())
				.send({
					token,
					email: fixtures.adminUser.email,
					newPassword,
					confirmNewPassword: newPassword,
				})
				.expect(200);

			const auth = await authenticate(
				http() as never,
				fixtures.adminUser.email,
				newPassword
			);
			expect(auth.accessToken).toBeTruthy();
		});

		it('clears the token so it cannot be replayed', async () => {
			const token = await requestToken();

			await http()
				.post(`${API}/auth/reset-password`)
				.set(await csrf())
				.send({
					token,
					email: fixtures.adminUser.email,
					newPassword,
					confirmNewPassword: newPassword,
				})
				.expect(200);

			const user = await prisma.user.findUniqueOrThrow({
				where: { id: fixtures.adminUser.id },
			});
			expect(user.resetPasswordToken).toBeNull();
			expect(user.resetPasswordExpiresAt).toBeNull();
		});

		it('rejects an expired token', async () => {
			const token = await requestToken();
			await prisma.user.update({
				where: { id: fixtures.adminUser.id },
				data: { resetPasswordExpiresAt: new Date(Date.now() - 1000) },
			});

			await http()
				.post(`${API}/auth/reset-password`)
				.set(await csrf())
				.send({
					token,
					email: fixtures.adminUser.email,
					newPassword,
					confirmNewPassword: newPassword,
				})
				.expect(400);
		});

		it('rejects a token belonging to nobody', async () => {
			await requestToken();

			await http()
				.post(`${API}/auth/reset-password`)
				.set(await csrf())
				.send({
					token: '11111111-2222-3333-4444-555555555555',
					email: fixtures.adminUser.email,
					newPassword,
					confirmNewPassword: newPassword,
				})
				.expect(400);
		});

		it('leaves the old password working when the reset is refused', async () => {
			await requestToken();

			await http()
				.post(`${API}/auth/reset-password`)
				.set(await csrf())
				.send({
					token: '11111111-2222-3333-4444-555555555555',
					email: fixtures.adminUser.email,
					newPassword,
					confirmNewPassword: newPassword,
				})
				.expect(400);

			const auth = await authenticate(
				http() as never,
				fixtures.adminUser.email,
				fixtures.password
			);
			expect(auth.accessToken).toBeTruthy();
		});
	});
});
