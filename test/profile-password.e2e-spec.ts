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
import request from 'supertest';

/**
 * `POST /auth/update-password` end to end.
 *
 * This route is the one place where a controller hands the request principal
 * to a service that expects a database row. Under JwtAuthGuard `req.user` is
 * the token payload — it carries no `password` — so the whole flow only works
 * if the service compares against the row it loads itself. These specs pin
 * that down: without them a regression is invisible, because every failure
 * mode here still returns a plausible-looking error.
 */
describe('Profile password (e2e)', () => {
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

	const login = (): Promise<AuthContext> =>
		authenticate(http() as never, fixtures.adminUser.email, fixtures.password);

	const newPassword = 'N3wE2ePassw0rd!Strong';

	it('accepts the correct current password and changes it', async () => {
		const auth = await login();

		await http()
			.post(`${API}/auth/update-password`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.send({
				current_password: fixtures.password,
				new_password: newPassword,
				confirm_new_password: newPassword,
			})
			.expect(200);
	});

	it('lets the user log in again with the new password', async () => {
		const auth = await login();

		await http()
			.post(`${API}/auth/update-password`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.send({
				current_password: fixtures.password,
				new_password: newPassword,
				confirm_new_password: newPassword,
			})
			.expect(200);

		// A fresh login is the only proof the stored hash actually changed:
		// the endpoint reports success before writing, so a 200 alone is not it.
		const reauth = await authenticate(
			http() as never,
			fixtures.adminUser.email,
			newPassword
		);
		expect(reauth.accessToken).toBeTruthy();
	});

	it('rejects a wrong current password', async () => {
		const auth = await login();

		await http()
			.post(`${API}/auth/update-password`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.send({
				current_password: 'NotTheCurrentPassw0rd!',
				new_password: newPassword,
				confirm_new_password: newPassword,
			})
			.expect(400);
	});

	it('leaves the stored password untouched when the current one is wrong', async () => {
		const auth = await login();
		const before = await prisma.user.findUniqueOrThrow({
			where: { id: fixtures.adminUser.id },
			select: { password: true },
		});

		await http()
			.post(`${API}/auth/update-password`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.send({
				current_password: 'NotTheCurrentPassw0rd!',
				new_password: newPassword,
				confirm_new_password: newPassword,
			})
			.expect(400);

		const after = await prisma.user.findUniqueOrThrow({
			where: { id: fixtures.adminUser.id },
			select: { password: true },
		});
		expect(after.password).toBe(before.password);
	});

	it('rejects a confirmation that does not match', async () => {
		const auth = await login();

		await http()
			.post(`${API}/auth/update-password`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.send({
				current_password: fixtures.password,
				new_password: newPassword,
				confirm_new_password: `${newPassword}-different`,
			})
			.expect(400);
	});

	it('rejects an unauthenticated request', async () => {
		await http()
			.post(`${API}/auth/update-password`)
			.set(apiKeyHeader())
			.send({
				current_password: fixtures.password,
				new_password: newPassword,
				confirm_new_password: newPassword,
			})
			.expect(401);
	});
});
