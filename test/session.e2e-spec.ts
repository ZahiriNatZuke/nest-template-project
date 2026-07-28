import type { PrismaService } from '@app/core/services/prisma/prisma.service';
import { envs } from '@app/env';
import {
	API,
	type AuthContext,
	authenticate,
	createE2EApp,
	type E2EContext,
	resetDatabase,
	type SeededFixtures,
	seedFixtures,
} from '@test/utils/e2e-app';
import request from 'supertest';

/**
 * Session management end to end.
 *
 * Sessions are created as a side effect of logging in, so these specs drive
 * the real login route rather than inserting rows: the concurrency limit is
 * enforced on that path and would not be exercised otherwise.
 */
describe('Sessions (e2e)', () => {
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
		await grantSessionDelete();
	});

	/** seedFixtures grants `sessions:read` but not `sessions:delete`. */
	async function grantSessionDelete(): Promise<void> {
		const permission = await prisma.permission.create({
			data: {
				resource: 'sessions',
				action: 'delete',
				identifier: 'sessions:delete',
			},
		});
		await prisma.rolePermission.create({
			data: { roleId: fixtures.adminRoleId, permissionId: permission.id },
		});
	}

	const loginAdmin = (device = 'jest-e2e'): Promise<AuthContext> =>
		authenticate(
			http() as never,
			fixtures.adminUser.email,
			fixtures.password,
			device
		);

	it('creates a session row when a user logs in', async () => {
		await loginAdmin();

		const sessions = await prisma.session.findMany({
			where: { userId: fixtures.adminUser.id },
		});
		expect(sessions.length).toBeGreaterThanOrEqual(1);
	});

	it('reads a single session by id', async () => {
		const auth = await loginAdmin();
		const session = await prisma.session.findFirstOrThrow({
			where: { userId: fixtures.adminUser.id },
		});

		const res = await http()
			.get(`${API}/session/${session.id}`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.expect(200);

		expect(res.body.data.id).toBe(session.id);
	});

	it('deletes a session', async () => {
		const auth = await loginAdmin();
		const session = await prisma.session.findFirstOrThrow({
			where: { userId: fixtures.adminUser.id },
		});

		await http()
			.delete(`${API}/session/${session.id}`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.expect(200);

		await expect(
			prisma.session.findUnique({ where: { id: session.id } })
		).resolves.toBeNull();
	});

	it('never keeps more than MAX_CONCURRENT_SESSIONS for one user', async () => {
		const limit = envs.MAX_CONCURRENT_SESSIONS;

		// One more login than the limit allows; the oldest session is expected to
		// be evicted rather than the new login being refused.
		for (let i = 0; i < limit + 2; i++) {
			await loginAdmin(`device-${i}`);
		}

		const sessions = await prisma.session.findMany({
			where: { userId: fixtures.adminUser.id },
		});
		expect(sessions.length).toBeLessThanOrEqual(limit);
	});

	it('denies a user without the sessions:delete permission', async () => {
		const plainAuth = await authenticate(
			http() as never,
			fixtures.plainUser.email,
			fixtures.password
		);
		const session = await prisma.session.findFirstOrThrow({
			where: { userId: fixtures.plainUser.id },
		});

		await http()
			.delete(`${API}/session/${session.id}`)
			.set(plainAuth.headers)
			.set('Cookie', plainAuth.cookie)
			.expect(403);
	});

	// The route declares no `:userId`, but the handler used to resolve
	// `@Param('userId', FindUserByIdPipe)` — the pipe got `undefined`, failed
	// its UUID check and answered 404 to everyone.
	it('lists the sessions of the authenticated user', async () => {
		const auth = await loginAdmin();

		const res = await http()
			.get(`${API}/session`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.expect(200);

		expect(Array.isArray(res.body.data)).toBe(true);
		expect(res.body.data.length).toBeGreaterThanOrEqual(1);
		for (const session of res.body.data) {
			expect(session.userId).toBe(fixtures.adminUser.id);
		}
	});

	it('does not leak sessions belonging to another user', async () => {
		await authenticate(
			http() as never,
			fixtures.plainUser.email,
			fixtures.password
		);
		const auth = await loginAdmin();

		const res = await http()
			.get(`${API}/session`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.expect(200);

		for (const session of res.body.data) {
			expect(session.userId).not.toBe(fixtures.plainUser.id);
		}
	});
});
