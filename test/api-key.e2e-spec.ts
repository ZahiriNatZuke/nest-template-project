import type { PrismaService } from '@app/core/services/prisma/prisma.service';
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
import * as bcrypt from 'bcrypt';
import request from 'supertest';

/**
 * API key management end to end.
 *
 * The key itself is only ever returned once, at creation, and stored as a
 * bcrypt hash — so the specs that matter here are the ones proving the
 * plaintext never comes back on a later read.
 */
describe('API keys (e2e)', () => {
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
		await grantApiKeyPermissions();
	});

	/**
	 * seedFixtures only creates the three permissions the RBAC specs need, so
	 * the api-key ones are added here rather than widening the shared helper
	 * and changing what every other suite sees.
	 */
	async function grantApiKeyPermissions(): Promise<void> {
		for (const action of ['read', 'write', 'delete']) {
			const permission = await prisma.permission.create({
				data: {
					resource: 'api-keys',
					action,
					identifier: `api-keys:${action}`,
				},
			});
			await prisma.rolePermission.create({
				data: { roleId: fixtures.adminRoleId, permissionId: permission.id },
			});
		}
	}

	const loginAdmin = (): Promise<AuthContext> =>
		authenticate(http() as never, fixtures.adminUser.email, fixtures.password);

	it('returns the plaintext key exactly once, on creation', async () => {
		const auth = await loginAdmin();

		const created = await http()
			.post(`${API}/api-key`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.send({ application: 'Reporting Service' })
			.expect(201);

		expect(created.body.plainKey).toEqual(expect.any(String));
		expect(created.body.plainKey.length).toBeGreaterThan(0);
		expect(created.body.data).not.toHaveProperty('keyHash');

		const read = await http()
			.get(`${API}/api-key/${created.body.data.id}`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.expect(200);

		expect(read.body).not.toHaveProperty('plainKey');
	});

	it('stores the key as a bcrypt hash, never as plaintext', async () => {
		const auth = await loginAdmin();

		const created = await http()
			.post(`${API}/api-key`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.send({ application: 'Reporting Service' })
			.expect(201);

		const row = await prisma.apiKey.findUniqueOrThrow({
			where: { id: created.body.data.id },
		});

		expect(row.keyHash).not.toBe(created.body.plainKey);
		expect(row.keyHash.startsWith('$2')).toBe(true);
		await expect(
			bcrypt.compare(created.body.plainKey, row.keyHash)
		).resolves.toBe(true);
	});

	it('lists keys without exposing any hash', async () => {
		const auth = await loginAdmin();

		await http()
			.post(`${API}/api-key`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.send({ application: 'Reporting Service' })
			.expect(201);

		const list = await http()
			.get(`${API}/api-key`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.expect(200);

		expect(Array.isArray(list.body.data)).toBe(true);
		for (const item of list.body.data) {
			expect(item).not.toHaveProperty('keyHash');
		}
	});

	it('deletes a non-default key', async () => {
		const auth = await loginAdmin();

		const created = await http()
			.post(`${API}/api-key`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.send({ application: 'Reporting Service' })
			.expect(201);

		await http()
			.delete(`${API}/api-key/${created.body.data.id}`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.expect(200);

		await expect(
			prisma.apiKey.findUnique({ where: { id: created.body.data.id } })
		).resolves.toBeNull();
	});

	it('refuses to delete the default key', async () => {
		const auth = await loginAdmin();
		const defaultKey = await prisma.apiKey.findFirstOrThrow({
			where: { default: true },
		});

		await http()
			.delete(`${API}/api-key/${defaultKey.id}`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.expect(400);

		// Deleting it would lock every client out, so the row has to survive.
		await expect(
			prisma.apiKey.findUnique({ where: { id: defaultKey.id } })
		).resolves.not.toBeNull();
	});

	it('denies a user without the api-keys permissions', async () => {
		const auth = await authenticate(
			http() as never,
			fixtures.plainUser.email,
			fixtures.password
		);

		await http()
			.get(`${API}/api-key`)
			.set(auth.headers)
			.set('Cookie', auth.cookie)
			.expect(403);
	});
});
