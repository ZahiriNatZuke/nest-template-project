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
import request from 'supertest';

/**
 * The dynamic settings store, and the audit trail its writes are supposed to
 * leave behind.
 *
 * `@LogAudit` is a decorator read by an interceptor — a combination that fails
 * silently if either half is misconfigured, since the request still succeeds.
 * These specs assert the row lands in the database, not that the endpoint
 * returned 200.
 */
describe('Settings and audit log (e2e)', () => {
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
		await grantPermissions();
	});

	async function grantPermissions(): Promise<void> {
		const wanted: Array<[string, string]> = [
			['settings', 'read'],
			['settings', 'write'],
			['settings', 'delete'],
			['audit', 'read'],
		];

		for (const [resource, action] of wanted) {
			const permission = await prisma.permission.create({
				data: { resource, action, identifier: `${resource}:${action}` },
			});
			await prisma.rolePermission.create({
				data: { roleId: fixtures.adminRoleId, permissionId: permission.id },
			});
		}
	}

	const loginAdmin = (): Promise<AuthContext> =>
		authenticate(http() as never, fixtures.adminUser.email, fixtures.password);

	describe('settings', () => {
		it('creates and reads back a key', async () => {
			const auth = await loginAdmin();

			await http()
				.post(`${API}/settings`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ key: 'maintenance_mode', value: false })
				.expect(201);

			const res = await http()
				.get(`${API}/settings/maintenance_mode`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			expect(res.body.data.key).toBe('maintenance_mode');
		});

		it('updates an existing key', async () => {
			const auth = await loginAdmin();

			await http()
				.post(`${API}/settings`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ key: 'retention_days', value: 30 })
				.expect(201);

			await http()
				.patch(`${API}/settings/retention_days`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ value: 90 })
				.expect(200);

			const row = await prisma.settings.findFirstOrThrow({
				where: { key: 'retention_days' },
			});
			expect(JSON.stringify(row.value)).toContain('90');
		});

		it('deletes a key', async () => {
			const auth = await loginAdmin();

			await http()
				.post(`${API}/settings`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ key: 'temporary_flag', value: true })
				.expect(201);

			await http()
				.delete(`${API}/settings/temporary_flag`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			await expect(
				prisma.settings.findFirst({ where: { key: 'temporary_flag' } })
			).resolves.toBeNull();
		});

		it('answers 404 for a key that does not exist', async () => {
			const auth = await loginAdmin();

			await http()
				.get(`${API}/settings/no_such_key`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(404);
		});

		it('denies a user without the settings permissions', async () => {
			const auth = await authenticate(
				http() as never,
				fixtures.plainUser.email,
				fixtures.password
			);

			await http()
				.get(`${API}/settings`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(403);
		});
	});

	describe('audit log', () => {
		it('records a settings creation', async () => {
			const auth = await loginAdmin();

			await http()
				.post(`${API}/settings`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ key: 'audited_key', value: 'x' })
				.expect(201);

			const entries = await prisma.auditLog.findMany({
				where: { action: 'settings.create' },
			});
			expect(entries.length).toBeGreaterThanOrEqual(1);
			expect(entries[0].entityType).toBe('settings');
		});

		it('records a settings deletion', async () => {
			const auth = await loginAdmin();

			await http()
				.post(`${API}/settings`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ key: 'doomed_key', value: 'x' })
				.expect(201);

			await http()
				.delete(`${API}/settings/doomed_key`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			const entries = await prisma.auditLog.findMany({
				where: { action: 'settings.delete' },
			});
			expect(entries.length).toBeGreaterThanOrEqual(1);
		});

		it('writes nothing for a read', async () => {
			const auth = await loginAdmin();
			await prisma.auditLog.deleteMany();

			await http()
				.get(`${API}/settings`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			// Only handlers carrying @LogAudit should produce a row; auditing every
			// read would bury the writes that matter.
			await expect(prisma.auditLog.count()).resolves.toBe(0);
		});

		it('exposes the entries through the API', async () => {
			const auth = await loginAdmin();

			await http()
				.post(`${API}/settings`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ key: 'listed_key', value: 'x' })
				.expect(201);

			const res = await http()
				.get(`${API}/audit-log`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			expect(Array.isArray(res.body.data)).toBe(true);
			expect(res.body.meta.total).toBeGreaterThanOrEqual(1);
		});

		it('filters by action', async () => {
			const auth = await loginAdmin();

			await http()
				.post(`${API}/settings`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ key: 'filtered_key', value: 'x' })
				.expect(201);

			const res = await http()
				.get(`${API}/audit-log?action=settings.create`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			for (const entry of res.body.data) {
				expect(entry.action).toBe('settings.create');
			}
		});

		it('denies a user without audit:read', async () => {
			const auth = await authenticate(
				http() as never,
				fixtures.plainUser.email,
				fixtures.password
			);

			await http()
				.get(`${API}/audit-log`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(403);
		});
	});
});
