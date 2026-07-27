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
 * RBAC through the real HTTP stack.
 *
 * `@Authz('users:read')` chains three guards — VerifyJwtGuard (Authorization
 * header), JwtAuthGuard (accessToken cookie) and PermissionsGuard — so these
 * specs are the only place the whole chain is exercised together.
 */
describe('RBAC (e2e)', () => {
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

	const loginAdmin = (): Promise<AuthContext> =>
		authenticate(http() as never, fixtures.adminUser.email, fixtures.password);

	const loginPlainUser = (): Promise<AuthContext> =>
		authenticate(http() as never, fixtures.plainUser.email, fixtures.password);

	describe('the guard chain', () => {
		it('rejects a request with neither credential', async () => {
			await http().get(`${API}/user`).set(apiKeyHeader()).expect(401);
		});

		it('rejects a request carrying only the cookie', async () => {
			const auth = await loginAdmin();

			await http()
				.get(`${API}/user`)
				.set(apiKeyHeader())
				.set('Cookie', auth.cookie)
				.expect(401);
		});

		it('rejects a request carrying only the bearer token', async () => {
			const auth = await loginAdmin();

			await http()
				.get(`${API}/user`)
				.set(apiKeyHeader())
				.set('authorization', `Bearer ${auth.accessToken}`)
				.expect(401);
		});

		it('rejects a malformed bearer token', async () => {
			const auth = await loginAdmin();

			await http()
				.get(`${API}/user`)
				.set(apiKeyHeader())
				.set('authorization', 'Bearer not-a-jwt')
				.set('Cookie', auth.cookie)
				.expect(401);
		});
	});

	describe('permission enforcement', () => {
		it('allows a user holding the required permission', async () => {
			const auth = await loginAdmin();

			const res = await http()
				.get(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie);

			expect(res.status).toBe(200);
		});

		it('denies a user without the required permission', async () => {
			// The plain user only holds sessions:read, not users:read.
			const auth = await loginPlainUser();

			const res = await http()
				.get(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie);

			expect(res.status).toBe(403);
		});

		it('denies a write to a user who only holds read', async () => {
			await prisma.rolePermission.deleteMany({
				where: { roleId: fixtures.adminRoleId },
			});
			const usersRead = await prisma.permission.findFirstOrThrow({
				where: { identifier: 'users:read' },
			});
			await prisma.rolePermission.create({
				data: { roleId: fixtures.adminRoleId, permissionId: usersRead.id },
			});
			const auth = await loginAdmin();

			const res = await http()
				.post(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({
					email: 'new@e2e.local',
					username: 'new_user',
					fullName: 'New User',
					password: 'E2ePassw0rd!Strong',
				});

			expect(res.status).toBe(403);
		});
	});

	describe('wildcard permissions', () => {
		it('grants a specific action through `resource:all`', async () => {
			await prisma.rolePermission.deleteMany({
				where: { roleId: fixtures.adminRoleId },
			});
			const wildcard = await prisma.permission.create({
				data: { resource: 'users', action: 'all', identifier: 'users:all' },
			});
			await prisma.rolePermission.create({
				data: { roleId: fixtures.adminRoleId, permissionId: wildcard.id },
			});
			const auth = await loginAdmin();

			const res = await http()
				.get(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie);

			expect(res.status).toBe(200);
		});

		it('does not let a wildcard cross resources', async () => {
			await prisma.rolePermission.deleteMany({
				where: { roleId: fixtures.adminRoleId },
			});
			const wildcard = await prisma.permission.create({
				data: {
					resource: 'settings',
					action: 'all',
					identifier: 'settings:all',
				},
			});
			await prisma.rolePermission.create({
				data: { roleId: fixtures.adminRoleId, permissionId: wildcard.id },
			});
			const auth = await loginAdmin();

			const res = await http()
				.get(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie);

			expect(res.status).toBe(403);
		});
	});

	describe('permissions are captured in the token', () => {
		// The JWT carries `perm`, and PermissionsGuard prefers it over a database
		// lookup. A grant made after sign-in therefore does nothing until the
		// token is reissued — worth knowing before debugging a "why is my new
		// permission not working" report.
		it('does not pick up a permission granted after login', async () => {
			const auth = await loginPlainUser();
			const usersRead = await prisma.permission.findFirstOrThrow({
				where: { identifier: 'users:read' },
			});
			await prisma.rolePermission.create({
				data: { roleId: fixtures.userRoleId, permissionId: usersRead.id },
			});

			const res = await http()
				.get(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie);

			expect(res.status).toBe(403);
		});

		it('applies the new permission on a fresh login', async () => {
			const usersRead = await prisma.permission.findFirstOrThrow({
				where: { identifier: 'users:read' },
			});
			await prisma.rolePermission.create({
				data: { roleId: fixtures.userRoleId, permissionId: usersRead.id },
			});
			const auth = await authenticate(
				http() as never,
				fixtures.plainUser.email,
				fixtures.password,
				'second-device'
			);

			const res = await http()
				.get(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie);

			expect(res.status).toBe(200);
		});
	});

	describe('temporary permissions', () => {
		it('honours a grant that has not expired', async () => {
			await prisma.rolePermission.updateMany({
				where: { roleId: fixtures.adminRoleId },
				data: { expiresAt: new Date(Date.now() + 60 * 60 * 1000) },
			});
			const auth = await loginAdmin();

			const res = await http()
				.get(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie);

			expect(res.status).toBe(200);
		});
	});

	describe('revoked sessions', () => {
		it('rejects a token that was blacklisted by a logout', async () => {
			const auth = await loginAdmin();

			await http()
				.post(`${API}/auth/logout`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			const res = await http()
				.get(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie);

			expect(res.status).toBe(401);
		});
	});
});
