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
 * Role and permission administration through the real HTTP stack.
 *
 * The RBAC specs already cover a permission being enforced. What is not
 * covered anywhere is administering them: creating a role, attaching a
 * permission, detaching it again, and the hierarchy that lets one role inherit
 * another's grants.
 */
describe('Roles and permissions (e2e)', () => {
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
		await grantAdminPermissions();
	});

	async function grantAdminPermissions(): Promise<void> {
		const wanted: Array<[string, string]> = [
			['roles', 'read'],
			['roles', 'write'],
			['roles', 'delete'],
			['permissions', 'read'],
			['permissions', 'write'],
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

	describe('role administration', () => {
		it('creates a role', async () => {
			const auth = await loginAdmin();

			const res = await http()
				.post(`${API}/role`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ identifier: 'AUDITOR_ROLE', name: 'Auditor' })
				.expect(201);

			expect(res.body.data.identifier).toBe('AUDITOR_ROLE');
		});

		it('lists roles', async () => {
			const auth = await loginAdmin();

			const res = await http()
				.get(`${API}/role`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			expect(Array.isArray(res.body.data)).toBe(true);
		});

		it('attaches a permission to a role and detaches it again', async () => {
			const auth = await loginAdmin();
			const role = await prisma.role.create({
				data: { identifier: 'AUDITOR_ROLE', name: 'Auditor' },
			});
			const permission = await prisma.permission.create({
				data: {
					resource: 'reports',
					action: 'read',
					identifier: 'reports:read',
				},
			});

			// Both of these used to answer 500: the handler invalidates the
			// sessions of everyone holding the role, and resolved
			// TokenBlacklistService through a string token nothing had registered.
			await http()
				.post(`${API}/role/${role.id}/permissions`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ permissionId: permission.id })
				.expect(200);

			await expect(
				prisma.rolePermission.findFirst({
					where: { roleId: role.id, permissionId: permission.id },
				})
			).resolves.not.toBeNull();

			await http()
				.delete(`${API}/role/${role.id}/permissions/${permission.id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			await expect(
				prisma.rolePermission.findFirst({
					where: { roleId: role.id, permissionId: permission.id },
				})
			).resolves.toBeNull();
		});

		it('denies a user without the roles permissions', async () => {
			const auth = await authenticate(
				http() as never,
				fixtures.plainUser.email,
				fixtures.password
			);

			await http()
				.get(`${API}/role`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(403);
		});
	});

	/**
	 * Same shape as the user routes: `:id` and `:permissionId` arrive with no
	 * pipe in front of them and went straight to `findUniqueOrThrow`, whose
	 * rejection is not an HttpException — so a missing row and a malformed id
	 * both came back as 500 rather than 404.
	 */
	describe('addressing something that is not there', () => {
		const missing = '3f8f1a52-0000-4000-8000-000000000000';

		it('answers 404 when assigning to a role that does not exist', async () => {
			const auth = await loginAdmin();
			const permission = await prisma.permission.create({
				data: {
					resource: 'reports',
					action: 'read',
					identifier: 'reports:read',
				},
			});

			await http()
				.post(`${API}/role/${missing}/permissions`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ permissionId: permission.id })
				.expect(404);
		});

		it('answers 404 when assigning a permission that does not exist', async () => {
			const auth = await loginAdmin();
			const role = await prisma.role.create({
				data: { identifier: 'AUDITOR_ROLE', name: 'Auditor' },
			});

			await http()
				.post(`${API}/role/${role.id}/permissions`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ permissionId: missing })
				.expect(404);
		});

		it('answers 404 when detaching a permission the role does not hold', async () => {
			const auth = await loginAdmin();
			const role = await prisma.role.create({
				data: { identifier: 'AUDITOR_ROLE', name: 'Auditor' },
			});
			const permission = await prisma.permission.create({
				data: {
					resource: 'reports',
					action: 'read',
					identifier: 'reports:read',
				},
			});

			await http()
				.delete(`${API}/role/${role.id}/permissions/${permission.id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(404);
		});

		it('answers 404 for a roleId that is not a UUID', async () => {
			const auth = await loginAdmin();
			const permission = await prisma.permission.create({
				data: {
					resource: 'reports',
					action: 'read',
					identifier: 'reports:read',
				},
			});

			await http()
				.post(`${API}/role/garbage/permissions`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ permissionId: permission.id })
				.expect(404);
		});
	});

	describe('permission administration', () => {
		it('creates a permission', async () => {
			const auth = await loginAdmin();

			const res = await http()
				.post(`${API}/permission`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({
					resource: 'invoices',
					action: 'read',
					identifier: 'invoices:read',
				})
				.expect(201);

			expect(res.body.data.identifier).toBe('invoices:read');
		});

		it('lists permissions', async () => {
			const auth = await loginAdmin();

			const res = await http()
				.get(`${API}/permission`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			expect(Array.isArray(res.body.data)).toBe(true);
		});
	});

	describe('role hierarchy', () => {
		/**
		 * Permissions are read from the JWT's `perm` claim, which is filled at
		 * login. Inheritance therefore has to be in place *before* the token is
		 * issued for it to show up — a grant made afterwards does nothing until
		 * the next login, which is behaviour the existing suites already pin.
		 */
		it('grants a child role the permissions of its parent', async () => {
			const parent = await prisma.role.create({
				data: { identifier: 'PARENT_ROLE', name: 'Parent' },
			});
			const inherited = await prisma.permission.create({
				data: {
					resource: 'reports',
					action: 'read',
					identifier: 'reports:read',
				},
			});
			await prisma.rolePermission.create({
				data: { roleId: parent.id, permissionId: inherited.id },
			});

			const child = await prisma.role.create({
				data: {
					identifier: 'CHILD_ROLE',
					name: 'Child',
					parentRoleId: parent.id,
				},
			});

			const user = await prisma.user.findUniqueOrThrow({
				where: { id: fixtures.plainUser.id },
			});
			await prisma.userRole.deleteMany({ where: { userId: user.id } });
			await prisma.userRole.create({
				data: { userId: user.id, roleId: child.id },
			});

			const auth = await authenticate(
				http() as never,
				fixtures.plainUser.email,
				fixtures.password
			);

			// The claim is the observable side of inheritance: the child role holds
			// no grant of its own, so `reports:read` can only come from the parent.
			const res = await http()
				.get(`${API}/auth/permissions/me`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			expect(res.body.data.permissions).toContain('reports:read');
		});

		it('survives a cycle in the hierarchy instead of hanging', async () => {
			const a = await prisma.role.create({
				data: { identifier: 'CYCLE_A', name: 'A' },
			});
			const b = await prisma.role.create({
				data: { identifier: 'CYCLE_B', name: 'B', parentRoleId: a.id },
			});
			// Close the loop: A → B → A.
			await prisma.role.update({
				where: { id: a.id },
				data: { parentRoleId: b.id },
			});

			await prisma.userRole.deleteMany({
				where: { userId: fixtures.plainUser.id },
			});
			await prisma.userRole.create({
				data: { userId: fixtures.plainUser.id, roleId: a.id },
			});

			const auth = await authenticate(
				http() as never,
				fixtures.plainUser.email,
				fixtures.password
			);

			await http()
				.get(`${API}/auth/permissions/me`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);
		});
	});
});
