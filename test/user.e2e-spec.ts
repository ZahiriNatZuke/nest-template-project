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
 * User administration through the real HTTP stack.
 *
 * `user` was the last module with no e2e coverage at all: eight endpoints —
 * CRUD, soft delete, restore and role assignment — none of them exercised
 * end to end. The RBAC suite proves a permission is enforced; nothing proved
 * the handlers behind it worked.
 */
describe('User administration (e2e)', () => {
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

	const loginPlain = (): Promise<AuthContext> =>
		authenticate(http() as never, fixtures.plainUser.email, fixtures.password);

	/** A user row created straight through Prisma, bypassing the API. */
	async function seedUser(overrides: {
		email: string;
		username: string;
		fullName: string;
	}): Promise<{ id: string }> {
		return prisma.user.create({
			data: {
				...overrides,
				password: 'not-a-real-hash',
				confirmed: true,
				blocked: false,
			},
			select: { id: true },
		});
	}

	describe('creation', () => {
		it('creates a user and attaches the default role', async () => {
			const auth = await loginAdmin();

			const res = await http()
				.post(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({
					username: 'created_one',
					email: 'created.one@e2e.local',
					fullName: 'Created One',
					password: 'Str0ngPassw0rd!',
				})
				.expect(201);

			expect(res.body.data.username).toBe('created_one');
			// createUser() looks up USER_ROLE and wires the join row itself.
			const roles = await prisma.userRole.findMany({
				where: { userId: res.body.data.id },
			});
			expect(roles).toHaveLength(1);
			expect(roles[0].roleId).toBe(fixtures.userRoleId);
		});

		it('starts a created user unconfirmed', async () => {
			const auth = await loginAdmin();

			const res = await http()
				.post(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({
					username: 'unconfirmed_one',
					email: 'unconfirmed.one@e2e.local',
					fullName: 'Unconfirmed One',
					password: 'Str0ngPassw0rd!',
				})
				.expect(201);

			expect(res.body.data.confirmed).toBe(false);
		});

		it('rejects a password under the minimum length', async () => {
			const auth = await loginAdmin();

			await http()
				.post(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({
					username: 'weak_one',
					email: 'weak.one@e2e.local',
					fullName: 'Weak One',
					password: 'short',
				})
				.expect(400);
		});

		it('rejects a malformed email', async () => {
			const auth = await loginAdmin();

			await http()
				.post(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({
					username: 'bad_email',
					email: 'not-an-email',
					fullName: 'Bad Email',
					password: 'Str0ngPassw0rd!',
				})
				.expect(400);
		});
	});

	describe('reading', () => {
		it('returns a single user', async () => {
			const auth = await loginAdmin();

			const res = await http()
				.get(`${API}/user/${fixtures.plainUser.id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			expect(res.body.data.email).toBe(fixtures.plainUser.email);
		});

		it('answers 404 for a well-formed id that matches nothing', async () => {
			const auth = await loginAdmin();

			await http()
				.get(`${API}/user/3f8f1a52-0000-4000-8000-000000000000`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(404);
		});

		/**
		 * FindUserByIdPipe reports a malformed UUID as 404 rather than 400. That
		 * is a deliberate choice of the pipe — it refuses to distinguish "not a
		 * user id" from "no such user" — and it is pinned here so a change to it
		 * is a decision rather than an accident.
		 */
		it('answers 404 for an id that is not a UUID', async () => {
			const auth = await loginAdmin();

			await http()
				.get(`${API}/user/not-a-uuid`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(404);
		});
	});

	describe('listing', () => {
		it('lists the seeded users', async () => {
			const auth = await loginAdmin();

			const res = await http()
				.get(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			const emails = (res.body.data as Array<{ email: string }>).map(
				u => u.email
			);
			expect(emails).toEqual(
				expect.arrayContaining([
					fixtures.adminUser.email,
					fixtures.plainUser.email,
				])
			);
		});

		it('splits the result across pages and reports the full total', async () => {
			const auth = await loginAdmin();
			// Two seeded users plus three more: five rows, pages of two.
			for (const n of [1, 2, 3]) {
				await seedUser({
					email: `paged${n}@e2e.local`,
					username: `paged_${n}`,
					fullName: `Paged ${n}`,
				});
			}

			const first = await http()
				.get(`${API}/user?take=2&page=1`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			expect(first.body.data).toHaveLength(2);
			expect(first.body.meta.total).toBe(5);

			const third = await http()
				.get(`${API}/user?take=2&page=3`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			expect(third.body.data).toHaveLength(1);

			// No row appears on two pages.
			const ids = [...first.body.data, ...third.body.data].map(
				(u: { id: string }) => u.id
			);
			expect(new Set(ids).size).toBe(ids.length);
		});

		it('narrows the result by querySearch', async () => {
			const auth = await loginAdmin();
			await seedUser({
				email: 'needle@e2e.local',
				username: 'needle_user',
				fullName: 'needle person',
			});

			const res = await http()
				.get(`${API}/user?querySearch=needle`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			expect(res.body.data).toHaveLength(1);
			expect(res.body.data[0].username).toBe('needle_user');
		});

		it('matches on the email as well as the username', async () => {
			const auth = await loginAdmin();
			await seedUser({
				email: 'findable@e2e.local',
				username: 'unrelated_handle',
				fullName: 'unrelated name',
			});

			const res = await http()
				.get(`${API}/user?querySearch=findable`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			expect(res.body.data).toHaveLength(1);
			expect(res.body.data[0].username).toBe('unrelated_handle');
		});

		/**
		 * TrimQuerySearchPipe lowercases whatever it is handed, and Postgres
		 * `contains` is case-sensitive — so before the `mode: 'insensitive'`
		 * that now sits on these three filters, a search only ever matched rows
		 * that happened to be stored in lower case. The seeded admin is called
		 * "E2E Admin" and searching for it returned an empty list.
		 */
		it('finds a user whose stored name is not lower case', async () => {
			const auth = await loginAdmin();

			const res = await http()
				.get(`${API}/user?querySearch=E2E Admin`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			expect(res.body.data).toHaveLength(1);
			expect(res.body.data[0].email).toBe(fixtures.adminUser.email);
		});

		it('ignores the case of the search term itself', async () => {
			const auth = await loginAdmin();
			await seedUser({
				email: 'Casing@e2e.local',
				username: 'CasedHandle',
				fullName: 'Cased Person',
			});

			for (const term of ['CasedHandle', 'casedhandle', 'CASEDHANDLE']) {
				const res = await http()
					.get(`${API}/user?querySearch=${term}`)
					.set(auth.headers)
					.set('Cookie', auth.cookie)
					.expect(200);

				expect(res.body.data).toHaveLength(1);
				expect(res.body.data[0].username).toBe('CasedHandle');
			}
		});

		it('returns nothing when the search matches nothing', async () => {
			const auth = await loginAdmin();

			const res = await http()
				.get(`${API}/user?querySearch=zzz-no-such-user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			expect(res.body.data).toHaveLength(0);
			expect(res.body.meta.total).toBe(0);
		});
	});

	describe('updating', () => {
		it('updates the editable fields', async () => {
			const auth = await loginAdmin();

			const res = await http()
				.patch(`${API}/user/${fixtures.plainUser.id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ fullName: 'Renamed Person', bio: 'a short bio' })
				.expect(200);

			expect(res.body.data.fullName).toBe('Renamed Person');
			expect(res.body.data.bio).toBe('a short bio');
		});

		it('blocks a user', async () => {
			const auth = await loginAdmin();

			await http()
				.patch(`${API}/user/${fixtures.plainUser.id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ blocked: true })
				.expect(200);

			const row = await prisma.user.findUniqueOrThrow({
				where: { id: fixtures.plainUser.id },
			});
			expect(row.blocked).toBe(true);
		});

		it('rejects a malformed field instead of writing it', async () => {
			const auth = await loginAdmin();

			await http()
				.patch(`${API}/user/${fixtures.plainUser.id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ email: 'not-an-email' })
				.expect(400);

			const row = await prisma.user.findUniqueOrThrow({
				where: { id: fixtures.plainUser.id },
			});
			expect(row.email).toBe(fixtures.plainUser.email);
		});
	});

	describe('soft delete and restore', () => {
		it('hides a deleted user from the listing and from lookup', async () => {
			const auth = await loginAdmin();
			const doomed = await seedUser({
				email: 'doomed@e2e.local',
				username: 'doomed_user',
				fullName: 'Doomed User',
			});

			await http()
				.delete(`${API}/user/${doomed.id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			// The row survives — this is a soft delete, not a purge.
			const row = await prisma.user.findUniqueOrThrow({
				where: { id: doomed.id },
			});
			expect(row.deletedAt).not.toBeNull();

			const list = await http()
				.get(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);
			expect(
				(list.body.data as Array<{ id: string }>).map(u => u.id)
			).not.toContain(doomed.id);

			await http()
				.get(`${API}/user/${doomed.id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(404);
		});

		it('brings a deleted user back', async () => {
			const auth = await loginAdmin();
			const doomed = await seedUser({
				email: 'returning@e2e.local',
				username: 'returning_user',
				fullName: 'Returning User',
			});

			await http()
				.delete(`${API}/user/${doomed.id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			await http()
				.patch(`${API}/user/${doomed.id}/restore`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			await http()
				.get(`${API}/user/${doomed.id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			const list = await http()
				.get(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);
			expect(
				(list.body.data as Array<{ id: string }>).map(u => u.id)
			).toContain(doomed.id);
		});

		it('keeps a deleted user out of the search results', async () => {
			const auth = await loginAdmin();
			const doomed = await seedUser({
				email: 'searchable@e2e.local',
				username: 'searchable_user',
				fullName: 'searchable user',
			});

			await http()
				.delete(`${API}/user/${doomed.id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			const res = await http()
				.get(`${API}/user?querySearch=searchable`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			expect(res.body.data).toHaveLength(0);
		});
	});

	describe('role assignment', () => {
		/**
		 * These two used to be the same 500 that broke the role endpoints: the
		 * handler invalidates the target's sessions and reaches
		 * TokenBlacklistService through `moduleRef.get('TokenBlacklistService')`,
		 * a string token nothing had registered. `moduleRef.get` throws rather
		 * than returning undefined, so the `if (tokenBlacklist)` guard below it
		 * never ran. The alias in auth.module.ts fixed the role path and was
		 * assumed to fix this one; these specs are what actually check it.
		 *
		 * Verified by removing the alias again: these four and the
		 * response-shape spec below drop to 500, the rest of the file stays
		 * green. They fail for the reason they claim to.
		 */
		it('assigns a role to a user', async () => {
			const auth = await loginAdmin();

			const res = await http()
				.post(`${API}/user/${fixtures.plainUser.id}/roles`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ roleId: fixtures.adminRoleId })
				.expect(200);

			expect(res.body.message).toBe('Role assigned to user');
			await expect(
				prisma.userRole.findFirst({
					where: {
						userId: fixtures.plainUser.id,
						roleId: fixtures.adminRoleId,
					},
				})
			).resolves.not.toBeNull();
		});

		it('is idempotent — assigning the same role twice is not an error', async () => {
			const auth = await loginAdmin();

			for (const _ of [1, 2]) {
				await http()
					.post(`${API}/user/${fixtures.plainUser.id}/roles`)
					.set(auth.headers)
					.set('Cookie', auth.cookie)
					.send({ roleId: fixtures.adminRoleId })
					.expect(200);
			}

			const rows = await prisma.userRole.findMany({
				where: {
					userId: fixtures.plainUser.id,
					roleId: fixtures.adminRoleId,
				},
			});
			expect(rows).toHaveLength(1);
		});

		it('removes a role from a user', async () => {
			const auth = await loginAdmin();

			await http()
				.delete(
					`${API}/user/${fixtures.plainUser.id}/roles/${fixtures.userRoleId}`
				)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);

			await expect(
				prisma.userRole.findFirst({
					where: { userId: fixtures.plainUser.id, roleId: fixtures.userRoleId },
				})
			).resolves.toBeNull();
		});

		it('rejects a roleId that is not a UUID', async () => {
			const auth = await loginAdmin();

			await http()
				.post(`${API}/user/${fixtures.plainUser.id}/roles`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ roleId: 'not-a-uuid' })
				.expect(400);
		});

		/**
		 * The claim the guards read is `perm`, filled at login. A role granted
		 * afterwards therefore changes nothing until the next login — behaviour
		 * the RBAC suite already pins, re-checked here from the assignment side.
		 */
		it('grants the new role permissions on the next login', async () => {
			const admin = await loginAdmin();

			const before = await loginPlain();
			await http()
				.get(`${API}/user`)
				.set(before.headers)
				.set('Cookie', before.cookie)
				.expect(403);

			await http()
				.post(`${API}/user/${fixtures.plainUser.id}/roles`)
				.set(admin.headers)
				.set('Cookie', admin.cookie)
				.send({ roleId: fixtures.adminRoleId })
				.expect(200);

			const after = await loginPlain();
			await http()
				.get(`${API}/user`)
				.set(after.headers)
				.set('Cookie', after.cookie)
				.expect(200);
		});
	});

	/**
	 * Four handlers take the id straight off the URL with no pipe in front of
	 * them — `delete`, `restore` and the two role routes — and used to hand it
	 * to Prisma unchecked. A missing row made `findUniqueOrThrow` throw, a
	 * malformed id made Postgres reject the uuid cast, and neither is an
	 * HttpException, so the global filter rendered both as 500.
	 *
	 * `GET /user/:id` has answered 404 for exactly these inputs all along,
	 * through FindUserByIdPipe. The routes without a pipe are the odd ones out.
	 */
	describe('addressing something that is not there', () => {
		const missing = '3f8f1a52-0000-4000-8000-000000000000';

		it('answers 404 when deleting a user that does not exist', async () => {
			const auth = await loginAdmin();

			await http()
				.delete(`${API}/user/${missing}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(404);
		});

		it('answers 404 when deleting an id that is not a UUID', async () => {
			const auth = await loginAdmin();

			await http()
				.delete(`${API}/user/garbage`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(404);
		});

		it('answers 404 when restoring a user that does not exist', async () => {
			const auth = await loginAdmin();

			await http()
				.patch(`${API}/user/${missing}/restore`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(404);
		});

		it('answers 404 when assigning a role to a user that does not exist', async () => {
			const auth = await loginAdmin();

			await http()
				.post(`${API}/user/${missing}/roles`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ roleId: fixtures.adminRoleId })
				.expect(404);
		});

		it('answers 404 when assigning a role that does not exist', async () => {
			const auth = await loginAdmin();

			await http()
				.post(`${API}/user/${fixtures.plainUser.id}/roles`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ roleId: missing })
				.expect(404);
		});

		it('answers 404 when removing a role the user does not hold', async () => {
			const auth = await loginAdmin();

			await http()
				.delete(
					`${API}/user/${fixtures.plainUser.id}/roles/${fixtures.adminRoleId}`
				)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(404);
		});

		it('answers 404 when removing a roleId that is not a UUID', async () => {
			const auth = await loginAdmin();

			await http()
				.delete(`${API}/user/${fixtures.plainUser.id}/roles/garbage`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(404);
		});

		it('leaves the user untouched when the role lookup fails', async () => {
			const auth = await loginAdmin();

			await http()
				.post(`${API}/user/${fixtures.plainUser.id}/roles`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ roleId: missing })
				.expect(404);

			// Only the role seeded for this user, nothing half-written.
			const rows = await prisma.userRole.findMany({
				where: { userId: fixtures.plainUser.id },
			});
			expect(rows).toHaveLength(1);
			expect(rows[0].roleId).toBe(fixtures.userRoleId);
		});
	});

	describe('authorization', () => {
		it('denies a user without users:read', async () => {
			const auth = await loginPlain();

			await http()
				.get(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(403);
		});

		it('denies a user without users:write', async () => {
			const auth = await loginPlain();

			await http()
				.patch(`${API}/user/${fixtures.plainUser.id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ fullName: 'Should Not Happen' })
				.expect(403);
		});

		it('rejects a request with no credentials at all', async () => {
			await http().get(`${API}/user`).expect(401);
		});
	});

	/**
	 * UserMapper.omitDefault is the only thing standing between the password
	 * hash and every response this controller sends. A handler that forgets to
	 * call it leaks the hash of every listed user in one request, so every
	 * response shape is checked rather than a representative one.
	 */
	describe('the password hash never leaves the server', () => {
		const secrets = [
			'password',
			'confirmationToken',
			'confirmationTokenExpiresAt',
			'resetPasswordToken',
			'resetPasswordExpiresAt',
		];

		const expectNoSecrets = (payload: unknown) => {
			const users = Array.isArray(payload) ? payload : [payload];
			for (const user of users) {
				for (const key of secrets) {
					expect(user).not.toHaveProperty(key);
				}
			}
		};

		it('is absent from every response the controller sends', async () => {
			const auth = await loginAdmin();

			const created = await http()
				.post(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({
					username: 'secret_check',
					email: 'secret.check@e2e.local',
					fullName: 'Secret Check',
					password: 'Str0ngPassw0rd!',
				})
				.expect(201);
			expectNoSecrets(created.body.data);
			const id = created.body.data.id as string;

			const list = await http()
				.get(`${API}/user`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);
			expectNoSecrets(list.body.data);

			const one = await http()
				.get(`${API}/user/${id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);
			expectNoSecrets(one.body.data);

			const updated = await http()
				.patch(`${API}/user/${id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ fullName: 'Secret Check II' })
				.expect(200);
			expectNoSecrets(updated.body.data);

			const assigned = await http()
				.post(`${API}/user/${id}/roles`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.send({ roleId: fixtures.adminRoleId })
				.expect(200);
			expectNoSecrets(assigned.body.data);

			const unassigned = await http()
				.delete(`${API}/user/${id}/roles/${fixtures.adminRoleId}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);
			expectNoSecrets(unassigned.body.data);

			const deleted = await http()
				.delete(`${API}/user/${id}`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);
			expectNoSecrets(deleted.body.data);

			const restored = await http()
				.patch(`${API}/user/${id}/restore`)
				.set(auth.headers)
				.set('Cookie', auth.cookie)
				.expect(200);
			expectNoSecrets(restored.body.data);
		});
	});
});
