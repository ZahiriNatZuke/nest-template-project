import type { PrismaService } from '@app/core/services/prisma/prisma.service';
import {
	API,
	apiKeyHeader,
	createE2EApp,
	type E2EContext,
	resetDatabase,
	type SeededFixtures,
	seedFixtures,
} from '@test/utils/e2e-app';
import request from 'supertest';

describe('Authentication (e2e)', () => {
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

	/**
	 * Pulls a single `name=value` pair out of a response's Set-Cookie headers,
	 * ready to be sent straight back as a Cookie header. Throws rather than
	 * returning undefined so a missing cookie fails the test where it happened
	 * instead of further down as a confusing type error.
	 */
	const cookieFrom = (
		res: { headers: Record<string, unknown> },
		name: string
	): string => {
		const cookies = (res.headers['set-cookie'] ?? []) as string[];
		const match = cookies.find(c => c.startsWith(`${name}=`));
		if (!match) {
			throw new Error(`No ${name} cookie in response: ${cookies.join(' | ')}`);
		}
		return match.split(';')[0];
	};

	/** Fetches a CSRF token the way a browser client would. */
	const getCsrfToken = async (): Promise<string> => {
		const res = await http().get(`${API}/auth/csrf`).expect(200);
		return res.body.csrfToken;
	};

	const login = async (identifier: string, password: string) => {
		const csrfToken = await getCsrfToken();
		return http()
			.post(`${API}/auth/login`)
			.set(apiKeyHeader())
			.set('x-csrf-token', csrfToken)
			.send({ identifier, password, device: 'jest-e2e' });
	};

	describe('the application boots', () => {
		it('exposes the health endpoint under the global prefix', async () => {
			const res = await http().get(`${API}/health`);

			// The overall status is not asserted: the health check fails RSS above
			// 300MB, and a Jest worker running Nest plus Prisma is routinely over
			// that. What matters here is that the route is mounted and the database
			// indicator is reachable.
			expect([200, 503]).toContain(res.status);
			expect(res.body.details.database).toMatchObject({ status: 'up' });
		});

		it('serves nothing at the unprefixed path', async () => {
			await http().get('/health').expect(404);
		});
	});

	describe('API key enforcement', () => {
		it('rejects a protected route with no X-API-KEY header', async () => {
			await http().get(`${API}/user`).expect(401);
		});

		it('rejects an unknown API key', async () => {
			await http()
				.get(`${API}/user`)
				.set('x-api-key', 'not-a-real-key')
				.expect(401);
		});

		it('lets public routes through without an API key', async () => {
			// Listed in PUBLIC_ROUTES, so the middleware skips it entirely.
			await http().get(`${API}/auth/csrf`).expect(200);
		});
	});

	describe('GET /auth/csrf', () => {
		it('returns a token and persists it', async () => {
			const res = await http().get(`${API}/auth/csrf`).expect(200);

			expect(typeof res.body.csrfToken).toBe('string');
			expect(res.body.csrfToken).toHaveLength(64);

			await expect(
				prisma.csrfToken.findUnique({ where: { token: res.body.csrfToken } })
			).resolves.not.toBeNull();
		});

		it('sets the token in a readable XSRF-TOKEN cookie', async () => {
			const res = await http().get(`${API}/auth/csrf`).expect(200);
			const cookies = res.headers['set-cookie'] as unknown as string[];

			expect(cookies.join(';')).toContain(`XSRF-TOKEN=${res.body.csrfToken}`);
		});

		it('issues a different token on every call', async () => {
			const [first, second] = await Promise.all([
				getCsrfToken(),
				getCsrfToken(),
			]);

			expect(first).not.toBe(second);
		});
	});

	describe('CSRF enforcement on mutations', () => {
		it('rejects a login with no CSRF token', async () => {
			await http()
				.post(`${API}/auth/login`)
				.set(apiKeyHeader())
				.send({
					identifier: fixtures.adminUser.email,
					password: fixtures.password,
					device: 'jest-e2e',
				})
				.expect(403);
		});

		// The guard has to actually validate the token against storage, not
		// merely check that the header is present.
		it('rejects a login with a well-formed but unissued CSRF token', async () => {
			await http()
				.post(`${API}/auth/login`)
				.set(apiKeyHeader())
				.set('x-csrf-token', 'f'.repeat(64))
				.send({
					identifier: fixtures.adminUser.email,
					password: fixtures.password,
					device: 'jest-e2e',
				})
				.expect(403);
		});

		it('rejects a login with an expired CSRF token', async () => {
			const csrfToken = await getCsrfToken();
			await prisma.csrfToken.update({
				where: { token: csrfToken },
				data: { expiresAt: new Date(Date.now() - 1000) },
			});

			await http()
				.post(`${API}/auth/login`)
				.set(apiKeyHeader())
				.set('x-csrf-token', csrfToken)
				.send({
					identifier: fixtures.adminUser.email,
					password: fixtures.password,
					device: 'jest-e2e',
				})
				.expect(403);
		});
	});

	describe('POST /auth/login', () => {
		it('authenticates with an email identifier', async () => {
			const res = await login(fixtures.adminUser.email, fixtures.password);

			expect(res.status).toBe(200);
			expect(res.body).toMatchObject({
				statusCode: 200,
				message: 'Login Success',
				requiresTwoFactor: false,
			});
		});

		it('authenticates with a username identifier', async () => {
			const res = await login(fixtures.adminUser.username, fixtures.password);

			expect(res.status).toBe(200);
		});

		it('sets HttpOnly access and refresh cookies', async () => {
			const res = await login(fixtures.adminUser.email, fixtures.password);
			const cookies = (res.headers['set-cookie'] as unknown as string[]).join(
				';'
			);

			expect(cookies).toContain('accessToken=');
			expect(cookies).toContain('refreshToken=');
			expect(cookies).toContain('HttpOnly');
			// The refresh cookie is scoped to the refresh endpoint so it is never
			// sent on ordinary requests.
			expect(cookies).toContain('Path=/api/v1/auth/refresh');
		});

		it('creates a session row bound to the device', async () => {
			await login(fixtures.adminUser.email, fixtures.password);

			const session = await prisma.session.findFirst({
				where: { userId: fixtures.adminUser.id },
			});
			expect(session).toMatchObject({ device: 'jest-e2e' });
		});

		it('rejects a wrong password', async () => {
			const res = await login(fixtures.adminUser.email, 'WrongPassw0rd!');

			expect(res.status).toBe(401);
		});

		it('rejects an unknown identifier', async () => {
			const res = await login('nobody@e2e.local', fixtures.password);

			expect(res.status).toBe(401);
		});

		it('records a failed attempt', async () => {
			await login(fixtures.adminUser.email, 'WrongPassw0rd!');

			const attempts = await prisma.loginAttempt.findMany({
				where: { identifier: fixtures.adminUser.email, success: false },
			});
			expect(attempts.length).toBeGreaterThan(0);
		});

		it('rejects a blocked user', async () => {
			await prisma.user.update({
				where: { id: fixtures.adminUser.id },
				data: { blocked: true },
			});

			const res = await login(fixtures.adminUser.email, fixtures.password);

			expect(res.status).toBe(401);
		});

		it('rejects an unconfirmed user', async () => {
			await prisma.user.update({
				where: { id: fixtures.adminUser.id },
				data: { confirmed: false },
			});

			const res = await login(fixtures.adminUser.email, fixtures.password);

			expect(res.status).toBe(401);
		});

		it('rejects a soft-deleted user', async () => {
			await prisma.user.update({
				where: { id: fixtures.adminUser.id },
				data: { deletedAt: new Date() },
			});

			const res = await login(fixtures.adminUser.email, fixtures.password);

			expect(res.status).toBe(401);
		});

		describe('payload validation', () => {
			it('rejects a missing device', async () => {
				const csrfToken = await getCsrfToken();

				const res = await http()
					.post(`${API}/auth/login`)
					.set(apiKeyHeader())
					.set('x-csrf-token', csrfToken)
					.send({
						identifier: fixtures.adminUser.email,
						password: fixtures.password,
					});

				expect(res.status).toBe(400);
			});

			// Guards run before pipes in Nest, so LocalAuthGuard rejects the
			// credentials as unauthorized before the Zod pipe ever sees that the
			// password is too short. 401, not 400 — and worth pinning, because it
			// means the schema's `min(8)` is never the message a caller gets.
			it('answers 401 for a too-short password, not a validation error', async () => {
				const csrfToken = await getCsrfToken();

				const res = await http()
					.post(`${API}/auth/login`)
					.set(apiKeyHeader())
					.set('x-csrf-token', csrfToken)
					.send({
						identifier: fixtures.adminUser.email,
						password: 'short',
						device: 'jest-e2e',
					});

				expect(res.status).toBe(401);
			});
		});
	});

	describe('POST /auth/refresh', () => {
		it('rejects a request with no refresh cookie', async () => {
			const csrfToken = await getCsrfToken();

			await http()
				.post(`${API}/auth/refresh`)
				.set('x-csrf-token', csrfToken)
				.expect(401);
		});

		it('issues a new session for a valid refresh token', async () => {
			const loginRes = await login(fixtures.adminUser.email, fixtures.password);
			const refreshCookie = cookieFrom(loginRes, 'refreshToken');
			const csrfToken = await getCsrfToken();

			const res = await http()
				.post(`${API}/auth/refresh`)
				.set('x-csrf-token', csrfToken)
				.set('Cookie', refreshCookie);

			expect(res.status).toBe(200);
			expect(res.body).toMatchObject({ success: true });
		});

		it('rejects a refresh token that was never issued', async () => {
			const csrfToken = await getCsrfToken();

			await http()
				.post(`${API}/auth/refresh`)
				.set('x-csrf-token', csrfToken)
				.set('Cookie', 'refreshToken=not-a-real-token')
				.expect(401);
		});
	});

	describe('POST /auth/logout', () => {
		it('closes the session and clears the cookies', async () => {
			const loginRes = await login(fixtures.adminUser.email, fixtures.password);
			const accessCookie = cookieFrom(loginRes, 'accessToken');
			const csrfToken = await getCsrfToken();

			const res = await http()
				.post(`${API}/auth/logout`)
				.set(apiKeyHeader())
				.set('x-csrf-token', csrfToken)
				.set('Cookie', accessCookie);

			expect(res.status).toBe(200);
			await expect(
				prisma.session.count({ where: { userId: fixtures.adminUser.id } })
			).resolves.toBe(0);
		});

		it('rejects a logout with no authentication', async () => {
			const csrfToken = await getCsrfToken();

			await http()
				.post(`${API}/auth/logout`)
				.set(apiKeyHeader())
				.set('x-csrf-token', csrfToken)
				.expect(401);
		});
	});
});
