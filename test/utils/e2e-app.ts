import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { envs } from '@app/env';
import { Logger } from '@nestjs/common';
import {
	FastifyAdapter,
	type NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { Test } from '@nestjs/testing';
import { ThrottlerStorage } from '@nestjs/throttler';
import { AppModule } from '@src/app.module';
import { configureApp } from '@src/bootstrap/configure-app';
import * as bcrypt from 'bcrypt';

/** Path prefix every request in the e2e suites has to carry. */
export const API = '/api/v1';

export interface E2EContext {
	app: NestFastifyApplication;
	prisma: PrismaService;
	/** The raw HTTP server supertest binds to. */
	server: unknown;
	close: () => Promise<void>;
}

/**
 * Boots the real application — same modules, same `configureApp` the
 * production process runs — against the database in `.env.test`.
 *
 * Swagger is skipped: building the OpenAPI document scans every route and
 * buys nothing here.
 */
export async function createE2EApp({
	throttling = false,
}: {
	throttling?: boolean;
} = {}): Promise<E2EContext> {
	const builder = Test.createTestingModule({ imports: [AppModule] });

	// AppModule registers ThrottlerGuard as a global APP_GUARD at 3 requests per
	// second. A spec that logs in a dozen times would spend most of its
	// assertions on 429s instead of on the behaviour it is about, so throttling
	// is off unless a spec explicitly asks for it.
	//
	// The storage is stubbed rather than the guard: `overrideGuard` does not
	// reach a guard registered through the APP_GUARD token, so the real guard
	// still runs — it just always sees a fresh counter.
	if (!throttling) {
		builder.overrideProvider(ThrottlerStorage).useValue({
			increment: async () => ({
				totalHits: 1,
				timeToExpire: 60,
				isBlocked: false,
				timeToBlockExpire: 0,
			}),
		});
	}

	const moduleRef = await builder.compile();

	const app = moduleRef.createNestApplication<NestFastifyApplication>(
		new FastifyAdapter({
			logger: false,
			routerOptions: {
				ignoreTrailingSlash: true,
				ignoreDuplicateSlashes: true,
			},
		})
	);

	// The application's own logger would otherwise write through Pino to both
	// the console and ./logs for every request the suite makes.
	app.useLogger(false);

	await configureApp(app, { withSwagger: false });
	await app.init();
	// Fastify needs an explicit ready() before its routes can be injected into.
	await app.getHttpAdapter().getInstance().ready();

	const prisma = app.get(PrismaService);

	return {
		app,
		prisma,
		server: app.getHttpServer(),
		close: async () => {
			await app.close();
		},
	};
}

/**
 * Order matters: children before parents, so foreign keys never block the
 * delete. `deleteMany` rather than TRUNCATE keeps this driver-agnostic.
 */
export async function resetDatabase(prisma: PrismaService): Promise<void> {
	await prisma.twoFactorAttempt.deleteMany();
	await prisma.rolePermission.deleteMany();
	await prisma.userRole.deleteMany();
	await prisma.policy.deleteMany();
	await prisma.resourceOwnership.deleteMany();
	await prisma.session.deleteMany();
	await prisma.loginAttempt.deleteMany();
	await prisma.auditChangeLog.deleteMany();
	await prisma.auditLog.deleteMany();
	await prisma.csrfToken.deleteMany();
	await prisma.tokenBlacklist.deleteMany();
	await prisma.settings.deleteMany();
	await prisma.apiKey.deleteMany();
	// Roles reference themselves through parentRoleId, so detach first.
	await prisma.role.updateMany({ data: { parentRoleId: null } });
	await prisma.user.deleteMany();
	await prisma.role.deleteMany();
	await prisma.permission.deleteMany();
}

export interface SeededFixtures {
	adminUser: { id: string; email: string; username: string };
	plainUser: { id: string; email: string; username: string };
	adminRoleId: string;
	userRoleId: string;
	/** Plaintext password shared by both seeded users. */
	password: string;
}

/**
 * Minimal fixture set for the e2e suites.
 *
 * Deliberately independent of `prisma/seed.ts`: that script is driven by
 * environment variables and is meant for bootstrapping a real deployment, so
 * coupling the tests to it would make them fail for reasons that have nothing
 * to do with the code under test.
 */
export async function seedFixtures(
	prisma: PrismaService
): Promise<SeededFixtures> {
	const password = 'E2ePassw0rd!Strong';
	// Cost 4 is the bcrypt minimum: these hashes are re-created for every spec
	// file and the work factor is not what is being tested.
	const passwordHash = await bcrypt.hash(password, 4);

	const permissions = await Promise.all(
		[
			{ resource: 'users', action: 'read', identifier: 'users:read' },
			{ resource: 'users', action: 'write', identifier: 'users:write' },
			{ resource: 'sessions', action: 'read', identifier: 'sessions:read' },
		].map(p => prisma.permission.create({ data: p }))
	);
	const sessionsRead = permissions.find(
		p => p.identifier === 'sessions:read'
	) as (typeof permissions)[number];

	const userRole = await prisma.role.create({
		data: { identifier: 'USER_ROLE', name: 'User', default: true },
	});
	const adminRole = await prisma.role.create({
		data: { identifier: 'ADMIN_ROLE', name: 'Admin' },
	});

	// Admin gets everything; the plain user only gets sessions:read, which is
	// what makes the RBAC assertions meaningful.
	await prisma.rolePermission.createMany({
		data: permissions.map(p => ({
			roleId: adminRole.id,
			permissionId: p.id,
		})),
	});
	await prisma.rolePermission.create({
		data: { roleId: userRole.id, permissionId: sessionsRead.id },
	});

	const adminUser = await prisma.user.create({
		data: {
			email: 'admin@e2e.local',
			username: 'e2e_admin',
			fullName: 'E2E Admin',
			password: passwordHash,
			confirmed: true,
			blocked: false,
		},
	});
	const plainUser = await prisma.user.create({
		data: {
			email: 'user@e2e.local',
			username: 'e2e_user',
			fullName: 'E2E User',
			password: passwordHash,
			confirmed: true,
			blocked: false,
		},
	});

	await prisma.userRole.createMany({
		data: [
			{ userId: adminUser.id, roleId: adminRole.id },
			{ userId: plainUser.id, roleId: userRole.id },
		],
	});

	// The API key middleware bcrypt-compares the header against every stored
	// hash, so the key from .env.test has to exist as a row.
	await prisma.apiKey.create({
		data: {
			application: 'Web App',
			keyHash: await bcrypt.hash(envs.WEB_APP_API_KEY, 4),
			default: true,
		},
	});

	return {
		adminUser,
		plainUser,
		adminRoleId: adminRole.id,
		userRoleId: userRole.id,
		password,
	};
}

/** Header name and value the API key middleware expects. */
export const apiKeyHeader = (): Record<string, string> => ({
	'x-api-key': envs.WEB_APP_API_KEY,
});

// Keeps the Nest logger quiet even for modules that build one at import time.
Logger.overrideLogger(false);
