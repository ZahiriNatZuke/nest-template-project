import type { PrismaService } from '@app/core/services/prisma/prisma.service';

/**
 * Every delegate method the application actually calls on a Prisma model.
 * Kept explicit rather than proxy-generated so that a typo in a spec fails
 * loudly instead of silently resolving to a fresh mock.
 */
const DELEGATE_METHODS = [
	'findUnique',
	'findUniqueOrThrow',
	'findFirst',
	'findFirstOrThrow',
	'findMany',
	'create',
	'createMany',
	'update',
	'updateMany',
	'upsert',
	'delete',
	'deleteMany',
	'count',
	'aggregate',
	'groupBy',
] as const;

type DelegateMethod = (typeof DELEGATE_METHODS)[number];

export type MockDelegate = Record<DelegateMethod, jest.Mock>;

/** Models declared in prisma/schema.prisma, as their Prisma client keys. */
const MODELS = [
	'user',
	'role',
	'permission',
	'userRole',
	'rolePermission',
	'policy',
	'resourceOwnership',
	'session',
	'apiKey',
	'settings',
	'tokenBlacklist',
	'auditLog',
	'csrfToken',
	'loginAttempt',
	'auditChangeLog',
	'twoFactorAttempt',
] as const;

type ModelName = (typeof MODELS)[number];

export type PrismaMock = Record<ModelName, MockDelegate> & {
	$transaction: jest.Mock;
	$connect: jest.Mock;
	$disconnect: jest.Mock;
	$queryRaw: jest.Mock;
	$executeRaw: jest.Mock;
};

function createDelegate(): MockDelegate {
	return Object.fromEntries(
		DELEGATE_METHODS.map(method => [method, jest.fn()])
	) as MockDelegate;
}

/**
 * Builds a fully mocked PrismaService for unit tests.
 *
 * `$transaction` mirrors the two shapes the real client supports:
 * - an array of promises -> resolves them all
 * - a callback -> invokes it with the mock itself, so nested calls are
 *   recorded on the same delegates the spec asserts against
 *
 * Usage:
 *   const prisma = createPrismaMock();
 *   prisma.user.findUnique.mockResolvedValue(buildUser());
 *   const module = await Test.createTestingModule({
 *     providers: [MyService, { provide: PrismaService, useValue: prisma }],
 *   }).compile();
 */
export function createPrismaMock(): PrismaMock {
	const mock = Object.fromEntries(
		MODELS.map(model => [model, createDelegate()])
	) as unknown as PrismaMock;

	mock.$transaction = jest.fn(async (arg: unknown) => {
		if (typeof arg === 'function') {
			return (arg as (tx: PrismaMock) => unknown)(mock);
		}
		return Promise.all(arg as Promise<unknown>[]);
	});
	mock.$connect = jest.fn().mockResolvedValue(undefined);
	mock.$disconnect = jest.fn().mockResolvedValue(undefined);
	mock.$queryRaw = jest.fn();
	mock.$executeRaw = jest.fn();

	return mock;
}

/**
 * Same mock, typed as the real PrismaService, for the `useValue` slot of a
 * testing module where Nest expects the concrete provider type.
 */
export function asPrismaService(mock: PrismaMock): PrismaService {
	return mock as unknown as PrismaService;
}
