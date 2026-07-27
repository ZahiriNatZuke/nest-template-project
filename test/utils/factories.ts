/**
 * Fixture builders for the Prisma models used across the test suites.
 *
 * Each builder returns a complete, valid row and accepts a partial override,
 * so a spec only has to state the fields it actually cares about:
 *
 *   buildUser({ blocked: true })
 *
 * IDs are deterministic per call via an incrementing counter rather than
 * random UUIDs, which keeps failure output stable and diffable.
 */

let counter = 0;

/** Resets the id counter. Call from `beforeEach` when a spec asserts on ids. */
export function resetFactories(): void {
	counter = 0;
}

function nextId(prefix: string): string {
	counter += 1;
	return `${prefix}-${String(counter).padStart(4, '0')}`;
}

const FIXED_DATE = new Date('2026-01-01T00:00:00.000Z');

export interface UserFixture {
	id: string;
	username: string;
	email: string;
	fullName: string;
	password: string;
	resetPasswordToken: string | null;
	resetPasswordExpiresAt: Date | null;
	confirmationToken: string | null;
	confirmationTokenExpiresAt: Date | null;
	confirmed: boolean;
	confirmedAt: Date | null;
	blocked: boolean;
	deletedAt: Date | null;
	avatarUrl: string | null;
	phone: string | null;
	address: string | null;
	bio: string | null;
	twoFactorEnabled: boolean;
	twoFactorRequired: boolean;
	twoFactorSecret: string | null;
	twoFactorBackupCodes: unknown;
	createdAt: Date;
	updatedAt: Date;
}

export function buildUser(overrides: Partial<UserFixture> = {}): UserFixture {
	const id = overrides.id ?? nextId('user');
	return {
		id,
		username: `user_${id}`,
		email: `${id}@test.local`,
		fullName: 'Test User',
		// bcrypt hash of "TestPassw0rd!" — never a plaintext password.
		password: '$2b$10$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQR',
		resetPasswordToken: null,
		resetPasswordExpiresAt: null,
		confirmationToken: null,
		confirmationTokenExpiresAt: null,
		confirmed: true,
		confirmedAt: FIXED_DATE,
		blocked: false,
		deletedAt: null,
		avatarUrl: null,
		phone: null,
		address: null,
		bio: null,
		twoFactorEnabled: false,
		twoFactorRequired: false,
		twoFactorSecret: null,
		twoFactorBackupCodes: null,
		createdAt: FIXED_DATE,
		updatedAt: FIXED_DATE,
		...overrides,
	};
}

export interface RoleFixture {
	id: string;
	identifier: string;
	name: string;
	description: string | null;
	default: boolean;
	parentRoleId: string | null;
	createdAt: Date;
	updatedAt: Date;
}

export function buildRole(overrides: Partial<RoleFixture> = {}): RoleFixture {
	const id = overrides.id ?? nextId('role');
	return {
		id,
		identifier: `role_${id}`,
		name: `Role ${id}`,
		description: null,
		default: false,
		parentRoleId: null,
		createdAt: FIXED_DATE,
		updatedAt: FIXED_DATE,
		...overrides,
	};
}

export interface PermissionFixture {
	id: string;
	resource: string;
	action: string;
	identifier: string;
	description: string | null;
	createdAt: Date;
	updatedAt: Date;
}

export function buildPermission(
	overrides: Partial<PermissionFixture> = {}
): PermissionFixture {
	const id = overrides.id ?? nextId('perm');
	const resource = overrides.resource ?? 'users';
	const action = overrides.action ?? 'read';
	return {
		id,
		resource,
		action,
		identifier: `${resource}:${action}`,
		description: null,
		createdAt: FIXED_DATE,
		updatedAt: FIXED_DATE,
		...overrides,
	};
}

export interface SessionFixture {
	id: string;
	loginSessionId: string | null;
	accessToken: string;
	refreshToken: string;
	device: string;
	ipAddress: string | null;
	userAgent: string | null;
	lastActivityAt: Date;
	createdAt: Date;
	updatedAt: Date;
	userId: string;
}

export function buildSession(
	overrides: Partial<SessionFixture> = {}
): SessionFixture {
	const id = overrides.id ?? nextId('session');
	return {
		id,
		loginSessionId: `login-${id}`,
		accessToken: `access-token-${id}`,
		refreshToken: `refresh-token-${id}`,
		device: 'jest',
		ipAddress: '127.0.0.1',
		userAgent: 'jest-test-runner',
		lastActivityAt: FIXED_DATE,
		createdAt: FIXED_DATE,
		updatedAt: FIXED_DATE,
		userId: nextId('user'),
		...overrides,
	};
}

export interface PolicyFixture {
	id: string;
	identifier: string;
	description: string | null;
	roleId: string;
	condition: unknown;
	active: boolean;
	createdAt: Date;
	updatedAt: Date;
}

export function buildPolicy(
	overrides: Partial<PolicyFixture> = {}
): PolicyFixture {
	const id = overrides.id ?? nextId('policy');
	return {
		id,
		identifier: `policy_${id}`,
		description: null,
		roleId: nextId('role'),
		condition: { field: 'status', operator: 'eq', value: 'active' },
		active: true,
		createdAt: FIXED_DATE,
		updatedAt: FIXED_DATE,
		...overrides,
	};
}

export interface ApiKeyFixture {
	id: string;
	keyHash: string;
	application: string;
	default: boolean;
	createdAt: Date;
	updatedAt: Date;
}

export function buildApiKey(
	overrides: Partial<ApiKeyFixture> = {}
): ApiKeyFixture {
	const id = overrides.id ?? nextId('apikey');
	return {
		id,
		keyHash: `$2b$10$hash-for-${id}`,
		application: `app-${id}`,
		default: false,
		createdAt: FIXED_DATE,
		updatedAt: FIXED_DATE,
		...overrides,
	};
}

export interface LoginAttemptFixture {
	id: string;
	identifier: string;
	ipAddress: string;
	userAgent: string | null;
	success: boolean;
	createdAt: Date;
}

export function buildLoginAttempt(
	overrides: Partial<LoginAttemptFixture> = {}
): LoginAttemptFixture {
	const id = overrides.id ?? nextId('attempt');
	return {
		id,
		identifier: 'user@test.local',
		ipAddress: '127.0.0.1',
		userAgent: 'jest-test-runner',
		success: false,
		createdAt: FIXED_DATE,
		...overrides,
	};
}
