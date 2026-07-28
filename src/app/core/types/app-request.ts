import { JWTPayload } from '@app/modules/auth/interface/jwt.payload';
import { User } from '@prisma/client';
import { FastifyRequest } from 'fastify';

export type AppRequest = FastifyRequest & {
	user: ValidatedUser;
	cookies: Record<string, string>;
	apiKey: ApiKey;
	resourceOwnership?: {
		resourceType: string;
		resourceId: string;
		accessLevel: 'owner' | 'editor' | 'viewer';
	};
};

export type ValidatedUser =
	| {
			user: SafeUser;
			status: boolean;
	  }
	| {
			user: SafeUser;
			status: 'miss_activate';
	  }
	| {
			user: null;
			status: false;
	  };

export type SafeUser = Omit<
	User,
	| 'password'
	| 'resetPasswordToken'
	| 'resetPasswordExpiresAt'
	| 'confirmationToken'
	| 'confirmationTokenExpiresAt'
	| 'deletedAt'
>;

/**
 * What JwtAuthGuard attaches to the request: the token payload, plus `id` as
 * an alias of `userId`.
 *
 * The alias is not cosmetic — PermissionsGuard, the 2FA controller and the
 * profile controller all read `user.id`, and passport's JwtStrategy attaches
 * it under that name too. Without it those consumers see `undefined`.
 */
export type JwtPrincipal = JWTPayload & { id: string };

/**
 * A request that has passed JwtAuthGuard.
 *
 * `user` is the JWT principal — **not** a `User` row. It used to be typed as
 * `User`, which was a lie the compiler could not catch: the payload carries
 * `userId`, `fullName`, `email`, `device` and `perm`, and nothing else. Every
 * consumer reading a column that only exists in the database (`password`,
 * `confirmed`, `blocked`, …) silently got `undefined`, which is how the
 * `update-password` and ABAC-context defects survived a typecheck and a full
 * test suite. Anything that needs a column has to load the row itself.
 */
export type AuthRequest = FastifyRequest & { user: JwtPrincipal };

export type ApiKey = {
	id: string;
	keyHash: string;
	application: string;
} | null;
