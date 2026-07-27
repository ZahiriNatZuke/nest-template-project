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

export type AuthRequest = FastifyRequest & { user: User };

/**
 * What JwtAuthGuard attaches to the request: the token payload, plus `id` as
 * an alias of `userId`.
 *
 * The alias is not cosmetic — PermissionsGuard, the 2FA controller and the
 * profile controller all read `user.id`, and passport's JwtStrategy attaches
 * it under that name too. Without it those consumers see `undefined`.
 */
export type JwtPrincipal = JWTPayload & { id: string };

export type ApiKey = {
	id: string;
	keyHash: string;
	application: string;
} | null;
