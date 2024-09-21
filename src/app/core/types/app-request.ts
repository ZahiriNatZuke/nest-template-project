import { User } from '@prisma/client';
import { FastifyRequest } from 'fastify';

export type AppRequest = FastifyRequest & { user: ValidatedUser };
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
	'password' | 'resetPasswordToken' | 'confirmationToken'
>;

export type AuthRequest = FastifyRequest & { user: User };
