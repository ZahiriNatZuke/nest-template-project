import type { ExecutionContext } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { JwtAuthGuard } from './jwt-auth.guard';

describe('JwtAuthGuard', () => {
	let guard: JwtAuthGuard;
	let jwtService: { verify: jest.Mock };

	const PAYLOAD = {
		userId: 'user-0001',
		device: 'web',
		email: 'a@b.c',
		fullName: 'A B',
		perm: ['users:read'],
	};

	/** Captures what the guard writes back onto the request. */
	const contextFor = (cookies: Record<string, string> = {}) => {
		const request: Record<string, unknown> = { cookies };
		return {
			request,
			context: {
				switchToHttp: () => ({ getRequest: () => request }),
			} as unknown as ExecutionContext,
		};
	};

	beforeEach(async () => {
		jwtService = { verify: jest.fn() };

		const module: TestingModule = await Test.createTestingModule({
			providers: [JwtAuthGuard, { provide: JwtService, useValue: jwtService }],
		}).compile();

		guard = module.get<JwtAuthGuard>(JwtAuthGuard);
	});

	describe('token presence', () => {
		it('rejects a request with no accessToken cookie', async () => {
			const { context } = contextFor();

			await expect(guard.canActivate(context)).rejects.toMatchObject({
				response: { error: 'Unauthorized', code: 'TOKEN_MISSING' },
			});
			expect(jwtService.verify).not.toHaveBeenCalled();
		});

		it('rejects a request with no cookies at all', async () => {
			const request: Record<string, unknown> = {};
			const context = {
				switchToHttp: () => ({ getRequest: () => request }),
			} as unknown as ExecutionContext;

			await expect(guard.canActivate(context)).rejects.toMatchObject({
				response: { code: 'TOKEN_MISSING' },
			});
		});

		it('reads the token from the cookie, not the Authorization header', async () => {
			jwtService.verify.mockReturnValue(PAYLOAD);
			const { context } = contextFor({ accessToken: 'the-token' });

			await guard.canActivate(context);

			expect(jwtService.verify).toHaveBeenCalledWith('the-token');
		});
	});

	describe('invalid tokens', () => {
		it('rejects a token the service refuses to verify', async () => {
			jwtService.verify.mockImplementation(() => {
				throw new Error('jwt expired');
			});
			const { context } = contextFor({ accessToken: 'expired' });

			await expect(guard.canActivate(context)).rejects.toMatchObject({
				response: { error: 'Unauthorized', code: 'TOKEN_EXPIRED' },
			});
		});
	});

	describe('the attached principal', () => {
		it('admits a valid token', async () => {
			jwtService.verify.mockReturnValue(PAYLOAD);
			const { context } = contextFor({ accessToken: 'good' });

			await expect(guard.canActivate(context)).resolves.toBe(true);
		});

		// The regression this guards against: the payload names the subject
		// `userId`, but PermissionsGuard, the 2FA controller and the profile
		// controller all read `user.id`. Without the alias every @Authz() route
		// answered 403 "Unauthorized principal" — even for an authorised caller —
		// and every 2FA route looked the user up by `undefined`.
		it('exposes the subject as `id`, not only as `userId`', async () => {
			jwtService.verify.mockReturnValue(PAYLOAD);
			const { request, context } = contextFor({ accessToken: 'good' });

			await guard.canActivate(context);

			expect(request.user).toMatchObject({
				id: PAYLOAD.userId,
				userId: PAYLOAD.userId,
			});
		});

		it('carries the cached permissions through untouched', async () => {
			jwtService.verify.mockReturnValue(PAYLOAD);
			const { request, context } = contextFor({ accessToken: 'good' });

			await guard.canActivate(context);

			expect(request.user).toMatchObject({ perm: ['users:read'] });
		});

		it('keeps the remaining payload claims', async () => {
			jwtService.verify.mockReturnValue(PAYLOAD);
			const { request, context } = contextFor({ accessToken: 'good' });

			await guard.canActivate(context);

			expect(request.user).toMatchObject({
				device: 'web',
				email: 'a@b.c',
				fullName: 'A B',
			});
		});
	});
});
