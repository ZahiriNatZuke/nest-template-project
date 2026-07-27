import { CsrfService } from '@app/core/services/csrf/csrf.service';
import type { ExecutionContext } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { CsrfGuard } from './csrf.guard';

describe('CsrfGuard', () => {
	let guard: CsrfGuard;
	let csrfService: { validateToken: jest.Mock };

	const contextFor = (
		method: string,
		headers: Record<string, string> = {}
	): ExecutionContext =>
		({
			switchToHttp: () => ({
				getRequest: () => ({ method, headers }),
			}),
		}) as unknown as ExecutionContext;

	beforeEach(async () => {
		csrfService = { validateToken: jest.fn() };

		const module: TestingModule = await Test.createTestingModule({
			providers: [CsrfGuard, { provide: CsrfService, useValue: csrfService }],
		}).compile();

		guard = module.get<CsrfGuard>(CsrfGuard);
	});

	describe('safe methods', () => {
		it.each(['GET', 'HEAD', 'OPTIONS'])(
			'allows %s without consulting the token store',
			async method => {
				await expect(guard.canActivate(contextFor(method))).resolves.toBe(true);
				expect(csrfService.validateToken).not.toHaveBeenCalled();
			}
		);
	});

	describe('mutating methods', () => {
		const MUTATIONS = ['POST', 'PUT', 'PATCH', 'DELETE'];

		it.each(MUTATIONS)('rejects %s with no token header', async method => {
			await expect(guard.canActivate(contextFor(method))).rejects.toMatchObject(
				{
					response: { error: 'CSRF token invalid', code: 'CSRF_INVALID' },
				}
			);
			expect(csrfService.validateToken).not.toHaveBeenCalled();
		});

		it.each(MUTATIONS)('allows %s with a valid token', async method => {
			csrfService.validateToken.mockResolvedValue(true);

			await expect(
				guard.canActivate(contextFor(method, { 'x-csrf-token': 'good' }))
			).resolves.toBe(true);
			expect(csrfService.validateToken).toHaveBeenCalledWith('good');
		});

		// The regression this guards against: `validateToken` is async, so a
		// synchronous `if (!this.csrfService.validateToken(t))` tests a Promise,
		// which is always truthy — every token, valid or not, was accepted.
		it.each(MUTATIONS)('rejects %s when the token is unknown', async method => {
			csrfService.validateToken.mockResolvedValue(false);

			await expect(
				guard.canActivate(contextFor(method, { 'x-csrf-token': 'forged' }))
			).rejects.toMatchObject({
				response: { error: 'CSRF token invalid', code: 'CSRF_INVALID' },
			});
		});

		it('awaits the validation rather than trusting the returned promise', async () => {
			csrfService.validateToken.mockReturnValue(Promise.resolve(false));

			await expect(
				guard.canActivate(contextFor('POST', { 'x-csrf-token': 'forged' }))
			).rejects.toBeDefined();
		});

		it('rejects an empty token header', async () => {
			await expect(
				guard.canActivate(contextFor('POST', { 'x-csrf-token': '' }))
			).rejects.toBeDefined();
			expect(csrfService.validateToken).not.toHaveBeenCalled();
		});
	});
});
