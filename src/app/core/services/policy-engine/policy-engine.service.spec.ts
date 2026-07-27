import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Test, TestingModule } from '@nestjs/testing';
import { buildPolicy } from '@test/utils/factories';
import {
	asPrismaService,
	createPrismaMock,
	type PrismaMock,
} from '@test/utils/prisma-mock';
import {
	type PolicyCondition,
	PolicyEngineService,
} from './policy-engine.service';

describe('PolicyEngineService', () => {
	let service: PolicyEngineService;
	let prisma: PrismaMock;

	beforeEach(async () => {
		prisma = createPrismaMock();

		const module: TestingModule = await Test.createTestingModule({
			providers: [
				PolicyEngineService,
				{ provide: PrismaService, useValue: asPrismaService(prisma) },
			],
		}).compile();

		service = module.get<PolicyEngineService>(PolicyEngineService);
	});

	describe('evaluateCondition', () => {
		const evaluate = (
			condition: PolicyCondition,
			context: Record<string, unknown>
		) => service.evaluateCondition(condition, context);

		describe('missing context', () => {
			it.each([
				['absent', {}],
				['undefined', { status: undefined }],
				['null', { status: null }],
			])('denies when the field is %s', (_label, context) => {
				expect(
					evaluate(
						{ field: 'status', operator: 'eq', value: 'active' },
						context
					)
				).toBe(false);
			});

			// Denying on a missing field means `ne` cannot be used to grant access
			// to contexts that simply lack the attribute — deny-by-default wins.
			it('denies an `ne` condition when the field is absent', () => {
				expect(
					evaluate({ field: 'status', operator: 'ne', value: 'banned' }, {})
				).toBe(false);
			});
		});

		describe('eq / ne', () => {
			it('matches an identical string', () => {
				expect(
					evaluate(
						{ field: 'status', operator: 'eq', value: 'active' },
						{ status: 'active' }
					)
				).toBe(true);
			});

			// Strict equality: no type coercion between "1" and 1.
			it('does not coerce types', () => {
				expect(
					evaluate({ field: 'level', operator: 'eq', value: 1 }, { level: '1' })
				).toBe(false);
			});

			it('inverts the comparison for `ne`', () => {
				expect(
					evaluate(
						{ field: 'status', operator: 'ne', value: 'banned' },
						{ status: 'active' }
					)
				).toBe(true);
			});
		});

		describe('numeric comparisons', () => {
			it.each([
				['gt', 5, 3, true],
				['gt', 3, 5, false],
				['gt', 5, 5, false],
				['gte', 5, 5, true],
				['lt', 3, 5, true],
				['lt', 5, 5, false],
				['lte', 5, 5, true],
			] as const)(
				'%s: context %s against %s -> %s',
				(operator, contextValue, conditionValue, expected) => {
					expect(
						evaluate(
							{ field: 'hour', operator, value: conditionValue },
							{ hour: contextValue }
						)
					).toBe(expected);
				}
			);

			// Numeric operators coerce, so a numeric string still compares.
			it('coerces numeric strings', () => {
				expect(
					evaluate({ field: 'hour', operator: 'lt', value: 18 }, { hour: '9' })
				).toBe(true);
			});

			it('denies when the value is not numeric, rather than throwing', () => {
				expect(
					evaluate(
						{ field: 'hour', operator: 'gt', value: 5 },
						{ hour: 'not-a-number' }
					)
				).toBe(false);
			});
		});

		describe('in', () => {
			it('matches a member of the list', () => {
				expect(
					evaluate(
						{
							field: 'ipAddress',
							operator: 'in',
							value: ['10.0.0.1', '10.0.0.2'],
						},
						{ ipAddress: '10.0.0.2' }
					)
				).toBe(true);
			});

			it('denies a non-member', () => {
				expect(
					evaluate(
						{ field: 'ipAddress', operator: 'in', value: ['10.0.0.1'] },
						{ ipAddress: '203.0.113.9' }
					)
				).toBe(false);
			});

			it('denies against an empty list', () => {
				expect(
					evaluate(
						{ field: 'ipAddress', operator: 'in', value: [] },
						{ ipAddress: '10.0.0.1' }
					)
				).toBe(false);
			});
		});

		describe('string operators', () => {
			it('contains matches a substring', () => {
				expect(
					evaluate(
						{ field: 'email', operator: 'contains', value: '@corp.com' },
						{ email: 'someone@corp.com' }
					)
				).toBe(true);
			});

			it('contains is case sensitive', () => {
				expect(
					evaluate(
						{ field: 'email', operator: 'contains', value: '@CORP.com' },
						{ email: 'someone@corp.com' }
					)
				).toBe(false);
			});

			it('startsWith matches a prefix', () => {
				expect(
					evaluate(
						{ field: 'path', operator: 'startsWith', value: '/admin' },
						{ path: '/admin/users' }
					)
				).toBe(true);
			});

			it('startsWith denies a mid-string match', () => {
				expect(
					evaluate(
						{ field: 'path', operator: 'startsWith', value: 'admin' },
						{ path: '/admin/users' }
					)
				).toBe(false);
			});
		});
	});

	describe('evaluateConditions', () => {
		const context = { status: 'active', hour: 9 };

		it('requires every condition to hold (AND semantics)', () => {
			expect(
				service.evaluateConditions(
					[
						{ field: 'status', operator: 'eq', value: 'active' },
						{ field: 'hour', operator: 'lt', value: 18 },
					],
					context
				)
			).toBe(true);
		});

		it('denies when a single condition fails', () => {
			expect(
				service.evaluateConditions(
					[
						{ field: 'status', operator: 'eq', value: 'active' },
						{ field: 'hour', operator: 'gt', value: 18 },
					],
					context
				)
			).toBe(false);
		});

		// `Array.every` on an empty array is true, so a policy stored with no
		// conditions grants access unconditionally. Pinned here because it is a
		// sharp edge, not because it is obviously desirable.
		it('grants access for an empty condition list', () => {
			expect(service.evaluateConditions([], context)).toBe(true);
		});
	});

	describe('evaluatePolicy', () => {
		it('evaluates the stored conditions of an active policy', async () => {
			prisma.policy.findUnique.mockResolvedValue(
				buildPolicy({
					condition: [{ field: 'status', operator: 'eq', value: 'active' }],
				})
			);

			await expect(
				service.evaluatePolicy('policy-1', { status: 'active' })
			).resolves.toBe(true);
		});

		it('denies when the policy does not exist', async () => {
			prisma.policy.findUnique.mockResolvedValue(null);

			await expect(
				service.evaluatePolicy('missing', { status: 'active' })
			).resolves.toBe(false);
		});

		it('denies when the policy exists but is inactive', async () => {
			prisma.policy.findUnique.mockResolvedValue(
				buildPolicy({
					active: false,
					condition: [{ field: 'status', operator: 'eq', value: 'active' }],
				})
			);

			await expect(
				service.evaluatePolicy('policy-1', { status: 'active' })
			).resolves.toBe(false);
		});
	});

	describe('hasPolicy', () => {
		it('looks the policy up by role and identifier, restricted to active ones', async () => {
			prisma.policy.findFirst.mockResolvedValue(buildPolicy({ condition: [] }));

			await service.hasPolicy('role-1', 'can_edit_users', {});

			expect(prisma.policy.findFirst).toHaveBeenCalledWith({
				where: { roleId: 'role-1', identifier: 'can_edit_users', active: true },
			});
		});

		it('denies when the role has no such policy', async () => {
			prisma.policy.findFirst.mockResolvedValue(null);

			await expect(
				service.hasPolicy('role-1', 'nope', { status: 'active' })
			).resolves.toBe(false);
		});

		it('evaluates the conditions when the policy is found', async () => {
			prisma.policy.findFirst.mockResolvedValue(
				buildPolicy({
					condition: [{ field: 'status', operator: 'eq', value: 'active' }],
				})
			);

			await expect(
				service.hasPolicy('role-1', 'can_edit_users', { status: 'banned' })
			).resolves.toBe(false);
		});
	});

	describe('getPoliciesByRole', () => {
		it('returns only active policies for the role', async () => {
			const policies = [buildPolicy(), buildPolicy()];
			prisma.policy.findMany.mockResolvedValue(policies);

			await expect(service.getPoliciesByRole('role-1')).resolves.toBe(policies);
			expect(prisma.policy.findMany).toHaveBeenCalledWith({
				where: { roleId: 'role-1', active: true },
			});
		});
	});

	describe('createPolicy', () => {
		const validCondition: PolicyCondition = {
			field: 'status',
			operator: 'eq',
			value: 'active',
		};

		it('persists the policy as active', async () => {
			prisma.policy.create.mockResolvedValue(buildPolicy());

			await service.createPolicy('role-1', 'can_edit', 'desc', [
				validCondition,
			]);

			expect(prisma.policy.create).toHaveBeenCalledWith({
				data: {
					roleId: 'role-1',
					identifier: 'can_edit',
					description: 'desc',
					condition: [validCondition],
					active: true,
				},
			});
		});

		it('rejects an unknown operator without touching the database', async () => {
			await expect(
				service.createPolicy('role-1', 'bad', undefined, [
					{
						field: 'status',
						operator: 'regex' as never,
						value: 'active',
					},
				])
			).rejects.toThrow('Invalid operator: regex');
			expect(prisma.policy.create).not.toHaveBeenCalled();
		});

		it.each([
			['a missing field', { operator: 'eq', value: 'active' }],
			['a missing operator', { field: 'status', value: 'active' }],
			['a missing value', { field: 'status', operator: 'eq' }],
		])('rejects %s', async (_label, condition) => {
			await expect(
				service.createPolicy('role-1', 'bad', undefined, [
					condition as PolicyCondition,
				])
			).rejects.toThrow('Invalid condition format');
		});

		// A `false` value is legitimate and must not be mistaken for "missing".
		it('accepts a boolean false value', async () => {
			prisma.policy.create.mockResolvedValue(buildPolicy());

			await expect(
				service.createPolicy('role-1', 'ok', undefined, [
					{ field: 'confirmed', operator: 'eq', value: false },
				])
			).resolves.toBeDefined();
		});
	});

	describe('updatePolicy', () => {
		it('updates only the description when no conditions are given', async () => {
			prisma.policy.update.mockResolvedValue(buildPolicy());

			await service.updatePolicy('policy-1', 'new description');

			expect(prisma.policy.update).toHaveBeenCalledWith({
				where: { id: 'policy-1' },
				data: { description: 'new description' },
			});
		});

		it('sends an empty update when nothing is provided', async () => {
			prisma.policy.update.mockResolvedValue(buildPolicy());

			await service.updatePolicy('policy-1');

			expect(prisma.policy.update).toHaveBeenCalledWith({
				where: { id: 'policy-1' },
				data: {},
			});
		});

		it('validates new conditions before writing', async () => {
			await expect(
				service.updatePolicy('policy-1', undefined, [
					{ field: 'status', operator: 'nope' as never, value: 'x' },
				])
			).rejects.toThrow('Invalid operator: nope');
			expect(prisma.policy.update).not.toHaveBeenCalled();
		});
	});

	describe('deactivatePolicy', () => {
		it('flips active to false rather than deleting the row', async () => {
			prisma.policy.update.mockResolvedValue(buildPolicy({ active: false }));

			await service.deactivatePolicy('policy-1');

			expect(prisma.policy.update).toHaveBeenCalledWith({
				where: { id: 'policy-1' },
				data: { active: false },
			});
			expect(prisma.policy.delete).not.toHaveBeenCalled();
		});
	});

	describe('buildUserContext', () => {
		it('derives userStatus from `confirmed` when status is absent', () => {
			expect(
				service.buildUserContext({ id: 'u1', confirmed: true })
			).toMatchObject({ userId: 'u1', userStatus: 'active' });

			expect(
				service.buildUserContext({ id: 'u1', confirmed: false })
			).toMatchObject({ userStatus: 'pending' });
		});

		it('prefers an explicit status over the confirmed flag', () => {
			expect(
				service.buildUserContext({
					id: 'u1',
					status: 'banned',
					confirmed: true,
				})
			).toMatchObject({ userStatus: 'banned' });
		});

		it('includes the role identifier and a timestamp', () => {
			const context = service.buildUserContext({
				id: 'u1',
				role: { identifier: 'admin' },
			});

			expect(context.userRole).toBe('admin');
			expect(typeof context.timestamp).toBe('string');
		});

		// Request attributes are spread last, so they can override the derived
		// ones — worth knowing before passing user-controlled data in.
		it('lets request attributes override derived fields', () => {
			const context = service.buildUserContext(
				{ id: 'u1', confirmed: true },
				{ userStatus: 'overridden', ipAddress: '10.0.0.1' }
			);

			expect(context.userStatus).toBe('overridden');
			expect(context.ipAddress).toBe('10.0.0.1');
		});
	});

	describe('getCommonPolicies', () => {
		it('returns example policies whose conditions all validate', async () => {
			const policies = PolicyEngineService.getCommonPolicies();
			prisma.policy.create.mockResolvedValue(buildPolicy());

			expect(policies.length).toBeGreaterThan(0);
			for (const policy of policies) {
				await expect(
					service.createPolicy(
						'role-1',
						policy.identifier,
						policy.description,
						policy.conditions
					)
				).resolves.toBeDefined();
			}
		});
	});
});
