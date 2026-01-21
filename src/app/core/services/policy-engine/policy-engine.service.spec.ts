import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Test, TestingModule } from '@nestjs/testing';
import {
	PolicyCondition,
	PolicyContext,
	PolicyEngineService,
} from './policy-engine.service';

describe('PolicyEngineService', () => {
	let service: PolicyEngineService;
	let _prismaService: PrismaService;

	const mockPrismaService = {
		policy: {
			findMany: jest.fn(),
			findUnique: jest.fn(),
			findFirst: jest.fn(),
			create: jest.fn(),
			update: jest.fn(),
		},
	};

	beforeEach(async () => {
		const module: TestingModule = await Test.createTestingModule({
			providers: [
				PolicyEngineService,
				{
					provide: PrismaService,
					useValue: mockPrismaService,
				},
			],
		}).compile();

		service = module.get<PolicyEngineService>(PolicyEngineService);
		_prismaService = module.get<PrismaService>(PrismaService);

		jest.clearAllMocks();
	});

	it('should be defined', () => {
		expect(service).toBeDefined();
	});

	describe('evaluateCondition', () => {
		it('should evaluate eq operator', () => {
			const condition: PolicyCondition = {
				field: 'status',
				operator: 'eq',
				value: 'active',
			};
			const context: PolicyContext = { status: 'active' };

			const result = service.evaluateCondition(condition, context);
			expect(result).toBe(true);
		});

		it('should evaluate ne operator', () => {
			const condition: PolicyCondition = {
				field: 'status',
				operator: 'ne',
				value: 'blocked',
			};
			const context: PolicyContext = { status: 'active' };

			const result = service.evaluateCondition(condition, context);
			expect(result).toBe(true);
		});

		it('should evaluate gt operator', () => {
			const condition: PolicyCondition = {
				field: 'age',
				operator: 'gt',
				value: 18,
			};
			const context: PolicyContext = { age: 25 };

			const result = service.evaluateCondition(condition, context);
			expect(result).toBe(true);
		});

		it('should evaluate gte operator', () => {
			const condition: PolicyCondition = {
				field: 'age',
				operator: 'gte',
				value: 18,
			};
			const context: PolicyContext = { age: 18 };

			const result = service.evaluateCondition(condition, context);
			expect(result).toBe(true);
		});

		it('should evaluate lt operator', () => {
			const condition: PolicyCondition = {
				field: 'age',
				operator: 'lt',
				value: 65,
			};
			const context: PolicyContext = { age: 45 };

			const result = service.evaluateCondition(condition, context);
			expect(result).toBe(true);
		});

		it('should evaluate lte operator', () => {
			const condition: PolicyCondition = {
				field: 'age',
				operator: 'lte',
				value: 65,
			};
			const context: PolicyContext = { age: 65 };

			const result = service.evaluateCondition(condition, context);
			expect(result).toBe(true);
		});

		it('should evaluate in operator', () => {
			const condition: PolicyCondition = {
				field: 'role',
				operator: 'in',
				value: ['admin', 'manager'],
			};
			const context: PolicyContext = { role: 'admin' };

			const result = service.evaluateCondition(condition, context);
			expect(result).toBe(true);
		});

		it('should evaluate contains operator', () => {
			const condition: PolicyCondition = {
				field: 'email',
				operator: 'contains',
				value: '@company.com',
			};
			const context: PolicyContext = { email: 'user@company.com' };

			const result = service.evaluateCondition(condition, context);
			expect(result).toBe(true);
		});

		it('should evaluate startsWith operator', () => {
			const condition: PolicyCondition = {
				field: 'username',
				operator: 'startsWith',
				value: 'admin_',
			};
			const context: PolicyContext = { username: 'admin_user1' };

			const result = service.evaluateCondition(condition, context);
			expect(result).toBe(true);
		});

		it('should return false for missing field', () => {
			const condition: PolicyCondition = {
				field: 'status',
				operator: 'eq',
				value: 'active',
			};
			const context: PolicyContext = {};

			const result = service.evaluateCondition(condition, context);
			expect(result).toBe(false);
		});
	});

	describe('evaluateConditions', () => {
		it('should return true when all conditions are met', () => {
			const conditions: PolicyCondition[] = [
				{ field: 'status', operator: 'eq', value: 'active' },
				{ field: 'role', operator: 'in', value: ['admin', 'manager'] },
			];
			const context: PolicyContext = { status: 'active', role: 'admin' };

			const result = service.evaluateConditions(conditions, context);
			expect(result).toBe(true);
		});

		it('should return false when one condition fails', () => {
			const conditions: PolicyCondition[] = [
				{ field: 'status', operator: 'eq', value: 'active' },
				{ field: 'role', operator: 'in', value: ['admin'] },
			];
			const context: PolicyContext = { status: 'active', role: 'user' };

			const result = service.evaluateConditions(conditions, context);
			expect(result).toBe(false);
		});

		it('should return true for empty conditions array', () => {
			const result = service.evaluateConditions([], {});
			expect(result).toBe(true);
		});
	});

	describe('evaluatePolicy', () => {
		it('should evaluate policy with conditions met', async () => {
			const policyId = 'policy1';
			const conditions: PolicyCondition[] = [
				{ field: 'status', operator: 'eq', value: 'active' },
			];

			mockPrismaService.policy.findUnique.mockResolvedValue({
				id: policyId,
				condition: conditions,
				active: true,
			});

			const context: PolicyContext = { status: 'active' };
			const result = await service.evaluatePolicy(policyId, context);

			expect(result).toBe(true);
		});

		it('should return false for inactive policy', async () => {
			const policyId = 'policy1';

			mockPrismaService.policy.findUnique.mockResolvedValue({
				id: policyId,
				active: false,
			});

			const result = await service.evaluatePolicy(policyId, {});

			expect(result).toBe(false);
		});
	});

	describe('hasPolicy', () => {
		it('should return true if role has policy and conditions are met', async () => {
			const roleId = 'role1';
			const policyIdentifier = 'can_edit_active_users';
			const conditions: PolicyCondition[] = [
				{ field: 'status', operator: 'eq', value: 'active' },
			];

			mockPrismaService.policy.findFirst.mockResolvedValue({
				id: 'policy1',
				identifier: policyIdentifier,
				condition: conditions,
				active: true,
			});

			const context: PolicyContext = { status: 'active' };
			const result = await service.hasPolicy(roleId, policyIdentifier, context);

			expect(result).toBe(true);
		});

		it('should return false if role does not have policy', async () => {
			mockPrismaService.policy.findFirst.mockResolvedValue(null);

			const result = await service.hasPolicy('role1', 'unknown_policy', {});

			expect(result).toBe(false);
		});
	});

	describe('createPolicy', () => {
		it('should create a new policy', async () => {
			const roleId = 'role1';
			const identifier = 'can_edit_users';
			const conditions: PolicyCondition[] = [
				{ field: 'status', operator: 'eq', value: 'active' },
			];

			mockPrismaService.policy.create.mockResolvedValue({
				id: 'policy1',
				roleId,
				identifier,
				condition: conditions,
				active: true,
			});

			const result = await service.createPolicy(
				roleId,
				identifier,
				undefined,
				conditions
			);

			expect(result.identifier).toBe(identifier);
			expect(mockPrismaService.policy.create).toHaveBeenCalled();
		});

		it('should reject invalid conditions', async () => {
			const invalidConditions = [
				{ field: 'status', operator: 'invalid_op', value: 'active' },
			] as unknown as PolicyCondition[];

			await expect(
				service.createPolicy('role1', 'test', undefined, invalidConditions)
			).rejects.toThrow();
		});
	});

	describe('buildUserContext', () => {
		it('should build user context from user object', () => {
			const user = {
				id: 'user1',
				status: 'active',
				confirmed: true,
				role: { identifier: 'admin' },
			};

			const context = service.buildUserContext(user);

			expect(context.userId).toBe('user1');
			expect(context.userStatus).toBe('active');
			expect(context.userRole).toBe('admin');
		});

		it('should handle missing user', () => {
			const context = service.buildUserContext({});

			expect(context.userStatus).toBe('pending');
		});
	});

	describe('getCommonPolicies', () => {
		it('should return predefined common policies', () => {
			const policies = PolicyEngineService.getCommonPolicies();

			expect(policies.length).toBeGreaterThan(0);
			expect(policies[0]).toHaveProperty('identifier');
			expect(policies[0]).toHaveProperty('conditions');
		});
	});
});
