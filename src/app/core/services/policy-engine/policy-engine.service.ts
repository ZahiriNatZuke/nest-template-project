import { PrismaService } from '@app/core/services/prisma/prisma.service';
import { Injectable, Logger } from '@nestjs/common';
import type { Policy, Prisma } from '@prisma/client';

/**
 * Tipos para ABAC (Attribute-Based Access Control)
 */
type PolicyConditionValue = string | number | boolean;

export type PolicyCondition =
	| {
			field: string;
			operator:
				| 'eq'
				| 'ne'
				| 'gt'
				| 'gte'
				| 'lt'
				| 'lte'
				| 'contains'
				| 'startsWith';
			value: PolicyConditionValue;
	  }
	| {
			field: string;
			operator: 'in';
			value: PolicyConditionValue[];
	  };

export interface PolicyContext {
	[key: string]: unknown; // Contexto dinámico (user status, resource type, etc)
}

/**
 * Servicio para evaluar políticas condicionales (2.3 - ABAC)
 * Permite permisos basados en atributos (ej: "puede leer usuarios si status=active")
 */
@Injectable()
export class PolicyEngineService {
	private readonly logger = new Logger(PolicyEngineService.name);

	constructor(private prisma: PrismaService) {}

	/**
	 * Obtiene todas las políticas de un rol
	 */
	async getPoliciesByRole(roleId: string): Promise<Policy[]> {
		return this.prisma.policy.findMany({
			where: {
				roleId,
				active: true,
			},
		});
	}

	/**
	 * Evalúa si una política se cumple en el contexto dado
	 */
	async evaluatePolicy(
		policyId: string,
		context: PolicyContext
	): Promise<boolean> {
		const policy = await this.prisma.policy.findUnique({
			where: { id: policyId },
		});

		if (!policy || !policy.active) {
			this.logger.warn(`Policy ${policyId} not found or inactive`);
			return false;
		}

		return this.evaluateConditions(
			policy.condition as unknown as PolicyCondition[],
			context
		);
	}

	/**
	 * Evalúa condiciones Y (AND) - todas deben cumplirse
	 */
	evaluateConditions(
		conditions: PolicyCondition[],
		context: PolicyContext
	): boolean {
		return conditions.every(condition =>
			this.evaluateCondition(condition, context)
		);
	}

	/**
	 * Evalúa una condición individual
	 */
	public evaluateCondition(
		condition: PolicyCondition,
		context: PolicyContext
	): boolean {
		const value = context[condition.field];

		if (value === undefined || value === null) {
			this.logger.debug(
				`Field "${condition.field}" not found in context for condition evaluation`
			);
			return false;
		}

		switch (condition.operator) {
			case 'eq':
				return value === condition.value;
			case 'ne':
				return value !== condition.value;
			case 'gt':
				return Number(value) > Number(condition.value);
			case 'gte':
				return Number(value) >= Number(condition.value);
			case 'lt':
				return Number(value) < Number(condition.value);
			case 'lte':
				return Number(value) <= Number(condition.value);
			case 'in':
				return condition.value.includes(value as PolicyConditionValue);
			case 'contains':
				return String(value).includes(String(condition.value));
			case 'startsWith':
				return String(value).startsWith(String(condition.value));
		}
	}

	/**
	 * Verifica si un rol tiene una política específica que se cumple
	 */
	async hasPolicy(
		roleId: string,
		policyIdentifier: string,
		context: PolicyContext
	): Promise<boolean> {
		const policy = await this.prisma.policy.findFirst({
			where: {
				roleId,
				identifier: policyIdentifier,
				active: true,
			},
		});

		if (!policy) {
			return false;
		}

		return this.evaluateConditions(
			policy.condition as unknown as PolicyCondition[],
			context
		);
	}

	/**
	 * Crea una nueva política para un rol
	 */
	async createPolicy(
		roleId: string,
		identifier: string,
		description: string | undefined,
		conditions: PolicyCondition[]
	): Promise<Policy> {
		// Validar que las condiciones sean válidas
		this.validateConditions(conditions);

		return this.prisma.policy.create({
			data: {
				roleId,
				identifier,
				description,
				condition: conditions as unknown as Prisma.InputJsonValue,
				active: true,
			},
		});
	}

	/**
	 * Valida que las condiciones tengan formato correcto
	 */
	private validateConditions(conditions: PolicyCondition[]): void {
		const validOperators = [
			'eq',
			'ne',
			'gt',
			'gte',
			'lt',
			'lte',
			'in',
			'contains',
			'startsWith',
		];

		for (const condition of conditions) {
			if (
				!condition.field ||
				!condition.operator ||
				condition.value === undefined
			) {
				throw new Error('Invalid condition format');
			}

			if (!validOperators.includes(condition.operator)) {
				throw new Error(`Invalid operator: ${condition.operator}`);
			}
		}
	}

	/**
	 * Actualiza una política
	 */
	async updatePolicy(
		policyId: string,
		description?: string,
		conditions?: PolicyCondition[]
	): Promise<Policy> {
		const data: Prisma.PolicyUpdateInput = {};

		if (description !== undefined) {
			data.description = description;
		}

		if (conditions) {
			this.validateConditions(conditions);
			data.condition = conditions as unknown as Prisma.InputJsonValue;
		}

		return this.prisma.policy.update({
			where: { id: policyId },
			data,
		});
	}

	/**
	 * Desactiva una política
	 */
	async deactivatePolicy(policyId: string): Promise<Policy> {
		return this.prisma.policy.update({
			where: { id: policyId },
			data: { active: false },
		});
	}

	/**
	 * Obtiene el contexto del usuario (para evaluar políticas)
	 * Puede ser extendido para incluir más información
	 */
	buildUserContext(
		user: {
			id?: string;
			status?: string;
			confirmed?: boolean;
			role?: { identifier?: string };
		},
		request?: Record<string, unknown>
	): PolicyContext {
		return {
			userId: user?.id,
			userStatus: user?.status || (user?.confirmed ? 'active' : 'pending'),
			userRole: user?.role?.identifier,
			timestamp: new Date().toISOString(),
			// Agregar más campos según sea necesario
			...request,
		};
	}

	/**
	 * Ejemplos de políticas comunes
	 */
	static getCommonPolicies(): Array<{
		identifier: string;
		description: string;
		conditions: PolicyCondition[];
	}> {
		return [
			{
				identifier: 'can_edit_active_users',
				description: 'Can edit users only if they are active',
				conditions: [
					{
						field: 'userStatus',
						operator: 'eq',
						value: 'active',
					},
				],
			},
			{
				identifier: 'can_access_before_hours',
				description: 'Can access only before 18:00',
				conditions: [
					{
						field: 'currentHour',
						operator: 'lt',
						value: 18,
					},
				],
			},
			{
				identifier: 'can_access_from_allowed_ips',
				description: 'Can access only from allowed IPs',
				conditions: [
					{
						field: 'ipAddress',
						operator: 'in',
						value: ['192.168.1.0', '10.0.0.0'],
					},
				],
			},
		];
	}
}
