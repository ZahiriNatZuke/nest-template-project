import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const AssignRoleSchema = z.object({
	roleId: z.uuid('Invalid role ID format'),
});

export class AssignRoleZodDto extends createZodDto(AssignRoleSchema) {
	roleId!: string; // for TS intellisense in controllers
}
