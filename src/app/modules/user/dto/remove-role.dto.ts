import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const RemoveRoleSchema = z.object({
	roleId: z.uuid('Invalid role ID format'),
});

export class RemoveRoleZodDto extends createZodDto(RemoveRoleSchema) {}
