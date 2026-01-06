import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const UpdateRoleSchema = z.object({
	identifier: z.string().optional(),
	name: z.string().optional(),
});

export class UpdateRoleZodDto extends createZodDto(UpdateRoleSchema) {}
