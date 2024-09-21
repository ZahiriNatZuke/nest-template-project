import { createZodDto } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

export const UpdateRoleSchema = z.object({
	identifier: z.string().optional(),
	name: z.string().optional(),
});

export class UpdateRoleZodDto extends createZodDto(UpdateRoleSchema) {}
