import { createZodDto } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

export const CreateRoleSchema = z.object({
	identifier: z.string(),
	name: z.string(),
});

export class CreateRoleZodDto extends createZodDto(CreateRoleSchema) {}
