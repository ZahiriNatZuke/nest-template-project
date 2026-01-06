import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const CreateRoleSchema = z.object({
	identifier: z.string(),
	name: z.string(),
});

export class CreateRoleZodDto extends createZodDto(CreateRoleSchema) {}
