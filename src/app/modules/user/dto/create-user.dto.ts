import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const CreateUserSchema = z.object({
	username: z.string(),
	email: z.string().email(),
	fullName: z.string(),
	password: z
		.string()
		.min(8)
		.min(8, 'Password must be at least 8 characters long'),
});

export class CreateUserZodDto extends createZodDto(CreateUserSchema) {}
