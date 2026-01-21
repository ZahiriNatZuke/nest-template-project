import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const CreateUserSchema = z.object({
	username: z.string(),
	email: z.email(),
	fullName: z.string(),
	password: z
		.string()
		.min(8)
		.min(8, 'Password must be at least 8 characters long'),
	avatarUrl: z.string().url().optional(),
	phone: z.string().min(5).max(30).optional(),
	address: z.string().max(255).optional(),
	bio: z.string().max(500).optional(),
});

export class CreateUserZodDto extends createZodDto(CreateUserSchema) {}
