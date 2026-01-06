import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const LoginSchema = z.object({
	identifier: z.string().max(128),
	password: z.string().min(8, 'Password must be at least 8 characters long'),
	device: z.string(),
	rememberMe: z.boolean().optional().default(false),
});

export class LoginZodDto extends createZodDto(LoginSchema) {}
