import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const UpdateUserSchema = z.object({
	username: z.string().optional(),
	email: z.email().optional(),
	fullName: z.string().optional(),
	confirmed: z.boolean().optional(),
	blocked: z.boolean().optional(),
	roleId: z.uuid().optional(),
	avatarUrl: z.url().optional(),
	phone: z.string().min(5).max(30).optional(),
	address: z.string().max(255).optional(),
	bio: z.string().max(500).optional(),
});

export class UpdateUserZodDto extends createZodDto(UpdateUserSchema) {}
