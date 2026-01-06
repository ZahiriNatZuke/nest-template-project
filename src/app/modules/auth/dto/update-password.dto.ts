import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const UpdatePasswordSchema = z.object({
	current_password: z
		.string()
		.min(8, 'Current Password must be at least 8 characters long'),
	new_password: z
		.string()
		.min(8, 'New Password must be at least 8 characters long'),
	confirm_new_password: z
		.string()
		.min(8, 'Confirmation New Password must be at least 8 characters long'),
});

export class UpdatePasswordZodDto extends createZodDto(UpdatePasswordSchema) {}
