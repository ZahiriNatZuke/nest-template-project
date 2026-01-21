import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const ResetPasswordSchema = z
	.object({
		token: z.jwt(),
		email: z.email(),
		newPassword: z.string().min(8),
		confirmNewPassword: z.string().min(8),
	})
	.refine(data => data.newPassword === data.confirmNewPassword, {
		message: 'Passwords must match',
		path: ['confirmNewPassword'],
	});

export class ResetPasswordZodDto extends createZodDto(ResetPasswordSchema) {}
