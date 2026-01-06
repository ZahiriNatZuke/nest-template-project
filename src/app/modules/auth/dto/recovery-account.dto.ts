import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const RecoveryAccountSchema = z.object({
	email: z.string().email(),
	newPassword: z
		.string()
		.min(8, 'New Password must be at least 8 characters long'),
	confirmNewPassword: z
		.string()
		.min(8, 'Confirm New Password must be at least 8 characters long'),
});

export class RecoveryAccountZodDto extends createZodDto(
	RecoveryAccountSchema
) {}

export type RecoveryAccountDto = z.infer<typeof RecoveryAccountSchema>;
