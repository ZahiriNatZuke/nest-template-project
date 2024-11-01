import { createZodDto } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

export const RecoveryAccountSchema = z.object({
	email: z.string().email(),
	newPassword: z
		.password()
		.min(8, 'New Password must be at least 8 characters long')
		.atLeastOne(
			'lowercase',
			'New Password must contain at least one lowercase letter'
		)
		.atLeastOne(
			'uppercase',
			'New Password must contain at least one uppercase letter'
		)
		.atLeastOne('digit', 'New Password must contain at least one number')
		.atLeastOne(
			'special',
			'New Password must contain at least one special character'
		),
	confirmNewPassword: z
		.password()
		.min(8, 'Confirm New Password must be at least 8 characters long')
		.atLeastOne(
			'lowercase',
			'Confirm New Password must contain at least one lowercase letter'
		)
		.atLeastOne(
			'uppercase',
			'Confirm New Password must contain at least one uppercase letter'
		)
		.atLeastOne(
			'digit',
			'Confirm New Password must contain at least one number'
		)
		.atLeastOne(
			'special',
			'Confirm New Password must contain at least one special character'
		),
});

export class RecoveryAccountZodDto extends createZodDto(
	RecoveryAccountSchema
) {}

export type RecoveryAccountDto = z.infer<typeof RecoveryAccountSchema>;
