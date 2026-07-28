import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const ResetPasswordSchema = z
	.object({
		// A UUID, not a JWT. `forgotPassword` stores `randomUUID()` in
		// `resetPasswordToken`, so the `z.jwt()` this used to declare rejected
		// every token the application itself had just issued — the whole
		// forgot → reset flow answered 400 and no password was ever reset.
		//
		// The JWT belongs to the other recovery flow, `request-recovery-account`
		// → `recovery-account`, which signs one and never touches this column.
		// The constraint was almost certainly copied across from there.
		token: z.uuid(),
		email: z.email(),
		newPassword: z.string().min(8),
		confirmNewPassword: z.string().min(8),
	})
	.refine(data => data.newPassword === data.confirmNewPassword, {
		message: 'Passwords must match',
		path: ['confirmNewPassword'],
	});

export class ResetPasswordZodDto extends createZodDto(ResetPasswordSchema) {}
