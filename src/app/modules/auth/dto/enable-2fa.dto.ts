import { z } from 'zod';

export const Enable2FAZodSchema = z.object({
	token: z
		.string()
		.length(6, 'TOTP token must be 6 digits')
		.regex(/^\d{6}$/, 'TOTP token must contain only digits'),
});

export type Enable2FAZodDto = z.infer<typeof Enable2FAZodSchema>;
