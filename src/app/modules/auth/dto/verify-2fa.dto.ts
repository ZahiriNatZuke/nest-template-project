import { z } from 'zod';

export const Verify2FAZodSchema = z.object({
	token: z
		.string()
		.min(6, 'Token must be at least 6 characters')
		.max(8, 'Token must be at most 8 characters'),
});

export type Verify2FAZodDto = z.infer<typeof Verify2FAZodSchema>;
