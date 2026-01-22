import { z } from 'zod';

export const LoginResponse2FAZodSchema = z.object({
	requiresTwoFactor: z.boolean(),
	sessionId: z.string().optional(),
	message: z.string().optional(),
});

export type LoginResponse2FAZodDto = z.infer<typeof LoginResponse2FAZodSchema>;
