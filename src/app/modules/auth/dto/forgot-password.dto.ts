import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const ForgotPasswordSchema = z.object({
	email: z.email(),
});

export class ForgotPasswordZodDto extends createZodDto(ForgotPasswordSchema) {}
