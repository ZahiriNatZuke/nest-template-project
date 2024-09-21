import { createZodDto } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

export const RequestRecoveryAccountSchema = z.object({
	email: z.string().email(),
});

export class RequestRecoveryAccountZodDto extends createZodDto(
	RequestRecoveryAccountSchema
) {}
