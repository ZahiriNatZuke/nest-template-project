import { createZodDto } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

export const TokenSchema = z.object({
	token: z.string(),
	activation_code: z.string().max(8).optional(),
});

export class TokenZodDto extends createZodDto(TokenSchema) {}
