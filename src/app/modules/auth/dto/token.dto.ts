import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const TokenSchema = z.object({
	token: z.jwt(),
	activation_code: z.string().max(8).optional(),
});

export class TokenZodDto extends createZodDto(TokenSchema) {}
