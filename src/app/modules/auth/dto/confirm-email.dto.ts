import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const ConfirmEmailSchema = z.object({
	token: z.jwt(),
});

export class ConfirmEmailZodDto extends createZodDto(ConfirmEmailSchema) {}
