import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const RequestRecoveryAccountSchema = z.object({
	email: z.email(),
});

export class RequestRecoveryAccountZodDto extends createZodDto(
	RequestRecoveryAccountSchema
) {}
