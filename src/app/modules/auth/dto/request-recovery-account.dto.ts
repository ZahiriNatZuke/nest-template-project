import { z } from 'nestjs-zod/z';
import { createZodDto } from 'nestjs-zod';

export const RequestRecoveryAccountSchema = z.object({
  email: z.string().email(),
});

export class RequestRecoveryAccountZodDto extends createZodDto(RequestRecoveryAccountSchema) {
}
