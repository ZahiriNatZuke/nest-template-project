import { z } from 'nestjs-zod/z';
import { createZodDto } from 'nestjs-zod';

export const RefreshSchema = z.object({
  refresh: z.string(),
});

export class RefreshZodDto extends createZodDto(RefreshSchema) {
}
