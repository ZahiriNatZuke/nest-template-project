import { createZodDto } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

export const RefreshSchema = z.object({
	refresh: z.string(),
});

export class RefreshZodDto extends createZodDto(RefreshSchema) {}
