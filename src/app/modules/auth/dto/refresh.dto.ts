import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const RefreshSchema = z.object({
	refresh: z.string(),
});

export class RefreshZodDto extends createZodDto(RefreshSchema) {}
