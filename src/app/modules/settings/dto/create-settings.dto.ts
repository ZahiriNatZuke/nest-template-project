import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const CreateSettingsSchema = z.object({
	key: z.string(),
	value: z.any(),
});

export class CreateSettingsZodDto extends createZodDto(CreateSettingsSchema) {}
