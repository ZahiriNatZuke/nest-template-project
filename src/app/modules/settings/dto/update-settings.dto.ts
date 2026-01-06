import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const UpdateSettingsSchema = z.object({
	value: z.any(),
});

export class UpdateSettingsZodDto extends createZodDto(UpdateSettingsSchema) {}
