import { createZodDto } from '@app/core/utils/zod';
import { z } from 'zod';

export const UpdateManySettingsSchema = z.object({
	data: z.array(
		z.object({
			key: z.string(),
			value: z.any(),
		})
	),
});

export class UpdateManySettingsZodDto extends createZodDto(
	UpdateManySettingsSchema
) {}
