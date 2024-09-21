import { createZodDto } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

export const UpdateManySettingsSchema = z.object({
	data: z.array(
		z.object({
			key: z.string(),
			value: z.any({
				required_error: 'Value is required',
			}),
		})
	),
});

export class UpdateManySettingsZodDto extends createZodDto(
	UpdateManySettingsSchema
) {}
