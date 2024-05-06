import { z } from 'nestjs-zod/z';
import { createZodDto } from 'nestjs-zod';

export const UpdateSettingsSchema = z.object({
  value: z.any({
    required_error: 'Value is required',
  }),
});

export class UpdateSettingsZodDto extends createZodDto(UpdateSettingsSchema) {
}
