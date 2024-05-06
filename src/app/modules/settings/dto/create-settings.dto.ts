import { z } from 'nestjs-zod/z';
import { createZodDto } from 'nestjs-zod';

export const CreateSettingsSchema = z.object({
  key: z.string(),
  value: z.any({
    required_error: 'Value is required',
  }),
});

export class CreateSettingsZodDto extends createZodDto(CreateSettingsSchema) {
}
