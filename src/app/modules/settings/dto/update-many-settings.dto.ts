import { z } from 'nestjs-zod/z';
import { createZodDto } from 'nestjs-zod';

export class UpdateSetting {
  key: string;
  value: any;
}

export const UpdateManySettingsSchema = z.object({
  data: z.array(
    z.object({
      key: z.string(),
      value: z.any({
        required_error: 'Value is required',
      }),
    }),
  ),
});

export class UpdateManySettingsZodDto extends createZodDto(UpdateManySettingsSchema) {
}
