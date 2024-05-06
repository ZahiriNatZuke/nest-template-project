import { z } from 'nestjs-zod/z';
import { createZodDto } from 'nestjs-zod';

export const CreateRoleSchema = z.object({
  identifier: z.string(),
  name: z.string(),
});

export class CreateRoleZodDto extends createZodDto(CreateRoleSchema) {
}
