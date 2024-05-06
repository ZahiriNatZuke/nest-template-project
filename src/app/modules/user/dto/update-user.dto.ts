import { z } from 'nestjs-zod/z';
import { createZodDto } from 'nestjs-zod';

export const UpdateUserSchema = z.object({
  username: z.string().optional(),
  email: z.string().email().optional(),
  fullName: z.string().optional(),
  confirmed: z.boolean().optional(),
  blocked: z.boolean().optional(),
  roleId: z.string().uuid().optional(),
});

export class UpdateUserZodDto extends createZodDto(UpdateUserSchema) {
}
