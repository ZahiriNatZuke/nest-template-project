import { z } from 'nestjs-zod/z';
import { createZodDto } from 'nestjs-zod';

export const LoginSchema = z.object({
  identifier: z.string().max(128),
  password: z.password()
    .min(8, 'Password must be at least 8 characters long')
    .atLeastOne('lowercase', 'Password must contain at least one lowercase letter')
    .atLeastOne('uppercase', 'Password must contain at least one uppercase letter')
    .atLeastOne('digit', 'Password must contain at least one number')
    .atLeastOne('special', 'Password must contain at least one special character'),
  device: z.string(),
});

export class LoginZodDto extends createZodDto(LoginSchema) {
}
