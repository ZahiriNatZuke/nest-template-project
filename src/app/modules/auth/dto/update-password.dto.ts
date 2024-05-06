import { z } from 'nestjs-zod/z';
import { createZodDto } from 'nestjs-zod';

export const UpdatePasswordSchema = z.object({
  current_password: z.password()
    .min(8, 'Current Password must be at least 8 characters long')
    .atLeastOne('lowercase', 'Current Password must contain at least one lowercase letter')
    .atLeastOne('uppercase', 'Current Password must contain at least one uppercase letter')
    .atLeastOne('digit', 'Current Password must contain at least one number')
    .atLeastOne('special', 'Current Password must contain at least one special character'),
  new_password: z.password()
    .min(8, 'New Password must be at least 8 characters long')
    .atLeastOne('lowercase', 'New Password must contain at least one lowercase letter')
    .atLeastOne('uppercase', 'New Password must contain at least one uppercase letter')
    .atLeastOne('digit', 'New Password must contain at least one number')
    .atLeastOne('special', 'New Password must contain at least one special character'),
  confirm_new_password: z.password()
    .min(8, 'Confirmation New Password must be at least 8 characters long')
    .atLeastOne('lowercase', 'Confirmation New Password must contain at least one lowercase letter')
    .atLeastOne('uppercase', 'Confirmation New Password must contain at least one uppercase letter')
    .atLeastOne('digit', 'Confirmation New Password must contain at least one number')
    .atLeastOne('special', 'Confirmation New Password must contain at least one special character'),
});

export class UpdatePasswordZodDto extends createZodDto(UpdatePasswordSchema) {
}
