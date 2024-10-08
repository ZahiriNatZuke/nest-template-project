import { createZodDto } from 'nestjs-zod';
import { z } from 'nestjs-zod/z';

export const CreateUserSchema = z.object({
	username: z.string(),
	email: z.string().email(),
	fullName: z.string(),
	password: z
		.password()
		.min(8, 'Password must be at least 8 characters long')
		.atLeastOne(
			'lowercase',
			'Password must contain at least one lowercase letter'
		)
		.atLeastOne(
			'uppercase',
			'Password must contain at least one uppercase letter'
		)
		.atLeastOne('digit', 'Password must contain at least one number')
		.atLeastOne(
			'special',
			'Password must contain at least one special character'
		),
});

export class CreateUserZodDto extends createZodDto(CreateUserSchema) {}
