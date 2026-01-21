import { getPasswordErrors } from '@app/core/utils/password-validation';
import { BadRequestException, Injectable, PipeTransform } from '@nestjs/common';

/**
 * Pipe para validar la fuerza de contraseña en DTOs
 * Uso: @Body(new PasswordStrengthPipe()) dto: CreateUserDto
 */
@Injectable()
export class PasswordStrengthPipe implements PipeTransform {
	transform(value: Record<string, unknown>): Record<string, unknown> {
		// Buscar campos de contraseña en común
		const passwordFields = ['password', 'newPassword', 'confirmPassword'];

		for (const field of passwordFields) {
			if (value[field] && typeof value[field] === 'string') {
				const errors = getPasswordErrors(value[field] as string);
				if (errors.length > 0) {
					throw new BadRequestException({
						statusCode: 400,
						message: 'Password does not meet security requirements',
						errors,
						details: {
							field,
							requirements: {
								minLength: 12,
								maxLength: 128,
								uppercase: 'At least one uppercase letter (A-Z)',
								lowercase: 'At least one lowercase letter (a-z)',
								numbers: 'At least one number (0-9)',
								specialChars:
									'At least one special character (!@#$%^&*()_+-=[]{};\':"|,.<>/?)',
								strength: 'Strong password (score >= 2)',
							},
						},
					});
				}
			}
		}

		return value;
	}
}
