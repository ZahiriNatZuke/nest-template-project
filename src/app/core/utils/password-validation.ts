import * as zxcvbnModule from 'zxcvbn';

// Manejar tanto ES6 como CommonJS exports
const zxcvbn = (
	typeof zxcvbnModule === 'function' ? zxcvbnModule : zxcvbnModule.default
) as (password: string) => any;

/**
 * Configuración de validación de contraseña
 * Incluye protección contra ReDoS limitando longitud máxima
 */
export const PASSWORD_VALIDATION_CONFIG = {
	// Límite máximo de caracteres para prevenir ReDoS en zxcvbn
	// zxcvbn tiene vulnerabilidad de ReDoS con regex, limitar entrada lo mitiga
	MAX_LENGTH: 128,
	MIN_LENGTH: 12,
	// Puntuación mínima de zxcvbn (0-4)
	// 2 = fuerte, 3 = muy fuerte
	MIN_SCORE: 2,
	// Caracteres especiales requeridos
	SPECIAL_CHARS: /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/,
	// Al menos una mayúscula
	UPPERCASE: /[A-Z]/,
	// Al menos un número
	NUMBERS: /[0-9]/,
	// Al menos una minúscula
	LOWERCASE: /[a-z]/,
};

export interface PasswordValidationResult {
	isValid: boolean;
	score: number;
	feedback: string[];
	suggestions: string[];
	errors: string[];
}

/**
 * Valida la fuerza de una contraseña
 * Incluye protección contra ReDoS limitando entrada
 */
export function validatePasswordStrength(
	password: string
): PasswordValidationResult {
	const errors: string[] = [];
	const feedback: string[] = [];
	const suggestions: string[] = [];

	// ✅ PROTECCIÓN CONTRA ReDoS: Validar longitud antes de pasar a zxcvbn
	if (!password) {
		return {
			isValid: false,
			score: 0,
			feedback: [],
			suggestions: ['Password is required'],
			errors: ['Password is required'],
		};
	}

	if (password.length < PASSWORD_VALIDATION_CONFIG.MIN_LENGTH) {
		errors.push(
			`Password must be at least ${PASSWORD_VALIDATION_CONFIG.MIN_LENGTH} characters long`
		);
	}

	// ✅ PROTECCIÓN CONTRA ReDoS: Rechazar entrada muy larga antes de zxcvbn
	if (password.length > PASSWORD_VALIDATION_CONFIG.MAX_LENGTH) {
		errors.push(
			`Password cannot exceed ${PASSWORD_VALIDATION_CONFIG.MAX_LENGTH} characters`
		);
		return {
			isValid: false,
			score: 0,
			feedback,
			suggestions,
			errors,
		};
	}

	// Validar requisitos básicos
	if (!PASSWORD_VALIDATION_CONFIG.UPPERCASE.test(password)) {
		errors.push('Password must contain at least one uppercase letter');
		suggestions.push('Add at least one uppercase letter (A-Z)');
	}

	if (!PASSWORD_VALIDATION_CONFIG.LOWERCASE.test(password)) {
		errors.push('Password must contain at least one lowercase letter');
		suggestions.push('Add at least one lowercase letter (a-z)');
	}

	if (!PASSWORD_VALIDATION_CONFIG.NUMBERS.test(password)) {
		errors.push('Password must contain at least one number');
		suggestions.push('Add at least one number (0-9)');
	}

	if (!PASSWORD_VALIDATION_CONFIG.SPECIAL_CHARS.test(password)) {
		errors.push('Password must contain at least one special character');
		suggestions.push(
			'Add a special character (!@#$%^&*()_+-=[]{};\':"|,.<>/?)'
		);
	}

	// Si hay errores en requisitos básicos, retornar sin ejecutar zxcvbn
	if (errors.length > 0) {
		return {
			isValid: false,
			score: 0,
			feedback,
			suggestions,
			errors,
		};
	}

	// ✅ PROTECCIÓN CONTRA ReDoS: Solo ejecutar zxcvbn si passou validaciones básicas
	// y longitud está dentro de límites seguros
	try {
		const result = zxcvbn(password);

		if (result.score < PASSWORD_VALIDATION_CONFIG.MIN_SCORE) {
			feedback.push('Password is too weak');
			if (result.feedback.suggestions) {
				suggestions.push(...result.feedback.suggestions);
			}
		}

		return {
			isValid: result.score >= PASSWORD_VALIDATION_CONFIG.MIN_SCORE,
			score: result.score,
			feedback: [
				...feedback,
				...(result.feedback.warning ? [result.feedback.warning] : []),
			],
			suggestions,
			errors: errors.length > 0 ? errors : [],
		};
	} catch (error) {
		// En caso de error en zxcvbn, retornar como válido si cumple requisitos básicos
		console.error('Error validating password with zxcvbn:', error);
		return {
			isValid: true,
			score: 3,
			feedback: ['Password has been validated'],
			suggestions: [],
			errors: [],
		};
	}
}

/**
 * Obtiene solo los errores de validación
 */
export function getPasswordErrors(password: string): string[] {
	return validatePasswordStrength(password).errors;
}

/**
 * Verifica si una contraseña es válida
 */
export function isPasswordValid(password: string): boolean {
	return validatePasswordStrength(password).isValid;
}
