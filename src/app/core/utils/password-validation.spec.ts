import {
	getPasswordErrors,
	isPasswordValid,
	PASSWORD_VALIDATION_CONFIG,
	validatePasswordStrength,
} from './password-validation';

describe('Password Validation Utils', () => {
	describe('validatePasswordStrength', () => {
		it('should reject empty password', () => {
			const result = validatePasswordStrength('');
			expect(result.isValid).toBe(false);
			expect(result.errors).toContain('Password is required');
		});

		it('should reject password shorter than minimum', () => {
			const result = validatePasswordStrength('Short1!');
			expect(result.isValid).toBe(false);
			expect(result.errors.length).toBeGreaterThan(0);
		});

		it('should reject password longer than maximum', () => {
			const longPassword = `A${'b'.repeat(200)}1!`;
			const result = validatePasswordStrength(longPassword);
			expect(result.isValid).toBe(false);
			expect(result.errors).toContain(
				`Password cannot exceed ${PASSWORD_VALIDATION_CONFIG.MAX_LENGTH} characters`
			);
		});

		it('should reject password without uppercase', () => {
			const result = validatePasswordStrength('password123!');
			expect(result.isValid).toBe(false);
			expect(result.errors).toContain(
				'Password must contain at least one uppercase letter'
			);
		});

		it('should reject password without lowercase', () => {
			const result = validatePasswordStrength('PASSWORD123!');
			expect(result.isValid).toBe(false);
			expect(result.errors).toContain(
				'Password must contain at least one lowercase letter'
			);
		});

		it('should reject password without numbers', () => {
			const result = validatePasswordStrength('PasswordTest!');
			expect(result.isValid).toBe(false);
			expect(result.errors).toContain(
				'Password must contain at least one number'
			);
		});

		it('should reject password without special characters', () => {
			const result = validatePasswordStrength('PasswordTest123');
			expect(result.isValid).toBe(false);
			expect(result.errors).toContain(
				'Password must contain at least one special character'
			);
		});

		it('should accept strong password', () => {
			const result = validatePasswordStrength('StrongPass123!@#');
			expect(result.isValid).toBe(true);
			expect(result.errors.length).toBe(0);
			expect(result.score).toBeGreaterThanOrEqual(
				PASSWORD_VALIDATION_CONFIG.MIN_SCORE
			);
		});

		it('should accept very strong password', () => {
			const result = validatePasswordStrength('MySuper$ecureP@ssw0rd!');
			expect(result.isValid).toBe(true);
			expect(result.score).toBeGreaterThanOrEqual(
				PASSWORD_VALIDATION_CONFIG.MIN_SCORE
			);
		});

		it('should provide suggestions for weak passwords', () => {
			const result = validatePasswordStrength('password123!');
			expect(result.suggestions.length).toBeGreaterThan(0);
		});

		it('should handle various special characters', () => {
			const specialChars = [
				'Pasw0rd!@#$%',
				'Pasw0rd^&*()',
				'Pasw0rd-_+=[]',
				'Pasw0rd{}|:";',
				'Pasw0rd<>,?/',
			];

			specialChars.forEach(password => {
				const result = validatePasswordStrength(password);
				expect(result.isValid).toBe(true);
			});
		});

		it('should be at max length boundary', () => {
			const maxPassword = `A${'b'.repeat(PASSWORD_VALIDATION_CONFIG.MAX_LENGTH - 3)}1!`;
			const result = validatePasswordStrength(maxPassword);
			expect(result.isValid).toBe(true);
		});

		// ReDoS Protection Tests
		it('should protect against ReDoS by rejecting very long passwords', () => {
			const veryLongPassword = `A${'a'.repeat(500)}1!${'X'.repeat(500)}`;
			const result = validatePasswordStrength(veryLongPassword);
			expect(result.isValid).toBe(false);
			expect(result.errors).toContain(
				`Password cannot exceed ${PASSWORD_VALIDATION_CONFIG.MAX_LENGTH} characters`
			);
		});

		it('should handle special regex characters safely', () => {
			const result = validatePasswordStrength('Pass.*+?^${}()|[]\\word1!');
			// Should not crash or timeout
			expect(result).toBeDefined();
		});

		it('should handle repeating patterns safely', () => {
			const result = validatePasswordStrength(`Aa${'0'.repeat(50)}!`);
			// Should not crash or timeout
			expect(result).toBeDefined();
		});
	});

	describe('isPasswordValid', () => {
		it('should return true for valid password', () => {
			expect(isPasswordValid('ValidPass123!')).toBe(true);
		});

		it('should return false for invalid password', () => {
			expect(isPasswordValid('weak')).toBe(false);
		});
	});

	describe('getPasswordErrors', () => {
		it('should return empty array for valid password', () => {
			const errors = getPasswordErrors('ValidPass123!');
			expect(errors).toEqual([]);
		});

		it('should return array of errors for invalid password', () => {
			const errors = getPasswordErrors('password');
			expect(errors.length).toBeGreaterThan(0);
			expect(Array.isArray(errors)).toBe(true);
		});
	});

	describe('PASSWORD_VALIDATION_CONFIG', () => {
		it('should have appropriate limits for ReDoS protection', () => {
			expect(PASSWORD_VALIDATION_CONFIG.MAX_LENGTH).toBeLessThanOrEqual(256);
			expect(PASSWORD_VALIDATION_CONFIG.MIN_LENGTH).toBeGreaterThanOrEqual(8);
		});

		it('should have MIN_LENGTH less than MAX_LENGTH', () => {
			expect(PASSWORD_VALIDATION_CONFIG.MIN_LENGTH).toBeLessThan(
				PASSWORD_VALIDATION_CONFIG.MAX_LENGTH
			);
		});

		it('should have MIN_SCORE between 0 and 4', () => {
			expect(PASSWORD_VALIDATION_CONFIG.MIN_SCORE).toBeGreaterThanOrEqual(0);
			expect(PASSWORD_VALIDATION_CONFIG.MIN_SCORE).toBeLessThanOrEqual(4);
		});
	});
});
