import {
	getPasswordErrors,
	isPasswordValid,
	PASSWORD_VALIDATION_CONFIG,
	validatePasswordStrength,
} from './password-validation';

describe('validatePasswordStrength', () => {
	const STRONG = 'Tr0ub4dor&3xample!';

	describe('empty input', () => {
		it('rejects an empty password without reporting per-rule errors', () => {
			const result = validatePasswordStrength('');

			expect(result.isValid).toBe(false);
			expect(result.score).toBe(0);
			expect(result.errors).toEqual(['Password is required']);
			expect(result.suggestions).toEqual(['Password is required']);
		});
	});

	describe('length bounds', () => {
		it(`rejects a password shorter than ${PASSWORD_VALIDATION_CONFIG.MIN_LENGTH} characters`, () => {
			const result = validatePasswordStrength('Ab1!xyz');

			expect(result.isValid).toBe(false);
			expect(result.errors).toContain(
				`Password must be at least ${PASSWORD_VALIDATION_CONFIG.MIN_LENGTH} characters long`
			);
		});

		it('accepts a password exactly at the minimum length', () => {
			const atMinimum = 'Xk9#mQ2vLp4!'.slice(
				0,
				PASSWORD_VALIDATION_CONFIG.MIN_LENGTH
			);

			expect(atMinimum).toHaveLength(PASSWORD_VALIDATION_CONFIG.MIN_LENGTH);
			expect(validatePasswordStrength(atMinimum).errors).not.toContain(
				`Password must be at least ${PASSWORD_VALIDATION_CONFIG.MIN_LENGTH} characters long`
			);
		});

		// The max-length check is a ReDoS guard: zxcvbn must never see the input.
		it(`short-circuits above ${PASSWORD_VALIDATION_CONFIG.MAX_LENGTH} characters without running zxcvbn`, () => {
			const tooLong = `Aa1!${'x'.repeat(PASSWORD_VALIDATION_CONFIG.MAX_LENGTH)}`;

			const result = validatePasswordStrength(tooLong);

			expect(result.isValid).toBe(false);
			expect(result.score).toBe(0);
			expect(result.errors).toEqual([
				`Password cannot exceed ${PASSWORD_VALIDATION_CONFIG.MAX_LENGTH} characters`,
			]);
			// Only the length error — the character-class rules never ran.
			expect(result.errors).toHaveLength(1);
		});

		it('accepts a password exactly at the maximum length', () => {
			const atMaximum = `Aa1!${'xKq7#'.repeat(100)}`.slice(
				0,
				PASSWORD_VALIDATION_CONFIG.MAX_LENGTH
			);

			expect(atMaximum).toHaveLength(PASSWORD_VALIDATION_CONFIG.MAX_LENGTH);
			expect(validatePasswordStrength(atMaximum).errors).not.toContain(
				`Password cannot exceed ${PASSWORD_VALIDATION_CONFIG.MAX_LENGTH} characters`
			);
		});
	});

	describe('character class requirements', () => {
		it.each([
			['no uppercase', 'tr0ub4dor&3xample!', 'uppercase letter'],
			['no lowercase', 'TR0UB4DOR&3XAMPLE!', 'lowercase letter'],
			['no number', 'Troubadour&Example!', 'number'],
			['no special character', 'Tr0ub4dor3xample1', 'special character'],
		])('rejects a password with %s', (_label, password, expected) => {
			const result = validatePasswordStrength(password);

			expect(result.isValid).toBe(false);
			expect(result.errors.join(' ')).toContain(expected);
		});

		it('reports every failing rule at once instead of stopping at the first', () => {
			const result = validatePasswordStrength('aaaaaaaaaaaaaaaa');

			expect(result.errors).toHaveLength(3); // uppercase, number, special
			expect(result.suggestions).toHaveLength(3);
		});

		it('returns score 0 and skips zxcvbn when a basic rule fails', () => {
			// Long and high-entropy, but with no uppercase: zxcvbn would score it
			// highly, so a non-zero score here would mean it ran anyway.
			const result = validatePasswordStrength('9x#kq7&vm2!zpw4$hn8');

			expect(result.score).toBe(0);
			expect(result.isValid).toBe(false);
		});
	});

	describe('strength scoring', () => {
		it('accepts a strong password that satisfies every rule', () => {
			const result = validatePasswordStrength(STRONG);

			expect(result.isValid).toBe(true);
			expect(result.score).toBeGreaterThanOrEqual(
				PASSWORD_VALIDATION_CONFIG.MIN_SCORE
			);
			expect(result.errors).toEqual([]);
		});

		it('rejects a password that passes every rule but scores too low', () => {
			// Satisfies all four character classes and the length floor, yet is a
			// well-known weak pattern that zxcvbn scores below MIN_SCORE.
			const result = validatePasswordStrength('Password123!');

			expect(result.score).toBeLessThan(PASSWORD_VALIDATION_CONFIG.MIN_SCORE);
			expect(result.isValid).toBe(false);
			expect(result.feedback).toContain('Password is too weak');
			expect(result.errors).toEqual([]);
		});
	});
});

describe('getPasswordErrors', () => {
	it('returns the errors of the underlying validation', () => {
		expect(getPasswordErrors('short')).toEqual(
			validatePasswordStrength('short').errors
		);
	});

	it('returns an empty array for a strong password', () => {
		expect(getPasswordErrors('Tr0ub4dor&3xample!')).toEqual([]);
	});
});

describe('isPasswordValid', () => {
	it.each([
		['Tr0ub4dor&3xample!', true],
		['Password123!', false],
		['short', false],
		['', false],
	])('returns %s -> %s', (password, expected) => {
		expect(isPasswordValid(password as string)).toBe(expected);
	});
});
