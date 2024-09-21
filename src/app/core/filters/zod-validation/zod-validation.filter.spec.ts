import { ZodValidationExceptionFilter } from '@app/core/filters';

describe('ZodValidationFilter', () => {
	it('should be defined', () => {
		expect(new ZodValidationExceptionFilter()).toBeDefined();
	});
});
