import { HttpExceptionFilter } from '@app/core/filters';

describe('HttpExceptionFilter', () => {
	it('should be defined', () => {
		expect(new HttpExceptionFilter()).toBeDefined();
	});
});
