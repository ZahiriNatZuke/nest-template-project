import { BadRequestException } from '@nestjs/common';
import { ZodError, ZodSchema, ZodTypeAny, z } from 'zod';

// Custom exception to carry the ZodError
export class ZodValidationException extends BadRequestException {
	constructor(
		public readonly zodError: ZodError,
		message = 'Validation failed'
	) {
		super(message);
	}
}

// Helper that mimics nestjs-zod createZodDto: attaches schema to class for the pipe
export function createZodDto<T extends ZodTypeAny>(schema: T) {
	// biome-ignore lint/complexity/noStaticOnlyClass: zod dto class factory
	class ZodDtoClass {
		static schema: ZodSchema = schema;
	}
	// Cast to class so Nest can instantiate and type inference can work on controllers
	return ZodDtoClass as unknown as { new (): z.infer<T>; schema: ZodSchema };
}

// Utility to extract schema from a metatype
export const getZodSchema = (metatype?: unknown): ZodSchema | undefined => {
	if (!metatype || typeof metatype !== 'function') return undefined;
	return (metatype as { schema?: ZodSchema }).schema;
};
