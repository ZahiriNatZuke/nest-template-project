import {
	ArgumentMetadata,
	Injectable,
	Logger,
	PipeTransform,
} from '@nestjs/common';
import { ZodSchema } from 'zod';
import { getZodSchema, ZodValidationException } from '../utils/zod';

@Injectable()
export class ZodValidationPipe implements PipeTransform {
	private readonly logger = new Logger(ZodValidationPipe.name);

	transform(value: unknown, metadata: ArgumentMetadata) {
		// Only validate if metatype is explicitly available and has a schema
		if (!metadata.metatype || metadata.type === 'custom') {
			return value;
		}

		const schema = getZodSchema(metadata.metatype);
		if (!schema) {
			return value;
		}

		this.logger.debug(
			`Validating ${metadata.type} (${metadata.metatype?.name}) with value: ${JSON.stringify(value)}`
		);

		const result = (schema as ZodSchema).safeParse(value);
		if (result.success) {
			return result.data;
		}

		this.logger.warn(
			`Validation failed for ${metadata.metatype?.name}: ${JSON.stringify(result.error.issues)}`
		);

		// Throw custom exception carrying the ZodError
		throw new ZodValidationException(result.error);
	}
}
