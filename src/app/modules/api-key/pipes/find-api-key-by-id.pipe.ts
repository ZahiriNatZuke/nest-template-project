import { ApiKeyService } from '@app/modules/api-key/api-key.service';
import {
	HttpException,
	HttpStatus,
	Injectable,
	PipeTransform,
} from '@nestjs/common';
import { z } from 'nestjs-zod/z';

@Injectable()
export class FindApiKeyByIdPipe implements PipeTransform {
	constructor(private apiKeyService: ApiKeyService) {}

	async transform(value: string) {
		const result = z.string().uuid('Invalid UUID').safeParse(value);
		if (!result.success)
			throw new HttpException(
				{
					message: result.error.message,
					error: result.error.errors,
				},
				HttpStatus.NOT_FOUND
			);

		try {
			return await this.apiKeyService.findOne({ id: result.data }, true);
		} catch (_) {
			throw new HttpException(
				{ message: 'Api Key not found' },
				HttpStatus.NOT_FOUND
			);
		}
	}
}
