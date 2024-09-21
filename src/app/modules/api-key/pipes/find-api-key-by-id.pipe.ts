import { ApiKeyService } from '@app/modules/api-key/api-key.service';
import {
	ArgumentMetadata,
	HttpStatus,
	Injectable,
	NotFoundException,
	ParseUUIDPipe,
	PipeTransform,
} from '@nestjs/common';

@Injectable()
export class FindApiKeyByIdPipe implements PipeTransform {
	constructor(private apiKeyService: ApiKeyService) {}

	transform(value: string, metadata: ArgumentMetadata) {
		return new Promise((resolve, reject) => {
			const uuidPipe = new ParseUUIDPipe({
				version: '4',
				errorHttpStatusCode: HttpStatus.BAD_REQUEST,
			});
			uuidPipe.transform(value, metadata).then(async id => {
				try {
					const apiKey = await this.apiKeyService.findOne({ id }, true);
					resolve(apiKey);
				} catch (_) {
					reject(new NotFoundException('Api key not found'));
				}
			});
		});
	}
}
