import {
  ArgumentMetadata,
  HttpStatus,
  Injectable,
  NotFoundException,
  ParseUUIDPipe,
  PipeTransform,
} from '@nestjs/common';
import { ApiKeyService } from '../../api-key.service';

@Injectable()
export class FindApiKeyByIdPipe implements PipeTransform {
  constructor(private apiKeyService: ApiKeyService) {
  }

  transform(value: string, metadata: ArgumentMetadata) {
    return new Promise(async (resolve, reject) => {
      const uuidPipe = new ParseUUIDPipe({
        version: '4',
        errorHttpStatusCode: HttpStatus.BAD_REQUEST,
      });
      await uuidPipe.transform(value, metadata).then(async (id) => {
        try {
          const apiKey = await this.apiKeyService.findOne({ id }, true);
          resolve(apiKey);
        } catch ( _ ) {
          reject(new NotFoundException('Api key not found'));
        }
      });
    });
  }
}
