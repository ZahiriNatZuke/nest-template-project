import { SessionService } from '@app/modules/session/session.service';
import {
	ArgumentMetadata,
	HttpStatus,
	Injectable,
	NotFoundException,
	ParseUUIDPipe,
	PipeTransform,
} from '@nestjs/common';

@Injectable()
export class FindSessionByIdPipe implements PipeTransform {
	constructor(private sessionService: SessionService) {}

	transform(value: string, metadata: ArgumentMetadata) {
		return new Promise((resolve, reject) => {
			const uuidPipe = new ParseUUIDPipe({
				version: '4',
				errorHttpStatusCode: HttpStatus.BAD_REQUEST,
			});
			uuidPipe
				.transform(value, metadata)
				.then(async id => {
					try {
						const session = await this.sessionService.findOne({ id }, true);
						resolve(session);
					} catch (_) {
						reject(new NotFoundException('Session not found'));
					}
				})
				.catch(() => reject(new NotFoundException('UUID not valid')));
		});
	}
}
