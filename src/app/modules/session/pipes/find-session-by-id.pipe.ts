import { SessionService } from '@app/modules/session/session.service';
import {
	HttpException,
	HttpStatus,
	Injectable,
	PipeTransform,
} from '@nestjs/common';
import { z } from 'zod';

@Injectable()
export class FindSessionByIdPipe implements PipeTransform {
	constructor(private sessionService: SessionService) {}

	async transform(value: string) {
		const result = z.uuid('Invalid UUID').safeParse(value);
		if (!result.success)
			throw new HttpException(
				{
					message: result.error.message,
					error: result.error.issues,
				},
				HttpStatus.NOT_FOUND
			);

		try {
			return await this.sessionService.findOne({ id: result.data }, true);
		} catch (_) {
			throw new HttpException(
				{ message: 'Session not found' },
				HttpStatus.NOT_FOUND
			);
		}
	}
}
