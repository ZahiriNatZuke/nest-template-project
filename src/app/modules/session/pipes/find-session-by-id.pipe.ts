import { SessionService } from '@app/modules/session/session.service';
import {
	HttpException,
	HttpStatus,
	Injectable,
	PipeTransform,
} from '@nestjs/common';
import { z } from 'nestjs-zod/z';

@Injectable()
export class FindSessionByIdPipe implements PipeTransform {
	constructor(private sessionService: SessionService) {}

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
			return await this.sessionService.findOne({ id: result.data }, true);
		} catch (_) {
			throw new HttpException(
				{ message: 'Session not found' },
				HttpStatus.NOT_FOUND
			);
		}
	}
}
