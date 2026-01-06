import {
	HttpException,
	HttpStatus,
	Injectable,
	PipeTransform,
} from '@nestjs/common';
import { z } from 'zod';
import { UserService } from '../user.service';

@Injectable()
export class FindUserByIdPipe implements PipeTransform {
	constructor(private userService: UserService) {}

	async transform(value: string) {
		const result = z.string().uuid('Invalid UUID').safeParse(value);
		if (!result.success)
			throw new HttpException(
				{
					message: result.error.message,
					error: result.error.issues,
				},
				HttpStatus.NOT_FOUND
			);

		try {
			return await this.userService.findOne({ id: result.data }, true);
		} catch (_) {
			throw new HttpException(
				{ message: 'User not found' },
				HttpStatus.NOT_FOUND
			);
		}
	}
}
