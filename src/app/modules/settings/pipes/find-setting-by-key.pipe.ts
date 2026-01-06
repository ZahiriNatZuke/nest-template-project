import { SettingsService } from '@app/modules/settings/settings.service';
import {
	HttpException,
	HttpStatus,
	Injectable,
	PipeTransform,
} from '@nestjs/common';
import { z } from 'zod';

@Injectable()
export class FindSettingByKeyPipe implements PipeTransform {
	constructor(private settingsService: SettingsService) {}

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
			return await this.settingsService.findOne({ id: result.data }, true);
		} catch (_) {
			throw new HttpException(
				{ message: 'Setting not found' },
				HttpStatus.NOT_FOUND
			);
		}
	}
}
