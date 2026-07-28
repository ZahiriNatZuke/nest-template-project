import { SettingsService } from '@app/modules/settings/settings.service';
import {
	HttpException,
	HttpStatus,
	Injectable,
	PipeTransform,
} from '@nestjs/common';

/**
 * Resolves the `:key` route parameter to its Settings row.
 *
 * This used to validate the value as a UUID and then look the row up by `id` —
 * the body of FindUserByIdPipe, copied across without adapting it. Since the
 * routes are `/settings/:key` and a key is an arbitrary string like
 * `maintenance_mode`, the UUID check rejected every real key and
 * GET, PATCH and DELETE all answered 404 for anything that existed.
 *
 * `key` is `@unique` in the schema, so it identifies a row on its own.
 */
@Injectable()
export class FindSettingByKeyPipe implements PipeTransform {
	constructor(private settingsService: SettingsService) {}

	async transform(value: string) {
		const key = value?.trim();

		if (!key) {
			throw new HttpException(
				{ message: 'Setting key is required' },
				HttpStatus.NOT_FOUND
			);
		}

		try {
			return await this.settingsService.findOne({ key }, true);
		} catch (_) {
			throw new HttpException(
				{ message: 'Setting not found' },
				HttpStatus.NOT_FOUND
			);
		}
	}
}
