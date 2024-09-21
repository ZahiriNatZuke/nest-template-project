import { SettingsService } from '@app/modules/settings/settings.service';
import { Injectable, NotFoundException, PipeTransform } from '@nestjs/common';

@Injectable()
export class FindSettingByKeyPipe implements PipeTransform {
	constructor(private settingsService: SettingsService) {}

	transform(key: string) {
		return new Promise((resolve, reject) => {
			try {
				this.settingsService.findOne({ key }, true).then(setting => {
					resolve(setting);
				});
			} catch (_) {
				reject(new NotFoundException('Settings not found'));
			}
		});
	}
}
