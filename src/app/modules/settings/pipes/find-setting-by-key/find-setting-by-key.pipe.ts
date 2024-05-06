import { Injectable, NotFoundException, PipeTransform } from '@nestjs/common';
import { SettingsService } from '../../settings.service';

@Injectable()
export class FindSettingByKeyPipe implements PipeTransform {
  constructor(private settingsService: SettingsService) {
  }

  transform(key: string) {
    return new Promise(async (resolve, reject) => {
      try {
        const setting = await this.settingsService.findOne({ key }, true);
        resolve(setting);
      } catch ( _ ) {
        reject(new NotFoundException('Settings not found'));
      }
    });
  }
}
